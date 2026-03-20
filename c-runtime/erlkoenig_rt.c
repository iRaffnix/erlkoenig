/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * erlkoenig_rt.c - Erlkoenig container runtime.
 *
 * This is the privileged C component that creates and manages
 * containerised processes in isolated Linux namespaces. It
 * communicates with the Erlang control plane via the Erlkoenig
 * wire protocol ({packet, 4} framing).
 *
 * Two I/O modes are supported:
 *
 *   Port mode (legacy, default):
 *     Erlang starts this as an Erlang Port with {packet, 4}.
 *     stdin = commands from Erlang, stdout = replies to Erlang.
 *     Connection loss (pipe break) terminates the runtime.
 *
 *   Socket mode (--socket PATH):
 *     The runtime creates a Unix Domain Socket and listens for
 *     connections. The protocol is identical ({packet, 4}).
 *     Connection loss does NOT terminate the runtime — the child
 *     process survives and the runtime waits for a reconnect.
 *     This enables crash recovery: the BEAM can crash and restart,
 *     then reconnect to the still-running container.
 *
 * Architecture: One erlkoenig_rt process per container.
 *
 * Responsibilities:
 *   - Receive commands (SPAWN, GO, KILL, QUERY_STATUS)
 *   - Create child process in new namespaces (PID, NET, MNT, UTS)
 *   - Wait for child exit, report back to Erlang
 *   - Clean up resources on exit
 *
 * stderr = debug logging (not part of protocol)
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include "erlkoenig_proto.h"
#include "erlkoenig_log.h"
#include "erlkoenig_cleanup.h"
#include "erlkoenig_ns.h"
#include "erlkoenig_netcfg.h"
#include "erlkoenig_devfilter.h"
#include "erlkoenig_metrics.h"
#include "erlkoenig_nodecert.h"

#define ERLKOENIG_MAX_MSG		(64 * 1024)

/* Event loop return codes */
#define LOOP_SHUTDOWN		0	/* Graceful shutdown requested */
#define LOOP_DISCONNECT		1	/* Connection lost (socket mode) */

/* Container state */
enum erlkoenig_state {
	STATE_IDLE = 0,		/* No container yet */
	STATE_CREATED,		/* Child cloned, waiting for GO */
	STATE_RUNNING,		/* Child is executing */
	STATE_STOPPED,		/* Child has exited */
};

static struct {
	enum erlkoenig_state state;
	struct erlkoenig_container ct;
	int exit_code;
	int term_signal;
	uint64_t started_at;		/* Monotonic clock (ms) */
	int stdout_open;		/* 1 if stdout pipe still readable */
	int stderr_open;		/* 1 if stderr pipe still readable */
	int pty_open;			/* 1 if pty_master still readable */
	struct ek_metrics_ctx metrics;	/* eBPF tracepoint metrics */
	int exit_pending;		/* 1 if child exited while disconnected */
} g_state;

/*
 * g_write_fd - The fd used for sending protocol replies.
 * In port mode: STDOUT_FILENO (set once at startup).
 * In socket mode: the accepted connection fd (changes on reconnect).
 */
static int g_write_fd = STDOUT_FILENO;

/*
 * g_read_fd - The fd used for reading protocol commands.
 * In port mode: STDIN_FILENO (set once at startup).
 * In socket mode: the accepted connection fd (same as g_write_fd).
 */
static int g_read_fd = STDIN_FILENO;

/*
 * g_connected - Whether we have an active Erlang connection.
 * In port mode: always 1 (connection loss = exit).
 * In socket mode: 0 when disconnected, 1 when connected.
 */
static int g_connected = 1;

/*
 * g_socket_mode - Whether we're running in socket mode.
 * 0 = port mode (legacy), 1 = socket mode.
 */
static int g_socket_mode;

/* Volatile flag set by SIGCHLD handler */
static volatile sig_atomic_t g_sigchld_received;

/* Volatile flag set by SIGTERM/SIGINT handler for graceful shutdown */
static volatile sig_atomic_t g_shutdown_requested;

/* -- Monotonic clock helper --------------------------------------- */

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* -- Reply helpers ------------------------------------------------ */

/*
 * send_reply - Write a reply frame to the Erlang connection.
 * @tag:	Message tag (ERLKOENIG_TAG_REPLY_*)
 * @payload:	Payload data (may be NULL if len == 0)
 * @len:	Payload length
 *
 * Builds <<Tag:8, Payload/binary>> and sends as {packet,4} frame.
 * Returns -1 if not connected or write fails.
 */
static int send_reply(uint8_t tag, const uint8_t *payload, size_t len)
{
	uint8_t frame[ERLKOENIG_MAX_MSG];
	size_t total = 1 + len;

	if (!g_connected)
		return -1;

	if (total > sizeof(frame)) {
		LOG_ERR("reply too large: %zu bytes", total);
		return -1;
	}

	frame[0] = tag;
	if (len > 0 && payload)
		memcpy(frame + 1, payload, len);

	return erlkoenig_write_frame(g_write_fd, frame, total);
}

static int send_reply_ok(const uint8_t *data, uint16_t data_len)
{
	uint8_t payload[2 + UINT16_MAX];
	struct erlkoenig_buf b;

	erlkoenig_buf_init(&b, payload, sizeof(payload));
	if (buf_write_u16(&b, data_len))
		return -1;
	if (data_len > 0 && buf_write_bytes(&b, data, data_len))
		return -1;

	return send_reply(ERLKOENIG_TAG_REPLY_OK, payload, b.pos);
}

static int send_reply_error(int32_t code, const char *msg)
{
	uint8_t payload[4 + 2 + ERLKOENIG_MAX_PATH];
	struct erlkoenig_buf b;
	uint16_t msg_len;

	if (!msg)
		msg = "unknown error";
	msg_len = (uint16_t)strlen(msg);

	erlkoenig_buf_init(&b, payload, sizeof(payload));
	if (buf_write_i32(&b, code))
		return -1;
	if (buf_write_str16(&b, msg, msg_len))
		return -1;

	return send_reply(ERLKOENIG_TAG_REPLY_ERROR, payload, b.pos);
}

static int send_reply_container_pid(uint32_t pid, const char *netns_path)
{
	uint8_t payload[4 + 2 + ERLKOENIG_NETNS_PATH_LEN];
	struct erlkoenig_buf b;
	uint16_t path_len = (uint16_t)strlen(netns_path);

	erlkoenig_buf_init(&b, payload, sizeof(payload));
	if (buf_write_u32(&b, pid))
		return -1;
	if (buf_write_str16(&b, netns_path, path_len))
		return -1;

	return send_reply(ERLKOENIG_TAG_REPLY_CONTAINER_PID, payload, b.pos);
}

static int send_reply_exited(int32_t exit_code, uint8_t term_signal)
{
	uint8_t payload[5];
	struct erlkoenig_buf b;

	erlkoenig_buf_init(&b, payload, sizeof(payload));
	if (buf_write_i32(&b, exit_code))
		return -1;
	if (buf_write_u8(&b, term_signal))
		return -1;

	return send_reply(ERLKOENIG_TAG_REPLY_EXITED, payload, b.pos);
}

static int send_reply_status(uint8_t state, uint32_t pid, uint64_t uptime_ms)
{
	uint8_t payload[13];
	struct erlkoenig_buf b;

	erlkoenig_buf_init(&b, payload, sizeof(payload));
	if (buf_write_u8(&b, state))
		return -1;
	if (buf_write_u32(&b, pid))
		return -1;
	if (buf_write_u64(&b, uptime_ms))
		return -1;

	return send_reply(ERLKOENIG_TAG_REPLY_STATUS, payload, b.pos);
}

/* -- Command handlers --------------------------------------------- */

/*
 * strbuf_copy - Copy a string into opts->strbuf, null-terminated.
 * Returns pointer to the copy, or NULL if strbuf is full.
 */
static char *strbuf_copy(struct erlkoenig_spawn_opts *opts,
			 const uint8_t *data, size_t len)
{
	if (opts->strbuf_used + len + 1 > sizeof(opts->strbuf))
		return NULL;

	char *dst = opts->strbuf + opts->strbuf_used;
	memcpy(dst, data, len);
	dst[len] = '\0';
	opts->strbuf_used += len + 1;
	return dst;
}

/*
 * handle_cmd_spawn - Create a new container.
 *
 * Wire: <<Path:str16, Args:list8(str16), Env:list8(kv(str8,str16)),
 *         Uid:32, Gid:32, SeccompProfile:8>>
 */
static void handle_cmd_spawn(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	struct erlkoenig_spawn_opts opts;
	const uint8_t *path_data;
	uint16_t path_len;
	int ret;

	if (g_state.state != STATE_IDLE) {
		send_reply_error(-EBUSY, "container already exists");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);
	memset(&opts, 0, sizeof(opts));

	/* Read path */
	if (buf_read_str16(&b, &path_data, &path_len)) {
		send_reply_error(-EINVAL, "failed to read path");
		return;
	}

	if (path_len == 0 || path_len >= ERLKOENIG_MAX_PATH) {
		send_reply_error(-ENAMETOOLONG, "path too long or empty");
		return;
	}

	memcpy(opts.binary_path, path_data, path_len);
	opts.binary_path[path_len] = '\0';

	/* argv[0] is always "/app" (the bind-mounted binary) */
	opts.argv[0] = (char *)"/app";
	opts.argc = 1;

	/* Read args: <<Count:8, [<<Len:16, Data/binary>>]>> */
	uint8_t num_args;

	if (buf_read_u8(&b, &num_args)) {
		send_reply_error(-EINVAL, "failed to read args count");
		return;
	}

	for (uint8_t i = 0; i < num_args; i++) {
		const uint8_t *arg_data;
		uint16_t arg_len;

		if (buf_read_str16(&b, &arg_data, &arg_len)) {
			send_reply_error(-EINVAL, "failed to read arg");
			return;
		}
		if (opts.argc >= ERLKOENIG_MAX_ARGS + 1) {
			send_reply_error(-E2BIG, "too many arguments");
			return;
		}
		opts.argv[opts.argc] = strbuf_copy(&opts, arg_data, arg_len);
		if (!opts.argv[opts.argc]) {
			send_reply_error(-ENOMEM, "args too large");
			return;
		}
		opts.argc++;
	}
	opts.argv[opts.argc] = NULL;

	/* Read env: <<Count:8, [<<KLen:8, Key, VLen:16, Value>>]>> */
	uint8_t num_env;

	if (buf_read_u8(&b, &num_env)) {
		send_reply_error(-EINVAL, "failed to read env count");
		return;
	}

	/* Default env entries */
	opts.envp[0] = (char *)"HOME=/tmp";
	opts.envp[1] = (char *)"PATH=/";
	opts.envc = 2;

	for (uint8_t i = 0; i < num_env; i++) {
		const uint8_t *key_data, *val_data;
		uint8_t key_len;
		uint16_t val_len;

		if (buf_read_str8(&b, &key_data, &key_len)) {
			send_reply_error(-EINVAL, "failed to read env key");
			return;
		}
		if (buf_read_str16(&b, &val_data, &val_len)) {
			send_reply_error(-EINVAL, "failed to read env value");
			return;
		}
		if (opts.envc >= ERLKOENIG_MAX_ENV) {
			send_reply_error(-E2BIG, "too many env vars");
			return;
		}

		/*
		 * Build "KEY=VALUE" string in strbuf.
		 * Need: key_len + 1 ('=') + val_len + 1 ('\0')
		 */
		size_t entry_len = (size_t)key_len + 1 + val_len;
		if (opts.strbuf_used + entry_len + 1 > sizeof(opts.strbuf)) {
			send_reply_error(-ENOMEM, "env too large");
			return;
		}
		char *dst = opts.strbuf + opts.strbuf_used;
		memcpy(dst, key_data, key_len);
		dst[key_len] = '=';
		memcpy(dst + key_len + 1, val_data, val_len);
		dst[entry_len] = '\0';
		opts.strbuf_used += entry_len + 1;

		opts.envp[opts.envc++] = dst;
	}
	opts.envp[opts.envc] = NULL;

	/* Read uid, gid, seccomp_profile, rootfs_size_mb */
	if (buf_read_u32(&b, &opts.uid))
		opts.uid = 65534;	/* nobody */
	if (buf_read_u32(&b, &opts.gid))
		opts.gid = 65534;
	if (buf_read_u8(&b, &opts.seccomp_profile))
		opts.seccomp_profile = 0;
	if (buf_read_u32(&b, &opts.rootfs_size_mb))
		opts.rootfs_size_mb = 0;	/* 0 = default 64 MB */
	if (buf_read_u64(&b, &opts.caps_keep))
		opts.caps_keep = 0;		/* 0 = drop all caps */
	if (buf_read_u32(&b, &opts.dns_ip))
		opts.dns_ip = 0;		/* 0 = default 10.0.0.1 */
	if (buf_read_u32(&b, &opts.flags))
		opts.flags = 0;

	/* Read volumes: <<NumVolumes:8, [<<SrcLen:16, Src, DstLen:16, Dst, Opts:32>>]*>>
	 * Optional: missing volume data (older Erlang core) → num_volumes = 0. */
	opts.num_volumes = 0;
	{
		uint8_t num_volumes;
		if (!buf_read_u8(&b, &num_volumes)) {
			if (num_volumes > ERLKOENIG_MAX_VOLUMES) {
				send_reply_error(-EINVAL, "too many volumes");
				return;
			}
			for (uint8_t i = 0; i < num_volumes; i++) {
				const uint8_t *src_data, *dst_data;
				uint16_t src_len, dst_len;
				uint32_t vol_opts;

				if (buf_read_str16(&b, &src_data, &src_len)) {
					send_reply_error(-EINVAL, "failed to read volume source");
					return;
				}
				if (buf_read_str16(&b, &dst_data, &dst_len)) {
					send_reply_error(-EINVAL, "failed to read volume dest");
					return;
				}
				if (buf_read_u32(&b, &vol_opts)) {
					send_reply_error(-EINVAL, "failed to read volume opts");
					return;
				}
				if (src_len >= ERLKOENIG_MAX_PATH - 1) {
					send_reply_error(-ENAMETOOLONG, "volume source too long");
					return;
				}
				if (dst_len >= ERLKOENIG_MAX_PATH - 1) {
					send_reply_error(-ENAMETOOLONG, "volume dest too long");
					return;
				}
				memcpy(opts.volumes[i].source, src_data, src_len);
				opts.volumes[i].source[src_len] = '\0';
				memcpy(opts.volumes[i].dest, dst_data, dst_len);
				opts.volumes[i].dest[dst_len] = '\0';
				opts.volumes[i].opts = vol_opts;
			}
			opts.num_volumes = num_volumes;
		}
	}

	LOG_INFO("SPAWN path=%s argc=%d envc=%d uid=%u gid=%u flags=0x%x",
		 opts.binary_path, opts.argc, opts.envc,
		 opts.uid, opts.gid, opts.flags);

	/* Do the actual spawn */
	ret = erlkoenig_spawn(&opts, &g_state.ct);
	if (ret) {
		send_reply_error((int32_t)ret, strerror(-ret));
		return;
	}

	g_state.state = STATE_CREATED;
	g_state.stdout_open = (g_state.ct.stdout_fd >= 0);
	g_state.stderr_open = (g_state.ct.stderr_fd >= 0);
	g_state.pty_open = (g_state.ct.pty_master >= 0);
	send_reply_container_pid((uint32_t)g_state.ct.child_pid,
				 g_state.ct.netns_path);
}

static void handle_cmd_go(void)
{
	int ret;

	if (g_state.state != STATE_CREATED) {
		send_reply_error(-EINVAL, "no container waiting for GO");
		return;
	}

	ret = erlkoenig_go(&g_state.ct);
	if (ret) {
		send_reply_error((int32_t)ret, strerror(-ret));
		return;
	}

	/*
	 * Check the execve error pipe. The write-end has O_CLOEXEC:
	 * if execve succeeds, it's closed (we read EOF = success).
	 * If execve fails, PID 2 writes errno before _exit(127).
	 *
	 * We read non-blocking here. The actual error may arrive
	 * later (child still in caps/seccomp setup), but we'll get
	 * the exit notification via SIGCHLD/reap_child in that case.
	 * This is a best-effort early detection.
	 */
	if (g_state.ct.exec_err_fd >= 0) {
		int exec_errno = 0;
		ssize_t n;

		/* Set non-blocking for the read attempt */
		int fl = fcntl(g_state.ct.exec_err_fd, F_GETFL);

		if (fl >= 0)
			fcntl(g_state.ct.exec_err_fd, F_SETFL,
			      fl | O_NONBLOCK);

		n = read(g_state.ct.exec_err_fd, &exec_errno,
			 sizeof(exec_errno));

		if (n == (ssize_t)sizeof(exec_errno) && exec_errno != 0) {
			LOG_ERR("execve failed: %s", strerror(exec_errno));
			/* Don't close yet -- reap_child will handle cleanup */
		}

		/* Restore blocking mode (reap_child may read it later) */
		if (fl >= 0)
			fcntl(g_state.ct.exec_err_fd, F_SETFL, fl);
	}

	g_state.state = STATE_RUNNING;
	g_state.started_at = monotonic_ms();
	send_reply_ok(NULL, 0);
}

static void handle_cmd_kill(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	uint8_t signal_num;

	if (g_state.state != STATE_CREATED &&
	    g_state.state != STATE_RUNNING) {
		send_reply_error(-EINVAL, "no container to kill");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);
	if (buf_read_u8(&b, &signal_num)) {
		send_reply_error(-EINVAL, "missing signal number");
		return;
	}
	if (signal_num == 0 || signal_num > 64) {
		send_reply_error(-EINVAL, "signal number out of range");
		return;
	}

	LOG_INFO("KILL signal=%u pid=%d",
		 signal_num, (int)g_state.ct.child_pid);

	if (kill(g_state.ct.child_pid, (int)signal_num)) {
		int err = errno;

		send_reply_error(-err, strerror(err));
		return;
	}

	send_reply_ok(NULL, 0);
}

/*
 * handle_cmd_net_setup - Configure networking inside the container's netns.
 *
 * Wire: <<IfName:str16, IpA:8, IpB:8, IpC:8, IpD:8,
 *          Prefixlen:8, GwA:8, GwB:8, GwC:8, GwD:8>>
 */
static void handle_cmd_net_setup(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	const uint8_t *ifname_data;
	uint16_t ifname_len;
	uint8_t ip_bytes[4], gw_bytes[4], prefixlen;
	char ifname[IF_NAMESIZE];
	uint32_t ip, gateway;
	int ret;

	if (g_state.state != STATE_CREATED) {
		send_reply_error(-EINVAL,
				 "net_setup requires state CREATED");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);

	if (buf_read_str16(&b, &ifname_data, &ifname_len)) {
		send_reply_error(-EINVAL, "failed to read ifname");
		return;
	}
	if (ifname_len == 0 || ifname_len >= IF_NAMESIZE) {
		send_reply_error(-EINVAL, "ifname too long or empty");
		return;
	}
	memcpy(ifname, ifname_data, ifname_len);
	ifname[ifname_len] = '\0';

	if (buf_read_bytes(&b, ip_bytes, 4) ||
	    buf_read_u8(&b, &prefixlen) ||
	    buf_read_bytes(&b, gw_bytes, 4)) {
		send_reply_error(-EINVAL, "failed to read net params");
		return;
	}

	memcpy(&ip, ip_bytes, 4);
	memcpy(&gateway, gw_bytes, 4);

	LOG_INFO("NET_SETUP if=%s ip=%u.%u.%u.%u/%u gw=%u.%u.%u.%u pid=%d",
		 ifname,
		 ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
		 prefixlen,
		 gw_bytes[0], gw_bytes[1], gw_bytes[2], gw_bytes[3],
		 (int)g_state.ct.child_pid);

	ret = erlkoenig_netcfg_setup(g_state.ct.child_pid, ifname,
				   ip, prefixlen, gateway);
	if (ret) {
		send_reply_error((int32_t)ret, strerror(-ret));
		return;
	}

	send_reply_ok(NULL, 0);
}

/*
 * handle_cmd_write_file - Write a file into the container rootfs.
 *
 * Wire: <<Path:str16, Mode:16, DataLen:32, Data/binary>>
 *
 * Path must be absolute, no ".." components, resolved relative
 * to the container rootfs. Missing parent directories are created.
 */
static void handle_cmd_write_file(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	const uint8_t *path_data, *file_data;
	uint16_t path_len, mode;
	uint32_t data_len;
	char path[1024];
	char full_path[ERLKOENIG_ROOTFS_MAX + 1024];
	int ret;

	if (g_state.state != STATE_CREATED) {
		send_reply_error(-EINVAL,
				 "write_file requires state CREATED");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);

	if (buf_read_str16(&b, &path_data, &path_len)) {
		send_reply_error(-EINVAL, "failed to read path");
		return;
	}
	if (path_len == 0 || path_len >= (uint16_t)sizeof(path)) {
		send_reply_error(-EINVAL, "path too long or empty");
		return;
	}
	memcpy(path, path_data, path_len);
	path[path_len] = '\0';

	if (buf_read_u16(&b, &mode)) {
		send_reply_error(-EINVAL, "failed to read mode");
		return;
	}

	if (buf_read_u32(&b, &data_len)) {
		send_reply_error(-EINVAL, "failed to read data length");
		return;
	}
	if (b.pos + data_len > b.len) {
		send_reply_error(-EINVAL, "data truncated");
		return;
	}
	file_data = b.data + b.pos;

	/* Validate path: must start with /, no .. components */
	if (path[0] != '/') {
		send_reply_error(-EINVAL, "path must be absolute");
		return;
	}
	if (strstr(path, "..")) {
		send_reply_error(-EINVAL, "path must not contain ..");
		return;
	}

	/*
	 * Enter the child's mount namespace via setns(), temporarily
	 * remount "/" read-write, write the file, restore read-only,
	 * then return to our original mount namespace.
	 *
	 * This is necessary because the child's rootfs (tmpfs) is
	 * only visible inside its mount namespace and is mounted
	 * read-only after pivot_root.
	 */
	{
		char ns_path[64];
		_cleanup_close_ int child_mnt_fd = -1;
		_cleanup_close_ int orig_mnt_fd = -1;

		/* Save our mount namespace */
		orig_mnt_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
		if (orig_mnt_fd < 0) {
			send_reply_error(-errno, "open(self ns/mnt)");
			return;
		}

		/* Open child's mount namespace */
		snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt",
			 (int)g_state.ct.child_pid);
		child_mnt_fd = open(ns_path, O_RDONLY | O_CLOEXEC);
		if (child_mnt_fd < 0) {
			send_reply_error(-errno, "open(child ns/mnt)");
			return;
		}

		/* Enter child's mount namespace */
		if (setns(child_mnt_fd, CLONE_NEWNS)) {
			send_reply_error(-errno, "setns(child mnt)");
			return;
		}

		/* Now "/" is the child's rootfs -- remount read-write */
		if (mount(NULL, "/", NULL, MS_REMOUNT | MS_BIND, NULL)) {
			int e = errno;
			setns(orig_mnt_fd, CLONE_NEWNS);
			send_reply_error(-e, "remount rw");
			return;
		}

		/* Build path (now relative to child's /) */
		ret = snprintf(full_path, sizeof(full_path), "%s", path);
		if (ret < 0 || (size_t)ret >= sizeof(full_path)) {
			mount(NULL, "/", NULL,
			      MS_REMOUNT | MS_RDONLY | MS_BIND, NULL);
			setns(orig_mnt_fd, CLONE_NEWNS);
			send_reply_error(-ENAMETOOLONG, "path too long");
			return;
		}

		/* Create parent directories (mkdir -p) */
		{
			char dir[sizeof(full_path)];

			snprintf(dir, sizeof(dir), "%s", full_path);
			for (char *p = dir + 1; *p; p++) {
				if (*p == '/') {
					*p = '\0';
					mkdir(dir, 0755);
					*p = '/';
				}
			}
		}

		/* Write file */
		{
			int fd = open(full_path,
				      O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
				      (mode_t)mode);
			if (fd < 0) {
				int e = errno;
				mount(NULL, "/", NULL,
				      MS_REMOUNT | MS_RDONLY | MS_BIND, NULL);
				setns(orig_mnt_fd, CLONE_NEWNS);
				send_reply_error(-e, "open failed");
				return;
			}

			size_t written = 0;

			while (written < data_len) {
				ssize_t n = write(fd, file_data + written,
						  data_len - written);
				if (n < 0) {
					if (errno == EINTR)
						continue;
					int e = errno;
					close(fd);
					mount(NULL, "/", NULL,
					      MS_REMOUNT | MS_RDONLY | MS_BIND,
					      NULL);
					setns(orig_mnt_fd, CLONE_NEWNS);
					send_reply_error(-e, "write failed");
					return;
				}
				written += (size_t)n;
			}
			close(fd);
		}

		/* Restore read-only rootfs */
		mount(NULL, "/", NULL,
		      MS_REMOUNT | MS_RDONLY | MS_BIND, NULL);

		/* Return to our original mount namespace */
		if (setns(orig_mnt_fd, CLONE_NEWNS)) {
			LOG_ERR("FATAL: cannot restore mount namespace: %s",
				strerror(errno));
			_exit(1);
		}
	}

	LOG_DBG("WRITE_FILE %s mode=%04o size=%u", path, mode, data_len);
	send_reply_ok(NULL, 0);
}

/*
 * handle_cmd_stdin - Send data to container stdin or PTY.
 * Fire-and-forget: no reply sent.
 *
 * Wire: <<DataLen:16, Data/binary>>
 */
static void handle_cmd_stdin(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	uint16_t data_len;
	const uint8_t *data;
	int fd;

	if (g_state.state != STATE_RUNNING) {
		/* Silently drop -- fire-and-forget semantics */
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);
	if (buf_read_u16(&b, &data_len) || b.pos + data_len > b.len)
		return;
	data = b.data + b.pos;

	/* Choose target FD: PTY master or stdin pipe */
	if (g_state.ct.pty_master >= 0)
		fd = g_state.ct.pty_master;
	else if (g_state.ct.stdin_fd >= 0)
		fd = g_state.ct.stdin_fd;
	else
		return;

	size_t total = 0;

	while (total < data_len) {
		ssize_t n = write(fd, data + total, data_len - total);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			LOG_WARN("write(stdin): %s", strerror(errno));
			return;
		}
		total += (size_t)n;
	}
}

/*
 * handle_cmd_resize - Resize container PTY.
 *
 * Wire: <<Rows:16, Cols:16>>
 */
static void handle_cmd_resize(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	uint16_t rows, cols;

	if (g_state.state != STATE_RUNNING) {
		send_reply_error(-EINVAL, "no running container");
		return;
	}

	if (g_state.ct.pty_master < 0) {
		send_reply_error(-EINVAL, "not in PTY mode");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);
	if (buf_read_u16(&b, &rows) || buf_read_u16(&b, &cols)) {
		send_reply_error(-EINVAL, "failed to read rows/cols");
		return;
	}

	struct winsize ws = {
		.ws_row = rows,
		.ws_col = cols,
	};

	if (ioctl(g_state.ct.pty_master, TIOCSWINSZ, &ws)) {
		send_reply_error(-errno, "TIOCSWINSZ failed");
		return;
	}

	LOG_DBG("RESIZE rows=%u cols=%u", rows, cols);
	send_reply_ok(NULL, 0);
}

/*
 * handle_cmd_device_filter - Attach eBPF device filter to container cgroup.
 *
 * Wire format: <<CgroupPath:str16, RuleCount:8, Rules/binary>>
 * Each rule:   <<Type:8, Major:32/signed, Minor:32/signed, Access:8>>
 *
 * If RuleCount == 0, uses the built-in OCI default allowlist.
 * Must be called in STATE_CREATED (before GO), after cgroup setup.
 */
static void handle_cmd_device_filter(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	const uint8_t *path_data;
	uint16_t path_len;
	uint8_t rule_count;
	int ret;

	if (g_state.state != STATE_CREATED) {
		send_reply_error(-EINVAL, "device filter requires CREATED state");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);

	/* Read cgroup path */
	if (buf_read_str16(&b, &path_data, &path_len)) {
		send_reply_error(-EINVAL, "failed to read cgroup path");
		return;
	}

	char cgroup_path[512];
	if (path_len >= sizeof(cgroup_path)) {
		send_reply_error(-ENAMETOOLONG, "cgroup path too long");
		return;
	}
	memcpy(cgroup_path, path_data, path_len);
	cgroup_path[path_len] = '\0';

	/* Read rule count */
	if (buf_read_u8(&b, &rule_count)) {
		send_reply_error(-EINVAL, "failed to read rule count");
		return;
	}

	if (rule_count == 0) {
		/* Use default OCI allowlist */
		LOG_DBG("DEVICE_FILTER cgroup=%s rules=default(%zu)",
			cgroup_path, ek_default_dev_rules_count);
		ret = ek_devfilter_attach(cgroup_path,
					  ek_default_dev_rules,
					  ek_default_dev_rules_count);
	} else {
		/* Parse custom rules from payload */
		struct ek_dev_rule rules[64];
		if (rule_count > 64) {
			send_reply_error(-E2BIG, "too many device rules");
			return;
		}

		for (uint8_t i = 0; i < rule_count; i++) {
			uint8_t type, access;
			int32_t major, minor;

			if (buf_read_u8(&b, &type) ||
			    buf_read_i32(&b, &major) ||
			    buf_read_i32(&b, &minor) ||
			    buf_read_u8(&b, &access)) {
				send_reply_error(-EINVAL,
						 "failed to read device rule");
				return;
			}
			rules[i].type   = (int32_t)type;
			rules[i].major  = major;
			rules[i].minor  = minor;
			rules[i].access = (uint32_t)access;
		}

		LOG_DBG("DEVICE_FILTER cgroup=%s rules=%u",
			cgroup_path, rule_count);
		ret = ek_devfilter_attach(cgroup_path, rules,
					  (size_t)rule_count);
	}

	if (ret < 0) {
		send_reply_error((int32_t)ret, "device filter attach failed");
	} else {
		send_reply_ok(NULL, 0);
	}
}

/*
 * handle_cmd_metrics_start - Start eBPF tracepoint metrics.
 *
 * Wire: <<CgroupPath:str16>>
 *
 * Loads BPF programs for fork/exec/exit/oom tracepoints,
 * filtered by the container's cgroup ID. Events stream back
 * as REPLY_METRICS_EVENT frames.
 */
static void handle_cmd_metrics_start(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	const uint8_t *path_data;
	uint16_t path_len;
	int ret;

	if (g_state.state != STATE_CREATED &&
	    g_state.state != STATE_RUNNING) {
		send_reply_error(-EINVAL,
				 "metrics requires CREATED or RUNNING state");
		return;
	}

	if (g_state.metrics.ringbuf_fd >= 0) {
		send_reply_error(-EALREADY, "metrics already active");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);

	if (buf_read_str16(&b, &path_data, &path_len)) {
		send_reply_error(-EINVAL, "failed to read cgroup path");
		return;
	}

	char cgroup_path[512];
	if (path_len >= sizeof(cgroup_path)) {
		send_reply_error(-ENAMETOOLONG, "cgroup path too long");
		return;
	}
	memcpy(cgroup_path, path_data, path_len);
	cgroup_path[path_len] = '\0';

	LOG_INFO("METRICS_START cgroup=%s", cgroup_path);

	ret = ek_metrics_start(cgroup_path, &g_state.metrics);
	if (ret < 0) {
		send_reply_error((int32_t)ret, "metrics start failed");
	} else {
		send_reply_ok(NULL, 0);
	}
}

static void handle_cmd_metrics_stop(void)
{
	LOG_INFO("METRICS_STOP");
	ek_metrics_stop(&g_state.metrics);
	send_reply_ok(NULL, 0);
}

/*
 * metrics_event_callback - Serialize a metrics event as a protocol frame.
 *
 * Called from ek_metrics_consume() for each ring buffer event.
 * Sends REPLY_METRICS_EVENT: <<Type:8, Pid:32, Tgid:32, Ts:64, Data/binary>>
 */
static void metrics_event_callback(const struct ek_metrics_event *ev,
				    void *userdata)
{
	(void)userdata;
	uint8_t payload[64];
	struct erlkoenig_buf b;

	erlkoenig_buf_init(&b, payload, sizeof(payload));
	buf_write_u8(&b, ev->type);
	buf_write_u32(&b, ev->pid);
	buf_write_u32(&b, ev->tgid);
	buf_write_u64(&b, ev->timestamp_ns);

	switch (ev->type) {
	case EK_METRICS_FORK:
		buf_write_u32(&b, ev->fork_ev.child_pid);
		break;
	case EK_METRICS_EXEC:
		buf_write_bytes(&b, (const uint8_t *)ev->exec_ev.comm, 16);
		break;
	case EK_METRICS_EXIT:
		buf_write_i32(&b, ev->exit_ev.exit_code);
		break;
	case EK_METRICS_OOM:
		buf_write_u32(&b, ev->oom_ev.victim_pid);
		break;
	default:
		return;
	}

	send_reply(ERLKOENIG_TAG_REPLY_METRICS_EVENT, payload, b.pos);
}

/*
 * handle_cmd_query_status - Report container status.
 *
 * Enhanced for crash recovery: includes exit code and signal
 * so a reconnecting Erlang node can learn what happened while
 * it was disconnected.
 *
 * Reply: <<State:8, Pid:32, ExitCode:32/signed, TermSignal:8, Uptime:64>>
 *   State 0 = idle, 1 = alive (created or running), 2 = stopped
 */
static void handle_cmd_query_status(void)
{
	uint8_t state = 0;
	uint32_t pid = 0;
	uint64_t uptime_ms = 0;

	switch (g_state.state) {
	case STATE_IDLE:
		state = 0;
		break;
	case STATE_CREATED:
	case STATE_RUNNING:
		state = 1;
		pid = (uint32_t)g_state.ct.child_pid;
		if (g_state.started_at > 0) {
			uint64_t now = monotonic_ms();
			if (now > g_state.started_at)
				uptime_ms = now - g_state.started_at;
		}
		break;
	case STATE_STOPPED:
		state = 2;
		break;
	}

	send_reply_status(state, pid, uptime_ms);

	/*
	 * If the child exited while we were disconnected (socket mode),
	 * send the REPLY_EXITED notification so the Erlang side gets
	 * the same event it would have received if connected at the
	 * time of exit. This is sent AFTER the status reply so the
	 * reconnecting Erlang node sees the correct state transition.
	 */
	if (g_state.exit_pending) {
		g_state.exit_pending = 0;
		send_reply_exited((int32_t)g_state.exit_code,
				  (uint8_t)g_state.term_signal);
	}
}

/* -- Child reaping ------------------------------------------------ */

/*
 * reap_child - Check if the child has exited (non-blocking).
 *
 * Called from the event loop when SIGCHLD was received or
 * periodically as a safety net.
 *
 * In socket mode, if the Erlang connection is down, the exit
 * status is buffered and sent when the connection is restored.
 */
static void reap_child(void)
{
	int status;
	pid_t ret;

	if (g_state.state != STATE_CREATED &&
	    g_state.state != STATE_RUNNING)
		return;

	do {
		ret = waitpid(g_state.ct.child_pid, &status, WNOHANG);
	} while (ret < 0 && errno == EINTR);

	if (ret <= 0)
		return;

	/* Child has exited -- check execve error pipe for diagnostics */
	int32_t exit_code = 0;
	uint8_t term_signal = 0;

	if (g_state.ct.exec_err_fd >= 0) {
		int exec_errno = 0;
		ssize_t en;

		do {
			en = read(g_state.ct.exec_err_fd,
				  &exec_errno, sizeof(exec_errno));
		} while (en < 0 && errno == EINTR);

		if (en == (ssize_t)sizeof(exec_errno) && exec_errno != 0)
			LOG_ERR("execve(/app) failed: %s",
				strerror(exec_errno));

		close(g_state.ct.exec_err_fd);
		g_state.ct.exec_err_fd = -1;
	}

	if (WIFSIGNALED(status)) {
		term_signal = (uint8_t)WTERMSIG(status);
		exit_code = -1;
		LOG_INFO("child killed by signal %u", term_signal);
	} else if (WIFEXITED(status)) {
		exit_code = (int32_t)WEXITSTATUS(status);
		/*
		 * The container's mini-init (PID 1) can't die from
		 * signals (kernel protection), so it uses the shell
		 * convention: exit(128 + signal_number). Decode this
		 * back into a proper signal report.
		 */
		if (exit_code > 128 && exit_code < 256) {
			term_signal = (uint8_t)(exit_code - 128);
			exit_code = -1;
			LOG_INFO("child killed by signal %u "
				 "(via init exit code)", term_signal);
		} else {
			LOG_INFO("child exited with code %d", exit_code);
		}
	}

	g_state.state = STATE_STOPPED;
	g_state.exit_code = exit_code;
	g_state.term_signal = term_signal;

	if (g_connected) {
		send_reply_exited(exit_code, term_signal);
	} else {
		/*
		 * Socket mode, disconnected: buffer the exit status.
		 * It will be sent when Erlang reconnects and queries status.
		 */
		g_state.exit_pending = 1;
		LOG_INFO("child exited while disconnected, buffering status");
	}

	erlkoenig_cleanup(&g_state.ct);
}

/* -- Child output forwarding -------------------------------------- */

/*
 * forward_output - Read from a child pipe and send as protocol frame.
 * @fd:		Read-end of the child's stdout or stderr pipe
 * @tag:	ERLKOENIG_TAG_REPLY_STDOUT or ERLKOENIG_TAG_REPLY_STDERR
 *
 * Returns 1 if data was forwarded, 0 on EOF, -1 on error.
 */
static int forward_output(int fd, uint8_t tag)
{
	uint8_t buf[4096];
	ssize_t n;

	n = read(fd, buf, sizeof(buf));
	if (n > 0) {
		send_reply(tag, buf, (size_t)n);
		return 1;
	}
	if (n == 0)
		return 0; /* EOF */
	if (errno == EINTR || errno == EAGAIN)
		return 1; /* Retry later */
	return -1;
}

/* -- Signal handling ---------------------------------------------- */

static void sigchld_handler(int sig)
{
	(void)sig;
	g_sigchld_received = 1;
}

static void shutdown_handler(int sig)
{
	(void)sig;
	g_shutdown_requested = 1;
}

static int setup_signals(void)
{
	struct sigaction sa;

	/* SIGCHLD: non-blocking reap notification */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGCHLD, &sa, NULL)) {
		LOG_SYSCALL("sigaction(SIGCHLD)");
		return -errno;
	}

	/* SIGTERM/SIGINT: graceful shutdown (socket mode needs this) */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = shutdown_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGTERM, &sa, NULL)) {
		LOG_SYSCALL("sigaction(SIGTERM)");
		return -errno;
	}
	if (sigaction(SIGINT, &sa, NULL)) {
		LOG_SYSCALL("sigaction(SIGINT)");
		return -errno;
	}

	return 0;
}

/* -- Protocol handshake ------------------------------------------- */

/*
 * do_handshake - Perform the protocol version handshake.
 * @read_fd:		fd to read the peer's handshake from
 * @write_fd:		fd to write our handshake reply to
 * @my_node_hash:	Our node certificate SHA-256 hash
 * @have_node_cert:	Whether we loaded a node certificate
 *
 * Returns 0 on success, -1 on failure.
 */
static int do_handshake(int read_fd, int write_fd,
			const uint8_t *my_node_hash, int have_node_cert)
{
	uint8_t hs_buf[1 + ERLKOENIG_NODE_CERT_HASH_LEN];
	ssize_t hs_len;

	hs_len = erlkoenig_read_frame(read_fd, hs_buf, sizeof(hs_buf));
	if (hs_len < 1) {
		LOG_ERR("handshake: expected >= 1 byte, got %zd", hs_len);
		return -1;
	}

	uint8_t peer_version = hs_buf[0];

	if (peer_version == 1 && have_node_cert) {
		if (!getenv("ERLKOENIG_ALLOW_V1")) {
			LOG_ERR("handshake: peer sent v1 but node cert "
				"requires v2 (set ERLKOENIG_ALLOW_V1 "
				"to override during migration)");
			uint8_t reply = ERLKOENIG_PROTOCOL_VERSION;
			erlkoenig_write_frame(write_fd, &reply, 1);
			return -1;
		}
		LOG_WARN("handshake: accepting v1 peer (migration mode)");
	} else if (peer_version == 2) {
		if (hs_len != 1 + ERLKOENIG_NODE_CERT_HASH_LEN) {
			LOG_ERR("handshake: v2 expected %d bytes, got %zd",
				1 + ERLKOENIG_NODE_CERT_HASH_LEN, hs_len);
			return -1;
		}

		uint8_t *peer_hash = hs_buf + 1;
		int peer_has_cert = !ek_nodecert_hash_is_zero(peer_hash);

		if (have_node_cert && peer_has_cert) {
			if (ek_nodecert_hash_compare(my_node_hash,
						     peer_hash)) {
				LOG_ERR("handshake: node cert hash "
					"MISMATCH (Erlang and C have "
					"different node.pem)");
				return -1;
			}
			LOG_INFO("handshake: node cert verified "
				 "(hash=%02x%02x%02x%02x...)",
				 my_node_hash[0], my_node_hash[1],
				 my_node_hash[2], my_node_hash[3]);
		} else if (have_node_cert != peer_has_cert) {
			LOG_WARN("handshake: cert mismatch "
				 "(C=%s, Erlang=%s)",
				 have_node_cert ? "yes" : "no",
				 peer_has_cert ? "yes" : "no");
		}
	} else if (peer_version != 1 && peer_version != 2) {
		LOG_ERR("handshake: unsupported version %d", peer_version);
		uint8_t reply = ERLKOENIG_PROTOCOL_VERSION;
		erlkoenig_write_frame(write_fd, &reply, 1);
		return -1;
	}

	/* Send our reply (always v2 with hash) */
	uint8_t reply[1 + ERLKOENIG_NODE_CERT_HASH_LEN];
	reply[0] = ERLKOENIG_PROTOCOL_VERSION;
	memcpy(reply + 1, my_node_hash, ERLKOENIG_NODE_CERT_HASH_LEN);
	if (erlkoenig_write_frame(write_fd, reply, sizeof(reply)) < 0) {
		LOG_ERR("handshake: failed to send reply");
		return -1;
	}
	LOG_INFO("handshake ok (protocol v%d)", peer_version);
	return 0;
}

/* -- Dispatch ----------------------------------------------------- */

/*
 * dispatch_command - Route a received command to its handler.
 * @buf:	Payload (starts with tag byte)
 * @len:	Payload length (including tag)
 */
static void dispatch_command(const uint8_t *buf, size_t len)
{
	if (len < 1) {
		send_reply_error(-EINVAL, "empty message");
		return;
	}

	uint8_t tag = buf[0];
	const uint8_t *payload = buf + 1;
	size_t payload_len = len - 1;

	LOG_DBG("received tag=0x%02X (%s) payload=%zu bytes",
		tag, erlkoenig_tag_name(tag), payload_len);

	switch (tag) {
	case ERLKOENIG_TAG_CMD_SPAWN:
		handle_cmd_spawn(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_GO:
		handle_cmd_go();
		break;
	case ERLKOENIG_TAG_CMD_KILL:
		handle_cmd_kill(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_NET_SETUP:
		handle_cmd_net_setup(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_WRITE_FILE:
		handle_cmd_write_file(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_QUERY_STATUS:
		handle_cmd_query_status();
		break;
	case ERLKOENIG_TAG_CMD_STDIN:
		handle_cmd_stdin(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_RESIZE:
		handle_cmd_resize(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_DEVICE_FILTER:
		handle_cmd_device_filter(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_METRICS_START:
		handle_cmd_metrics_start(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_METRICS_STOP:
		handle_cmd_metrics_stop();
		break;
	default:
		LOG_WARN("unknown command tag 0x%02X", tag);
		send_reply_error(-ENOSYS, "unknown command");
		break;
	}
}

/* -- Event loop --------------------------------------------------- */

/*
 * event_loop - Main command/output polling loop.
 *
 * Polls the command fd for incoming commands and child output fds
 * for stdout/stderr data. Reaps children on SIGCHLD.
 *
 * Returns:
 *   LOOP_SHUTDOWN    - Graceful shutdown (port mode: stdin closed;
 *                      socket mode: SIGTERM or child dead + no container)
 *   LOOP_DISCONNECT  - Connection lost (socket mode only)
 */
static int event_loop(void)
{
	uint8_t msg_buf[ERLKOENIG_MAX_MSG];
	ssize_t msg_len;

	for (;;) {
		struct pollfd pfds[5];
		nfds_t nfds = 1;
		nfds_t metrics_pfd_idx = 0; /* 0 = not in pfds */
		int pret;

		/* Check for graceful shutdown request (SIGTERM/SIGINT) */
		if (g_shutdown_requested) {
			LOG_INFO("shutdown signal received");
			return LOOP_SHUTDOWN;
		}

		/* Check for child exit */
		if (g_sigchld_received) {
			g_sigchld_received = 0;
			reap_child();
		}

		/* Always poll the command fd */
		pfds[0].fd = g_read_fd;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;

		/* Poll child stdout if open and connected */
		if (g_connected && g_state.stdout_open &&
		    g_state.ct.stdout_fd >= 0) {
			pfds[nfds].fd = g_state.ct.stdout_fd;
			pfds[nfds].events = POLLIN;
			pfds[nfds].revents = 0;
			nfds++;
		}

		/* Poll child stderr if open and connected */
		if (g_connected && g_state.stderr_open &&
		    g_state.ct.stderr_fd >= 0) {
			pfds[nfds].fd = g_state.ct.stderr_fd;
			pfds[nfds].events = POLLIN;
			pfds[nfds].revents = 0;
			nfds++;
		}

		/* Poll PTY master if open and connected (PTY mode) */
		if (g_connected && g_state.pty_open &&
		    g_state.ct.pty_master >= 0) {
			pfds[nfds].fd = g_state.ct.pty_master;
			pfds[nfds].events = POLLIN;
			pfds[nfds].revents = 0;
			nfds++;
		}

		/* Poll eBPF ring buffer for metrics events */
		if (g_connected) {
			int mfd = ek_metrics_poll_fd(&g_state.metrics);
			if (mfd >= 0) {
				metrics_pfd_idx = nfds;
				pfds[nfds].fd = mfd;
				pfds[nfds].events = POLLIN;
				pfds[nfds].revents = 0;
				nfds++;
			}
		}

		/*
		 * ppoll with empty sigmask: SIGCHLD is delivered
		 * atomically during the wait, eliminating the race
		 * between checking g_sigchld_received and entering poll.
		 */
		{
			sigset_t empty_mask;
			struct timespec timeout = { .tv_sec = 0,
						    .tv_nsec = 100000000 };

			sigemptyset(&empty_mask);
			pret = ppoll(pfds, nfds, &timeout, &empty_mask);
		}
		if (pret < 0) {
			if (errno == EINTR)
				continue;
			LOG_SYSCALL("ppoll");
			return LOOP_SHUTDOWN;
		}
		if (pret == 0)
			continue; /* Timeout, recheck SIGCHLD */

		/* Check command fd */
		if (pfds[0].revents & POLLNVAL) {
			LOG_ERR("command fd invalid");
			return g_socket_mode ? LOOP_DISCONNECT : LOOP_SHUTDOWN;
		}

		if (pfds[0].revents & POLLIN) {
			msg_len = erlkoenig_read_frame(g_read_fd,
						     msg_buf,
						     sizeof(msg_buf));
			if (msg_len < 0) {
				if (g_socket_mode) {
					LOG_INFO("connection lost (read error)");
					return LOOP_DISCONNECT;
				}
				LOG_INFO("stdin closed, shutting down");
				return LOOP_SHUTDOWN;
			}
			dispatch_command(msg_buf, (size_t)msg_len);
		}

		if (pfds[0].revents & (POLLERR | POLLHUP)) {
			if (g_socket_mode) {
				LOG_INFO("connection lost (POLLHUP/POLLERR)");
				return LOOP_DISCONNECT;
			}
			LOG_INFO("stdin closed, shutting down");
			return LOOP_SHUTDOWN;
		}

		/* Forward child stdout/stderr/pty output */
		for (nfds_t i = 1; i < nfds; i++) {
			/* Skip metrics fd -- handled separately below */
			if (metrics_pfd_idx > 0 && i == metrics_pfd_idx)
				continue;

			if (!(pfds[i].revents & (POLLIN | POLLHUP)))
				continue;

			int fd = pfds[i].fd;
			uint8_t tag;
			int *open_flag;

			if (fd == g_state.ct.stdout_fd) {
				tag = ERLKOENIG_TAG_REPLY_STDOUT;
				open_flag = &g_state.stdout_open;
			} else if (fd == g_state.ct.pty_master) {
				tag = ERLKOENIG_TAG_REPLY_STDOUT;
				open_flag = &g_state.pty_open;
			} else {
				tag = ERLKOENIG_TAG_REPLY_STDERR;
				open_flag = &g_state.stderr_open;
			}

			if (pfds[i].revents & POLLIN) {
				if (forward_output(fd, tag) == 0)
					*open_flag = 0; /* EOF */
			} else {
				/* POLLHUP without POLLIN = EOF */
				*open_flag = 0;
			}
		}

		/* Consume eBPF ring buffer events */
		if (metrics_pfd_idx > 0 &&
		    (pfds[metrics_pfd_idx].revents & POLLIN)) {
			ek_metrics_consume(&g_state.metrics,
					   metrics_event_callback, NULL);
		}
	}
}

/* -- Socket mode -------------------------------------------------- */

/*
 * create_listen_socket - Create and bind a Unix Domain Socket.
 * @path:	Filesystem path for the socket
 *
 * Removes any stale socket at the path, creates a new one,
 * and starts listening with a backlog of 1 (only one Erlang
 * connection at a time per container).
 *
 * Returns the listen fd on success, -1 on error.
 */
static int create_listen_socket(const char *path)
{
	int fd = -1;
	struct sockaddr_un addr;

	if (strlen(path) >= sizeof(addr.sun_path)) {
		LOG_ERR("socket path too long: %s", path);
		return -1;
	}

	/* Remove stale socket from a previous run */
	unlink(path);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		LOG_SYSCALL("socket(AF_UNIX)");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		LOG_SYSCALL("bind");
		goto err;
	}

	if (chmod(path, 0660) < 0) {
		LOG_SYSCALL("chmod");
		goto err;
	}

	/* Backlog 1: only one Erlang connection per container */
	if (listen(fd, 1) < 0) {
		LOG_SYSCALL("listen");
		goto err;
	}

	return fd;

err:
	close(fd);
	return -1;
}

/*
 * run_socket_mode - Socket mode main loop.
 * @sock_path:		Path for the Unix Domain Socket
 * @my_node_hash:	Node certificate hash for handshake
 * @have_node_cert:	Whether we have a node cert
 *
 * Creates a listen socket and enters the accept-event-reconnect loop.
 * The child process survives connection loss. The runtime exits only
 * on SIGTERM/SIGINT or when the child has exited and no reconnect
 * is expected.
 */
static int run_socket_mode(const char *sock_path,
			   const uint8_t *my_node_hash, int have_node_cert)
{
	int listen_fd;
	int rc = 0;

	listen_fd = create_listen_socket(sock_path);
	if (listen_fd < 0)
		return 1;

	LOG_INFO("socket mode: listening on %s", sock_path);

	/* Outer loop: accept connections, survive disconnects */
	for (;;) {
		int conn_fd;

		/* Check for shutdown before blocking on accept */
		if (g_shutdown_requested) {
			LOG_INFO("shutdown signal received");
			break;
		}

		/*
		 * Check if child is dead and there's nothing to
		 * reconnect for. In socket mode with no container
		 * (STATE_IDLE) or a stopped container, we still wait
		 * for at least one connection so Erlang can query status.
		 * After delivering the exit status on reconnect, we
		 * continue listening until shutdown.
		 */
		if (g_sigchld_received) {
			g_sigchld_received = 0;
			reap_child();
		}

		LOG_INFO("waiting for connection on %s", sock_path);

		/*
		 * Use ppoll on the listen fd to allow SIGCHLD/SIGTERM
		 * to interrupt the wait. accept() alone would block
		 * until a connection arrives, ignoring signals.
		 */
		{
			struct pollfd pfd;
			sigset_t empty_mask;
			struct timespec timeout = { .tv_sec = 1,
						    .tv_nsec = 0 };

			pfd.fd = listen_fd;
			pfd.events = POLLIN;
			pfd.revents = 0;

			sigemptyset(&empty_mask);
			int pr = ppoll(&pfd, 1, &timeout, &empty_mask);

			if (pr < 0) {
				if (errno == EINTR)
					continue;
				LOG_SYSCALL("ppoll(listen)");
				rc = 1;
				break;
			}
			if (pr == 0)
				continue; /* Timeout, re-check signals */

			if (!(pfd.revents & POLLIN))
				continue;
		}

		conn_fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
		if (conn_fd < 0) {
			if (errno == EINTR)
				continue;
			LOG_SYSCALL("accept4");
			rc = 1;
			break;
		}

		LOG_INFO("connection accepted (fd=%d)", conn_fd);

		/* Set the connection as our I/O channel */
		g_read_fd = conn_fd;
		g_write_fd = conn_fd;
		g_connected = 1;

		/* Perform protocol handshake */
		if (do_handshake(conn_fd, conn_fd,
				 my_node_hash, have_node_cert) < 0) {
			LOG_WARN("handshake failed, closing connection");
			close(conn_fd);
			g_connected = 0;
			g_read_fd = -1;
			g_write_fd = -1;
			continue;
		}

		/* Run the event loop until disconnect or shutdown */
		int loop_rc = event_loop();

		/* Connection is done -- clean up */
		close(conn_fd);
		g_connected = 0;
		g_read_fd = -1;
		g_write_fd = -1;

		if (loop_rc == LOOP_SHUTDOWN) {
			LOG_INFO("graceful shutdown requested");
			break;
		}

		/* LOOP_DISCONNECT: connection lost, go back to accept */
		LOG_INFO("connection lost, waiting for reconnect...");
	}

	close(listen_fd);
	unlink(sock_path);

	/* Final cleanup: kill child if still alive on shutdown */
	ek_metrics_stop(&g_state.metrics);

	if (g_state.state == STATE_CREATED ||
	    g_state.state == STATE_RUNNING) {
		LOG_INFO("killing child pid=%d on shutdown",
			 (int)g_state.ct.child_pid);
		kill(g_state.ct.child_pid, SIGKILL);
		while (waitpid(g_state.ct.child_pid, NULL, 0) < 0 &&
		       errno == EINTR)
			;
		erlkoenig_cleanup(&g_state.ct);
	}

	LOG_INFO("exiting (socket mode)");
	return rc;
}

/*
 * run_port_mode - Legacy port mode (STDIN/STDOUT pipes).
 * @my_node_hash:	Node certificate hash for handshake
 * @have_node_cert:	Whether we have a node cert
 *
 * This is the original behavior: reads commands from stdin,
 * writes replies to stdout. Connection loss terminates the runtime.
 */
static int run_port_mode(const uint8_t *my_node_hash, int have_node_cert)
{
	g_read_fd = STDIN_FILENO;
	g_write_fd = STDOUT_FILENO;
	g_connected = 1;
	g_socket_mode = 0;

	/* Protocol handshake */
	if (do_handshake(STDIN_FILENO, STDOUT_FILENO,
			 my_node_hash, have_node_cert) < 0)
		return 1;

	/* Run event loop until stdin closes */
	event_loop();

	/* Cleanup: stop metrics and kill child if still alive */
	ek_metrics_stop(&g_state.metrics);

	if (g_state.state == STATE_CREATED ||
	    g_state.state == STATE_RUNNING) {
		LOG_INFO("killing child pid=%d on shutdown",
			 (int)g_state.ct.child_pid);
		kill(g_state.ct.child_pid, SIGKILL);
		while (waitpid(g_state.ct.child_pid, NULL, 0) < 0 &&
		       errno == EINTR)
			;
		erlkoenig_cleanup(&g_state.ct);
	}

	LOG_INFO("exiting (port mode)");
	return 0;
}

/* -- Argument parsing --------------------------------------------- */

static void print_usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"\n"
		"Options:\n"
		"  --socket PATH  Run in socket mode (Unix Domain Socket)\n"
		"  --id ID        Container ID for log messages\n"
		"  --help         Show this help\n"
		"\n"
		"Without --socket, runs in legacy port mode (STDIN/STDOUT).\n",
		argv0);
}

int main(int argc, char *argv[])
{
	const char *sock_path = NULL;
	const char *container_id = NULL;

	static const struct option long_opts[] = {
		{ "socket", required_argument, NULL, 's' },
		{ "id",     required_argument, NULL, 'i' },
		{ "help",   no_argument,       NULL, 'h' },
		{ NULL,     0,                 NULL, 0   },
	};

	int opt;

	while ((opt = getopt_long(argc, argv, "s:i:h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 's':
			sock_path = optarg;
			break;
		case 'i':
			container_id = optarg;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	erlkoenig_log_init();

	if (container_id)
		LOG_INFO("starting (pid=%d uid=%d id=%s)",
			 (int)getpid(), (int)getuid(), container_id);
	else
		LOG_INFO("starting (pid=%d uid=%d)",
			 (int)getpid(), (int)getuid());

	/* Ignore SIGPIPE: on broken connection we want write() to
	 * return EPIPE, not kill the process. Essential in both modes. */
	signal(SIGPIPE, SIG_IGN);

	if (setup_signals())
		return 1;

	memset(&g_state, 0, sizeof(g_state));
	g_state.state = STATE_IDLE;
	g_state.ct.child_pid = -1;
	g_state.ct.go_pipe = -1;
	g_state.ct.stdout_fd = -1;
	g_state.ct.stderr_fd = -1;
	g_state.ct.exec_err_fd = -1;
	g_state.ct.stdin_fd = -1;
	g_state.ct.pty_master = -1;
	ek_metrics_ctx_init(&g_state.metrics);

	/*
	 * Load node certificate hash (before handshake).
	 * If no cert exists, hash is all zeros -- v1 fallback behavior.
	 */
	uint8_t my_node_hash[ERLKOENIG_NODE_CERT_HASH_LEN];
	int have_node_cert = (ek_nodecert_load_hash(my_node_hash) == 0);

	if (sock_path) {
		g_socket_mode = 1;
		return run_socket_mode(sock_path, my_node_hash,
				       have_node_cert);
	}

	return run_port_mode(my_node_hash, have_node_cert);
}
