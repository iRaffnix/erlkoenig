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
 * erlkoenig_ns.c - Container namespace setup.
 *
 * Creates a child process in isolated PID/NET/MNT/UTS/IPC/CGROUP
 * namespaces. The child inherits file capabilities from the parent
 * (set via setcap on the erlkoenig_rt binary) and uses them for
 * mount, pivot_root, setresuid, and capability dropping.
 *
 * Flow:
 *   1. Parent: mkdtemp(), clone(CLONE_NEWPID|CLONE_NEWNET|...)
 *   2. Parent: sends rootfs path via sync_pipe, replies to Erlang
 *   3. Child: mounts tmpfs, bind-mounts devices, pivot_root
 *   4. Erlang: cgroup, network setup, sends CMD_GO
 *   5. Parent: sends 'G' on go_pipe
 *   6. Child: drop caps, seccomp, execve
 */

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "erlkoenig_ns.h"
#include "erlkoenig_proto.h"
#include "erlkoenig_log.h"
#include "erlkoenig_cleanup.h"
#include "erlkoenig_caps.h"
#include "erlkoenig_seccomp.h"
#include "erlkoenig_ns_internal.h"

#define STACK_SIZE	(1024 * 1024)


/*
 * No CLONE_NEWUSER: erlkoenig_rt uses file capabilities (setcap).
 * The child inherits the parent's caps after clone() and uses them
 * for mount/pivot_root/setresuid/cap-dropping. This avoids user
 * namespace complications (AppArmor userns policy, /proc access).
 *
 * Required file caps: cap_sys_admin, cap_net_admin, cap_sys_chroot,
 * cap_sys_ptrace, cap_setpcap, cap_setuid, cap_setgid, cap_dac_override
 */
#define CLONE_FLAGS	(CLONE_NEWPID | CLONE_NEWNET | \
			 CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | \
			 CLONE_NEWCGROUP | SIGCHLD)

/*
 * clone3() support (Linux 5.3+).
 * Structured interface, supports CLONE_CLEAR_SIGHAND (5.5+) to
 * reset all signal handlers in the child — cleaner than inheriting
 * the parent's handlers. Falls back to clone() on ENOSYS.
 */
#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND	0x100000000ULL
#endif

struct clone3_args {
	uint64_t flags;
	uint64_t pidfd;
	uint64_t child_tid;
	uint64_t parent_tid;
	uint64_t exit_signal;
	uint64_t stack;
	uint64_t stack_size;
	uint64_t tls;
	uint64_t set_tid;
	uint64_t set_tid_size;
	uint64_t cgroup;
};

static pid_t try_clone3(int (*fn)(void *), void *arg, int clone_flags)
{
	struct clone3_args cl_args;

	memset(&cl_args, 0, sizeof(cl_args));
	cl_args.flags = ((uint64_t)(unsigned int)clone_flags & ~(uint64_t)0xFF) |
			CLONE_CLEAR_SIGHAND;
	cl_args.exit_signal = (uint64_t)((unsigned int)clone_flags & 0xFFu);
	/*
	 * Do NOT set stack/stack_size. With stack=0 the child
	 * inherits the parent's stack (copy-on-write), like fork().
	 * Setting an explicit stack causes the child's SP to move
	 * to the new stack, but the return address from syscall()
	 * is on the old stack — instant SIGSEGV.
	 * The explicit stack is only needed for the clone() fallback.
	 */

	pid_t pid = (pid_t)syscall(SYS_clone3, &cl_args, sizeof(cl_args));

	if (pid == 0) {
		/* Child: call the init function, then exit */
		_exit(fn(arg));
	}
	return pid;
}

/*
 * close_safe - Close an FD and set it to -1.
 * Avoids double-close bugs in error paths.
 */
#define close_safe(fd) do {			\
	if ((fd) >= 0) {			\
		if (close(fd) && errno != EINTR)\
			LOG_WARN("close(%d): %s",\
				 (fd), strerror(errno));\
		(fd) = -1;			\
	}					\
} while (0)

struct child_args {
	int sync_pipe_rd;	/* Receives rootfs base path from parent */
	int go_pipe_rd;
	int stdout_wr;		/* -1 in PTY mode */
	int stderr_wr;		/* -1 in PTY mode */
	int stdin_rd;		/* Stdin pipe read-end (-1 in PTY mode) */
	int pty_slave;		/* PTY slave FD (-1 in pipe mode) */
	int error_pipe_wr;	/* CLOEXEC pipe: closed on exec, errno on failure */
	int binary_fd;		/* FD for app binary (opened before clone) */
	const struct erlkoenig_spawn_opts *opts;
};

/*
 * mkdtemp_rootfs - Create a temporary directory for the container rootfs.
 *
 * Only creates the directory. The child process handles mounting
 * tmpfs, creating devices, and pivot_root.
 *
 * Returns 0 on success, negative errno on failure.
 */
int ek_mkdtemp_rootfs(char *rootfs, size_t rootfs_len)
{
	int ret;
	const char *base = getenv("ERLKOENIG_ROOTFS_BASE");

	if (!base || base[0] == '\0')
		base = "/tmp";
	ret = snprintf(rootfs, rootfs_len, "%s/erlkoenig_XXXXXX", base);
	if (ret < 0 || (size_t)ret >= rootfs_len)
		return -ENAMETOOLONG;

	if (!mkdtemp(rootfs))
		return -errno;

	return 0;
}

/*
 * bind_mount_dev - Bind-mount a host device node into the rootfs.
 *
 * We create an empty file and bind-mount the host device on top.
 * This is the same approach used by podman/crun/bubblewrap.
 *
 * Must be called BEFORE pivot_root (host /dev still visible).
 */
int ek_bind_mount_dev(const char *rootfs, const char *name,
		      const char *host_path, mode_t mode)
{
	char path[ERLKOENIG_ROOTFS_MAX + 64];

	snprintf(path, sizeof(path), "%s/dev/%s", rootfs, name);

	/* Create empty mount target */
	{
		_cleanup_close_ int fd = open(path,
					      O_CREAT | O_WRONLY | O_CLOEXEC,
					      mode);
		if (fd < 0) {
			LOG_SYSCALL("open(dev)");
			return -errno;
		}
	}

	if (mount(host_path, path, NULL, MS_BIND, NULL)) {
		LOG_SYSCALL("mount(bind-dev)");
		return -errno;
	}

	return 0;
}

/*
 * ek_mkdir_p - Create directory and all parent components under rootfs.
 * @base:	Base path (rootfs prefix)
 * @relpath:	Path relative to base (must start with '/')
 * @mode:	Directory mode for newly created directories
 *
 * Returns 0 on success, negative errno on failure.
 */
static int ek_mkdir_p(const char *base, const char *relpath, mode_t mode)
{
	char path[ERLKOENIG_MAX_PATH];
	int ret;
	size_t base_len = strlen(base);

	ret = snprintf(path, sizeof(path), "%s%s", base, relpath);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -ENAMETOOLONG;

	/* Walk each component after base, creating directories */
	for (size_t i = base_len + 1; path[i] != '\0'; i++) {
		if (path[i] == '/') {
			path[i] = '\0';
			if (mkdir(path, mode) && errno != EEXIST) {
				LOG_SYSCALL("mkdir(mkdir_p)");
				return -errno;
			}
			path[i] = '/';
		}
	}
	/* Create the final component */
	if (mkdir(path, mode) && errno != EEXIST) {
		LOG_SYSCALL("mkdir(mkdir_p final)");
		return -errno;
	}
	return 0;
}

/*
 * ek_validate_dest_path - Validate a container destination path.
 *
 * Checks: must be absolute, no empty segments, no "." or ".." components.
 * Returns 0 on valid, -EINVAL on invalid.
 */
static int ek_validate_dest_path(const char *dest)
{
	const char *p;
	const char *seg_start;

	if (!dest || dest[0] != '/')
		return -EINVAL;

	p = dest;
	while (*p == '/')
		p++;

	while (*p) {
		seg_start = p;
		while (*p && *p != '/')
			p++;
		size_t seg_len = (size_t)(p - seg_start);

		if (seg_len == 0) {
			/* skip consecutive slashes */
			p++;
			continue;
		}
		if (seg_len == 1 && seg_start[0] == '.')
			return -EINVAL;
		if (seg_len == 2 && seg_start[0] == '.' && seg_start[1] == '.')
			return -EINVAL;

		while (*p == '/')
			p++;
	}

	return 0;
}

/*
 * ek_bind_mount_volume - Bind-mount a host directory into the container rootfs.
 * @rootfs:	Path to the rootfs root (before pivot_root)
 * @source:	Absolute host directory path
 * @dest:	Absolute container directory path
 * @opts:	EK_VOLUME_F_* flags
 *
 * The source must be an existing directory. The destination is created
 * (mkdir -p) under rootfs. The mount is done before pivot_root, so host
 * paths are still visible.
 *
 * For read-only mounts: initial MS_BIND followed by MS_BIND|MS_REMOUNT|MS_RDONLY.
 * Direct MS_RDONLY on initial bind-mount is not reliable.
 *
 * Returns 0 on success, negative errno on failure.
 */
int ek_bind_mount_volume(const char *rootfs, const char *source,
			 const char *dest, uint32_t opts)
{
	char target[ERLKOENIG_MAX_PATH];
	struct stat st;
	int ret;

	/* 1. Validate source: absolute, exists, is a directory */
	if (!source || source[0] != '/') {
		LOG_ERR("volume source must be absolute: %s",
			source ? source : "(null)");
		return -EINVAL;
	}
	if (stat(source, &st)) {
		LOG_SYSCALL("stat(volume source)");
		return -errno;
	}
	if (!S_ISDIR(st.st_mode)) {
		LOG_ERR("volume source is not a directory: %s", source);
		return -ENOTDIR;
	}

	/* 2. Validate dest: absolute, no traversal */
	ret = ek_validate_dest_path(dest);
	if (ret) {
		LOG_ERR("volume dest path invalid: %s", dest);
		return ret;
	}

	/* 3. Create target directory under rootfs */
	ret = ek_mkdir_p(rootfs, dest, 0755);
	if (ret) {
		LOG_ERR("failed to create volume target: %s%s", rootfs, dest);
		return ret;
	}

	/* 4. Build full target path */
	ret = snprintf(target, sizeof(target), "%s%s", rootfs, dest);
	if (ret < 0 || (size_t)ret >= sizeof(target))
		return -ENAMETOOLONG;

	/* 5. Bind-mount */
	if (mount(source, target, NULL, MS_BIND, NULL)) {
		LOG_SYSCALL("mount(bind-volume)");
		return -errno;
	}

	/* 6. Read-only remount if requested */
	if (opts & EK_VOLUME_F_READONLY) {
		if (mount(NULL, target, NULL,
			  MS_BIND | MS_REMOUNT | MS_RDONLY, NULL)) {
			LOG_SYSCALL("mount(remount-ro volume)");
			/* Try to clean up the bind mount */
			umount2(target, MNT_DETACH);
			return -errno;
		}
	}

	LOG_INFO("volume mounted: %s -> %s%s%s", source, rootfs, dest,
		 (opts & EK_VOLUME_F_READONLY) ? " (ro)" : " (rw)");
	return 0;
}

/*
 * prepare_rootfs_in_child - Set up the rootfs inside the child.
 *
 * Called by the child after clone(). The child inherits file
 * capabilities from the parent and can mount tmpfs, bind-mount
 * devices, etc.
 *
 * Layout:
 *   <rootfs>/
 *     proc/        (mountpoint for procfs)
 *     dev/
 *       null       bind-mount from /dev/null
 *       zero       bind-mount from /dev/zero
 *       random     bind-mount from /dev/random
 *       urandom    bind-mount from /dev/urandom
 *     etc/
 *       resolv.conf  nameserver <dns_ip>
 *     tmp/         (writable tmpfs for application)
 *     app          (bind-mount of binary, read-only)
 */
static int prepare_rootfs_in_child(const char *rootfs,
				   const struct erlkoenig_spawn_opts *opts,
				   int binary_fd)
{
	char path[ERLKOENIG_ROOTFS_MAX + 64];
	int ret;

	_cleanup_umask_ mode_t old_umask = umask(0);

	if (strlen(rootfs) + 17 > sizeof(path))
		return -ENAMETOOLONG;

	/* Mount tmpfs on the rootfs directory */
	char mount_opts[64];
	uint32_t size = opts->rootfs_size_mb > 0 ? opts->rootfs_size_mb : 64;

	snprintf(mount_opts, sizeof(mount_opts),
		 "size=%um,mode=0755", size);

	if (mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, mount_opts)) {
		LOG_SYSCALL("mount(tmpfs)");
		return -errno;
	}

	/* Create directory structure */
	snprintf(path, sizeof(path), "%s/proc", rootfs);
	if (mkdir(path, 0555)) {
		ret = -errno;
		goto out_umount;
	}

	snprintf(path, sizeof(path), "%s/dev", rootfs);
	if (mkdir(path, 0755)) {
		ret = -errno;
		goto out_umount;
	}

	snprintf(path, sizeof(path), "%s/tmp", rootfs);
	if (mkdir(path, 01777)) {
		ret = -errno;
		goto out_umount;
	}

	snprintf(path, sizeof(path), "%s/etc", rootfs);
	if (mkdir(path, 0755)) {
		ret = -errno;
		goto out_umount;
	}

	/* Bind-mount device nodes from host /dev */
	ret = ek_bind_mount_dev(rootfs, "null",    "/dev/null",    0666);
	if (ret) goto out_umount;
	ret = ek_bind_mount_dev(rootfs, "zero",    "/dev/zero",    0666);
	if (ret) goto out_umount;
	ret = ek_bind_mount_dev(rootfs, "random",  "/dev/random",  0444);
	if (ret) goto out_umount;
	ret = ek_bind_mount_dev(rootfs, "urandom", "/dev/urandom", 0444);
	if (ret) goto out_umount;

	/* Bind-mount persistent volumes (before pivot_root, host paths visible) */
	for (uint8_t i = 0; i < opts->num_volumes; i++) {
		ret = ek_bind_mount_volume(rootfs, opts->volumes[i].source,
					   opts->volumes[i].dest,
					   opts->volumes[i].opts);
		if (ret) goto out_umount;
	}

	/* Create /etc/resolv.conf */
	snprintf(path, sizeof(path), "%s/etc/resolv.conf", rootfs);
	{
		_cleanup_close_ int fd = open(path,
					      O_CREAT | O_WRONLY | O_CLOEXEC,
					      0644);
		if (fd < 0) {
			ret = -errno;
			LOG_SYSCALL("open(resolv.conf)");
			goto out_umount;
		}

		char resolv[48];
		uint8_t *ip = (uint8_t *)&opts->dns_ip;

		if (opts->dns_ip != 0) {
			snprintf(resolv, sizeof(resolv),
				 "nameserver %u.%u.%u.%u\n",
				 ip[0], ip[1], ip[2], ip[3]);
		} else {
			snprintf(resolv, sizeof(resolv),
				 "nameserver 10.0.0.1\n");
		}

		if (write(fd, resolv, strlen(resolv)) < 0) {
			ret = -errno;
			LOG_SYSCALL("write(resolv.conf)");
			goto out_umount;
		}
	}

	/* Copy the target binary to /app on the tmpfs.
	 *
	 * The parent opens the binary FD before clone(), and the child
	 * copies it via the FD. This avoids path traversal issues with
	 * restricted paths (e.g. mode 700 home dirs).
	 */
	snprintf(path, sizeof(path), "%s/app", rootfs);
	{
		_cleanup_close_ int dst = open(path,
					       O_CREAT | O_WRONLY | O_CLOEXEC,
					       0555);
		if (dst < 0) {
			ret = -errno;
			LOG_SYSCALL("open(app)");
			goto out_umount;
		}

		char buf[8192];
		ssize_t nr;

		while ((nr = read(binary_fd, buf, sizeof(buf))) > 0) {
			ssize_t written = 0;

			while (written < nr) {
				ssize_t nw = write(dst, buf + written,
						   (size_t)(nr - written));
				if (nw < 0) {
					if (errno == EINTR)
						continue;
					ret = -errno;
					LOG_SYSCALL("write(app)");
					goto out_umount;
				}
				written += nw;
			}
		}
		if (nr < 0) {
			ret = -errno;
			LOG_SYSCALL("read(binary_fd)");
			goto out_umount;
		}
	}

	return 0;

out_umount:
	umount2(rootfs, MNT_DETACH);
	return ret;
}

static int do_pivot_root_syscall(const char *new_root, const char *put_old)
{
	return (int)syscall(SYS_pivot_root, new_root, put_old);
}

int ek_mount_procfs(const char *rootfs)
{
	char proc_path[ERLKOENIG_ROOTFS_MAX + 32];

	snprintf(proc_path, sizeof(proc_path), "%s/proc", rootfs);
	if (mount("proc", proc_path, "proc",
		  MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=2")) {
		LOG_SYSCALL("mount(proc)");
		return -errno;
	}
	return 0;
}

int ek_pivot_root(const char *rootfs)
{
	/*
	 * Make the entire mount tree private. Without this,
	 * shared mount propagation causes pivot_root to fail
	 * with EINVAL (same issue in runc/crun).
	 */
	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
		LOG_SYSCALL("mount(private /)");
		return -errno;
	}

	/*
	 * pivot_root(".", ".") trick (runc, since Linux 3.17):
	 *
	 * 1. Bind-mount rootfs on itself (required: must be mount point)
	 * 2. chdir into it
	 * 3. pivot_root(".", ".") swaps root and cwd atomically
	 * 4. umount2(".", MNT_DETACH) drops the old root
	 *
	 * This eliminates the .put_old directory entirely. The old root
	 * ends up as "." after the pivot, which we immediately detach.
	 * Simpler, race-free, and matches what runc/crun do.
	 */
	if (mount(rootfs, rootfs, NULL, MS_BIND | MS_REC, NULL)) {
		LOG_SYSCALL("mount(bind rootfs)");
		return -errno;
	}

	if (chdir(rootfs)) {
		LOG_SYSCALL("chdir(rootfs)");
		return -errno;
	}

	if (do_pivot_root_syscall(".", ".")) {
		LOG_SYSCALL("pivot_root");
		return -errno;
	}

	/* Old root is now "." — detach it */
	if (umount2(".", MNT_DETACH)) {
		LOG_SYSCALL("umount2(old root)");
		return -errno;
	}

	if (chdir("/")) {
		LOG_SYSCALL("chdir(/)");
		return -errno;
	}

	return 0;
}

/*
 * OCI standard masked paths. Bind-mount /dev/null over sensitive
 * files, mount empty read-only tmpfs over sensitive directories.
 * Prevents container processes from reading kernel information.
 */
static const char *masked_paths[] = {
	"/proc/acpi",
	"/proc/kcore",
	"/proc/keys",
	"/proc/latency_stats",
	"/proc/timer_list",
	"/proc/sched_debug",
	"/proc/scsi",
	"/proc/sysrq-trigger",
};

#define N_MASKED_PATHS (sizeof(masked_paths) / sizeof(masked_paths[0]))

int ek_mask_paths(void)
{
	struct stat st;
	size_t i;

	for (i = 0; i < N_MASKED_PATHS; i++) {
		if (stat(masked_paths[i], &st)) {
			if (errno == ENOENT || errno == EACCES)
				continue;
			LOG_WARN("stat(%s): %s",
				 masked_paths[i], strerror(errno));
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			/* Mount empty read-only tmpfs over directory */
			if (mount("tmpfs", masked_paths[i], "tmpfs",
				  MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
				  "size=0,nr_inodes=1")) {
				if (errno == ENOENT || errno == EACCES)
					continue;
				LOG_SYSCALL("mount(mask-dir)");
				return -errno;
			}
		} else {
			/* Bind-mount /dev/null over file */
			if (mount("/dev/null", masked_paths[i], NULL,
				  MS_BIND, NULL)) {
				if (errno == ENOENT || errno == EACCES)
					continue;
				LOG_SYSCALL("mount(mask-file)");
				return -errno;
			}
			/* Remount bind read-only */
			mount(NULL, masked_paths[i], NULL,
			      MS_REMOUNT | MS_BIND | MS_RDONLY |
			      MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
		}

		LOG_DBG("masked %s", masked_paths[i]);
	}

	return 0;
}

int ek_setup_readonly_rootfs(uint32_t rootfs_size_mb)
{
	uint32_t size = rootfs_size_mb > 0 ? rootfs_size_mb : 64;

	/*
	 * Read-only rootfs: create /tmp mount point while rootfs is
	 * still writable, then remount / read-only, then mount a
	 * writable tmpfs on /tmp for application scratch space.
	 *
	 * Order: mkdir -> remount-ro -> mount-tmpfs
	 */
	if (mkdir("/tmp", 0777) && errno != EEXIST) {
		LOG_SYSCALL("mkdir(/tmp)");
		return -errno;
	}

	if (mount("", "/", "", MS_REMOUNT | MS_RDONLY | MS_BIND, NULL)) {
		LOG_SYSCALL("mount(remount-ro)");
		return -errno;
	}

	{
		char tmpfs_opts[64];

		snprintf(tmpfs_opts, sizeof(tmpfs_opts), "size=%um", size);

		if (mount("tmpfs", "/tmp", "tmpfs",
			  MS_NOSUID | MS_NODEV | MS_NOEXEC, tmpfs_opts)) {
			LOG_SYSCALL("mount(/tmp)");
			return -errno;
		}
	}

	LOG_INFO("rootfs remounted read-only, /tmp writable (%u MB)", size);
	return 0;
}

int ek_set_rlimits(void)
{
	struct rlimit rl;

	/* Max 1024 processes (fork bomb protection) */
	rl.rlim_cur = 1024;
	rl.rlim_max = 1024;
	if (setrlimit(RLIMIT_NPROC, &rl)) {
		LOG_SYSCALL("setrlimit(NPROC)");
		return -errno;
	}

	/* Max 1024 open file descriptors */
	rl.rlim_cur = 1024;
	rl.rlim_max = 1024;
	if (setrlimit(RLIMIT_NOFILE, &rl)) {
		LOG_SYSCALL("setrlimit(NOFILE)");
		return -errno;
	}

	/* Max 256 MB file size (prevents filling /tmp) */
	rl.rlim_cur = 256 * 1024 * 1024;
	rl.rlim_max = 256 * 1024 * 1024;
	if (setrlimit(RLIMIT_FSIZE, &rl)) {
		LOG_SYSCALL("setrlimit(FSIZE)");
		return -errno;
	}

	/* No core dumps (prevent info leak) */
	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rl)) {
		LOG_SYSCALL("setrlimit(CORE)");
		return -errno;
	}

	return 0;
}

/*
 * Mini-Init (PID 1 in container namespace)
 * =========================================
 *
 * Problem: In einem PID-Namespace ist der erste Prozess PID 1
 * (init). Der Linux-Kernel schuetzt PID 1 besonders:
 *
 *   - Signale ohne installierten Handler werden IGNORIERT
 *     (auch SIGSEGV via raise()!)
 *   - Nur SIGKILL/SIGSTOP vom Parent-Namespace wirken immer
 *   - SIGTERM, SIGINT etc. werden verworfen wenn kein Handler da ist
 *
 * Das heisst: eine normale Binary als PID 1 kann nicht sauber per
 * SIGTERM gestoppt werden, und Crashes (SIGSEGV, SIGABRT) werden
 * verschluckt -- der Prozess laeuft einfach weiter oder exitiert
 * mit Code 0 statt dem erwarteten Signal.
 *
 * Loesung: Nach dem Namespace-Setup forkt child_init() sich selbst.
 * PID 1 wird unser Mini-Init, die eigentliche Binary laeuft als
 * PID 2. Der Init-Prozess:
 *
 *   1. Installiert Signal-Handler fuer SIGTERM, SIGINT, SIGHUP,
 *      SIGUSR1, SIGUSR2, SIGQUIT
 *   2. Leitet empfangene Signale an PID 2 (die App) weiter
 *   3. Wartet per waitpid() auf das Ende der App
 *   4. Exitiert mit dem gleichen Status:
 *      - Normaler Exit: exit(code)
 *      - Signal-Tod: re-raised das Signal mit SIG_DFL
 *
 * Dieses Muster ist identisch mit Docker's --init (tini) und
 * loest das Problem transparent fuer alle Container-Binaries.
 */

/* PID of the actual application (PID 2), used by signal handler */
static volatile pid_t g_app_pid;

/*
 * init_signal_handler - Forward signals to the app process.
 *
 * Runs as PID 1's signal handler. Sends the received signal
 * to the app (PID 2). If the app is already gone, the kill()
 * fails harmlessly with ESRCH.
 */
static void init_signal_handler(int sig)
{
	pid_t pid = g_app_pid;

	if (pid > 0)
		kill(pid, sig);
}

/*
 * Signals that the init process forwards to the app.
 * SIGKILL/SIGSTOP can't be caught, so they're not listed.
 * SIGCHLD is handled separately (waitpid).
 */
static const int forwarded_signals[] = {
	SIGTERM, SIGINT, SIGHUP, SIGUSR1, SIGUSR2, SIGQUIT
};

#define N_FORWARDED (sizeof(forwarded_signals) / sizeof(forwarded_signals[0]))

int ek_reset_signals(void)
{
	struct sigaction dfl;
	size_t i;

	memset(&dfl, 0, sizeof(dfl));
	dfl.sa_handler = SIG_DFL;
	for (i = 0; i < N_FORWARDED; i++)
		sigaction(forwarded_signals[i], &dfl, NULL);

	return 0;
}

/*
 * run_init - Mini-init main loop (runs as PID 1).
 * @app_pid:	PID of the application process (PID 2 in our namespace)
 *
 * Forwards signals, reaps zombies, exits when the app exits.
 * Never returns -- calls _exit() directly.
 */
static void run_init(pid_t app_pid)
{
	struct sigaction sa;
	int status;
	pid_t ret;
	size_t i;

	g_app_pid = app_pid;

	/* Install signal forwarding handlers */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = init_signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	for (i = 0; i < N_FORWARDED; i++)
		sigaction(forwarded_signals[i], &sa, NULL);

	/* Main loop: wait for children, reap zombies */
	for (;;) {
		do {
			ret = waitpid(-1, &status, 0);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0) {
			/* No more children -- shouldn't happen */
			_exit(1);
		}

		if (ret != app_pid)
			continue; /* Reap zombie, not our app */

		/*
		 * App exited. Reproduce its exit status so the
		 * parent (erlkoenig_rt) sees the correct cause of death.
		 */
		if (WIFSIGNALED(status)) {
			/*
			 * App killed by signal. We can't re-raise
			 * because we're PID 1 (kernel ignores it).
			 * Use the 128+sig convention instead --
			 * erlkoenig_rt decodes this back to a signal.
			 */
			_exit(128 + WTERMSIG(status));
		} else if (WIFEXITED(status)) {
			_exit(WEXITSTATUS(status));
		}

		_exit(1);
	}
}

/*
 * child_init - Runs inside the cloned child (PID 1 in new namespace).
 *
 * 1. Read rootfs path from sync pipe
 * 2. Prepare rootfs (mount tmpfs, bind-mount devices)
 * 3. Mount procfs, pivot_root
 * 4. Wait for GO signal from Erlang
 * 5. Set UID/GID, redirect stdio
 * 6. Fork: PID 1 becomes init, PID 2 does execve
 */
static int child_init(void *arg)
{
	struct child_args *ca = arg;
	const struct erlkoenig_spawn_opts *opts = ca->opts;
	char rootfs[ERLKOENIG_ROOTFS_MAX];
	ssize_t n;
	pid_t app_pid;
	int ret;

	/*
	 * Read rootfs path from parent via sync pipe.
	 * The child inherits file capabilities from the parent binary
	 * (set via setcap) and can perform privileged operations.
	 */
	do {
		n = read(ca->sync_pipe_rd, rootfs, sizeof(rootfs) - 1);
	} while (n < 0 && errno == EINTR);

	if (n <= 0) {
		LOG_ERR("child: failed to read rootfs path");
		return 1;
	}
	rootfs[(size_t)n] = '\0';

	close_safe(ca->sync_pipe_rd);

	/* Prepare rootfs: mount tmpfs, bind-mount devices, resolv.conf, binary */
	ret = prepare_rootfs_in_child(rootfs, opts, ca->binary_fd);
	close_safe(ca->binary_fd);
	if (ret) {
		LOG_ERR("child: prepare_rootfs_in_child failed: %s",
			strerror(-ret));
		return 1;
	}

	/* Mount procfs with hidepid=2 to hide other processes' info */
	if (ek_mount_procfs(rootfs))
		return 1;

	/* Isolate mount tree, pivot to new rootfs, detach old root */
	if (ek_pivot_root(rootfs))
		return 1;

	/* Mask sensitive /proc paths (OCI standard masked paths) */
	if (ek_mask_paths())
		return 1;

	/* Read-only rootfs with writable /tmp */
	if (ek_setup_readonly_rootfs(opts->rootfs_size_mb))
		return 1;

	/*
	 * Wait for GO byte from parent. This gives Erlang time to
	 * set up networking (veth pair into our netns) before execve.
	 */
	{
		uint8_t go_byte;
		ssize_t go_n;

		do {
			go_n = read(ca->go_pipe_rd, &go_byte, 1);
		} while (go_n < 0 && errno == EINTR);

		close_safe(ca->go_pipe_rd);

		if (go_n != 1 || go_byte != 'G') {
			LOG_ERR("child: failed to receive GO signal");
			return 1;
		}
	}

	/* Drop supplementary groups, then set GID/UID.
	 * setresgid/setresuid set all three IDs (real, effective, saved)
	 * atomically. Plain setgid/setuid may leave the saved-ID unchanged,
	 * enabling privilege escalation back to the original UID.
	 */
	if (setgroups(0, NULL) && errno != EPERM) {
		LOG_SYSCALL("setgroups");
		return 1;
	}
	if (opts->gid != 0) {
		if (setresgid(opts->gid, opts->gid, opts->gid)) {
			LOG_SYSCALL("setresgid");
			return 1;
		}
	}
	if (opts->uid != 0) {
		if (setresuid(opts->uid, opts->uid, opts->uid)) {
			LOG_SYSCALL("setresuid");
			return 1;
		}
	}

	/*
	 * Redirect stdin and stdout before fork (pipe mode only).
	 * In PTY mode, PID 2 sets up the slave terminal itself.
	 * stderr stays on the original FD so that LOG_* messages
	 * from caps/seccomp setup (in PID 2 before execve) go to
	 * erlkoenig_rt's stderr, not the container output pipe.
	 */
	if (ca->pty_slave < 0) {
		/* Pipe mode: redirect stdin and stdout */
		if (ca->stdin_rd >= 0) {
			if (dup2(ca->stdin_rd, STDIN_FILENO) < 0) {
				LOG_SYSCALL("dup2(stdin pipe)");
				return 1;
			}
			if (ca->stdin_rd > STDIN_FILENO)
				close(ca->stdin_rd);
		} else {
			int devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);

			if (devnull < 0) {
				LOG_SYSCALL("open(/dev/null)");
				return 1;
			}
			if (dup2(devnull, STDIN_FILENO) < 0) {
				LOG_SYSCALL("dup2(stdin)");
				return 1;
			}
			if (devnull > STDIN_FILENO)
				close(devnull);
		}
		if (dup2(ca->stdout_wr, STDOUT_FILENO) < 0) {
			LOG_SYSCALL("dup2(stdout)");
			return 1;
		}
		if (ca->stdout_wr > STDERR_FILENO)
			close(ca->stdout_wr);
	}

	/*
	 * Fork into init (PID 1) + app (PID 2).
	 *
	 * We stay as PID 1 and become the mini-init that forwards
	 * signals and reaps the app. The child (PID 2) does execve.
	 * See the "Mini-Init" comment block above for the rationale.
	 */
	app_pid = fork();
	if (app_pid < 0) {
		LOG_SYSCALL("fork(init)");
		return 1;
	}

	if (app_pid == 0) {
		/*
		 * Child (PID 2): harden, redirect I/O, execve.
		 *
		 * PTY mode: setsid + TIOCSCTTY + dup2 slave to all FDs.
		 * Pipe mode: dup2 stderr pipe.
		 *
		 * The error_pipe_wr has O_CLOEXEC set. On successful execve
		 * it is closed automatically (parent reads EOF = success).
		 * On failure we write errno into it so the parent can report
		 * the actual error.
		 */

		/* Reset signal handlers inherited from PID 1 (mini-init) */
		ek_reset_signals();

		/* Set resource limits (fork bomb, FD, file size, core) */
		ek_set_rlimits();

		if (erlkoenig_drop_caps(opts->caps_keep))
			_exit(126);
		if (opts->seccomp_profile != SECCOMP_PROFILE_NONE) {
			if (erlkoenig_apply_seccomp(opts->seccomp_profile))
				_exit(126);
		}

		if (ca->pty_slave >= 0) {
			/* PTY mode: new session, controlling terminal */
			if (setsid() < 0)
				_exit(126);
			if (ioctl(ca->pty_slave, TIOCSCTTY, 0) < 0)
				_exit(126);
			if (dup2(ca->pty_slave, STDIN_FILENO) < 0)
				_exit(126);
			if (dup2(ca->pty_slave, STDOUT_FILENO) < 0)
				_exit(126);
			if (dup2(ca->pty_slave, STDERR_FILENO) < 0)
				_exit(126);
			if (ca->pty_slave > STDERR_FILENO)
				close(ca->pty_slave);
		} else {
			/* Pipe mode: redirect stderr */
			if (dup2(ca->stderr_wr, STDERR_FILENO) < 0)
				_exit(126);
			if (ca->stderr_wr > STDERR_FILENO)
				close(ca->stderr_wr);
		}

		execve("/app", opts->argv, opts->envp);
		/* execve failed — report errno through the error pipe */
		{
			int err = errno;
			ssize_t wr;

			do {
				wr = write(ca->error_pipe_wr, &err, sizeof(err));
			} while (wr < 0 && errno == EINTR);
		}
		_exit(127);
	}

	/* PID 1: close FDs only PID 2 needs */
	if (ca->pty_slave >= 0)
		close(ca->pty_slave);
	if (ca->stderr_wr > STDERR_FILENO)
		close(ca->stderr_wr);

	/* Parent (PID 1): become init, forward signals, wait */
	run_init(app_pid);
	/* run_init never returns */
	return 1;
}

int erlkoenig_spawn(const struct erlkoenig_spawn_opts *opts,
		  struct erlkoenig_container *ct)
{
	_cleanup_close_ int sync_rd = -1, sync_wr = -1;
	_cleanup_close_ int go_rd = -1, go_wr = -1;
	_cleanup_close_ int out_rd = -1, out_wr = -1;
	_cleanup_close_ int err_rd = -1, err_wr = -1;
	_cleanup_close_ int exec_err_rd = -1, exec_err_wr = -1;
	_cleanup_close_ int in_rd = -1, in_wr = -1;
	_cleanup_close_ int pty_master = -1, pty_slave = -1;
	_cleanup_close_ int binary_fd = -1;
	char rootfs[ERLKOENIG_ROOTFS_MAX];
	struct child_args ca;
	void *child_stack = MAP_FAILED;
	int flags;
	pid_t pid;
	ssize_t written;
	int ret;
	int pty_mode = (opts->flags & ERLKOENIG_SPAWN_FLAG_PTY) != 0;

	memset(ct, 0, sizeof(*ct));
	ct->child_pid = -1;
	ct->go_pipe = -1;
	ct->stdout_fd = -1;
	ct->stderr_fd = -1;
	ct->exec_err_fd = -1;
	ct->stdin_fd = -1;
	ct->pty_master = -1;

	/* Validate binary path */
	size_t path_len = strlen(opts->binary_path);

	if (path_len == 0 || opts->binary_path[0] != '/') {
		LOG_ERR("binary path must be absolute: %s",
			opts->binary_path);
		return -EINVAL;
	}

	if (access(opts->binary_path, X_OK)) {
		ret = -errno;
		LOG_ERR("binary not executable: %s (%s)",
			opts->binary_path, strerror(errno));
		return ret;
	}

	/*
	 * Open binary FD before clone. The child copies the binary
	 * via this FD, avoiding path traversal issues.
	 */
	binary_fd = open(opts->binary_path, O_RDONLY | O_CLOEXEC);
	if (binary_fd < 0) {
		ret = -errno;
		LOG_ERR("open(O_PATH) %s: %s",
			opts->binary_path, strerror(errno));
		return ret;
	}

	/*
	 * Create temp directory for rootfs. The actual rootfs setup
	 * (mount tmpfs, devices, etc.) happens inside the child.
	 */
	ret = ek_mkdtemp_rootfs(rootfs, sizeof(rootfs));
	if (ret) {
		LOG_ERR("mkdtemp_rootfs failed: %s", strerror(-ret));
		return ret;
	}
	snprintf(ct->rootfs_path, sizeof(ct->rootfs_path), "%s", rootfs);

	/* Create sync pipe: parent writes rootfs path, child reads */
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(sync)");
			goto out_cleanup_rootfs;
		}
		sync_rd = p[0];
		sync_wr = p[1];
	}

	/* Create GO pipe: parent writes 'G' when Erlang is ready */
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(go)");
			goto out_cleanup_rootfs;
		}
		go_rd = p[0];
		go_wr = p[1];
	}

	/* Create stdout/stderr pipes: child writes, parent reads */
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(stdout)");
			goto out_cleanup_rootfs;
		}
		out_rd = p[0];
		out_wr = p[1];
	}
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(stderr)");
			goto out_cleanup_rootfs;
		}
		err_rd = p[0];
		err_wr = p[1];
	}

	/* Error pipe for execve failure reporting (CLOEXEC trick).
	 * On successful execve the write-end is closed automatically.
	 * On failure, PID 2 writes errno into it before _exit(127). */
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(exec_err)");
			goto out_cleanup_rootfs;
		}
		exec_err_rd = p[0];
		exec_err_wr = p[1];
	}

	/* Create PTY or stdin pipe depending on mode */
	if (pty_mode) {
		pty_master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
		if (pty_master < 0) {
			ret = -errno;
			LOG_SYSCALL("posix_openpt");
			goto out_cleanup_rootfs;
		}
		if (grantpt(pty_master)) {
			ret = -errno;
			LOG_SYSCALL("grantpt");
			goto out_cleanup_rootfs;
		}
		if (unlockpt(pty_master)) {
			ret = -errno;
			LOG_SYSCALL("unlockpt");
			goto out_cleanup_rootfs;
		}
		char *slave_name = ptsname(pty_master);

		if (!slave_name) {
			ret = -errno;
			LOG_SYSCALL("ptsname");
			goto out_cleanup_rootfs;
		}
		pty_slave = open(slave_name, O_RDWR | O_NOCTTY);
		if (pty_slave < 0) {
			ret = -errno;
			LOG_SYSCALL("open(pty slave)");
			goto out_cleanup_rootfs;
		}
		LOG_DBG("PTY allocated: master=%d slave=%s",
			pty_master, slave_name);
	} else {
		/* Pipe mode: create stdin pipe */
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(stdin)");
			goto out_cleanup_rootfs;
		}
		in_rd = p[0];
		in_wr = p[1];
	}

	/* Allocate clone stack via mmap with guard page.
	 * Better than static stack: no BSS bloat, guard page catches
	 * overflow, MAP_STACK hints the kernel for optimal placement. */
	child_stack = mmap(NULL, STACK_SIZE,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
			   -1, 0);
	if (child_stack == MAP_FAILED) {
		ret = -errno;
		LOG_SYSCALL("mmap(child_stack)");
		goto out_cleanup_rootfs;
	}

	ca.sync_pipe_rd = sync_rd;
	ca.go_pipe_rd = go_rd;
	ca.stdout_wr = pty_mode ? -1 : out_wr;
	ca.stderr_wr = pty_mode ? -1 : err_wr;
	ca.stdin_rd = pty_mode ? -1 : in_rd;
	ca.pty_slave = pty_mode ? pty_slave : -1;
	ca.error_pipe_wr = exec_err_wr;
	ca.binary_fd = binary_fd;
	ca.opts = opts;

	/*
	 * The read-ends must NOT have O_CLOEXEC in the child.
	 * clone() copies FDs; the child needs pipe read-ends.
	 * Clear CLOEXEC on all child-side FDs before clone.
	 */
	flags = fcntl(sync_rd, F_GETFD);
	if (flags < 0) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}
	if (fcntl(sync_rd, F_SETFD, flags & ~FD_CLOEXEC)) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}

	flags = fcntl(go_rd, F_GETFD);
	if (flags < 0) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}
	if (fcntl(go_rd, F_SETFD, flags & ~FD_CLOEXEC)) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}

	/* stdin read-end or PTY slave needs to survive into the child */
	if (pty_mode) {
		flags = fcntl(pty_slave, F_GETFD);
		if (flags < 0) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
		if (fcntl(pty_slave, F_SETFD, flags & ~FD_CLOEXEC)) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
	} else if (in_rd >= 0) {
		flags = fcntl(in_rd, F_GETFD);
		if (flags < 0) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
		if (fcntl(in_rd, F_SETFD, flags & ~FD_CLOEXEC)) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
	}

	/* stdout/stderr write-ends need to survive into the child (pipe mode) */
	if (!pty_mode) {
		flags = fcntl(out_wr, F_GETFD);
		if (flags < 0) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
		if (fcntl(out_wr, F_SETFD, flags & ~FD_CLOEXEC)) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}

		flags = fcntl(err_wr, F_GETFD);
		if (flags < 0) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
		if (fcntl(err_wr, F_SETFD, flags & ~FD_CLOEXEC)) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
	}

	/* binary_fd must survive into the child for copying the app binary */
	flags = fcntl(binary_fd, F_GETFD);
	if (flags < 0) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}
	if (fcntl(binary_fd, F_SETFD, flags & ~FD_CLOEXEC)) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}

	/*
	 * Try clone3() first (Linux 5.3+, CLONE_CLEAR_SIGHAND 5.5+).
	 * Falls back to clone() on older kernels (ENOSYS).
	 * clone3 inherits the parent's stack (COW), no explicit stack needed.
	 * The explicit stack is only used by the clone() fallback.
	 */
	pid = try_clone3(child_init, &ca, CLONE_FLAGS);
	if (pid < 0 && errno == ENOSYS) {
		LOG_INFO("clone3 not available, falling back to clone");
		pid = clone(child_init,
			    (char *)child_stack + STACK_SIZE,
			    CLONE_FLAGS,
			    &ca);
	}
	if (pid < 0) {
		ret = -errno;
		LOG_SYSCALL("clone");
		goto out_cleanup_rootfs;
	}

	/* Parent: close child-side FDs, child has its own copies */
	close_safe(sync_rd);
	close_safe(go_rd);
	close_safe(out_wr);
	close_safe(err_wr);
	close_safe(exec_err_wr);
	close_safe(in_rd);
	close_safe(pty_slave);
	close_safe(binary_fd);

	/* Free clone stack — child has its own copy after clone */
	munmap(child_stack, STACK_SIZE);
	child_stack = MAP_FAILED;

	/*
	 * Send rootfs path to child so it can prepare rootfs + pivot_root.
	 * The child blocks on read() until we write here.
	 * The path is always < PIPE_BUF (4096), so the write is atomic.
	 */
	do {
		written = write(sync_wr, rootfs, strlen(rootfs));
	} while (written < 0 && errno == EINTR);

	if (written != (ssize_t)strlen(rootfs)) {
		ret = (written < 0) ? -errno : -EIO;
		LOG_SYSCALL("write(rootfs path)");
		goto out_kill_child;
	}

	/* Close sync write-end: child only needs rootfs path once */
	close_safe(sync_wr);

	/* Fill container state -- steal FDs so cleanup won't close them */
	ct->child_pid = pid;
	ct->go_pipe = steal_fd(&go_wr);
	ct->exec_err_fd = steal_fd(&exec_err_rd);
	if (pty_mode) {
		ct->pty_master = steal_fd(&pty_master);
		ct->stdout_fd = -1;
		ct->stderr_fd = -1;
		ct->stdin_fd = -1;
	} else {
		ct->pty_master = -1;
		ct->stdout_fd = steal_fd(&out_rd);
		ct->stderr_fd = steal_fd(&err_rd);
		ct->stdin_fd = steal_fd(&in_wr);
	}
	snprintf(ct->netns_path, sizeof(ct->netns_path),
		 "/proc/%d/ns/net", (int)pid);

	LOG_INFO("spawned child pid=%d netns=%s", (int)pid, ct->netns_path);
	return 0;

out_kill_child:
	kill(pid, SIGKILL);
	while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
		;
out_cleanup_rootfs:
	/* Pipe FDs auto-closed by _cleanup_close_ at return */
	if (child_stack != MAP_FAILED)
		munmap(child_stack, STACK_SIZE);
	/*
	 * mkdtemp_rootfs only creates an empty directory.
	 * The tmpfs mount happens inside the child.
	 * If we get here before the child ran, just rmdir.
	 * If the child already mounted, umount first.
	 */
	umount2(rootfs, MNT_DETACH);	/* May fail (EINVAL) if not mounted */
	rmdir(rootfs);
	return ret;
}

int erlkoenig_go(struct erlkoenig_container *ct)
{
	uint8_t go_byte = 'G';
	ssize_t written;

	if (ct->go_pipe < 0)
		return -EINVAL;

	/*
	 * Send GO byte to child. The child is blocked in read()
	 * after pivot_root, waiting for this signal before execve.
	 * This gives Erlang time to set up networking (veth pair
	 * into the child's network namespace) between SPAWN and GO.
	 */
	do {
		written = write(ct->go_pipe, &go_byte, 1);
	} while (written < 0 && errno == EINTR);

	close_safe(ct->go_pipe);

	if (written != 1)
		return -errno;

	return 0;
}

void erlkoenig_cleanup(struct erlkoenig_container *ct)
{
	close_safe(ct->go_pipe);
	close_safe(ct->stdout_fd);
	close_safe(ct->stderr_fd);
	close_safe(ct->exec_err_fd);
	close_safe(ct->stdin_fd);
	close_safe(ct->pty_master);
	ct->child_pid = -1;
}
