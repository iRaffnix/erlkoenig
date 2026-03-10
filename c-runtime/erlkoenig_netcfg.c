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
 * erlkoenig_netcfg.c - Container network configuration via netlink.
 *
 * All operations use raw AF_NETLINK/NETLINK_ROUTE sockets.
 * The caller's network namespace is saved and restored via setns().
 *
 * Netlink message format (same as in the Erlang erlkoenig_netlink module):
 *   nlmsghdr (16 bytes) + type-specific struct + NLA attributes
 *   All integers are native endian (kernel ABI).
 *
 * Reference: man 7 netlink, man 7 rtnetlink
 */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "erlkoenig_netcfg.h"
#include "erlkoenig_log.h"
#include "erlkoenig_cleanup.h"

/* Maximum netlink message size */
#define NL_BUFSZ	4096

/*
 * The kernel NLA macros use signed int arithmetic which triggers
 * -Wsign-conversion. Define our own unsigned versions.
 */
#define NL_ATTR_HDRLEN		((size_t)4)
#define NL_ATTR_ALIGN(len)	(((len) + 3U) & ~3U)

/* -- Netlink helpers ---------------------------------------------- */

static int nl_open(void)
{
	return socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
}

/*
 * nl_send_recv_ack - Send a netlink message and wait for the ACK.
 * Returns 0 on success (ACK with error=0), negative errno on failure.
 */
static int nl_send_recv_ack(int nlfd, void *msg, size_t msg_len)
{
	uint8_t resp[NL_BUFSZ];
	struct nlmsghdr *nh;
	struct nlmsgerr *err;
	ssize_t n;

	if (send(nlfd, msg, msg_len, 0) < 0)
		return -errno;

	do {
		n = recv(nlfd, resp, sizeof(resp), 0);
	} while (n < 0 && errno == EINTR);

	if (n < 0)
		return -errno;

	if ((size_t)n < sizeof(struct nlmsghdr))
		return -EBADMSG;

	nh = (struct nlmsghdr *)resp;
	if (nh->nlmsg_type == NLMSG_ERROR) {
		if ((size_t)n < sizeof(struct nlmsghdr) + sizeof(int))
			return -EBADMSG;
		err = (struct nlmsgerr *)NLMSG_DATA(nh);
		if (err->error == 0)
			return 0;
		return err->error; /* Already negative */
	}

	/* Unexpected response type -- treat as success for NEWLINK etc. */
	return 0;
}

/*
 * nl_get_ifindex - Get the interface index by name.
 * Returns ifindex on success (>0), negative errno on failure.
 */
static int nl_get_ifindex(int nlfd, const char *ifname)
{
	struct {
		struct nlmsghdr	 nh;
		struct ifinfomsg ifi;
		char		 attrs[64];
	} req;
	uint8_t resp[NL_BUFSZ];
	struct nlmsghdr *nh;
	struct ifinfomsg *ifi;
	struct nlattr *nla;
	ssize_t n;
	size_t name_len = strlen(ifname) + 1; /* include NUL */
	uint16_t attr_len = (uint16_t)(NL_ATTR_HDRLEN + name_len);

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = (uint32_t)(NLMSG_LENGTH(sizeof(struct ifinfomsg)) +
			   NL_ATTR_ALIGN(attr_len));
	req.nh.nlmsg_type = RTM_GETLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST;
	req.nh.nlmsg_seq = 1;

	/* IFLA_IFNAME attribute */
	nla = (struct nlattr *)req.attrs;
	nla->nla_len = attr_len;
	nla->nla_type = IFLA_IFNAME;
	memcpy(req.attrs + NL_ATTR_HDRLEN, ifname, name_len);

	if (send(nlfd, &req, req.nh.nlmsg_len, 0) < 0)
		return -errno;

	do {
		n = recv(nlfd, resp, sizeof(resp), 0);
	} while (n < 0 && errno == EINTR);

	if (n < 0)
		return -errno;

	if ((size_t)n < sizeof(struct nlmsghdr))
		return -EBADMSG;

	nh = (struct nlmsghdr *)resp;

	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
		return err->error;
	}

	if (nh->nlmsg_type != RTM_NEWLINK)
		return -EBADMSG;

	if ((size_t)n < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
		return -EBADMSG;

	ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
	return ifi->ifi_index;
}

/*
 * nl_set_up - Set an interface UP by index.
 */
static int nl_set_up(int nlfd, int ifindex)
{
	struct {
		struct nlmsghdr	 nh;
		struct ifinfomsg ifi;
	} req;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = (uint32_t)NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_type = RTM_NEWLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_seq = 2;
	req.ifi.ifi_index = ifindex;
	req.ifi.ifi_flags = IFF_UP;
	req.ifi.ifi_change = IFF_UP;

	return nl_send_recv_ack(nlfd, &req, req.nh.nlmsg_len);
}

/*
 * nl_add_addr - Add an IPv4 address to an interface.
 * @ip is in network byte order.
 */
static int nl_add_addr(int nlfd, int ifindex,
		       uint32_t ip, uint8_t prefixlen)
{
	struct {
		struct nlmsghdr	 nh;
		struct ifaddrmsg ifa;
		char		 attrs[64];
	} req;
	size_t off;
	uint16_t attr_len = (uint16_t)(NL_ATTR_HDRLEN + 4);

	memset(&req, 0, sizeof(req));
	req.ifa.ifa_family = AF_INET;
	req.ifa.ifa_prefixlen = prefixlen;
	req.ifa.ifa_index = (uint32_t)ifindex;

	off = 0;

	/* IFA_LOCAL */
	*(uint16_t *)(req.attrs + off + 0) = attr_len;
	*(uint16_t *)(req.attrs + off + 2) = IFA_LOCAL;
	memcpy(req.attrs + off + NL_ATTR_HDRLEN, &ip, 4);
	off += NL_ATTR_ALIGN(attr_len);

	/* IFA_ADDRESS */
	*(uint16_t *)(req.attrs + off + 0) = attr_len;
	*(uint16_t *)(req.attrs + off + 2) = IFA_ADDRESS;
	memcpy(req.attrs + off + NL_ATTR_HDRLEN, &ip, 4);
	off += NL_ATTR_ALIGN(attr_len);

	req.nh.nlmsg_len = (uint32_t)(NLMSG_LENGTH(sizeof(struct ifaddrmsg)) +
			   off);
	req.nh.nlmsg_type = RTM_NEWADDR;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			     NLM_F_CREATE | NLM_F_EXCL;
	req.nh.nlmsg_seq = 3;

	return nl_send_recv_ack(nlfd, &req, req.nh.nlmsg_len);
}

/*
 * nl_add_default_route - Add a default route (0.0.0.0/0) via gateway.
 * @gateway is in network byte order.
 */
static int nl_add_default_route(int nlfd, uint32_t gateway)
{
	struct {
		struct nlmsghdr	nh;
		struct rtmsg	rt;
		char		attrs[32];
	} req;
	uint16_t attr_len = (uint16_t)(NL_ATTR_HDRLEN + 4);

	memset(&req, 0, sizeof(req));
	req.rt.rtm_family = AF_INET;
	req.rt.rtm_dst_len = 0;	/* default route */
	req.rt.rtm_table = RT_TABLE_MAIN;
	req.rt.rtm_protocol = RTPROT_BOOT;
	req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
	req.rt.rtm_type = RTN_UNICAST;

	/* RTA_GATEWAY */
	*(uint16_t *)(req.attrs + 0) = attr_len;
	*(uint16_t *)(req.attrs + 2) = RTA_GATEWAY;
	memcpy(req.attrs + NL_ATTR_HDRLEN, &gateway, 4);

	req.nh.nlmsg_len = (uint32_t)(NLMSG_LENGTH(sizeof(struct rtmsg)) +
			   NL_ATTR_ALIGN(attr_len));
	req.nh.nlmsg_type = RTM_NEWROUTE;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			     NLM_F_CREATE | NLM_F_EXCL;
	req.nh.nlmsg_seq = 4;

	return nl_send_recv_ack(nlfd, &req, req.nh.nlmsg_len);
}

/* -- Public API --------------------------------------------------- */

int erlkoenig_netcfg_setup(pid_t child_pid, const char *ifname,
			 uint32_t ip, uint8_t prefixlen,
			 uint32_t gateway)
{
	char ns_path[64];
	int orig_ns = -1;
	int child_ns = -1;
	int nlfd = -1;
	int ifindex;
	int lo_idx;
	int ret;

	/* Save our current network namespace */
	orig_ns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (orig_ns < 0) {
		ret = -errno;
		LOG_SYSCALL("open(/proc/self/ns/net)");
		goto out;
	}

	/* Open the child's network namespace */
	snprintf(ns_path, sizeof(ns_path),
		 "/proc/%d/ns/net", (int)child_pid);
	child_ns = open(ns_path, O_RDONLY | O_CLOEXEC);
	if (child_ns < 0) {
		ret = -errno;
		LOG_SYSCALL("open(child netns)");
		goto out;
	}

	/* Enter child's network namespace */
	if (setns(child_ns, CLONE_NEWNET)) {
		ret = -errno;
		LOG_SYSCALL("setns(child)");
		goto out;
	}

	/* Open netlink socket (now inside child's netns) */
	nlfd = nl_open();
	if (nlfd < 0) {
		ret = -errno;
		LOG_SYSCALL("nl_open");
		goto out_restore;
	}

	/* Get interface index */
	ifindex = nl_get_ifindex(nlfd, ifname);
	if (ifindex < 0) {
		ret = ifindex;
		LOG_ERR("netcfg: interface '%s' not found: %s",
			ifname, strerror(-ret));
		goto out_restore;
	}

	/* Add IP address */
	ret = nl_add_addr(nlfd, ifindex, ip, prefixlen);
	if (ret) {
		LOG_ERR("netcfg: add_addr failed: %s", strerror(-ret));
		goto out_restore;
	}

	/* Set interface UP */
	ret = nl_set_up(nlfd, ifindex);
	if (ret) {
		LOG_ERR("netcfg: set_up(%s) failed: %s",
			ifname, strerror(-ret));
		goto out_restore;
	}

	/* Set loopback UP */
	lo_idx = nl_get_ifindex(nlfd, "lo");
	if (lo_idx > 0) {
		ret = nl_set_up(nlfd, lo_idx);
		if (ret) {
			LOG_ERR("netcfg: set_up(lo) failed: %s",
				strerror(-ret));
			goto out_restore;
		}
	}

	/* Add default route via gateway */
	ret = nl_add_default_route(nlfd, gateway);
	if (ret) {
		LOG_ERR("netcfg: add_default_route failed: %s",
			strerror(-ret));
		goto out_restore;
	}

	LOG_INFO("netcfg: configured %s ifindex=%d in pid=%d netns",
		 ifname, ifindex, (int)child_pid);
	ret = 0;

out_restore:
	/* Restore original network namespace */
	if (setns(orig_ns, CLONE_NEWNET))
		LOG_SYSCALL("setns(restore)");

out:
	if (nlfd >= 0)
		close(nlfd);
	if (child_ns >= 0)
		close(child_ns);
	if (orig_ns >= 0)
		close(orig_ns);

	return ret;
}
