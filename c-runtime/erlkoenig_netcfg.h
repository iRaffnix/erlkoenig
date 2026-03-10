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
 * erlkoenig_netcfg.h - Container network configuration via netlink.
 *
 * Configures networking inside a container's network namespace:
 *   - Assign IPv4 address to an interface
 *   - Set interface and loopback UP
 *   - Add default route via gateway
 *
 * Uses setns() to temporarily enter the child's netns, then
 * restores the original namespace. All operations use raw
 * netlink (AF_NETLINK/NETLINK_ROUTE), no shell commands.
 */

#ifndef ERLKOENIG_NETCFG_H
#define ERLKOENIG_NETCFG_H

#include <stdint.h>
#include <sys/types.h>

/*
 * erlkoenig_netcfg_setup - Configure networking inside a container's netns.
 * @child_pid:	PID of the container process (host pidns)
 * @ifname:	Interface name inside the netns (e.g. "eth0")
 * @ip:		IPv4 address in network byte order
 * @prefixlen:	Subnet prefix length (e.g. 24)
 * @gateway:	Gateway IPv4 address in network byte order
 *
 * Enters the child's network namespace via setns(), configures
 * the interface, then restores the caller's original namespace.
 *
 * Returns 0 on success, negative errno on failure.
 */
int erlkoenig_netcfg_setup(pid_t child_pid, const char *ifname,
			 uint32_t ip, uint8_t prefixlen,
			 uint32_t gateway);

#endif /* ERLKOENIG_NETCFG_H */
