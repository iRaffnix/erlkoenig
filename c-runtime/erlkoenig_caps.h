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
 * erlkoenig_caps.h - POSIX Capabilities management for containers.
 *
 * Drops all capabilities except those explicitly kept via a
 * 64-bit bitmask. Applied in PID 2 BEFORE seccomp and execve().
 *
 * Linux splits root's power into ~41 individual capabilities.
 * By default we drop ALL of them, making root inside the
 * container effectively powerless. Specific capabilities can
 * be selectively kept (e.g. CAP_NET_BIND_SERVICE for port 80).
 *
 * Capability sets we clear:
 *   - Bounding set:   upper limit, dropped with prctl()
 *   - Ambient set:    auto-granted after execve, cleared entirely
 *   - Effective:      what the process can do NOW
 *   - Permitted:      what the process MAY raise into effective
 *   - Inheritable:    what survives across execve()
 *
 * Usage:
 *   erlkoenig_drop_caps(caps_keep_mask);  // before seccomp/execve
 *
 * caps_keep_mask: bit N set = keep CAP_N. 0 = drop everything.
 */

#ifndef ERLKOENIG_CAPS_H
#define ERLKOENIG_CAPS_H

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>

#include "erlkoenig_log.h"

/*
 * CAP_LAST_CAP might not be defined in older headers.
 * 40 covers all capabilities up to Linux 6.x.
 */
#ifndef CAP_LAST_CAP
#define CAP_LAST_CAP 40
#endif

/*
 * erlkoenig_drop_caps - Drop all capabilities except those in keep_mask.
 * @keep_mask:	64-bit bitmask, bit N = keep CAP_N (0 = drop all)
 *
 * Must be called in PID 2 BEFORE seccomp and execve().
 * Also sets PR_SET_NO_NEW_PRIVS unconditionally.
 *
 * Returns 0 on success, -errno on failure.
 */
static int erlkoenig_drop_caps(uint64_t keep_mask)
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data[2];
	int cap;

	/*
	 * PR_SET_NO_NEW_PRIVS: prevent gaining privileges via
	 * execve of setuid/setgid binaries. Also required by seccomp
	 * (set there too), but we set it unconditionally as first
	 * hardening step regardless of whether seccomp is enabled.
	 */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		LOG_SYSCALL("prctl(NO_NEW_PRIVS)");
		return -errno;
	}

	/*
	 * Step 1: Clear all ambient capabilities.
	 * Ambient caps are automatically added to effective/permitted
	 * after execve -- we don't want that.
	 */
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
	/* Ignore error -- old kernels may not support ambient caps */

	/*
	 * Step 2: Drop capabilities from the bounding set.
	 * The bounding set limits what can ever be gained.
	 * EINVAL means the capability doesn't exist on this kernel.
	 */
	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		if (keep_mask & (1ULL << cap))
			continue;
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) && errno != EINVAL) {
			LOG_SYSCALL("prctl(CAPBSET_DROP)");
			return -errno;
		}
	}

	/*
	 * Step 3: Set effective/permitted/inheritable via capset().
	 * Version 3 uses two data structs for 64-bit coverage:
	 *   data[0] = caps 0..31 (low 32 bits)
	 *   data[1] = caps 32..63 (high 32 bits)
	 */
	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));

	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0; /* 0 = current process */

	data[0].effective   = (uint32_t)(keep_mask & 0xFFFFFFFF);
	data[0].permitted   = (uint32_t)(keep_mask & 0xFFFFFFFF);
	data[0].inheritable = (uint32_t)(keep_mask & 0xFFFFFFFF);
	data[1].effective   = (uint32_t)((keep_mask >> 32) & 0xFFFFFFFF);
	data[1].permitted   = (uint32_t)((keep_mask >> 32) & 0xFFFFFFFF);
	data[1].inheritable = (uint32_t)((keep_mask >> 32) & 0xFFFFFFFF);

	if (syscall(SYS_capset, &hdr, data)) {
		LOG_SYSCALL("capset");
		return -errno;
	}

	/* Verify capabilities were actually dropped */
	{
		struct __user_cap_header_struct vhdr;
		struct __user_cap_data_struct vdata[2];

		memset(&vhdr, 0, sizeof(vhdr));
		vhdr.version = _LINUX_CAPABILITY_VERSION_3;
		vhdr.pid = 0;

		if (syscall(SYS_capget, &vhdr, vdata)) {
			LOG_SYSCALL("capget(verify)");
			return -errno;
		}

		uint32_t expect_lo = (uint32_t)(keep_mask & 0xFFFFFFFF);
		uint32_t expect_hi = (uint32_t)((keep_mask >> 32) & 0xFFFFFFFF);

		if (vdata[0].effective != expect_lo ||
		    vdata[1].effective != expect_hi) {
			LOG_ERR("cap verify failed: eff=0x%x:%x want=0x%x:%x",
				vdata[1].effective, vdata[0].effective,
				expect_hi, expect_lo);
			return -EPERM;
		}
	}

	if (keep_mask == 0)
		LOG_INFO("all capabilities dropped (verified)");
	else
		LOG_INFO("capabilities set to 0x%llx (verified)",
			 (unsigned long long)keep_mask);

	return 0;
}

#endif /* ERLKOENIG_CAPS_H */
