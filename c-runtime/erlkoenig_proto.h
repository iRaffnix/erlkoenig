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
 * erlkoenig_proto.h - Erlkoenig wire protocol definitions.
 *
 * Message tags and names for the binary protocol between
 * the Erlang control plane and the C runtime.
 *
 * See proto/erlkoenig.protocol for the full specification.
 */

#ifndef ERLKOENIG_PROTO_H
#define ERLKOENIG_PROTO_H

#include "erlkoenig_buf.h"

/* -- Protocol version --------------------------------------------- */

#define ERLKOENIG_PROTOCOL_VERSION	1

/* -- Reply tags (C -> Erlang, 0x01-0x0F) -------------------------- */

#define ERLKOENIG_TAG_REPLY_OK		0x01
#define ERLKOENIG_TAG_REPLY_ERROR		0x02
#define ERLKOENIG_TAG_REPLY_CONTAINER_PID	0x03
#define ERLKOENIG_TAG_REPLY_READY		0x04
#define ERLKOENIG_TAG_REPLY_EXITED	0x05
#define ERLKOENIG_TAG_REPLY_STATUS	0x06
#define ERLKOENIG_TAG_REPLY_STDOUT	0x07
#define ERLKOENIG_TAG_REPLY_STDERR	0x08

/* -- Container command tags (Erlang -> C, 0x10-0x1F) -------------- */

#define ERLKOENIG_TAG_CMD_SPAWN		0x10
#define ERLKOENIG_TAG_CMD_GO		0x11
#define ERLKOENIG_TAG_CMD_KILL		0x12
#define ERLKOENIG_TAG_CMD_CGROUP_SET	0x13
#define ERLKOENIG_TAG_CMD_QUERY_STATUS	0x14
#define ERLKOENIG_TAG_CMD_NET_SETUP	0x15
#define ERLKOENIG_TAG_CMD_WRITE_FILE	0x16
#define ERLKOENIG_TAG_CMD_STDIN		0x17
#define ERLKOENIG_TAG_CMD_RESIZE	0x18
#define ERLKOENIG_TAG_CMD_DEVICE_FILTER	0x19

/* -- Spawn flags -------------------------------------------------- */

#define ERLKOENIG_SPAWN_FLAG_PTY	0x01

/* -- Tag name lookup ---------------------------------------------- */

static inline const char *erlkoenig_tag_name(uint8_t tag)
{
	switch (tag) {
	case 0x01: return "REPLY_OK";
	case 0x02: return "REPLY_ERROR";
	case 0x03: return "REPLY_CONTAINER_PID";
	case 0x04: return "REPLY_READY";
	case 0x05: return "REPLY_EXITED";
	case 0x06: return "REPLY_STATUS";
	case 0x07: return "REPLY_STDOUT";
	case 0x08: return "REPLY_STDERR";
	case 0x10: return "CMD_SPAWN";
	case 0x11: return "CMD_GO";
	case 0x12: return "CMD_KILL";
	case 0x13: return "CMD_CGROUP_SET";
	case 0x14: return "CMD_QUERY_STATUS";
	case 0x15: return "CMD_NET_SETUP";
	case 0x16: return "CMD_WRITE_FILE";
	case 0x17: return "CMD_STDIN";
	case 0x18: return "CMD_RESIZE";
	case 0x19: return "CMD_DEVICE_FILTER";
	default:   return "UNKNOWN";
	}
}

#endif /* ERLKOENIG_PROTO_H */
