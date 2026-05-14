# Erlkoenig Error Code Reference

Auto-generated from `apps/erlkoenig/priv/error_catalog.term`. Do not hand-edit. Re-run `make docs/ERROR_CODES.md` after any catalog change.

**115 codes across 14 components.**

Codes are part of the public contract. They follow the stability rules in CONTRIBUTING.md (Error Handling Contract): stable identifiers, deprecation over removal, structured `{error, ErrorMap}` returns at module boundaries.

Operator usage:

```sh
ek explain EK_AUDIT_CHAIN_BROKEN     # detailed view
ek explain --component nft           # filter by component
ek explain --list                    # all codes
ek --format json explain EK_FOO      # for tooling
```

## Table of Contents

- [`admission`](#admission) (2 codes)
- [`audit`](#audit) (8 codes)
- [`config`](#config) (4 codes)
- [`ct`](#ct) (21 codes)
- [`dns`](#dns) (8 codes)
- [`host`](#host) (11 codes)
- [`network`](#network) (8 codes)
- [`nft`](#nft) (9 codes)
- [`operator`](#operator) (3 codes)
- [`quarantine`](#quarantine) (4 codes)
- [`runtime`](#runtime) (10 codes)
- [`security`](#security) (1 codes)
- [`threat`](#threat) (16 codes)
- [`volume`](#volume) (10 codes)

## admission

### `EK_ADMISSION_QUEUE_FULL`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** admission queue is full

**Operator action:** reduce concurrent starts or increase admission_queue_limit only after confirming host and zone spawn capacity

**Evidence fields:** scope, queued, queue_limit

**Iron rule:** _local admission is sovereign_

**Related:** SPEC-EK-003

---

### `EK_ADMISSION_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** admission wait timed out

**Operator action:** inspect current spawn concurrency, queued waiters and zone pressure before retrying the container start

**Evidence fields:** scope, timeout_ms, source

**Iron rule:** _local admission is sovereign_

**Related:** SPEC-EK-003

---

## audit

### `EK_AUDIT_CHAIN_BROKEN`

- **Severity:** `critical`
- **Since:** `0.9.0`
- **Description:** audit hash chain verification failed

**Operator action:** treat the audit log as tampered or corrupted; preserve the file, compare with external chain-head snapshots, and investigate the reported line

**Evidence fields:** path, line, reason

**Iron rule:** _audit integrity failures are forensic evidence, not recoverable noise_

**Related:** SPEC-AS-005

---

### `EK_AUDIT_QUERY_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** audit log query failed

**Operator action:** check audit path readability and retry with a smaller filter

**Evidence fields:** path, reason

**Related:** SPEC-AS-005

---

### `EK_AUDIT_READ_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** audit log could not be read

**Operator action:** check audit path existence, ownership, permissions and storage health

**Evidence fields:** path, reason

**Related:** SPEC-AS-005

---

### `EK_AUDIT_SEAL_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** audit day seal failed

**Operator action:** inspect the reason, live audit path and filesystem permissions; sealing must succeed before considering the day's archive complete

**Evidence fields:** path, reason

**Related:** SPEC-AS-005

---

### `EK_AUDIT_SEAL_HMAC_MISMATCH`

- **Severity:** `critical`
- **Since:** `0.9.0`
- **Description:** audit sealed file HMAC did not match

**Operator action:** treat the sealed audit archive as tampered or verified with the wrong HMAC key; preserve the archive and key metadata

**Evidence fields:** path

**Iron rule:** _audit seal failures are forensic evidence, not recoverable noise_

**Related:** SPEC-AS-005

---

### `EK_AUDIT_SEAL_INVALID`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** audit sealed file verification failed

**Operator action:** inspect seal metadata fields and verify that the file ends with a valid audit.seal event

**Evidence fields:** path, reason

**Related:** SPEC-AS-005

---

### `EK_AUDIT_SIGNATURE_INVALID`

- **Severity:** `critical`
- **Since:** `0.9.0`
- **Description:** audit event signature verification failed

**Operator action:** treat the audit log as tampered or signed with the wrong key; verify the node audit public key and preserve the affected file

**Evidence fields:** path, line, reason

**Iron rule:** _audit integrity failures are forensic evidence, not recoverable noise_

**Related:** SPEC-AS-005

---

### `EK_AUDIT_UNKNOWN_CALL`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** unknown audit gen_server call

**Operator action:** check caller version and audit API usage

---

## config

### `EK_CONFIG_CONFIG_LOAD_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** erlkoenig_config:load rejected term file

**Operator action:** inspect the parse or validation reason and fix the config file before retrying

**Evidence fields:** path, reason

---

### `EK_CONFIG_HOST_FW_LOCKOUT_RISK`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** host firewall stack would lock out the operator's SSH reconnect path

**Operator action:** either declare the live SSH port in the host input chain accept-list, or pass --allow-lockout if you have out-of-band recovery (serial console, KVM, hypervisor recovery mode) ready

**Evidence fields:** path, findings, override

**Related:** docs/ARCHITECTURE_BACKLOG.md#host-firewall-lockout-preflight

---

### `EK_CONFIG_PARSE_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** configuration parse failed

**Operator action:** validate the term or DSL file syntax and rerun with a smaller config if needed

**Evidence fields:** path, reason

---

### `EK_CONFIG_VALIDATE_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** configuration validation failed

**Operator action:** inspect the reported field and expected shape, then rerun ek config validate before loading the file

**Evidence fields:** path, reason

---

## ct

### `EK_CT_ADMISSION_QUEUE_FULL`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** admission queue is full

**Operator action:** reduce concurrent starts or increase admission queue capacity for the zone

**Evidence fields:** zone

---

### `EK_CT_ADMISSION_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** admission gate timed out

**Operator action:** inspect admission queue pressure and retry once capacity is available

**Evidence fields:** zone

---

### `EK_CT_ADMISSION_UNAVAILABLE`

- **Severity:** `critical`
- **Since:** `0.9.0`
- **Description:** admission gate is unavailable in production resource-protection mode

**Operator action:** inspect erlkoenig_admission supervision state before retrying the spawn

**Evidence fields:** zone

**Iron rule:** _local admission is sovereign_

---

### `EK_CT_CGROUP_SETUP_FAILED`

- **Severity:** `critical`
- **Since:** `0.9.0`
- **Description:** container cgroup setup failed in production resource-protection mode

**Operator action:** inspect cgroup v2 delegation, enabled controllers and cgroupfs permissions

**Evidence fields:** reason

**Iron rule:** _declared cgroup boundaries are hard fail-closed requirements_

---

### `EK_CT_CLEANUP_FAILED`

- **Severity:** `critical`
- **Since:** `0.9.0`
- **Description:** container cleanup failed before restart

**Operator action:** inspect stale ipvlan slave, netns and cgroup resources before retrying the container

**Evidence fields:** state, reason

**Iron rule:** _restart only after prior kernel resources are known to be cleaned up_

---

### `EK_CT_GO_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** erlkoenig_rt rejected CMD_GO

**Operator action:** inspect the runtime error code and message returned for CMD_GO

**Evidence fields:** code, message

**Related:** SPEC-PROTO-001

---

### `EK_CT_GO_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** container GO timed out

**Operator action:** inspect runtime logs after CMD_GO and check whether the child process blocked before sending readiness

**Evidence fields:** timeout_ms

**Related:** SPEC-PROTO-001

---

### `EK_CT_HANDSHAKE_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime handshake reply rejected during create

**Operator action:** verify BEAM and runtime protocol versions match and capture the raw handshake reply

**Evidence fields:** reason, reply

**Related:** SPEC-PROTO-001

---

### `EK_CT_KILL_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** container did not exit after forced kill

**Operator action:** inspect host process state, runtime socket state and kernel task state for the container pid

**Evidence fields:** timeout_ms

---

### `EK_CT_QUARANTINE_UNAVAILABLE`

- **Severity:** `critical`
- **Since:** `0.9.0`
- **Description:** quarantine gate is unavailable in production resource-protection mode

**Operator action:** inspect erlkoenig_quarantine supervision state before retrying the spawn

**Evidence fields:** zone

**Iron rule:** _quarantine is a hard local spawn boundary_

---

### `EK_CT_RECONNECT_EXHAUSTED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime reconnect attempts exhausted

**Operator action:** inspect runtime process health and socket path; container is considered failed after the reconnect budget is spent

**Evidence fields:** attempts

---

### `EK_CT_RECOVERY_SOCKET_CLOSED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime socket closed during recovery

**Operator action:** check whether the runtime exited while BEAM was recovering container state

**Evidence fields:** phase

---

### `EK_CT_RECOVERY_SOCKET_ERROR`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime socket errored during recovery

**Operator action:** inspect the socket error and runtime process state before retrying recovery

**Evidence fields:** phase, reason

---

### `EK_CT_RECOVERY_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** container recovery timed out

**Operator action:** check whether the runtime is still alive and responding to status queries

**Evidence fields:** timeout_ms

---

### `EK_CT_RESOURCE_ADMISSION_DENIED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** resource admission denied the container before spawn

**Operator action:** inspect declared memory and pids limits, aggregate containers/ headroom, and node resource pressure

**Evidence fields:** zone, reason, limits

**Iron rule:** _local resource admission is sovereign_

---

### `EK_CT_ROOTFS_SETUP_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** container rootfs setup failed

**Operator action:** inspect rootfs builder, image path, FUSE mount setup and temporary filesystem permissions

**Evidence fields:** reason

---

### `EK_CT_SIGNATURE_REJECTED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** container signature rejected

**Operator action:** verify the configured signature path, key trust root and binary digest before retrying

**Evidence fields:** reason

---

### `EK_CT_SOCKET_CLOSED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime socket closed during container lifecycle

**Operator action:** inspect the lifecycle phase and runtime logs to determine whether erlkoenig_rt exited early or the socket was closed by the peer

**Evidence fields:** phase

---

### `EK_CT_SOCKET_ERROR`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime socket errored during container lifecycle

**Operator action:** inspect the socket error reason and runtime process state

**Evidence fields:** phase, reason

---

### `EK_CT_SPAWN_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** container spawn timed out

**Operator action:** check runtime startup latency, cgroup setup, protocol handshake and spawn timeout settings

**Evidence fields:** timeout_ms

---

### `EK_CT_UNEXPECTED_REPLY`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** unexpected runtime reply during container lifecycle

**Operator action:** verify BEAM and runtime protocol versions match and capture the unexpected reply for protocol debugging

**Evidence fields:** phase, reply

**Related:** SPEC-PROTO-001

---

## dns

### `EK_DNS_BIND_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** DNS server socket could not bind to the zone address

**Operator action:** verify the zone gateway address exists locally, UDP/53 is free, and the service has permission to bind it

**Evidence fields:** zone, bind_ip, port, reason

**Related:** SPEC-AS-009

---

### `EK_DNS_INVALID_HOST_PATTERN`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** DNS allowlist entry was invalid and dropped

**Operator action:** fix the container DNS allowlist host pattern; only exact hosts and '*.<domain>' wildcards are accepted

**Evidence fields:** source

**Related:** SPEC-AS-009

---

### `EK_DNS_RECOVERY_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** DNS filter could not recover an allowlist from a running container

**Operator action:** inspect the container process state and restart the DNS filter or container if allowlist recovery keeps failing

**Evidence fields:** pid, class, reason

**Related:** SPEC-AS-009

---

### `EK_DNS_UPSTREAM_OPEN_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** DNS upstream forwarding socket could not be opened

**Operator action:** inspect host socket limits and UDP availability before retrying external DNS forwarding

**Evidence fields:** id, upstream, reason

**Related:** SPEC-AS-009

---

### `EK_DNS_UPSTREAM_REPLY_ID_MISMATCH`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** DNS upstream reply did not match the pending query id

**Operator action:** inspect resolver behaviour and possible stray UDP replies from a previous query on the same socket

**Evidence fields:** reply_id, expected_id, src_ip, src_port

**Related:** SPEC-AS-009

---

### `EK_DNS_UPSTREAM_REPLY_MALFORMED`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** DNS upstream reply was too short to parse

**Operator action:** capture the upstream DNS response and verify the configured resolver is not returning malformed UDP payloads

**Evidence fields:** reply_bytes

**Related:** SPEC-AS-009

---

### `EK_DNS_UPSTREAM_SEND_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** DNS query could not be sent to the upstream resolver

**Operator action:** verify the configured upstream resolver address, route, firewall policy and host UDP socket health

**Evidence fields:** id, upstream, port, reason

**Related:** SPEC-AS-009

---

### `EK_DNS_UPSTREAM_TIMEOUT`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** DNS upstream resolver did not answer before timeout

**Operator action:** check upstream resolver reachability, host packet loss and configured dns_upstream value

**Evidence fields:** id, src_ip, src_port, timeout_ms

**Related:** SPEC-AS-009

---

## host

### `EK_HOST_CGROUP_V2_MISSING`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** cgroup v2 controller file is not present

**Operator action:** boot with unified cgroup v2 and verify /sys/fs/cgroup is mounted with controllers available

**Evidence fields:** path

**Related:** SPEC-EK-003

---

### `EK_HOST_COOKIE_MISSING`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** Erlang distribution cookie file is not readable

**Operator action:** create /etc/erlkoenig/cookie or set ERLKOENIG_COOKIE_FILE to the cookie used by the running node

**Evidence fields:** path

---

### `EK_HOST_COOKIE_PERMISSIONS_WEAK`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** Erlang distribution cookie permissions are too broad or the cookie is empty

**Operator action:** set /etc/erlkoenig/cookie to a non-empty regular file owned by the service owner with mode 0400 or 0440

**Evidence fields:** path, mode, size, world_readable, group_writable, world_writable, reason, type

---

### `EK_HOST_COOKIE_SYMLINK_INVALID`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** legacy /opt/erlkoenig/cookie does not point at the canonical erlkoenig cookie

**Operator action:** re-run installer.sh or replace /opt/erlkoenig/cookie with a symlink to /etc/erlkoenig/cookie

**Evidence fields:** legacy, canonical, target, reason

---

### `EK_HOST_EPMD_LOCAL_BIND_MISSING`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** erlkoenig service does not pin EPMD to the loopback interface

**Operator action:** install the current systemd unit with ERL_EPMD_ADDRESS=127.0.0.1 and restart erlkoenig

**Evidence fields:** path, expected, reason

---

### `EK_HOST_NFT_MISSING`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** nft command line tool is not available

**Operator action:** install nftables so operators can inspect and debug kernel firewall state

**Evidence fields:** executable

---

### `EK_HOST_NODE_PING_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** ek cannot reach the erlkoenig node with Erlang distribution

**Operator action:** verify the erlkoenig service is running, the --node value matches the node name, and ek uses the same cookie as the service

**Evidence fields:** node, cookie_file, reason

---

### `EK_HOST_PROTOCOL_VECTORS_MISSING`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** protocol golden vector directory is not configured

**Operator action:** set ERLKOENIG_PROTOCOL_VECTORS in CI or development shells when running protocol drift checks

**Evidence fields:** env, path

**Related:** SPEC-PROTO-001

---

### `EK_HOST_RUNTIME_BINARY_MISSING`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** erlkoenig_rt binary is not discoverable

**Operator action:** install the runtime binary, verify the release layout, or set ERLKOENIG_RT to the runtime path

**Evidence fields:** paths_searched

---

### `EK_HOST_SOCKET_DIR_MISSING`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime socket directory does not exist

**Operator action:** create /run/erlkoenig/containers with service permissions or start the erlkoenig service to create it

**Evidence fields:** paths_searched

---

### `EK_HOST_SYSTEMD_UNIT_MISSING`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** erlkoenig systemd unit is not installed

**Operator action:** re-run installer.sh and verify /etc/systemd/system/erlkoenig.service exists

**Evidence fields:** path, reason, type

---

## network

### `EK_NETWORK_ATTACH_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** container network link attach failed

**Operator action:** check parent interface state, netlink permissions, target pid namespace, and whether a stale IPVLAN slave already exists

**Evidence fields:** zone, ifname, ip, reason

---

### `EK_NETWORK_ECONNREFUSED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** network connection was refused

**Operator action:** verify the peer process is listening and the address or socket path is correct

**Evidence fields:** ip, port, socket_path

---

### `EK_NETWORK_IP_ALLOC_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** container IP allocation failed

**Operator action:** inspect the configured zone IP pool, exhausted ranges, and whether stale allocations were released

**Evidence fields:** zone, reason

---

### `EK_NETWORK_NETNS_SETUP_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime rejected container network namespace setup

**Operator action:** inspect the runtime reply, interface name, IP, gateway and prefix; EADDRINUSE usually means a stale address is still being cleaned up

**Evidence fields:** reason, ifname, ip, gateway, prefixlen

---

### `EK_NETWORK_NETNS_SETUP_SOCKET_ERROR`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** container network namespace setup socket failed

**Operator action:** inspect runtime socket liveness and reconnect state before retrying network setup

**Evidence fields:** reason, ifname, ip, gateway, prefixlen

---

### `EK_NETWORK_NETNS_SETUP_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** container network namespace setup timed out

**Operator action:** check whether erlkoenig_rt is responsive and whether the target namespace setup path is blocked

**Evidence fields:** ifname, ip, gateway, prefixlen, timeout_ms

---

### `EK_NETWORK_NET_SETUP_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** erlkoenig_net:setup_container_net failed

**Operator action:** check zone network configuration, namespace setup permissions and host interface state

**Evidence fields:** zone, reason

---

### `EK_NETWORK_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** network operation timed out

**Operator action:** check peer availability, host load and configured timeout values

**Evidence fields:** ip, port, timeout_ms

---

## nft

### `EK_NFT_BATCH_REJECTED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** kernel rejected nf_tables batch

**Operator action:** inspect errno, sequence number and the nft operation being applied; EINVAL usually means an encoded rule or set expression is invalid

**Evidence fields:** errno, errno_name, seq

**Related:** SPEC-EK-007

---

### `EK_NFT_COUNTER_QUERY_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** nf_tables counter query failed

**Operator action:** verify the counter table and name exist, the nft server socket is healthy and the query response can be decoded

**Evidence fields:** family, table, name, seq, reset, reason

**Related:** SPEC-EK-007

---

### `EK_NFT_LIST_CHAINS_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** nf_tables chain listing failed

**Operator action:** verify the table exists and nftables query permissions are available on the host

**Evidence fields:** family, table, seq, reason

**Related:** SPEC-EK-007

---

### `EK_NFT_LIST_SET_ELEMS_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** nf_tables set element query failed

**Operator action:** verify the set exists in the expected table and inspect netlink decode errors for malformed kernel responses

**Evidence fields:** family, table, set, seq, reason

**Related:** SPEC-EK-007

---

### `EK_NFT_NETLINK_RECV_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** nf_tables netlink response could not be received

**Operator action:** check whether the netlink socket closed or returned an OS error while waiting for nft ACKs

**Evidence fields:** reason

**Related:** SPEC-EK-007

---

### `EK_NFT_NETLINK_SEND_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** nf_tables netlink batch could not be sent

**Operator action:** check netlink socket liveness, nft service supervision and whether the kernel rejected the socket before ACK parsing

**Evidence fields:** reason, batch_bytes

**Related:** SPEC-EK-007

---

### `EK_NFT_RULESET_QUERY_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** nf_tables ruleset query failed

**Operator action:** check kernel nftables support and decode errors from the ruleset dump response

**Evidence fields:** family, seq, reason

**Related:** SPEC-EK-007

---

### `EK_NFT_SOCKET_OPEN_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** nf_tables netlink socket could not be opened

**Operator action:** verify CAP_NET_ADMIN, netlink socket permissions and that nf_tables is available in the running kernel

**Evidence fields:** reason

**Related:** SPEC-EK-007

---

### `EK_NFT_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** nf_tables netlink ACK wait timed out

**Operator action:** inspect host load and kernel netlink responsiveness; stale ACKs will be drained before the next nft operation

**Evidence fields:** pending_acks

**Related:** SPEC-EK-007

---

## operator

### `EK_OPERATOR_BAD_ARGUMENT`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** operator-API call rejected on argument validation

**Operator action:** fix the caller — argument shape or format does not match the contract

**Evidence fields:** argument, value, expected

---

### `EK_OPERATOR_INTERNAL`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** operator-API wrapper received an unexpected return from an internal module

**Operator action:** inspect runtime logs for the underlying gen_server or event; this indicates contract drift between operator_api and an internal module

**Evidence fields:** op, raw

---

### `EK_OPERATOR_NOT_FOUND`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** operator-API lookup found no matching resource

**Operator action:** verify the supplied identifier (hash, uuid, container id) and recheck via the corresponding list verb

**Evidence fields:** resource, key

---

## quarantine

### `EK_QUARANTINE_BINARY_QUARANTINED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** binary is quarantined

**Operator action:** inspect the binary hash, crash history and operator quarantine reason before allowing this workload to spawn again

**Evidence fields:** path, hash, reason, since

**Iron rule:** _quarantine is a hard local spawn boundary_

**Related:** SPEC-AS-005

---

### `EK_QUARANTINE_CRASH_LOOP_DETECTED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** binary entered crash-loop quarantine

**Operator action:** treat repeated crashes as a local spawn stop; inspect recent exits and clear quarantine only after the binary or config is fixed

**Evidence fields:** hash, crash_count, window_ms, since

**Iron rule:** _quarantine is a hard local spawn boundary_

**Related:** SPEC-AS-005

---

### `EK_QUARANTINE_HASH_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** binary hash could not be computed

**Operator action:** verify the binary path exists, is readable and was not replaced between config validation and spawn

**Evidence fields:** path, reason

**Related:** SPEC-AS-005

---

### `EK_QUARANTINE_UNATTRIBUTABLE_CRASH`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** container crash could not be attributed to a binary hash

**Operator action:** check whether the binary path disappeared or was replaced during crash handling; repeated unattributable crashes should be investigated

**Evidence fields:** path, reason

**Related:** SPEC-AS-005

---

## runtime

### `EK_RUNTIME_BINARY_QUARANTINED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** spawn refused by quarantine

**Operator action:** inspect quarantine state and verify the binary signature or crash history before allowing it again

**Evidence fields:** hash_prefix, since_ms

**Related:** SPEC-AS-005

---

### `EK_RUNTIME_HANDSHAKE_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime rejected reconnect handshake reply

**Operator action:** verify BEAM and runtime protocol versions match and capture the raw handshake reply

**Evidence fields:** reason, reply

**Related:** SPEC-PROTO-001

---

### `EK_RUNTIME_HANDSHAKE_RECV_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime handshake reply could not be received

**Operator action:** check whether erlkoenig_rt accepted the socket and then closed it during handshake

**Evidence fields:** reason

**Related:** SPEC-PROTO-001

---

### `EK_RUNTIME_HANDSHAKE_SEND_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime handshake could not be sent

**Operator action:** check runtime socket liveness and whether reconnect raced with runtime shutdown

**Evidence fields:** reason

**Related:** SPEC-PROTO-001

---

### `EK_RUNTIME_NOT_CONNECTED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime socket is not connected

**Operator action:** inspect the container lifecycle timeline for tcp_closed or reconnect failures before retrying the command

**Evidence fields:** container_id, operation

---

### `EK_RUNTIME_NO_SOCKET_PATH`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime socket path is not set

**Operator action:** verify the container was created with a socket path before attempting recovery or reconnect

**Evidence fields:** operation

---

### `EK_RUNTIME_SOCKET_CONNECT_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** wait_and_connect to erlkoenig_rt socket failed

**Operator action:** verify erlkoenig_rt started, the socket path is correct, and the runtime process can bind its Unix socket

**Evidence fields:** socket_path, reason, timeout_ms

**Related:** SPEC-PROTO-001

---

### `EK_RUNTIME_SPAWN_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** erlkoenig_rt rejected CMD_SPAWN

**Operator action:** inspect the runtime error code and message; check binary path, seccomp, uid/gid, rootfs and volume options

**Evidence fields:** code, message, binary

**Related:** SPEC-PROTO-001

---

### `EK_RUNTIME_SYNC_COMMAND_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** runtime synchronous command failed

**Operator action:** inspect socket state and runtime logs for the setup command that did not return a reply

**Evidence fields:** reason, timeout_ms

**Related:** SPEC-PROTO-001

---

### `EK_RUNTIME_UNEXPECTED_SPAWN_REPLY`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** unknown reply to CMD_SPAWN

**Operator action:** verify BEAM and runtime protocol versions match and capture the raw reply for protocol debugging

**Evidence fields:** reply

**Related:** SPEC-PROTO-001

---

## security

### `EK_SECURITY_CAP_DROP_FAILED`

- **Severity:** `critical`
- **Since:** `0.9.0`
- **Description:** capability drop failed

**Operator action:** do not start the workload until the kernel capability setup path succeeds

**Evidence fields:** capability, reason

**Iron rule:** _declared security boundaries are hard fail-closed requirements_

---

## threat

### `EK_THREAT_ACTOR_BAN_TRIGGERED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** threat actor triggered a ban

**Operator action:** inspect the reason, duration and ban_count; the ban will be handed to threat_mesh for kernel enforcement

**Evidence fields:** ip, reason, duration_seconds, ban_count

**Related:** SPEC-EK-020

---

### `EK_THREAT_ACTOR_EVENT_BROADCAST_FAILED`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** threat actor event broadcast failed

**Operator action:** check pg membership for ct_guard_events; detection still proceeds, but dashboards may miss actor transition events

**Evidence fields:** message, class, error

**Related:** SPEC-EK-020

---

### `EK_THREAT_ACTOR_SUSPICIOUS_TRANSITION`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** threat actor entered suspicious state

**Operator action:** inspect recent connection ports for the source IP; this is a pre-ban detection state, not yet kernel enforcement

**Evidence fields:** ip, ports

**Related:** SPEC-EK-020

---

### `EK_THREAT_GUARD_ACTOR_START_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** ct_guard could not start threat actor

**Operator action:** inspect threat supervisor state and actor registry; conntrack events for this source are dropped until actor creation succeeds

**Evidence fields:** src, class, error

**Related:** SPEC-EK-020

---

### `EK_THREAT_GUARD_ACTOR_START_RETRY_EXHAUSTED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** ct_guard actor start retry budget was exhausted

**Operator action:** inspect stale starting markers in the actor registry and threat supervisor liveness

**Evidence fields:** src, retries

**Related:** SPEC-EK-020

---

### `EK_THREAT_GUARD_DISPATCH_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** ct_guard could not dispatch conntrack event to actor

**Operator action:** inspect actor registry health and threat supervisor state; conntrack events for this source may be dropped

**Evidence fields:** src, dport, event

**Related:** SPEC-EK-020

---

### `EK_THREAT_GUARD_STATS_BROADCAST_FAILED`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** ct_guard stats broadcast failed

**Operator action:** check pg membership for ct_guard_events; detection continues but stats consumers may miss a sample

**Evidence fields:** event, class, error

**Related:** SPEC-EK-020

---

### `EK_THREAT_GUARD_WHITELIST_PARSE_FAILED`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** ct_guard whitelist entry could not be parsed

**Operator action:** fix the ct_guard whitelist entry; invalid entries are ignored and will not protect an address from actor dispatch

**Evidence fields:** entry, reason

**Related:** SPEC-EK-020

---

### `EK_THREAT_KERNEL_BAN_CRASHED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** threat ban crashed while applying kernel state

**Operator action:** inspect the exception class and restart state for the nft service before relying on threat reaction

**Evidence fields:** ip, reason, class, error

**Related:** SPEC-EK-020

---

### `EK_THREAT_KERNEL_BAN_REJECTED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** kernel rejected threat ban

**Operator action:** inspect the nested nft error and verify the threat blocklist set, nft table and kernel permissions before trusting enforcement

**Evidence fields:** ip, reason, nft_code, nft_error

**Related:** SPEC-EK-020

---

### `EK_THREAT_KERNEL_BAN_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** threat ban timed out while applying kernel state

**Operator action:** treat threat enforcement as delayed; inspect nft ACK latency, host load and stale netlink messages

**Evidence fields:** ip, reason, nft_code, nft_error

**Related:** SPEC-EK-020

---

### `EK_THREAT_KERNEL_UNBAN_CRASHED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** threat unban crashed while applying kernel state

**Operator action:** inspect the exception class and nft service restart state; the IP may remain blocked until cleanup succeeds

**Evidence fields:** ip, class, error

**Related:** SPEC-EK-020

---

### `EK_THREAT_KERNEL_UNBAN_REJECTED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** kernel rejected threat unban

**Operator action:** inspect the nested nft error and verify whether the IP remains intentionally banned by another source

**Evidence fields:** ip, nft_code, nft_error

**Related:** SPEC-EK-020

---

### `EK_THREAT_KERNEL_UNBAN_TIMEOUT`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** threat unban timed out while applying kernel state

**Operator action:** inspect nft ACK latency and confirm whether the blocklist entry is still present before declaring the IP released

**Evidence fields:** ip, nft_code, nft_error

**Related:** SPEC-EK-020

---

### `EK_THREAT_MESH_PROPAGATION_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** threat mesh propagation failed

**Operator action:** check pg membership, cluster connectivity and whether remote nodes are receiving ban/unban events

**Evidence fields:** message, class, error

**Related:** SPEC-EK-020

---

### `EK_THREAT_WHITELIST_PARSE_FAILED`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** threat whitelist entry could not be parsed

**Operator action:** fix the whitelist entry format; invalid entries are ignored and will not protect an address from threat bans

**Evidence fields:** entry, reason

**Related:** SPEC-EK-020

---

## volume

### `EK_VOLUME_BACKING_CREATE_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** volume backing directory could not be created

**Operator action:** verify the volumes root exists, is writable by erlkoenig and has enough space/inodes for a new volume directory

**Evidence fields:** uuid, host_path, container, persist, reason

**Iron rule:** _rootfs and volume operations are spawn-time integrity checkpoints_

**Related:** SPEC-EK-003

---

### `EK_VOLUME_BY_NAME_PATH_INVALID`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** volume by-name symlink path is invalid

**Operator action:** fix the container name so the advisory by-name symlink cannot escape the volume root

**Evidence fields:** container, persist

**Iron rule:** _rootfs and volume operations are spawn-time integrity checkpoints_

**Related:** SPEC-EK-003

---

### `EK_VOLUME_CLEANUP_EPHEMERAL_PARTIAL_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** ephemeral volume cleanup partially failed

**Operator action:** inspect retained volume metadata and retry cleanup after fixing the destroy failure

**Evidence fields:** container, uuid, reason

**Related:** SPEC-EK-003

---

### `EK_VOLUME_DESTROY_RM_RF_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** volume destroy could not remove backing directory

**Operator action:** fix the underlying filesystem or permissions and retry destroy; metadata is intentionally retained to avoid orphaning data

**Evidence fields:** uuid, host_path, container, persist, reason

**Related:** SPEC-EK-003

---

### `EK_VOLUME_INDEX_OPEN_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** volume metadata index could not be opened

**Operator action:** check the volumes root path, DETS index file permissions and filesystem health

**Evidence fields:** path, reason

**Related:** SPEC-EK-003

---

### `EK_VOLUME_OWNERSHIP_RECONCILE_FAILED`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** volume ownership reconciliation failed

**Operator action:** check CAP_CHOWN and filesystem ownership; the volume remains usable but writes may fail for the container user

**Evidence fields:** path, uid, gid, reason

**Related:** SPEC-EK-003

---

### `EK_VOLUME_PATH_INVALID`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** volume persist name is invalid

**Operator action:** fix the DSL persist name; only lowercase letters, digits, dash and underscore are accepted, and the name must not escape the volume root

**Evidence fields:** container, persist, reason

**Iron rule:** _rootfs and volume operations are spawn-time integrity checkpoints_

**Related:** SPEC-EK-003

---

### `EK_VOLUME_QUOTA_APPLY_FAILED`

- **Severity:** `warn`
- **Since:** `0.9.0`
- **Description:** volume quota command failed

**Operator action:** check xfs_quota availability, filesystem type and project quota support; in enforce mode the quota operation failed and metadata was not updated

**Evidence fields:** tag, message, reason, mode, uuid, host_path

**Related:** SPEC-EK-003

---

### `EK_VOLUME_STORE_ENSURE_FAILED`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** volume store could not ensure backing path

**Operator action:** inspect the nested store reason, volume root permissions and quota configuration before retrying the spawn

**Evidence fields:** container, persist, reason

**Iron rule:** _rootfs and volume operations are spawn-time integrity checkpoints_

**Related:** SPEC-EK-003

---

### `EK_VOLUME_VOLUME_NOT_FOUND`

- **Severity:** `error`
- **Since:** `0.9.0`
- **Description:** volume metadata entry was not found

**Operator action:** verify the requested UUID still exists in the volume store before retrying the operation

**Evidence fields:** uuid, operation

**Related:** SPEC-EK-003

---
