# Chapter 12 — Runtime Architecture

The C runtime is a single static binary, 168 KB, built against musl.
It speaks a length-delimited TLV protocol over a Unix-domain socket,
spawns containers with `clone3()` into a fresh namespace bundle,
sets up the rootfs, applies seccomp and capability drops, and hands
over to `execve()`. This chapter follows a container end-to-end, from
the first byte on the wire to the first instruction of the target
binary.

## The binary

`erlkoenig_rt` is invoked once per BEAM instance, bound to
`/run/erlkoenig/containers/<container>.sock`. The binary's first act
is self-protection: it copies its own executable into a sealed
`memfd`, re-execs itself via `fexecve()`, and only then enters the
main loop. After the re-exec the process image lives entirely in
kernel memory — on-disk tampering affects nothing until the next
launch.

The main loop is straightforward. Frames arrive as length-prefixed
TLV messages; each frame is dispatched by its tag. Replies go out
the same socket in the same format.

## The TLV protocol

Every message carries a tag and a version, followed by zero or more
TLV attributes:

```
┌────────┬─────────┬──────────────────────────────┐
│ Tag:8  │ Ver:8   │ [TLV Attributes...]          │
└────────┴─────────┴──────────────────────────────┘

each attribute:
┌──────────┬──────────┬─────────────────┐
│ Type:16  │ Len:16   │ Value:Len bytes │
└──────────┴──────────┴─────────────────┘
```

Commands flow from Erlang to C, replies flow back. Major commands:

| Tag   | Name              | Purpose                                      |
|-------|-------------------|----------------------------------------------|
| 0x10  | CMD_SPAWN         | create container, return pid + netns path    |
| 0x11  | CMD_GO            | execute the target binary                    |
| 0x12  | CMD_KILL          | send a signal                                |
| 0x15  | CMD_NET_SETUP     | configure the container's network namespace  |
| 0x16  | CMD_WRITE_FILE    | drop a file into the rootfs                  |
| 0x17  | CMD_STDIN         | forward bytes to the container's stdin       |
| 0x19  | CMD_DEVICE_FILTER | apply a cgroup device-filter program         |
| 0x1A  | CMD_METRICS_START | begin cgroup stats collection                |
| 0x1C  | CMD_NFT_SETUP     | apply an nft batch inside the container netns |

Replies:

| Tag  | Name                  | Payload                             |
|------|-----------------------|-------------------------------------|
| 0x01 | REPLY_OK              | acknowledgement                     |
| 0x02 | REPLY_ERROR           | errno + message                     |
| 0x03 | REPLY_CONTAINER_PID   | child pid + netns path              |
| 0x04 | REPLY_READY           | the container has execve'd          |
| 0x05 | REPLY_EXITED          | exit code + term signal             |
| 0x07 | REPLY_STDOUT          | raw stdout bytes                    |
| 0x08 | REPLY_STDERR          | raw stderr bytes                    |
| 0x09 | REPLY_METRICS_EVENT   | BPF-tracepoint event                |

## CMD_SPAWN and its attributes

CMD_SPAWN carries everything the C runtime needs to build a
container. The BEAM encodes a map of options; the C runtime decodes
it into a `struct erlkoenig_spawn_opts`. The attributes:

| ID | Name             | Type           | Meaning                                    |
|----|------------------|----------------|--------------------------------------------|
| 1  | PATH             | bytes          | absolute path to the binary                |
| 2  | UID              | u32            | uid inside the container                   |
| 3  | GID              | u32            | gid inside the container                   |
| 4  | CAPS             | u64            | capability bitmask to retain               |
| 5  | ARG              | bytes (repeat) | one argv element                           |
| 6  | FLAGS            | u32            | spawn flags (pty, ...)                     |
| 7  | ENV              | bytes (repeat) | one environment entry "KEY\0VALUE"         |
| 8  | ROOTFS_MB        | u32            | tmpfs size for the rootfs                  |
| 9  | SECCOMP          | u8             | seccomp profile id                         |
| 10 | DNS_IP           | u32            | resolver IP for /etc/resolv.conf           |
| 11 | VOLUME           | bytes (repeat) | one volume, full mount spec                |
| 12 | MEMORY_MAX       | u64            | cgroup memory.max                          |
| 13 | PIDS_MAX         | u32            | cgroup pids.max                            |
| 14 | CPU_WEIGHT       | u32            | cgroup cpu.weight                          |
| 15 | IMAGE_PATH       | bytes          | optional EROFS image                       |

The volume attribute itself is structured: two null-terminated path
strings, a `flags:u32` bitmask of MS_* bits, a `clear:u32` bitmask
for remount, a `propagation:u8` enum, a `recursive:u8` boolean, a
`data_len:u16`, and `data_len` bytes of filesystem-specific data.

## Namespace setup

The C runtime calls `clone3()` with `CLONE_NEWPID | CLONE_NEWNET |
CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP`. User
namespaces are deliberately not used — capabilities are managed
explicitly via `setcap` on the runtime and selective drops inside
the child.

The child process sets up its own rootfs before pivoting into it:

1. **Mount a tmpfs** at a temporary directory. This becomes the
   future root.
2. **Bind-mount essential device nodes** — `/dev/null`, `/dev/zero`,
   `/dev/random`, `/dev/urandom`. Full `/dev` is not exposed.
3. **Mount procfs** at `/proc` with `hidepid=2` — other containers'
   process directories are invisible.
4. **Apply persistent volumes** — each `VOLUME` attribute maps to a
   three-step mount: bind, remount with flags, set propagation.
5. **Write injected files** from CMD_WRITE_FILE, including
   `/etc/resolv.conf`, `/etc/hostname`, signed-deployment metadata.
6. **`pivot_root`** into the new rootfs and unmount the old one.
7. **Signal the parent** by writing a ready byte into the sync
   pipe.

At this point the container is in its final filesystem layout but
hasn't yet executed the target binary.

## The spawn sequence end-to-end

1. BEAM → C: **CMD_SPAWN** with the full attribute set.
2. C: clones the child, waits for the child's "rootfs ready"
   signal, collects the child's pid, reads `/proc/<pid>/ns/net`.
3. C → BEAM: **REPLY_CONTAINER_PID** with pid and netns path.
4. BEAM: sets up the netns from outside — IPVLAN slave, IP, route,
   cgroup, firewall.
5. BEAM → C: **CMD_GO**.
6. C: sends the GO byte to the child's sync pipe.
7. Child: drops capabilities, applies seccomp, calls `execve()`.
8. C → BEAM: **REPLY_READY** on successful execve, or **REPLY_ERROR**
   if execve fails (communicated via the exec-error pipe the parent
   watches).

Failures at any step transition the BEAM's state machine into
`failed` with the reason captured for inspection.

## Capabilities and drops

The runtime itself carries cap_sys_admin, cap_net_admin,
cap_sys_chroot, cap_setuid, cap_setgid, cap_dac_override — granted
via `setcap`. The child inherits these through the clone, uses them
to mount, pivot, and chown, and then drops almost everything before
execve.

The sequence inside the child, just before execve:

1. `prctl(PR_SET_KEEPCAPS, 1)` — keep caps across the UID change.
2. `setresgid()` and `setresuid()` to the container's UID/GID.
3. `erlkoenig_drop_caps()` — keep only the bits the DSL declared.
4. Install the seccomp profile (→ Chapter 13).
5. `execve()` the target binary.

The target binary runs as an unprivileged user with a minimal
capability set and a strict seccomp filter. Everything below that is
the kernel's responsibility.

## Where this chapter hooks into

- Volumes and their mount sequence → Chapter 8.
- Seccomp profile generation → Chapter 13.
- Netlink from the BEAM during NET_SETUP and NFT_SETUP → Chapter 14.
- Wire-level errors and signature rejection → Chapter 10.
