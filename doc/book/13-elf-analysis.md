# Chapter 13 — ELF Analysis & Seccomp

erlkoenig reads the binary you're about to run. It parses the ELF
file, infers the source language from structural markers, walks the
instruction stream to enumerate every syscall the binary can issue,
and generates a seccomp-BPF profile restricting the kernel to
exactly that set. All of it happens in Erlang, without external
tools, at container spawn time (during rootfs setup, after the
namespace is ready). Results are cached per binary so subsequent
spawns of the same container skip the analysis.

## Why analyse binaries

A seccomp profile made by hand is either too narrow (and kills the
binary in production when it hits an unexpected syscall) or too
broad (and lets a compromised binary do things it never needed to).
Static analysis gives a third answer: the profile is the exact set
of syscalls the binary's instructions actually contain. Nothing more
is possible, nothing required is missing. It's auto-generated on the
first load of a new binary and cached in the artifact store.

## The ELF parser

`elf_parse.erl` reads ELF64 headers and section tables. Program
headers, section headers, symbol tables, string tables, DWARF debug
info — each has its own decoder module. Both little-endian and
big-endian files parse correctly; x86_64 and aarch64 are the
supported instruction architectures.

Architecture affects only the syscall-instruction decoder. The rest
of the pipeline is architecture-independent: the ELF structure is
the same across Linux targets.

## Language inference

Before analysing instructions, erlkoenig asks what language the
binary was written in. `elf_lang.erl` walks a priority list:

| Order | Check                                       | Signal                        |
|-------|---------------------------------------------|-------------------------------|
| 1     | `.go.buildinfo` section exists              | Go                            |
| 2     | `.gopclntab` section with Go magic          | Go (older builds)             |
| 3     | `_ZN` or `_R` mangled symbols               | Rust                          |
| 4     | `std.start` / `std.builtin` symbols         | Zig                           |
| 5     | DWARF `DW_AT_language` attribute            | C / C++ / other               |
| 6     | fallback                                    | unknown                       |

Language information shapes how syscalls are located. Go binaries
concentrate their syscall instructions inside runtime dispatch
functions; a naive scan misses most of them because the concrete
syscall number lives in a register set by the caller, not as an
immediate at the instruction. Rust and C binaries typically have
the immediate-before-syscall pattern inlined.

## Syscall detection

The scanner walks the `.text` section looking for syscall
instructions. For x86_64, that's the two-byte `0F 05` opcode. For
aarch64, it's the 32-bit `SVC #0` (`D4 00 00 01`). Each match is an
anchor; from there the decoder walks backwards looking for the
immediate that sets the syscall-number register (`RAX` on x86_64,
`X8` on aarch64).

Simple case — inlined syscall:

```
mov rax, 0x00000005   ; syscall number 5 = fstat
syscall               ; 0F 05
```

The backward walk finds the `mov` and records syscall 5.

Hard case — Go runtime dispatch:

```
; some Go callsite
mov rax, 0x00000005
call runtime.syscall.Syscall
```

The `syscall` instruction is inside `runtime.syscall.Syscall`, many
calls away from the immediate. `resolve_callsite_syscalls` walks the
call graph: find the dispatch function, find every site that calls
it, extract the `rax` immediate at each call site.

The resulting set is the complete list of syscall numbers the
binary can possibly issue.

## Generated seccomp profile

`elf_seccomp.erl` turns the set into an OCI-compatible JSON profile.
The shape is standard seccomp:

```json
{
  "defaultAction": "SCMP_ACT_KILL_PROCESS",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    { "names": ["read", "write", "close", ...],
      "action": "SCMP_ACT_ALLOW" }
  ]
}
```

Default action is `KILL_PROCESS` — anything not in the allowlist
terminates the container immediately. The allowlist is exactly the
syscalls the scanner detected, translated from numbers to names via
the syscall database `elf_syscall_db.erl`.

Two compilation strategies coexist. Under 20 allowed syscalls, the
profile is a linear chain of `JEQ` comparisons. Above that, the
compiler builds a balanced binary search tree of `JGE` branches —
O(log N) rather than O(N) per checked syscall. The cut-off reflects
common binary-footprint patterns; typical Go services land around 50
syscalls, Rust and C smaller.

## DSL integration

In the `container` block:

| Value            | Effect                                                 |
|------------------|--------------------------------------------------------|
| `seccomp: :default` | Generate profile from static analysis (the usual choice) |
| `seccomp: :none`    | No filter at all                                       |

The default mode is `:default`. Analysis happens inside
`erlkoenig_rootfs_builder:generate_seccomp/1` during rootfs
construction; the resulting profile is written into the container
rootfs and applied inside the child just before execve
(→ Chapter 12).

If analysis fails (unrecognised architecture, corrupted binary,
language not yet supported), the container spawn fails loud rather
than running with no filter. Operators who know what they're doing
can force `:none`, but the failure mode is designed to be a
deliberate choice, not a silent fallback.

## Hands-on: inspect the generated seccomp profile

This walkthrough runs the analyser on an arbitrary binary and shows
the resulting syscall set. No container spawn required — the analyser
is pure Erlang, call it directly.

**1. Parse the ELF header.**

```bash
erlkoenig eval '
  {ok, Elf} = erlkoenig_elf:parse(
    "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"),
  io:format("arch:     ~p~n", [maps:get(arch, Elf)]),
  io:format("class:    ~p~n", [maps:get(class, Elf)]),
  io:format("sections: ~p~n", [length(maps:get(sections, Elf, []))]).'
```

Expected:

    arch:     x86_64
    class:    elf64
    sections: 29

**2. Detect the source language.**

```bash
erlkoenig eval '
  {ok, Elf} = erlkoenig_elf:parse(
    "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"),
  Lang = elf_lang:detect(Elf),
  io:format("language: ~p~n", [Lang]).'
```

The heuristic scans for structural fingerprints: Go's `.gopclntab`
section with a magic header, Rust's `__RUST_` debug symbols, C++'s
mangled names. The demo binary is C — output:

    language: c

**3. Enumerate syscalls.**

```bash
erlkoenig eval '
  {ok, Syscalls} = erlkoenig_seccomp_gen:analyse(
    "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"),
  io:format("syscall count: ~p~n", [length(Syscalls)]),
  io:format("first 15: ~p~n", [lists:sublist(Syscalls, 15)]).'
```

Expected (subset will vary by binary):

    syscall count: 42
    first 15: [accept4, bind, brk, clock_gettime, close, connect,
               exit_group, fcntl, fstat, getsockopt, ioctl, listen,
               mmap, openat, read]

**4. Inspect the compiled BPF filter.**

```bash
erlkoenig eval '
  {ok, BPF} = erlkoenig_seccomp_gen:build(
    "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"),
  io:format("BPF bytes: ~p~n", [byte_size(BPF)]),
  %% First 16 bytes for sanity
  <<Head:16/binary, _/binary>> = BPF,
  io:format("head: ~p~n", [Head]).'
```

The bytes are the raw `sock_filter` array that gets passed to
`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` in the child.
Each filter entry is 8 bytes; a typical binary's profile is a few
hundred bytes.

**5. Compare against a different binary.**

```bash
# A Go binary (if you have one handy)
erlkoenig eval '
  {ok, Syscalls} = erlkoenig_seccomp_gen:analyse("/usr/bin/go"),
  io:format("~p syscalls~n", [length(Syscalls)]).'
```

Go binaries typically end up with 80–120 syscalls — Go's runtime
touches more of the kernel (scheduler signals, network poll,
timers) than a minimal C server.

**6. Force a failure mode.** Point the analyser at a non-ELF file:

```bash
erlkoenig eval '
  io:format("~p~n", [erlkoenig_elf:parse("/etc/passwd")]).'
# => {error, not_elf}
```

If you put `seccomp: :default` on a container whose binary fails
analysis, the spawn fails with an explicit error reason. The
container never runs with an empty filter.
