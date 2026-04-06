# ELF Binary Analysis

erlkoenig includes a pure Erlang ELF64 analyzer that inspects container
binaries at deploy time. It extracts syscalls, generates seccomp profiles,
detects the programming language, and finds dependencies — all without
external tools.

## What It Does

```
Binary (.elf)
    │
    ├── Parse ELF64 headers, sections, symbols
    │
    ├── Decode .text section
    │   ├── x86-64: find SYSCALL instructions, trace RAX
    │   └── AArch64: find SVC #0, trace X8
    │
    ├── Extract syscall numbers → names
    │   └── "read", "write", "openat", "clone", "mmap", ...
    │
    ├── Generate seccomp-BPF filter
    │   └── Allow only the syscalls the binary actually uses
    │
    ├── Detect language
    │   ├── Go: parse GOROOT, build info, module path
    │   ├── Rust: parse .cargo section, crate names
    │   ├── Zig: detect Zig runtime symbols
    │   └── C: default (no runtime markers)
    │
    └── Find dependencies
        ├── Go: module imports from build info
        └── Rust: crate names from debug info
```

## Usage

The main entry point is `erlkoenig_elf` — a facade that delegates to
internal modules.

### Parse a Binary

```erlang
{ok, Elf} = erlkoenig_elf:parse("/opt/myapp/server").
```

### Full Analysis

```erlang
{ok, Info} = erlkoenig_elf:analyze(Elf).
%% #{arch => x86_64,
%%   type => exec,
%%   is_static => true,
%%   is_pie => false,
%%   language => go,
%%   text_size => 4521984,
%%   total_size => 12345678,
%%   syscalls => #{numbers => [0,1,3,9,...], names => [...], categories => #{...}},
%%   language_info => #{...}}
```

### Extract Syscalls

```erlang
{ok, #{numbers := Numbers, names := Names}} = erlkoenig_elf:syscalls(Elf).
%% Numbers = [0, 1, 3, 9, 10, 11, ...]
%% Names = [<<"read">>, <<"write">>, <<"close">>, <<"mmap">>, ...]

{ok, Names} = erlkoenig_elf:syscall_names(Elf).
%% [<<"brk">>, <<"clone">>, <<"close">>, <<"exit_group">>, ...]
```

### Generate Seccomp Profile

```erlang
{ok, Profile} = erlkoenig_elf:seccomp_profile(Elf).
%% Allowlist: only the syscalls found in the binary

{ok, Json} = erlkoenig_elf:seccomp_json(Elf).
%% OCI-compatible seccomp profile JSON

{ok, Bpf} = erlkoenig_elf:seccomp_bpf(Elf).
%% Raw BPF bytecode for seccomp(SECCOMP_SET_MODE_FILTER)
```

### Detect Language

```erlang
go = erlkoenig_elf:language(Elf).

{ok, GoInfo} = erlkoenig_elf:go_info(Elf).
%% #{version => "go1.22.0", module => "github.com/...", ...}

{ok, RustInfo} = erlkoenig_elf:rust_info(Elf).
%% #{toolchain => "stable-x86_64-unknown-linux-gnu", crates => [...]}
```

### Find Dependencies

```erlang
{ok, Deps} = erlkoenig_elf:deps(Elf).
%% Go: module imports
%% Rust: crate list

{ok, Caps} = erlkoenig_elf:dep_capabilities(Elf).
%% #{<<"net/http">> => [network, ...], ...}

Anomalies = erlkoenig_elf:dep_anomalies(Elf).
%% [#{dep => <<"crypto/tls">>, level => warn, reason => unexpected_network}]
```

### Patch Functions

```erlang
ok = erlkoenig_elf:patch("/opt/myapp", "dangerous_func", nop).
%% Replace function body with NOPs

ok = erlkoenig_elf:patch_at("/opt/myapp", 16#401000, 64, ret).
%% Patch 64 bytes at address with immediate return
```

## Integration with erlkoenig

The ELF analyzer integrates automatically via `erlkoenig_rootfs_builder`.
When a container binary is deployed, erlkoenig:

1. Parses the ELF binary
2. Extracts the syscall set
3. Generates a seccomp-BPF profile
4. Applies the filter to the container's namespace

This means containers are automatically restricted to only the syscalls
their binary actually uses — zero-configuration, zero-overhead at runtime.

## Internal Modules

| Module | LOC | Purpose |
|--------|-----|---------|
| `elf_parse` | 493 | ELF64 header, section, segment parsing |
| `elf_parse_symtab` | 192 | Symbol table parsing |
| `elf_decode_x86_64` | 1160 | x86-64 instruction decoding, SYSCALL tracing |
| `elf_decode_aarch64` | 235 | AArch64 instruction decoding, SVC tracing |
| `elf_syscall` | 248 | Syscall extraction orchestrator |
| `elf_syscall_db` | 876 | Linux syscall number ↔ name database |
| `elf_seccomp` | 372 | Seccomp-BPF filter generation |
| `elf_lang` | 302 | Language detection (Go/Rust/Zig/C) |
| `elf_lang_go` | 556 | Go binary analysis (build info, modules) |
| `elf_lang_rust` | 417 | Rust binary analysis (crates, toolchain) |
| `elf_lang_dwarf` | 572 | DWARF debug info parsing |
| `elf_dep` | 385 | Dependency extraction |
| `elf_patch` | 263 | In-place function patching |
| `elf_report` | 283 | Human-readable analysis reports |
| `erlkoenig_elf` | 314 | Public facade |
