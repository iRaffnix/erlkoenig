# Build System

Everything is `make`. One Makefile, no wrapper scripts, no plugins.
The Makefile orchestrates three toolchains (CMake for C, rebar3 for
Erlang, Mix for the Elixir DSL).

## Quick start

```bash
# Install dependencies (Debian Trixie)
apt-get install erlang erlang-dev rebar3 cmake build-essential musl-tools golang

# Build everything and run all tests
make all

# Or step by step
make rt          # C runtime
make erl         # Erlang apps
make check       # tests (no root needed)
make release     # OTP release tarball
```

## Targets

### Build

| Target | What it does | Root needed |
|--------|-------------|-------------|
| `make all` | `rt` + `erl` + `check` + `release` | no |
| `make rt` | C runtime via CMake + musl-gcc -> `build/release/erlkoenig_rt` (68 KB static binary) | no |
| `make rt-san` | C runtime with AddressSanitizer + UBSan -> `build/san/erlkoenig_rt` | no |
| `make erl` | `rebar3 compile` -- all Erlang apps | no |
| `make release` | OTP release tarball -> `dist/erlkoenig-*.tar.gz` + `dist/erlkoenig-dsl` | no |
| `make dsl` | Elixir DSL (`mix compile`) | no |
| `make dsl-escript` | Standalone DSL binary (1.4 MB, needs only `erl`) | no |
| `make go-demos` | Static Go binaries (echo-server, reverse-proxy, api-server) | no |

### Test

| Target | What it does | Root needed |
|--------|-------------|-------------|
| `make check` | `test` + `dialyzer` + `test-dsl` -- all tests without root | no |
| `make test` | `rebar3 eunit` -- Erlang unit tests | no |
| `make dialyzer` | Dialyzer type analysis (filters noise, fails on real errors) | no |
| `make test-dsl` | `mix test` -- Elixir DSL tests (compiles all examples) | no |
| `make test-rt` | C runtime unit tests (libcheck, 12 tests) | **yes** (namespaces, mounts) |
| `make integration` | Integration tests (escripts, real containers) | **yes** |

### Install

Install from a GitHub Release or local CI artifacts:

```bash
# From GitHub release
sudo sh install.sh --version v0.2.0

# From local CI artifacts (testing)
sudo sh install.sh --local /tmp/artifacts
```

See [INSTALL.md](INSTALL.md) for details.

### Release

Tag a release (from `main` only):

```bash
make tag VERSION=0.2.0
git push origin main v0.2.0
```

### Clean

| Target | What it does |
|--------|-------------|
| `make clean` | Everything: `clean-rt` + `clean-erl` + `clean-dsl` + `dist/` |
| `make clean-rt` | Remove `build/` (all CMake outputs) |
| `make clean-erl` | `rebar3 clean` + remove `_build/` |
| `make clean-dsl` | `mix clean` + remove `dsl/_build/` |

## C Runtime Build

The C runtime is built with CMake, using musl-gcc for static linking:

```
make rt
  └── CC=musl-gcc cmake -B build/release -DCMAKE_BUILD_TYPE=Release
  └── cmake --build build/release -j$(nproc)
  └── build/release/erlkoenig_rt   (68 KB, statically linked)
```

The output is a fully static ELF binary. It runs on any Linux kernel
>= 5.2 without shared libraries.

### CMake options

| Option | Default | Purpose |
|--------|---------|---------|
| `ERLKOENIG_BUILD_DEMOS` | ON (release) | Build test binaries in `build/release/demo/` |
| `ERLKOENIG_BUILD_TESTS` | OFF | Build libcheck test suite |
| `ERLKOENIG_SANITIZE` | OFF | Enable ASan + UBSan (Debug builds) |

### Test binaries (c-runtime/demo/)

> **Warning:** These binaries (`crasher`, `mem_eater`, etc.) are
> designed to crash, consume RAM, or attempt forbidden syscalls.
> They exist to test container isolation -- **do not run them on a
> host system outside of an Erlkoenig container.**

On the server they are installed to `/opt/erlkoenig/rt/demo/` with
`chmod 700` (root-only). They are not included in the OTP release
tarball and are never added to `$PATH`.

| Binary | Purpose |
|--------|---------|
| `sleeper` | Sleep forever (lifecycle test) |
| `echo_server` | TCP echo (networking test) |
| `hello_output` | Print to stdout/stderr (output capture test) |
| `crasher` | Segfault after N seconds (crash handling test) |
| `mem_eater` | Allocate RAM until OOM-killed (memory limit test) |
| `disk_writer` | Write to filesystem (read-only rootfs test) |
| `proc_check` | Inspect /proc (proc masking test) |
| `stdin_echo` | Echo stdin (stdin forwarding test) |
| `syscall_fork` | Fork (PID limit test) |
| `syscall_mount` | Attempt mount (seccomp test) |
| `syscall_write_rootfs` | Write to / (read-only rootfs test) |

### Sanitizer build

For development, build with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
make rt-san
# Run manually:
build/san/erlkoenig_rt
```

This uses the system gcc (not musl-gcc) and links dynamically.
Only for development -- the output is not deployable.

### C runtime tests

The test suite uses [libcheck](https://libcheck.github.io/check/)
with fork-per-test isolation:

```bash
apt-get install check pkgconf    # one-time
sudo make test-rt                # needs root for namespace tests
```

12 tests covering namespace creation, mount setup, pivot_root,
capability drop, seccomp filters, signal handling, rlimits, and
/proc masking. Tests that need root are skipped when run unprivileged.

## Erlang Build

Standard rebar3 project with one OTP application and an external dependency:

```
apps/
└── erlkoenig_core/    Control plane (containers, zones, networking)

# External dependency (fetched by rebar3):
# erlkoenig_nft -- Firewall engine (https://github.com/iRaffnix/erlkoenig_nft)
```

```bash
make erl         # rebar3 compile
make test        # rebar3 eunit
make dialyzer    # rebar3 dialyzer (filtered for real errors)
```

### Dialyzer

The Makefile filters Dialyzer output to fail only on real type errors
(`no_return`, `will never be called`, `invalid_contract`). Warnings
about missing spec annotations are ignored.

## Elixir DSL Build

The DSL lives in `dsl/` and compiles `.exs` files into Erlang term files:

```bash
make dsl             # mix compile
make dsl-escript     # standalone binary -> dsl/erlkoenig-dsl
make test-dsl        # mix test (compiles all examples)
```

The escript bundles the Elixir compiler -- the output binary (1.4 MB)
needs only `erl` on the target system, not Elixir.

## OTP Release

```bash
make release
```

This runs `rebar3 release` + `rebar3 tar` and copies the output to `dist/`:

```
dist/
├── erlkoenig-0.1.0.tar.gz    OTP release (BEAM + ERTS, ~15 MB)
└── erlkoenig-dsl             Standalone DSL binary (1.4 MB)
```

The release includes ERTS -- no Erlang installation needed on the
target server. The C runtime is **not** included; it's installed
separately via `install.sh`.

### Release overlay

The release tarball includes documentation and examples:

```
doc/
├── README.md
├── ARCHITECTURE.md
└── STATIC_BINARIES.md

examples/
├── simple_echo.exs
├── hardened_worker.exs
├── web_cluster.exs
├── three_tier_live.exs
└── ... (11 .exs files)
```

## Directory layout

```
Makefile                 The one Makefile
rebar.config             Erlang build config + release overlay
install.sh               Production installer (ships with releases)
c-runtime/               C source (rt, namespaces, seccomp, netcfg)
  CMakeLists.txt         CMake build for C runtime
  test/                  libcheck test suite
apps/
  erlkoenig_core/        Control plane application
dsl/                     Elixir DSL
  mix.exs                Mix project
  examples/              .exs example configs
  vim/                   Vim syntax highlighting
demos/                   Go demo binaries (echo, proxy, api)
integration-tests/       Integration test scripts
docs/                    Public documentation
docs-intern/             Internal documentation (gitignored)
```
