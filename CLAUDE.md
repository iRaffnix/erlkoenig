# erlkoenig

Zero-trust container runtime for Linux, built on Erlang/OTP 28+ with a 68KB static C runtime.

## Build & Test

```
make              # full build (erlang + C runtime + tests + release)
make check        # all non-root tests (eunit + dialyzer + dsl)
make erl          # erlang compile only
make test         # eunit (no root)
make dialyzer     # type analysis
make rt           # C runtime (static musl)
make integration  # integration tests (needs sudo)
make release      # OTP release tarball
```

Formatter: `erlfmt` (runs via rebar3 plugin). Warnings are errors (`warnings_as_errors`).

## Project Structure

```
apps/
  erlkoenig_core/       # sole OTP app (v0.3.0, 33+ modules + C runtime)
    src/                 # erlang modules
    c-runtime/           # C container spawner (musl-static)
    config/              # sys.config
```

Single-app umbrella. External dep: `erlkoenig_nft` (nftables firewall, AF_NETLINK).

## Key Entry Points

| Module | Role |
|--------|------|
| `erlkoenig_app` | OTP application callback, boot sequence |
| `erlkoenig_zone` | Container lifecycle (create/start/stop/destroy) |
| `erlkoenig_zone_sup` | Per-zone supervisor tree |
| `erlkoenig_ctl` | Control socket API (Unix domain) |
| `erlkoenig_cgroup` | cgroup v2 resource limits and accounting |

## Scheduler Iron Rules

1. **Reserve = protected operations zone.** Cgroup reservation covers BEAM + systemd + journald + SSH + resolver + FS writeback. Not just "VM minimum".
2. **Memory and PIDs are kill factors, CPU is secondary.** Schedule against declared limits, never current usage. Memory/PIDs = hard constraints; CPU = soft preference.
3. **Local admission is sovereign.** Central scheduler may NEVER override a node's local admission rejection. No "force" flags.

## Architecture

Full design docs: `/home/dev/code/erlkoenigin/systems/erlkoenig.md`

## Constraints

- OTP 28+ required (`minimum_otp_vsn "28"`)
- `erlkoenig_nft` must be available (git dep, branch `main`)
- Integration tests and C runtime tests require root/sudo
- Apache-2.0 licensed
