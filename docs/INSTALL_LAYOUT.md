# Erlkoenig Install Layout

This document is the **source of truth** for what an erlkoenig install
under `$PREFIX` (default `/opt/erlkoenig`) is supposed to look like.
It exists because `/opt/erlkoenig` on long-lived hosts has accumulated
phantom copies, stale logs, and operator-generated artefacts that no
installer step ever placed there. The contents below are anchored to
what `install.sh` (the single supported installer) actually creates.

Two audit scripts cover the two distinct surfaces:

**`tools/release-tarball-audit.sh`** — manifest-only audit of a
release tarball. No host required. Wired into `Makefile:release` as
a fail-loud gate that runs against the source tarball under `_build/`
*before* the cp into `dist/`. A failed audit blocks publication.

```
tools/release-tarball-audit.sh dist/erlkoenig-0.9.0.tar.gz
tools/release-tarball-audit.sh --json dist/erlkoenig-0.9.0.tar.gz
```

**`tools/install-layout-audit.sh`** — host-side audit of an actual
install under `$PREFIX`. Local or via SSH, optional cross-check
against a tarball:

```
tools/install-layout-audit.sh                              # local
HOST=erlkoenig-2__root tools/install-layout-audit.sh       # remote
tools/install-layout-audit.sh --against-tarball X.tar.gz   # cross-check
tools/install-layout-audit.sh --json                       # CI mode
```

Wired into `make install-smoke` as the final probe — a green
install-smoke now implies zero layout drift under `$PREFIX`, not just
a working daemon.

## Categories

Every path under `$PREFIX` falls into exactly one category:

| Category              | Meaning                                                   |
|-----------------------|-----------------------------------------------------------|
| `required-release`    | OTP relx release artefact. **Treat as opaque.** Do not reorganise; relx-internal scripts depend on layout. |
| `required-operator`   | Operator-facing files: CLI, error catalog, systemd unit source. |
| `required-runtime`    | C runtime binary `rt/erlkoenig_rt` (capability-bearing).   |
| `optional-dsl`        | Bundled Elixir runtime + dsl libs needed only when operator runs `ek dsl compile`. Currently default-on. |
| `optional-examples`   | DSL examples + tutorials. **Should not live under `$PREFIX`** — they belong under `/usr/share/doc/erlkoenig/` (FHS) and are currently mis-placed. |
| `optional-showcase`   | Non-destructive showcase workload binaries (`rt/demo/case_mgmt`, `rt/demo/deadline_worker`). Built by `make agents-build` / `make showcase`, not part of erlkoenig core. |
| `test-runtime-binaries` | Runtime test binaries (`rt/demo/test-erlkoenig-*`). Some are intentionally destructive or resource-heavy. **Never present as examples; install only on test hosts.** |
| `installer-generated` | Files the installer creates **outside** the OTP release tarball — symlinks (cookie, systemd unit), config skeletons. May live under `$PREFIX` (e.g. cookie symlink) or in standard system locations (`/etc/systemd/system/`). |
| `runtime-generated`   | Files the running daemon/operator creates at execution time — sockets, logs, volume backings, cookie file itself. Live exclusively under `/etc/erlkoenig/`, `/run/erlkoenig/`, `/var/log/erlkoenig/`, `/var/lib/erlkoenig/` — never under `$PREFIX` in a clean install. |
| `stale`               | Anything else found under `$PREFIX` is a bug — either drift, manual hot-patch, or operator-generated content that should not be here. |

## Authoritative layout

Each entry is `path` `category` `expected owner` `notes`.

### `$PREFIX/`

| Path | Category | Owner | Notes |
|---|---|---|---|
| `bin/ek` | required-operator | `root:erlkoenig` | Shell wrapper around `share/ek.escript`. |
| `bin/ek-inspect` `ek-logs` `ek-ps` `ek-top` | required-operator | `root:erlkoenig` | Operator helper scripts. |
| `bin/erlkoenig` | required-release | `root:erlkoenig` | systemd entrypoint; delegates to per-version release script. **Glob bug**: picks first `erlkoenig-*` alphabetically. |
| `bin/erlkoenig-X.Y.Z` | required-release | `root:erlkoenig` | Per-version release bootstrap. **There must be exactly one** matching the active release. |
| `bin/install_upgrade.escript` `nodetool` `no_dot_erlang.boot` | required-release | `root:erlkoenig` | relx internals. Operator never calls these. Treat as opaque. |
| `cookie` | installer-generated | symlink | Symlink → `/etc/erlkoenig/cookie`. Installer creates the symlink; the cookie file itself is `runtime-generated` and lives outside `$PREFIX`. |
| `dist/erlkoenig.service` | required-operator | `root:erlkoenig` | systemd unit **source**. `/etc/systemd/system/erlkoenig.service` is a symlink here. **Do not delete.** |
| `doc/LICENSE` `doc/README.md` | optional-examples | `root:erlkoenig` | Misplaced; FHS says `/usr/share/doc/erlkoenig/`. Low-priority cleanup. |
| `elixir/` | optional-dsl | `root:erlkoenig` | Bundled Elixir for `ek dsl compile`. Currently default-on; product decision pending whether to make opt-in. |
| `erts-X.Y.Z/` | required-release | `root:erlkoenig` | Erlang VM. Opaque relx artefact. |
| `examples/*.exs` `examples/tutorial/*.exs` `examples/tutorial/README.md` | optional-examples | `root:erlkoenig` | DSL examples. Should move to `/usr/share/doc/erlkoenig/examples/`. |
| `examples/**/*.term` | **stale** (host) / **prevent** (tarball) | varies | Compiled DSL outputs from `ek dsl compile`. The current `0.9.0` release tarball does **not** ship any `.term` files under `examples/`; anything found on a host is operator-generated. The `examples/tutorial/` directory is currently bundled wholesale by `rebar.config`, so a stray committed `.term` would silently end up in future releases — **the audit must therefore guard both host AND tarball**. The proper fix is also to make `ek dsl compile` write to a writable working dir by default rather than next to its source. |
| `lib/erlkoenig-X.Y.Z/{ebin,priv}` | required-release | `root:erlkoenig` | erlkoenig OTP app. Opaque. |
| `lib/<otp-dep>-X.Y.Z/` | required-release | `root:erlkoenig` | OTP standard libs + 3rd-party deps (kernel, stdlib, ssl, public_key, crypto, amqp_client, rabbit_common, ranch, recon, thoas, syntax_tools, xmerl, inets, asn1, compiler, sasl, runtime_tools, credentials_obfuscation, tools). Opaque relx artefact. |
| `releases/start_erl.data` `releases/RELEASES` `releases/erlkoenig.rel` | required-release | `root:erlkoenig` | Boot manifest. |
| `releases/X.Y.Z/{start.boot,start_clean.boot,sys.config,vm.args,vm.args.src,no_dot_erlang.boot,erlkoenig.rel}` | required-release | `root:erlkoenig` | Per-version boot artefacts. |
| `rt/erlkoenig_rt` | required-runtime | `root:root` | musl-static C runtime. Bears file caps (`cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,cap_setpcap,cap_setuid,cap_setgid,cap_dac_override,cap_bpf,cap_sys_resource=ep`). Owner deliberately `root:root` (not `root:erlkoenig`). |
| `rt/demo/test-erlkoenig-*` | test-runtime-binaries | `root:root` | Runtime test binaries from `erlkoenig_rt` build. Some intentionally crash, burn CPU, allocate memory, write disks, or attempt blocked syscalls. **Test hosts only; not examples.** Mode `700`. |
| `rt/demo/case_mgmt` `rt/demo/deadline_worker` | optional-showcase | `root:root` | Showcase workloads (~16 MB combined). Built by `make agents-build` / `make showcase`, not by erlkoenig core. **Out of default install** — only present when operator opts in via `--with-demo`. |
| `share/ek.escript` | required-operator | `root:erlkoenig` | Operator CLI escript. Read by `bin/ek`. |
| `share/error_catalog.term` | required-operator | `root:erlkoenig` | Structured error code catalog (consumed by `ek explain`, AMQP events, etc.). |
| `tools/event_consumer.py` `tools/stream_consumer.py` | optional-examples | `root:erlkoenig` | Sample Python AMQP consumers. Should move to `/usr/share/doc/erlkoenig/tools/` or out of the install entirely. |

### Outside `$PREFIX`

| Path | Category | Owner | Notes |
|---|---|---|---|
| `/etc/erlkoenig/cookie` | installer-generated | `root:erlkoenig` | Auth cookie. **File** is created by `install.sh` if missing (then preserved across reinstalls). Mode 440. |
| `/etc/systemd/system/erlkoenig.service` | installer-generated | symlink | Symlink → `$PREFIX/dist/erlkoenig.service`, created by `install.sh`. |
| `/var/lib/erlkoenig/volumes/` | installer-generated (dir) / runtime-generated (contents) | `erlkoenig:erlkoenig` | Directory created by `install.sh`; volume subdirectories created by the daemon at runtime. |
| `/var/log/erlkoenig/` | installer-generated (dir) / runtime-generated (contents) | `erlkoenig:erlkoenig` | Directory created by `install.sh`; log files written by the daemon at runtime. |
| `/run/erlkoenig/containers/` | runtime-generated | varies | Per-container control sockets, created on demand by the daemon. |

## Known drift / cleanup targets (host audit)

These appear on long-lived hosts and have been observed on
`erlkoenig-2__root` (2026-04-29 audit). They are **stale** in the
sense above and may be removed once installer regression coverage
catches them re-appearing:

1. **`$PREFIX/release/` (entire 92 MB tree)** — phantom second copy of
   the install, including a stale `release/lib/erlkoenig-0.6.0/`. Not
   referenced by any live process: daemon argv reads from
   `$PREFIX/{erts-16.3,lib,releases,bin}` exclusively, no open file
   descriptors, wrapper script doesn't reference it. **Verified
   removable on `erlkoenig-2__root` as of the 2026-04-29 audit
   snapshot.** The same conclusion does not transfer to other hosts
   without re-running the same reachability checks (daemon argv,
   open FDs, wrapper paths).

2. **`$PREFIX/cookie.bak`** (32 bytes) — stale cookie backup, no
   referencing code path.

3. **`$PREFIX/release/log/erlang.log.1`** (97 KB) and
   `$PREFIX/release/log/run_erl.log` (306 B) — old log files from a
   previous install layout. Daemon writes to journald today.

4. **`$PREFIX/examples/tutorial/01_overview.term`,
   `06_multi_tier.term`** — operator-generated `ek dsl compile`
   outputs. Owner `root:root` instead of `root:erlkoenig` (the
   distinguishing fingerprint of operator-generated content under
   `$PREFIX`).

5. **Multiple `$PREFIX/bin/erlkoenig-X.Y.Z`** — `install.sh --force`
   is supposed to clean up older per-version wrappers, but doesn't.
   Causes the systemd wrapper's glob (`for f in
   $PREFIX/bin/erlkoenig-*`) to pick the first alphabetically, which
   may be older than the active release. Verified bug: hit twice
   during the 2026-04-27 / 2026-04-28 sessions.

## Phase-3 baseline findings (2026-04-29)

A clean-prefix install (`/opt/erlkoenig-clean`, manual prefix-scoped
steps replicating the prefix-scoped portion of `install.sh`) was
captured in
`docs/install-audit/erlkoenig-clean_2026-04-29.txt` and produced two
new findings beyond the original drift list:

**B-1 — release tarball ships stale per-version wrappers (FIXED)**

`make release` invoked `rebar3 release && rebar3 tar` without first
cleaning `_build/default/rel/erlkoenig/`. `rebar3` version-filters
`lib/` and `releases/` correctly when packaging the tarball, but
**not** `bin/`. As a result, `dist/erlkoenig-0.9.0.tar.gz` shipped
both `bin/erlkoenig-0.9.0` and a stale `bin/erlkoenig-0.8.0` from a
previous build. This was the **root cause** of the wrapper-glob
failures observed twice during the 2026-04-27/28 sessions: the
systemd entrypoint `bin/erlkoenig` globs `erlkoenig-*` and picks the
first alphabetically — a 0.8.0 wrapper installed alongside 0.9.0
loads `releases/0.8.0/vm.args`, which doesn't exist in a 0.9.0
release, and the daemon refuses to start.

Fixed in `Makefile:release`: a surgical `find ... -name 'erlkoenig-*'
-not -name 'erlkoenig-$(CURRENT_VERSION)' -delete` runs between
`rebar3 release` and `rebar3 tar`. Verified post-fix tarball ships
exactly one per-version wrapper (`bin/erlkoenig-0.9.0`).

**B-2 — drift vectors survive prefix-scoped re-install (Option A only)**

The Phase-3 Option-A re-install replicated only the prefix-scoped
extract-and-chown steps of `install.sh`. Four artificial drift vectors
were planted in `/opt/erlkoenig-clean` before the second pass:

| planted before Option-A re-install | survived? | install.sh would clean it? |
|---|---|---|
| `bin/erlkoenig-0.7.0` (foreign per-version wrapper) | yes | **yes** — wiped by the `rm -rf $PREFIX/bin …` step (install.sh:425) and again by the per-version cleanup loop (install.sh:454) |
| `cookie.bak` | yes | no — install.sh has no sweep step for `$PREFIX/cookie.bak` |
| `release/canary` (phantom subtree) | yes | no — install.sh's update wipe touches `bin/`, `erts-*`, `lib/`, `releases/`, `dist/`, but **not** `release/` |
| `examples/tutorial/01_overview.term` | yes | no — `examples/` is not in the wipe set, and `.term` files are not name-matched |

So the practical gaps for hardening are I-3 (pre-install drift warn)
and explicit sweeps for `cookie.bak`, `release/`, and
`examples/**/*.term` — **not** I-1, which is already implemented in
`install.sh:447-465` and demonstrably removes stale per-version
wrappers on real `install.sh --force` runs. The wrapper-glob failures
of 2026-04-27/28 traced to the tarball pollution itself (B-1), not to
install.sh leaving stale wrappers behind: any path that bypasses
`install.sh` (e.g. manual `tar xzf` into `$PREFIX`) inherits the
poisoned bin/ unchanged.

## Installer hardening backlog

Each item directly addresses a category of drift documented above.

- **(I-1)** `install.sh --force` removes every
  `$PREFIX/bin/erlkoenig-*` that does not match the version being
  installed. **Implemented** in `install.sh:447-465`. Listed here for
  completeness; verified by the install-layout-audit "exactly one
  per-version wrapper" check.
- **(I-2)** `install.sh` should emit a **post-install manifest** at a
  known path (e.g. `$PREFIX/share/install-manifest.json`) listing
  every file installed and its expected owner/mode/sha256. Drift
  detection becomes a diff against the manifest.
- **(I-3)** Pre-install: warn (or `--strict-fail`) when
  `$PREFIX` contains files **not** in the installer's manifest.
  Catches phantom copies and operator-deposited artefacts before they
  accumulate.
- **(I-4)** Split `rt/demo/` installation flags: one opt-in flag for
  non-destructive showcase workloads and a separate, test-host-only flag
  for `test-erlkoenig-*` runtime test binaries.
- **(I-5)** Move `examples/`, `doc/`, `tools/` out of `$PREFIX` to
  FHS-compliant `/usr/share/doc/erlkoenig/` paths, default off. Gate
  via `--with-examples`.
- **(I-6)** `ek dsl compile` default output: not next to source. Use
  `--out` arg or default to `$PWD` or `/tmp`. Avoids polluting
  `$PREFIX` when operator runs the example workflow.

## Audit scripts

Two audits cover orthogonal surfaces — both are required because a
release tarball can be intrinsically broken (build-side bug) *or* an
install that started from a clean tarball can drift over time
(host-side bug).

### Release-side: `tools/release-tarball-audit.sh`

Manifest-only audit of a tarball. Catches build-side bug classes
(B-1, B-2, B-3 in this document). Implemented checks:

- `releases/start_erl.data` exists and parses; declared version
  drives all per-version assertions.
- All required release files present: `bin/{ek,erlkoenig,
  install_upgrade.escript,nodetool,no_dot_erlang.boot,erlkoenig-X.Y.Z}`,
  `releases/X.Y.Z/{sys.config,vm.args.src,start.boot,start_clean.boot,
  erlkoenig.rel}`, `lib/erlkoenig-X.Y.Z/ebin/erlkoenig.app`,
  `share/{ek.escript,error_catalog.term}`, `dist/erlkoenig.service`,
  `releases/{start_erl.data,RELEASES}`, `erts-*/bin/erl`.
- Exactly one `bin/erlkoenig-X.Y.Z` matches the declared version
  (B-1 guard).
- Elixir bundle complete: `elixir/bin/elixir` present and
  `elixir/lib/{elixir,eex,logger,erlkoenig_dsl}/ebin/` each contain
  enough `.beam` files to actually launch (B-3 guard — empty
  `lib/elixir/ebin` with only the `.app` file means `ek dsl
  compile` silently breaks on a fresh prefix).
- No compiled DSL artefacts (`*.term`) under `examples/` (B-2 guard).
- No backup/swap/OS-metadata files (`*.bak`, `*~`, `*.tmp`,
  `*.orig`, `*.swp`, `.DS_Store`, `Thumbs.db`).
- No phantom `release/` subtree.
- All declared OTP/3rd-party deps present in `lib/`: `kernel`,
  `stdlib`, `sasl`, `crypto`, `ssl`, `public_key`, `compiler`,
  `amqp_client`.

Wired into `Makefile:release` between `rebar3 tar` and the cp into
`dist/`. A failure blocks the release target *and* keeps the broken
tarball out of `dist/`. A green CI build is no longer purely a
function of `rebar3` — the manifest must also pass.

### Host-side: `tools/install-layout-audit.sh`

Host-side enforcement of this document.
Implemented checks (each is a separate `[OK]`/`[FAIL]`/`[WARN]` line
with grouped drift report at the end):

- All required-release artefacts present for the active version
  (`bin/ek`, `bin/erlkoenig`, `bin/erlkoenig-X.Y.Z`,
  `releases/start_erl.data`, `releases/X.Y.Z/{sys.config,vm.args,start.boot}`,
  `lib/erlkoenig-X.Y.Z/ebin`, `erts-*/`, `rt/erlkoenig_rt`,
  `share/{ek.escript,error_catalog.term}`, `dist/erlkoenig.service`).
- Exactly one `bin/erlkoenig-X.Y.Z` matches active release
  (per-version wrapper count, `erlkoenig-dsl*` excluded).
- `rt/erlkoenig_rt` has the expected capability set
  (`cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,cap_setpcap,cap_setuid,cap_setgid,cap_dac_override,cap_bpf,cap_sys_resource=ep`,
  cap names normalised by sort to absorb getcap-output reordering).
- `$PREFIX` permissions = `750`.
- Ownership: `$PREFIX/*` is `root:erlkoenig`, `$PREFIX/rt/*` is
  `root:root`.
- `$PREFIX/cookie` is a symlink to `/etc/erlkoenig/cookie`.
- `/etc/systemd/system/erlkoenig.service` is a symlink to
  `$PREFIX/dist/erlkoenig.service` (warn-only when systemd absent).
- `/etc/erlkoenig/cookie` exists, mode `440`, owner `root:erlkoenig`.
- `/var/lib/erlkoenig/volumes` and `/var/log/erlkoenig` exist and are
  owned by `erlkoenig:erlkoenig`.
- No `$PREFIX/release/` subdirectory (phantom).
- No backup files (`*.bak`, `*~`, `*.tmp`, `*.orig`) under `$PREFIX`.
- No compiled DSL artefacts (`*.term`) under `$PREFIX/examples/`.
- `rt/demo/` either empty or contains only allowlisted filenames for the
  selected install profile. Showcase profile allows `case_mgmt` and
  `deadline_worker`; test-host profile additionally allows
  `test-erlkoenig-*`. Generic Go demo names (`echo-server`,
  `reverse-proxy`, `api-server`) are legacy drift candidates unless the
  installer grows an explicit profile for them.

Optional `--against-tarball PATH`: cross-checks the installed file
list against a release tarball. Reports both files on host that are
not in the tarball (operator-deposited or stale-install drift) and
files in the tarball not on host (incomplete install). Allowlist
covers legitimately-out-of-tarball paths: `cookie` (installer-generated
symlink), `rt/*` (separate runtime artefact), `releases/RELEASES`
(relx-generated on first start), `releases/X/vm.args`
(rebar3-generated from `vm.args.src` at boot), and
`release/*` (phantom subtree, already flagged as a top-level drift).

Wired into `make install-smoke` as the final `run_step`. Override with
`LAYOUT_AUDIT=0 make install-smoke ...` on hosts with known
long-lived drift that has not been cleaned up yet.

## Cleanup execution order (when ready)

1. Run audit script against current host. Baseline.
2. Fix root causes (I-1 through I-6) in installer. Drift never
   reappears.
3. Test fresh-prefix install: `install.sh --prefix /opt/erlkoenig-clean
   --erlkoenig-tar ...`. Audit it. Should be zero drift.
4. Replace existing host install via clean reinstall: stop service,
   move old prefix aside, install fresh, start, smoke-test.
5. Only then `rm -rf` the moved-aside old prefix.

Direct `rm -rf` of drift on a live host without going through (1)–(4)
is reserved for cases where evidence is overwhelming (e.g. `release/`
phantom on `erlkoenig-2__root`, where every reachability check came
back negative). Even then, `make install-smoke HOST=...` must stay
green after each step.
