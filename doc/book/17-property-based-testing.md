# Chapter 17 — Property-Based Testing

erlkoenig's test suite is split in two. Example-based eunit tests
answer "does this exact scenario work?" — they're the usual
reference cases. Alongside them, a second layer of property-based
tests (PropEr) answers "does this invariant hold across every
reachable sequence of operations?" That second layer is the safety
net: it catches the race conditions, off-by-one corner cases, and
state-machine transitions that no human writes an example for.

## What PropEr gives us

Every property-based test states an invariant, not an input. The
runner then generates hundreds of random inputs, checks the
invariant against each, and — crucially — **shrinks** any failing
input down to the smallest example that still breaks. That means a
bug discovered after three hundred random operations comes back as
a two-step minimal counter-example the moment the test fails.

Three patterns are used across the suite:

- **Pure-function properties** assert invariants on pure input/
  output functions. The parser, formatter, and flag-table logic in
  `erlkoenig_mount_opts` live here.
- **Stateful model tests** exercise a gen_server with random command
  sequences. A minimal test-side model of what *should* happen is
  compared against the real system after every command.
- **Integration-level properties** combine multiple subsystems — the
  volume store, admission gate, and quarantine together — as one
  system under test. (Not yet written; on the roadmap.)

## Pure-function properties: `mount_opts`

The mount-options parser is an obvious candidate: pure input
(binary), pure output (map), no side effects. The module's
`prop_*` functions assert:

- **Round-trip**: parsing, formatting, and re-parsing produces
  mount-fresh-equivalent options. The first parse and the third
  parse agree on flags, propagation, recursive, and data.
- **Format idempotence**: one format pass is enough; further passes
  change nothing.
- **Last-wins semantics**: appending `"ro"` or `"rw"` to any valid
  options string produces the expected final `MS_RDONLY` state.
- **Empty-input handling**: whitespace-only and empty strings
  always yield the default options.
- **Conflict detection**: two propagation modes from different
  families always yield a `conflicting_propagation` error.
- **Unknown-token strictness**: random bare words never silently
  succeed — they either return `unknown_flag` or, if they contain
  `=`, flow through as fs-specific data.

Running 200 iterations per property takes under half a second, and
a real asymmetry was surfaced on the first run: `format/1` ignores
the `clear` bitmask on output, so `parse("rw")` and
`parse(format(parse("rw")))` differ in the `clear` field. The
round-trip property documents this as a deliberate design choice
(clear is only meaningful on `MS_REMOUNT`) and checks a weaker
equivalence that reflects actual fresh-mount behaviour.

## Stateful model tests: `admission`, `quarantine`, `volume_store`

The three gen_servers built for operational semantics —
admission, quarantine, volume store — all use PropEr's
`proper_statem` behaviour. The pattern:

1. A small test-side `#state{}` record that mirrors what the model
   expects the system to look like after every command.
2. A `command/1` generator that produces a random valid command
   given the current model state.
3. A `next_state/3` that advances the model in lockstep with the
   real system.
4. A `postcondition/3` that asserts the real system's response
   matches the model's prediction.

Running 100 random command sequences per property covers cases an
example test doesn't reach: out-of-order acquire/release,
quarantine-then-unquarantine in tight loops, ephemeral-cleanup
during concurrent ensures, and so on.

### `admission_prop_test`

Commands: `acquire/1` with a scope (host or a zone name), `release/1`
with a token from a previous acquire or a bogus reference.

Invariants checked:

- Acquire succeeds iff the model says a slot is available; when it
  fails, the system returns `{error, timeout}` or
  `{error, queue_full}` — never silently returns an invalid token.
- Released tokens reduce the in-flight count by exactly one.
- Releasing an unknown token is a no-op, not a crash.

### `quarantine_prop_test`

Commands: `record_crash` with one of three test binaries, manual
`quarantine`/`unquarantine` by hash, `check/1` and
`is_quarantined/1` queries.

Invariants checked:

- A hash stays quarantined until explicitly unquarantined; no
  command sequence auto-lifts it.
- `check/1` returns an error iff the hash is in the quarantine
  set.
- Manual `quarantine` wins over everything: a binary with zero
  recorded crashes can still be forced into the set.
- Crashloop auto-quarantine triggers at the threshold (tested with
  threshold 3 and a very wide window so count-based reasoning
  matches timestamp-based reasoning in the system).

### `volume_store_prop_test`

Commands: `ensure` with random `(container, persist, lifecycle)`,
`find`, `list_by_container`, `destroy` with bogus UUIDs, and
`cleanup_ephemeral`.

Invariants checked:

- `ensure` returns a UUID matching `ek_vol_...` on first use;
  subsequent calls for the same `(container, persist)` pair return
  a record with the same shape (idempotent from the container's
  perspective).
- `list_by_container` returns exactly the volumes of that
  container and no others.
- `cleanup_ephemeral` removes all ephemeral volumes for a
  container in one operation; persistent volumes in the same
  container are untouched.
- Destroy of a bogus UUID returns `{error, not_found}` without
  corrupting state.

UUIDs themselves are deliberately not modelled — threading
generated UUIDs through PropEr's symbolic replay adds more noise
than value. The dedicated eunit tests cover destroy-by-known-UUID.

## Running the properties

Under `rebar3 eunit`, the properties run alongside the regular
eunit tests. They're not separated by a tag because they belong to
the same quality gate: a failing property blocks a release the
same way a failing example test does.

```bash
make check                              # everything
rebar3 eunit --module=erlkoenig_mount_opts_prop_test
rebar3 eunit --module=erlkoenig_admission_prop_test
rebar3 eunit --module=erlkoenig_quarantine_prop_test
rebar3 eunit --module=erlkoenig_volume_store_prop_test
```

Numtests defaults are conservative for CI (100 to 200 runs per
property). For deep pre-release validation, bump them:

```erlang
proper:quickcheck(prop_admission_stateful(), [{numtests, 5_000}]).
```

Five thousand runs of each stateful property take a few minutes
and have, on a real project, caught latent race conditions that
were invisible at 100 iterations.

## What PropEr doesn't replace

Example-based tests remain important. They name scenarios the team
cares about ("the hardened-uploads example with five replicas
works end-to-end"), they document intent, and they're cheaper to
read than a property plus a model. PropEr is additive: it finds
what examples don't.

Integration tests (escripts under `tests/integration/`) stay as
they are. They exercise the full C runtime, kernel namespaces, and
actual packet flow — that's outside what PropEr runs in eunit.
