# SPEC-DSL-001: Builder Sanierung

Status: draft

## Purpose

Sanitize the existing Erlkoenig DSL builder layer before ontology generation is
built on top of it. The ontology source of truth is validated builder state, so
silent builder drift must be removed first.

This spec is intentionally not an ontology spec. It prepares the builder API,
typing, validation, and file layout so later `to_facts/2` implementations can be
added without preserving known bugs.

## Scope

- `Erlkoenig.Stack` and stack-related builders.
- `Erlkoenig.Container` DSL and builder state.
- nft host, zone, container, guard, watch, table, chain, rule, set, map, vmap,
  flowtable, counter, and NFLOG group builders.
- `ErlkoenigNft.Firewall` macro and builder modules.

## Non-goals

- No ontology generation.
- No `.exs` source parsing.
- No operator CLI for ontology output.
- No runtime config schema change except where required to fix existing bugs.
- No compatibility bridge that derives future ontology facts from flattened
  runtime config.

## Required Fixes

### Reset and context bugs

The DSL must fail loud or reset state explicitly in all builder contexts.

Required changes:

- `Erlkoenig.Container.guard do ... end` must reject a second guard block for the
  same container instead of silently replacing the first guard state.
- The bare `Erlkoenig.Stack.container(name, opts)` form must reset
  `:ek_container_nft` in the same way as the block form. A preceding nft-enabled
  container must not influence the next container declaration.
- `ErlkoenigNft.Firewall` structural macros such as `set/2`, `map/2`, `chain/2`,
  and `rule/2` must raise a clear `CompileError` when used without a surrounding
  `firewall do ... end` wrapper.

Regression tests are mandatory for all three cases.

### Builder typespecs

Every builder module that owns DSL state must expose a real builder type.

Required pattern:

```elixir
@type t :: %__MODULE__{}

@spec new(keyword() | map()) :: t()
@spec validate!(t()) :: t()
@spec to_term(t()) :: term()
```

If a builder does not have a `validate!/1` function today, either add it or
document why validation is performed elsewhere and add the applicable specs for
the actual API. The long-term shape must still make the validation boundary
visible to Dialyzer and reviewers.

Builders that validate references against sibling builders may add explicit
context arguments, but they still return the validated builder:

```elixir
@spec validate!(t(), context()) :: t()
```

For example, `Erlkoenig.Host.Builder.validate!/3` validates host firewall
interface references against pod and container names collected by the enclosing
stack compiler.

### Firewall builder struct migration

`ErlkoenigNft.Firewall.Builder` must use `defstruct` instead of raw maps.

Rules:

- Public builder functions accept and return `%ErlkoenigNft.Firewall.Builder{}`.
- Internal helpers may normalize maps only at the boundary.
- Existing generated firewall terms must remain unchanged except for intentional
  bug fixes covered by tests.

### Stack module split

`dsl/lib/erlkoenig/stack.ex` is too large for continued ontology work. Split it
without changing the public DSL module name.

Target layout and module naming:

- `dsl/lib/erlkoenig/stack.ex`: public bracket/import module and shared compile
  hooks.
- `dsl/lib/erlkoenig/stack/host_macros.ex`:
  `Erlkoenig.Stack.HostMacros`.
- `dsl/lib/erlkoenig/stack/container_macros.ex`:
  `Erlkoenig.Stack.ContainerMacros`.
- `dsl/lib/erlkoenig/stack/nft_macros.ex`: `Erlkoenig.Stack.NftMacros` for nft
  table, chain, rule, set, map, vmap, flowtable, counter, and NFLOG group
  integration.
- `dsl/lib/erlkoenig/stack/guard_macros.ex`:
  `Erlkoenig.Stack.GuardMacros`.
- `dsl/lib/erlkoenig/stack/watch_macros.ex`:
  `Erlkoenig.Stack.WatchMacros`.

The public operator-facing DSL remains `use Erlkoenig.Stack`. The split is an
implementation cleanup, not a language change.

Do not name the stack-internal module `Erlkoenig.Stack.Container`. That is too
close to the existing single-container DSL module `Erlkoenig.Container` and makes
review and autocomplete ambiguous. Stack-internal modules use the `*Macros`
suffix until a stronger internal naming convention exists.

## Tests

Required tests:

- Duplicate container guard block raises `CompileError`.
- nft container A, bare container B, nft container C compiles with C observing a
  clean nft context.
- Stray `ErlkoenigNft.Firewall` macro outside `firewall do ... end` raises
  `CompileError` with a useful message.
- Representative stack `config/0` snapshot stays stable across the module split.
- The repo Dialyzer gate checks the DSL app and accepts the new builder structs
  and specs.

## Measurement Baseline

Before ontology embedding is added, record baseline numbers for a representative
large stack such as `examples/stacks/three_tier_ipvlan_fw.exs`:

- DSL compile time.
- generated BEAM size for the stack module.
- `make test-dsl` runtime.
- module load time if it is measurable without special runtime setup.

These numbers are not an optimization target in this spec. They are the baseline
for `SPEC-ONT-001`.

## Acceptance Criteria

- All reset/context bug tests are red before the fix and green after the fix.
- `ErlkoenigNft.Firewall.Builder` is a struct-backed builder.
- Builder modules have explicit `@type t` and API specs for construction,
  validation, and term emission.
- `stack.ex` is split while preserving the public DSL.
- `make test-dsl` is green.
- `make dialyzer` checks the DSL app and is green.
- Baseline measurements are recorded in the implementation PR or changelog entry.
