# Handoff 2026-05-08: DSL Builder Sanierung and Native Ontology

Status: WIP, no commits requested by the user.

This file captures the current state so work can resume without relying on chat
history.

## Repo Context

- Repo: `/home/dev/code/erlkoenig`
- User instruction still active: no commits.
- Worktree is intentionally dirty from earlier NFLOG/firewall work plus the
  current DSL/ontology work. Do not revert unrelated changes.

## DSL-001 Status

`SPEC-DSL-001-BUILDER-SANIERUNG.md` is effectively implemented.

Completed:

- Reset bugs fixed:
  - duplicate `Erlkoenig.Container.guard do ... end` now fails loud;
  - bare `Erlkoenig.Stack.container/2` resets `:ek_container_nft`;
  - stray `ErlkoenigNft.Firewall` structural macros outside `firewall do ... end`
    raise clear `CompileError`.
- Builder layer cleaned:
  - `ErlkoenigNft.Firewall.Builder` migrated from raw map to `defstruct`;
  - `Container.Builder`, `Guard.Builder`, `Watch.Builder`, and `Limits.Builder`
    also use structs;
  - relevant builders have `@type t`, `@spec new`, `validate!`, and `to_term`.
- `validate!` returns the validated builder consistently.
  - Cross-builder validation may have extra context args, e.g.
    `Host.Builder.validate!/3`, but it still returns the builder.
- `ChainBuilder.to_term/1` exists and `TableBuilder.to_term/1` uses it.
- Root `make dialyzer` now includes the DSL app via `dialyxir`.
- `stack.ex` was split into internal macro modules:
  - `Erlkoenig.Stack.HostMacros`
  - `Erlkoenig.Stack.ContainerMacros`
  - `Erlkoenig.Stack.NftMacros`
  - `Erlkoenig.Stack.GuardMacros`
  - `Erlkoenig.Stack.WatchMacros`
- Public DSL remains `use Erlkoenig.Stack`.

Baseline and split measurements:

- Before split:
  - `dsl/lib/erlkoenig/stack.ex`: 2043 lines
  - `Elixir.Erlkoenig.Stack.beam`: 60244 bytes
  - `mix compile --force`: 1.22s
  - `three_tier_ipvlan_fw.exs` compile: 0.60s
  - `make test-dsl`: 4.02s
- After split:
  - `stack.ex`: 178 lines
  - split macro files total: 2063 lines
  - `Elixir.Erlkoenig.Stack.beam`: 14244 bytes plus macro modules
  - `mix compile --force`: 1.13s
  - `three_tier_ipvlan_fw.exs` compile: 0.61s
  - `make test-dsl`: 3.97s
- `/tmp/three_tier_ipvlan_fw.baseline.term` and
  `/tmp/three_tier_ipvlan_fw.after_split.term` were byte-identical with `cmp`.

## ONT-001 Current Slice

Native ontology core exists in `dsl/lib/erlkoenig/ontology/`:

- `Erlkoenig.Ontology.Fact`
- `Erlkoenig.Ontology.Origin`
- `Erlkoenig.Ontology.World`
- `Erlkoenig.Ontology.Schema`
- `Erlkoenig.Ontology.EmitContext`
- `Erlkoenig.Ontology.Compiler`

Stack modules now expose:

```elixir
ontology()
```

Important design point: `ontology/0` is generated from validated builder state
captured in `__before_compile__`, not from `config/0`.

Current behavior:

- `ontology_data` is a compact compile-time constant containing:
  - module name;
  - stack origin;
  - host builder state;
  - pod builder state;
  - nft table builder state;
  - guard config;
  - watch configs.
- `World.t()` is built on demand by `Erlkoenig.Ontology.Compiler.from_stack/1`.
- `Fact` has a dedicated `metadata` field.
- `Schema.assert_known!/2` validates fact type and relation vocabulary.
- `World.validate!/1` checks:
  - schema vocabulary;
  - duplicate local refs;
  - missing local refs;
  - malformed refs;
  - explicit external refs shaped as `{:external, type, id}`.
- Stack-level origin is wired:
  - `Origin.from_caller(env, :stack)` is added in `Stack.__before_compile__/1`;
  - stack fact carries `origin`.
- `reverse_link/3` no-op was removed from the compiler.

`three_tier_ipvlan_fw.exs` currently emits 70 facts:

- `stack`: 1
- `host`: 1
- `interface`: 1
- `zone`: 1
- `pod`: 1
- `container`: 3
- `capability`: 3
- `publish`: 3
- `stream`: 1
- `guard`: 1
- `nft_table`: 2
- `nft_chain`: 9
- `nft_rule`: 37
- `nft_counter`: 3
- `nft_set`: 1
- `nflog_group`: 2

Golden snapshot:

- Fixture: `dsl/test/fixtures/three_tier_world.term`
- Test compares the full sorted fact term and a canonical SHA-256 hash.
- Current hash:
  `dacb980a3a4bd065fac90032759cabe1f21f6c37fe13323766a537668d73f676`

Ontology tests:

- `dsl/test/ontology_test.exs`
- Covers:
  - empty stack ontology;
  - stack origin;
  - unknown schema fact type rejection;
  - missing local ref rejection;
  - exact `three_tier_ipvlan_fw` fact counts;
  - deterministic fact order;
  - golden snapshot + hash.

## Last Validation

Last successful gates:

```text
mix test test/ontology_test.exs
7 tests, 0 failures

make test-dsl
20 properties, 361 tests, 0 failures

make dialyzer
DSL-Dialyxir Total errors: 0
Root wrapper ends with Dialyzer: OK
```

Root Erlang Dialyzer still prints existing warnings in unrelated modules. The
existing wrapper currently treats them as OK unless they match its hard-error
patterns.

## Known Remaining Gaps

These are intentional next-work items, not accidental omissions.

### 1. Builder `to_facts/2` Pushdown Missing

`SPEC-ONT-001` requires builder-local `to_facts/2` implementations. Currently
most emission logic is centralized in `Erlkoenig.Ontology.Compiler` helper
functions. This is acceptable as the first vertical slice, but it must not remain
the final shape.

Risk:

- `Compiler` reaches into builder internals directly, for example container field
  selection and chain property extraction.
- New builder fields can silently fail to appear in facts.

Target:

```elixir
@spec to_facts(t(), Erlkoenig.Ontology.EmitContext.t()) ::
        [Erlkoenig.Ontology.Fact.t()]
```

### 2. `EmitContext` Exists but Is Not Threaded Yet

`EmitContext` has the required fields:

- `parent_ref`
- `vocabulary`
- `origin_resolver`
- `id_namespace`

But the current compiler still uses local helper state and `namespace/2`.

Target:

- Every builder `to_facts/2` receives an `EmitContext`.
- Parent-child traversal uses `EmitContext.child/3`.
- Fact IDs use the context namespace rule from `SPEC-ONT-001`.
- `Schema.assert_known!/2` is called on emitted facts through the context schema.

### 3. Origin Is Only Wired at Stack Level

Origin wiring is proven with the stack fact. Builder-level origins are still not
captured at individual DSL declaration sites.

Target:

- Macro declarations pass `Origin.from_caller(__CALLER__, context)` into builder
  state.
- Builder-local `to_facts/2` attaches origin to emitted facts.

## Recommended Next Steps

Continue with `to_facts/2` pushdown in this order:

1. `Erlkoenig.Container.Builder`
   - Move container/capability/volume/publish/stream/container-nft fact emission
     out of `Compiler.add_container/4`.
   - Use `EmitContext.parent_ref` for pod relation.
   - Use `EmitContext.id_namespace` for stable IDs.
   - Keep counts and golden snapshot stable.

2. `Erlkoenig.Pod.Builder`
   - Emit pod fact.
   - Delegate each container to `Container.Builder.to_facts/2`.
   - Thread context with pod ref and namespace.

3. `Erlkoenig.Host.Builder`
   - Emit host/interface/zone facts.
   - Use explicit parent refs.

4. `Erlkoenig.Nft.ChainBuilder`
   - Emit chain facts and rule facts.
   - This is where rule emission should leave `Compiler.add_rules/4`.

5. `Erlkoenig.Nft.TableBuilder`
   - Emit table facts.
   - Delegate chains to `ChainBuilder.to_facts/2`.
   - Emit counters, sets, maps, vmaps, flowtables, and NFLOG groups.

6. Guard and Watch
   - Add `to_facts/2` to guard/watch builders or equivalent builder-owned
     emission path.

After each migration:

- Run `mix test test/ontology_test.exs`.
- Ensure `three_tier` counts and golden snapshot are unchanged unless the change
  is intentional.
- Then run `make test-dsl`.
- Run `make dialyzer` after a few migrations or whenever types change materially.

## Caution

Do not implement ONT-002 metadata yet. The next correct work is ONT-001
builder-local emission and `EmitContext` threading. Metadata should wait until
the fact source is fully builder-owned.
