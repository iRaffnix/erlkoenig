# SPEC-ONT-001: Native Ontology Core

Status: draft

Depends on: `SPEC-DSL-001`

## Purpose

Generate Erlkoenig ontology facts automatically from the existing validated DSL
builder state. The Erlkoenig DSL remains the source of truth. There is no second
policy language and no parser over `.exs` source files.

The experimental `erlkoenig_ontology` repository is a prototype input only. Its
useful concepts may be migrated, but the production implementation lives inside
the Erlkoenig repo.

## Source of Truth

Facts are emitted from builder state before it is flattened into runtime config.

Allowed source:

- builder structs and macro-collected builder state.

Forbidden as a contract:

- deriving the production world from `MyStack.config()`;
- asserting equality between config-derived facts and builder-derived facts;
- making a lossy `from_config/1` bridge the compatibility gate.

A temporary developer-only comparison against old prototype output is allowed as
a migration metric, but it must not become a required test contract.

## Public API

Stack modules expose:

```elixir
@spec ontology() :: Erlkoenig.Ontology.World.t()
def ontology()
```

Do not introduce `__erlkoenig_world__/0`. Double-underscore names imply compiler
or internal APIs, while ontology output is intended for operator tooling.

Use `Erlkoenig.Ontology.Compiler` or `Erlkoenig.Ontology.Generator` for the
implementation module. Do not use `Erlkoenig.Ontology.Stack`, because
`Erlkoenig.Stack` already names the DSL surface.

## Core Modules

Required modules:

- `Erlkoenig.Ontology.Fact`
- `Erlkoenig.Ontology.Origin`
- `Erlkoenig.Ontology.World`
- `Erlkoenig.Ontology.Schema`
- `Erlkoenig.Ontology.EmitContext`
- `Erlkoenig.Ontology.Compiler`

## Fact Model

Facts are closed-vocabulary records:

```elixir
%Erlkoenig.Ontology.Fact{
  ref: {:container, "web"},
  type: :container,
  properties: %{name: "web", image: "example/web:1"},
  metadata: %{"owner_team" => "platform"} | nil,
  links: [{:runs_in_zone, {:zone, :dmz}}],
  origin: %Erlkoenig.Ontology.Origin{} | nil
}
```

`properties` contains DSL-derived builder data. `metadata` contains
operator-supplied descriptive data such as `description`, ticket IDs, owner team,
or severity. Tooling must not need to infer which keys are runtime data and which
keys are operator annotations.

Default metadata is `nil`. Builders without metadata support can emit valid
facts without allocating empty metadata maps.

Reference forms:

- local reference: `{type, id}`
- external reference: `{:external, type, id}`

World validation fails on:

- duplicate local refs;
- unknown fact types;
- unknown relation names;
- links to missing local refs;
- malformed external refs.

Links to external refs are accepted only when the reference uses the explicit
`{:external, type, id}` shape.

## Origin

Origin is part of the core from the first implementation phase, not a later
retrofit.

Macros pass caller data into builders:

```elixir
Erlkoenig.Ontology.Origin.from_caller(__CALLER__, :container)
```

The origin value may later be stripped from release builds by `SPEC-ONT-002`, but
the builder API must be able to carry origin from day one.

## Emit Context

All builder fact emission uses an explicit context struct.

```elixir
defmodule Erlkoenig.Ontology.EmitContext do
  @type local_ref :: {atom(), term()}
  @type external_ref :: {:external, atom(), term()}
  @type ref :: local_ref() | external_ref()

  @type t :: %__MODULE__{
          parent_ref: local_ref() | nil,
          vocabulary: Erlkoenig.Ontology.Schema.t(),
          origin_resolver: (term() -> Erlkoenig.Ontology.Origin.t() | nil),
          id_namespace: term()
        }

  defstruct parent_ref: nil,
            vocabulary: nil,
            origin_resolver: nil,
            id_namespace: nil
end
```

Field meaning:

- `parent_ref`: the current parent entity for `has_*` relations.
- `vocabulary`: the checked schema used by `Schema.assert_known!/2`.
- `origin_resolver`: resolver for nested builder origin data.
- `id_namespace`: namespace used to derive stable IDs without collisions.

Builder modules must not invent their own context conventions.

Stable IDs use the form `{type, namespace_path}`. `namespace_path` is the parent
`id_namespace` plus the local declaration name joined by `"."`. Example:
`{:nft_chain, "erlkoenig_host.input"}`. Builders that cannot use a declaration
name must document the local ID component they derive and must keep it stable
across equivalent DSL input.

## Builder Contract

Every ontology-capable builder implements:

```elixir
@spec to_facts(t(), Erlkoenig.Ontology.EmitContext.t()) ::
        [Erlkoenig.Ontology.Fact.t()]
def to_facts(builder, context)
```

Initial implementers:

- stack/root builder
- host builder
- pod builder
- container builder
- nft table builder
- nft chain builder
- nft rule builder
- nft counter builder
- nft set builder
- nft map builder
- nft vmap builder
- nft flowtable builder
- NFLOG group builder
- guard builder
- watch builder

Every emitted fact must pass schema validation before it is added to a world.

## Schema

`Erlkoenig.Ontology.Schema` owns the closed vocabulary.

Initial fact types:

```elixir
[
  :stack,
  :host,
  :interface,
  :zone,
  :pod,
  :container,
  :capability,
  :volume,
  :publish,
  :stream,
  :nft_table,
  :nft_chain,
  :nft_rule,
  :nft_counter,
  :nft_set,
  :nft_map,
  :nft_vmap,
  :nft_flowtable,
  :nflog_group,
  :guard,
  :watch
]
```

Initial relations:

```elixir
[
  :has_host,
  :has_interface,
  :has_zone,
  :has_pod,
  :has_container,
  :runs_in_zone,
  :requires_capability,
  :mounts_volume,
  :publishes_metric,
  :streams_channel,
  :has_nft_table,
  :owns_nft_table,
  :has_chain,
  :has_rule,
  :uses_counter,
  :uses_set,
  :uses_map,
  :uses_vmap,
  :uses_flowtable,
  :logs_to_nflog_group,
  :performs_action,
  :jumps_to_chain,
  :has_guard,
  :has_watch,
  :watches_counter
]
```

Schema drift protection:

- `Schema.assert_known!/2` validates every fact type and relation during tests.
- Required signature:

```elixir
@spec assert_known!(t(), Erlkoenig.Ontology.Fact.t()) :: :ok | no_return()
```

- A CI test builds representative worlds and fails when emitted types or
  relations are not declared.
- Declared but unused vocabulary entries must either be covered by a fixture or
  documented as reserved for an already-existing DSL surface.

## Materialization Strategy

Do not embed a fully materialized world literal with `Macro.escape(world)` by
default.

Default behavior:

- compile a compact representation of validated builder data and origin data;
- build `World.t()` on demand in `ontology/0`;
- cache only if measurement shows repeated calls need it and caching does not
  hide stale compile-time state.

Required comparison before choosing literal embedding:

- generated BEAM size;
- DSL compile time;
- module load time;
- `ontology/0` runtime.

Use `examples/stacks/three_tier_ipvlan_fw.exs` as the benchmark fixture. If
literal world embedding increases BEAM size or compile time by more than 10%, it
is rejected as the default.

## Required Tests

- `ontology/0` returns a `World.t()` generated from builder state, not from
  flattened runtime config.
- Every emitted fact is accepted by `Schema.assert_known!/2`.
- World validation rejects duplicate refs, unknown relation names, missing local
  refs, and malformed external refs.
- `three_tier_ipvlan_fw.exs` emits deterministic counts for container facts,
  nft chain facts, nft rule facts, and NFLOG group facts.
- Origin is present in the builder-driven world when origin retention is enabled.
- Fact output order is deterministic.
- `three_tier_ipvlan_fw.exs` has a sorted golden world snapshot, for example
  `test/fixtures/three_tier_world.term`, and the snapshot hash matches. This
  catches content drift such as property renames, not only count drift.

## Acceptance Criteria

- `SPEC-DSL-001` is complete.
- `MyStack.ontology/0` exists for real Erlkoenig DSL stacks.
- No production test pins a lossy `from_config/1` world as the compatibility
  contract.
- `EmitContext` is explicit and used by all first-wave `to_facts/2`
  implementations.
- Schema drift gate is active in CI.
- `three_tier_ipvlan_fw.exs` has exact, checked fact counts.
- `three_tier_ipvlan_fw.exs` has a golden world snapshot whose sorted term and
  hash are checked in tests.
- `make dialyzer` checks ontology and DSL modules and is green.
- Compile-time and BEAM-size measurements are recorded against the pre-ontology
  baseline.
