# SPEC-ONT-002: Operator Metadata

Status: draft

Depends on: `SPEC-DSL-001`, `SPEC-ONT-001`

## Purpose

Add explicit operator-supplied metadata to Erlkoenig DSL declarations and expose
ontology output through operator tooling.

Metadata is descriptive only. It must not fill missing required DSL fields,
infer ownership, invent firewall policy, or change runtime behavior.

## Description Field

Use keyword options:

```elixir
container "web",
  image: "example/web:1",
  description: "public web frontend"
```

Do not add a positional `describe "..."` macro. A standalone description macro
would be stateful and would attach to the next declaration implicitly. That
violates the DSL requirement that important information appears on the datum it
describes.

## Metadata Field

Use keyword options:

```elixir
nft_counter "drop_invalid",
  description: "invalid packets dropped before application chains",
  metadata: %{
    "owner_team" => "platform",
    "ticket" => "NET-1042",
    "severity" => "high"
  }
```

Allowed metadata type:

```elixir
@type json_metadata ::
        %{String.t() => json_value()}

@type json_value ::
        nil
        | boolean()
        | number()
        | String.t()
        | [json_value()]
        | %{String.t() => json_value()}
```

Rejected values:

- atom keys;
- atom values;
- tuple values;
- structs;
- pids, ports, references, and functions;
- maps with non-string keys at any depth.

Validation happens in the DSL macro or builder path during compilation. Bad
metadata must fail loud before JSON or Mermaid output is attempted.

## Initial Metadata Surfaces

Add `description:` and `metadata:` where they help operators inspect generated
ontology:

- `ipvlan`
- `pod`
- `container`
- `volume`
- `nft_host`
- `nft_zone`
- `nft_ct`
- `base_chain`
- `nft_rule`
- `nft_counter`
- `nft_nflog_group`

Metadata is copied into the dedicated `metadata` field on
`Erlkoenig.Ontology.Fact`. It is never mixed into `properties`, which are reserved
for DSL-derived builder data. Metadata is not copied into runtime config unless
runtime config already has a documented metadata surface for that declaration.

## Origin Retention

Origin retention is a build-mode decision.

Required behavior:

- `ERLKOENIG_ONTOLOGY_ORIGIN=1` during DSL compilation retains file and line
  origin in compiled ontology data.
- When the variable is unset, release-oriented builds strip file and line origin
  from compiled ontology data.
- The builder API still carries origin internally so debug builds can retain it.

Tests must cover both modes.

## Operator CLI

After `SPEC-ONT-001` exists, add an operator command:

```text
ek dsl ontology <stack.exs> --format json
ek dsl ontology <stack.exs> --format mermaid
```

Rules:

- Use the official DSL compiler path.
- Do not parse `.exs` source directly.
- Output is deterministic.
- JSON output is stable by structure, not by raw key order.
- Mermaid output is a visible inspection artifact, not the only acceptance
  signal.

## Required Tests

- `description:` is accepted on all initial metadata surfaces.
- `metadata:` accepts only string-key JSON-compatible maps.
- Atom keys, atom values, tuples, structs, and functions raise compile-time
  errors.
- Metadata appears in the ontology fact `metadata` field but does not fill missing required DSL
  fields.
- Origin retention differs between default build and
  `ERLKOENIG_ONTOLOGY_ORIGIN=1`.
- `ek dsl ontology` JSON output for `three_tier_ipvlan_fw.exs` is deterministic.
- `ek dsl ontology` Mermaid output is deterministic and non-empty.

## Acceptance Criteria

- No `describe` macro exists.
- Description and metadata fields are explicit on the DSL declarations that use
  them.
- Invalid metadata fails during DSL compilation.
- Origin retention is controlled by the build environment and is tested.
- `ek dsl ontology` emits deterministic JSON and Mermaid from a real Erlkoenig
  DSL file.
- Tests assert exact fact counts for the representative stack instead of only
  checking that output was printed.
