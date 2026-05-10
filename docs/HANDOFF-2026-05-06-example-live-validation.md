# Handoff: example live validation on erlkoenig-2

Date: 2026-05-06
Branch: wip/nft-ownership-split-2026-05-04

## What was validated

Live host: `erlkoenig-2__root`

The runnable example configs were copied to `/root/erlkoenig-example-live/`
and tested through the installed operator CLI:

1. `ek dsl compile <file> -o /tmp/<file>.term`
2. `ek config validate /tmp/<file>.term`
3. `ek config load /tmp/<file>.term`
4. `ek --format json ps` checked for failed containers
5. `ek down <term>` and service restart between examples

Results:

- Runnable stack/tutorial/dev configs: `19 pass / 0 fail`
- Firewall-only examples: `5 pass / 0 fail`
- `examples/tutorial/05_storage_and_pki.exs`: `3/3 running`
- `examples/tutorial/06_multi_tier.exs`: `13/13 running`
- Host cleanup after validation: no running containers, no quarantine entries
- `rebar3 eunit --module=ek_tests`: `59 tests, 0 failures`
- `mix run ../examples/dev/audit_verifier_demo.exs`: `7/7 passed`
- `mix run ../examples/dev/journal_demo.exs`: passed

## Fixes made during validation

- `examples/tutorial/05_storage_and_pki.exs`
  - Removed mandatory per-container signature requirements from the runnable
    tutorial. The installed demo `test-erlkoenig-echo_server` binary is
    intentionally unsigned, so requiring signatures made the tutorial fail
    closed on a fresh install host.
  - Kept PKI as operator guidance and pointed fail-closed deployment shape to
    the dedicated signed deployment example/book chapter.

- `examples/tutorial/06_multi_tier.exs`
  - Changed frontend demo listener path from privileged `443` to `8443`.
  - Removed mandatory DB signature requirement for the same unsigned-demo-binary
    reason.
  - Changed backup sidecar argument from `"backup"` to a numeric demo port
    (`"15432"`), avoiding echo_server crash/restart/quarantine behavior.

- Host firewall / honeypot consistency
  - Removed SSH `22` from honeypot lists where the same config explicitly
    allows SSH on port 22. This fixed `ssh_port_in_honeypot` preflight failures.

- `examples/showcase/case_mgmt_stack.exs`
  - Moved `case_mgmt_stack.exs` out of normal runnable stacks into
    `examples/showcase/`.
  - Reason: it needs opt-in showcase setup, optional workload binaries, and
    service setup. It compiles and validates, but without the showcase DB/journal
    environment the agent restarts and should not be counted as a default
    runnable stack example.

- `dist/ek.escript`
  - Fixed plain `ek ct inspect` formatting for complex list fields such as
    `volumes`. Before the fix, inspecting a failed container with volume maps
    crashed with `error:badarg`.
  - Added `plain_ct_inspect_prints_complex_fields_test` in
    `apps/erlkoenig/test/ek_tests.erl`.

## Special cases

- `examples/stacks/signed_deployment.exs`
  - Compiles successfully.
  - Intentionally not live-loaded as a self-contained demo because it requires
    operator-supplied signed binaries and trust roots.

- `examples/dev/dsl_e2e_edge.exs`
  - Compiles successfully.
  - It is an integration-test harness fixture with a placeholder binary, not a
    normal operator example.

- Persistent volumes
  - Live validation created/left persistent volume metadata on `erlkoenig-2`.
  - They were intentionally not silently destroyed because persistent volume
    survival is the behavior under test. Clean them only with an explicit
    operator cleanup decision.

## Known command findings

- `ek up <relative .exs>` had a live-host path bug during testing:
  it compiled a relative `.term` path and the node tried to read it relative to
  service CWD, producing `read_failed ... enoent`.
  Workaround used for validation: compile to absolute `/tmp/*.term`, then
  validate/load that term explicitly.

## Suggested next step

Before closing the example/layout work, either:

1. Fix `ek up` so compiled terms are loaded via an absolute path or temp path,
   then add a small CLI regression test; or
2. Document `ek dsl compile -o /tmp/... && ek config load /tmp/...` as the
   robust install-host validation path and leave `ek up` for a follow-up.

