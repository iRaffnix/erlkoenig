# Handoff 2026-05-07: Interactive Firewall Live Integration

This is the current working-state checkpoint for the native interactive
firewall work. The tree is intentionally left dirty so the next session can
continue without losing context.

## Live Host State

Host used for validation: `erlkoenig-2__root`.

The current source release was built with:

```sh
make release
```

The resulting `dist/erlkoenig-0.9.0.tar.gz` was copied to:

```text
erlkoenig-2:/tmp/erlkoenig-0.9.0-live-demo.tar.gz
```

It was installed with:

```sh
ssh erlkoenig-2__root \
  sh /tmp/erlkoenig-install-live-demo.sh \
    --erlkoenig-tar /tmp/erlkoenig-0.9.0-live-demo.tar.gz \
    --rt-bin /opt/erlkoenig/rt/erlkoenig_rt \
    --force
```

The daemon was restarted by the installer and verified with:

```sh
ssh erlkoenig-2__root /opt/erlkoenig/bin/ek node ping
```

Result:

```text
pong
```

## What Works Now

The installed operator CLI on `erlkoenig-2` now contains:

```text
ek nft counters
ek firewall status
ek firewall events
ek firewall watch
```

The host ruleset now has real NFLOG instrumentation on ban-set drops:

```text
table inet erlkoenig_host {
  chain prerouting_ban {
    type filter hook prerouting priority raw; policy accept;
    ip saddr @blocklist counter name "banned" log prefix "banned" group 1 drop
    ip6 saddr @blocklist6 counter name "banned" log prefix "banned" group 1 drop
  }
}
```

This produced real kernel-origin packet events, not only threat actor events:

```text
kind=firewall_packet source=nflog src_ip=185.91.127.85 dst_ip=178.104.17.63 chain=banned
```

`ek nft counters` now shows live rates and cumulative kernel totals for host
counters:

```text
erlkoenig_host  input    ... total_packets ...
erlkoenig_host  output   ... total_packets ...
erlkoenig_host  banned   ... total_packets ...
```

Counter watcher events now include table ownership for new events:

```json
{
  "kind": "counter_rate",
  "source": "counter",
  "table": "erlkoenig_host",
  "table_owner": "host"
}
```

## Implemented In This Slice

Important changed files in this slice:

```text
apps/erlkoenig/src/erlkoenig_nft_firewall.erl
apps/erlkoenig/src/erlkoenig_nft_sup.erl
apps/erlkoenig/src/erlkoenig_nft_counter.erl
apps/erlkoenig/test/erlkoenig_nft_firewall_tests.erl
apps/erlkoenig/test/erlkoenig_firewall_event_tests.erl
```

Main behavior added:

* Host firewall normalization auto-adds observability counters for hooked
  input/forward/output chains.
* Host firewall adds default drop observability for policy-drop chains.
* Ban-set drop rules now inject `log group 1` before the terminal `drop`.
* Counter workers start by default for configured counters unless `watch` is
  explicitly `false`.
* `list_counters` falls back to direct kernel counter reads, so `ek nft counters`
  no longer depends only on watcher-baseline state.
* Counter events now include `table` and `table_owner`.
* The nft supervisor starts the host NFLOG receiver through
  `erlkoenig_nft_nflog:ensure_started(1)`.

## Validation Already Run

Local:

```text
rebar3 compile
rebar3 eunit --module=erlkoenig_nft_firewall_tests    25 tests, 0 failures
rebar3 eunit --module=erlkoenig_firewall_event_tests   6 tests, 0 failures
rebar3 eunit --module=erlkoenig_firewall_events_tests  4 tests, 0 failures
rebar3 eunit --module=erlkoenig_nft_nflog_tests        9 tests, 0 failures
rebar3 eunit --module=ek_tests                        65 tests, 0 failures
rebar3 eunit --module=erlkoenig_operator_api_tests    16 tests, 0 failures
rebar3 xref                                           ok
make release                                          tarball audit ok
```

Live:

```text
ek node ping                                           pong
nft list chain inet erlkoenig_host prerouting_ban      shows log group 1
ek nft counters                                        shows live host rates
ek firewall events --limit 10                          shows counter_rate and firewall_packet
ek --format json firewall events --limit 5              shows structured JSON events
```

`firewall watch` was tested with `timeout`. It prints events, then the timeout
terminates the local CLI. The daemon remained healthy after the timeout in
earlier live checks.

## Open Next Step

Resolved on 2026-05-08:

NFLOG packet events from host group `1` are now enriched in
`erlkoenig_nft_nflog` with:

```json
"table": "erlkoenig_host",
"table_owner": "host"
```

The production receiver now carries its configured NFLOG group into packet
message processing. `process_messages/1` remains available for existing
fuzzing/tests and defaults to no group metadata; `process_messages/2` is used
for grouped processing and regression coverage.

Validation run:

```text
rebar3 compile
rebar3 eunit --module=erlkoenig_nft_nflog_tests      10 tests, 0 failures
rebar3 eunit --module=erlkoenig_firewall_event_tests  6 tests, 0 failures
rebar3 eunit --module=erlkoenig_amqp_codec_tests      7 tests, 0 failures
rebar3 eunit --module=erlkoenig_operator_api_tests   16 tests, 0 failures
rebar3 eunit --module=ek_tests                       65 tests, 0 failures
rebar3 xref                                           ok
```

Live validation on `erlkoenig-2__root`:

```text
make release                                          tarball audit ok
scp dist/erlkoenig-0.9.0.tar.gz erlkoenig-2:/tmp/erlkoenig-0.9.0-live-demo.tar.gz
ssh erlkoenig-2__root sh /tmp/erlkoenig-install-live-demo.sh \
  --erlkoenig-tar /tmp/erlkoenig-0.9.0-live-demo.tar.gz \
  --rt-bin /opt/erlkoenig/rt/erlkoenig_rt \
  --force                                             ok
ek node ping                                          pong
ek --format json firewall events --limit 5            includes firewall_packet with host ownership
```

Observed live `firewall_packet` after reinstall:

```json
{
  "kind": "firewall_packet",
  "source": "nflog",
  "chain": "banned",
  "table": "erlkoenig_host",
  "table_owner": "host"
}
```

## Open Next Step

Resolved on 2026-05-08:

The explicit NFLOG group registry has been started:

* DSL now has `nft_nflog_group N, name: "..."`
* logged DSL rules must include `nflog_group: N`
* `TableBuilder` emits `nflog_groups` into the nft table IR
* `erlkoenig_config_nft` starts declared NFLOG receivers before applying
  rules, then commits group metadata to `erlkoenig_nft_nflog_registry` only
  after a successful table apply
* `erlkoenig_nft_nflog` enriches packet events from that registry, not from
  hard-coded group ownership or chain-name inference
* the legacy host-firewall owner path registers its installed host NFLOG group
  after successful host-table apply, so preserved `/etc/erlkoenig/firewall.term`
  installs are covered by the same registry

Example DSL shape:

```elixir
nft_host do
  nft_nflog_group 1, name: "host"

  base_chain "input", hook: :input, type: :filter,
    priority: :filter, policy: :drop do
    nft_rule :drop, counter: "input_drop",
      log_prefix: "HOST: ", nflog_group: 1
  end
end
```

Counter events and host-group NFLOG packet events now both include:

```json
"table": "erlkoenig_host",
"table_owner": "host"
```

Validation added/run for this slice:

```text
mix test test/nft_dsl_test.exs test/stack_test.exs      144 tests, 0 failures
rebar3 compile                                          ok
rebar3 eunit --module=erlkoenig_nft_nflog_tests         11 tests, 0 failures
rebar3 eunit --module=erlkoenig_config_nft_tests        22 tests, 0 failures
rebar3 eunit --module=erlkoenig_firewall_event_tests     6 tests, 0 failures
mix run ../examples/tutorial/03_firewall.exs            ok
mix run ../examples/stacks/simple_echo.exs              ok
mix run ../examples/stacks/signed_deployment.exs        ok
mix run ../examples/stacks/three_tier_ipvlan_fw.exs     ok
mix run ../examples/tutorial/06_multi_tier.exs          ok
make release                                            tarball audit ok
live install on erlkoenig-2__root                       ok
ek node ping                                            pong
firewall watch live firewall_packet                     table=erlkoenig_host table_owner=host
```

Resolved validation drift: `tutorial_shape_test.exs` now matches
`05_storage_and_pki.exs`. The runnable tutorial keeps unsigned demo binaries
and documents signature verification as an operator note instead of emitting
`signature_required` or `sig_path`.

`firewall watch` was again tested via `timeout`; as before, the local watch CLI
prints a SIGTERM/down message when killed, but `ek node ping` immediately after
returned `pong`.

Next useful implementation unit: expose `table` and `table_owner` in the
plain/table output for `ek firewall events` and `ek firewall watch`, not only
JSON.

Resolved on 2026-05-08:

`ek firewall events` and `ek firewall watch` table output now includes:

```text
source   table           owner  src_ip  dst_ip  chain
counter  erlkoenig_host  host   -       -       input
nflog    erlkoenig_host  host   ...     ...     banned
```

Validation run:

```text
rebar3 eunit --module=ek_tests                         65 tests, 0 failures
rebar3 xref                                            ok
make release                                           tarball audit ok
live install on erlkoenig-2__root                      ok
ek node ping                                           pong
ek firewall events --limit 8                           table/owner columns visible
timeout 8 ek firewall watch --limit 4                  table/owner columns visible
```

Resolved on 2026-05-08:

`firewall watch` table output now keeps stream state and prints the table
header only for the first non-empty batch. Later batches emit rows only.

Additional validation run:

```text
mix test test/tutorial_shape_test.exs                  31 tests, 0 failures
make test-dsl                                          20 properties, 351 tests, 0 failures
rebar3 eunit --module=ek_tests                         65 tests, 0 failures
rebar3 xref                                            ok
```

## Important Dirty-Tree Note

There were pre-existing dirty files before this larger integration session.
Do not revert unrelated changes. Work with the dirty tree.

Untracked/added files that are part of this feature:

```text
apps/erlkoenig/src/erlkoenig_firewall_correlator.erl
apps/erlkoenig/src/erlkoenig_firewall_event.erl
apps/erlkoenig/src/erlkoenig_firewall_events.erl
apps/erlkoenig/test/erlkoenig_firewall_correlator_tests.erl
apps/erlkoenig/test/erlkoenig_firewall_event_tests.erl
apps/erlkoenig/test/erlkoenig_firewall_events_tests.erl
docs/SPEC-INTERACTIVE-FIREWALL.md
docs/HANDOFF-2026-05-07-interactive-firewall-live.md
```

There is also an older untracked file:

```text
docs/HANDOFF-2026-05-06-example-live-validation.md
```
