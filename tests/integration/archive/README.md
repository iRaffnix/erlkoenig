# Archived Integration Tests

These escripts were written against the bridge/veth networking model that
was removed in ADR-0020 (IPVLAN L3S is now the only mode). They are kept
for historical reference only and are **not** invoked by `run_all.sh` or
`make integration`.

| File | Why archived |
|------|--------------|
| `02_networking.escript` | Header says "via Bridge" — container-to-container traffic in IPVLAN L3S is covered by `23_ipvlan.escript`. |
| `03_port_forwarding.escript` | DNAT via bridge gateway doesn't apply — IPVLAN slaves are L3-reachable directly. |
| `13_net_setup.escript` | Calls `erlkoenig_bridge:start_link()` — module deleted. Replaced conceptually by the IPVLAN setup path exercised in `23_ipvlan.escript`. |

If you need historical reproduction, check out the commit before ADR-0020
and run from there (bridge/veth code was removed, not hidden behind a
feature flag).
