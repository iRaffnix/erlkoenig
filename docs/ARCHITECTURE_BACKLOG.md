# Erlkoenig Architecture Backlog

This document captures architectural findings that are larger than a
single tutorial or install-script fix.

## Quarantine Scope And Spawn Classification

Observed during example start testing on 2026-04-29:
`examples/tutorial/05_storage_and_pki.exs` used production-form PKI
settings (`signature: :required`) with unsigned demo binaries and no
trust-root setup. The DB container failed before exec, retried under a
`:permanent` restart policy, and triggered crash-loop quarantine for the
shared `test-erlkoenig-echo_server` binary. Other examples using the
same binary were then blocked by `EK_RUNTIME_BINARY_QUARANTINED`.

Backlog items:

- Quarantine is binary-global today. Consider scoping automatic
  crash-loop quarantine by binary plus workload context, or otherwise
  preventing one DSL/config error from blocking unrelated containers that
  happen to use the same binary.
- Spawn-time failures and runtime crashes are classified together for
  crash-loop quarantine. Consider counting only post-exec runtime exits
  toward crash-loop quarantine, while keeping pre-exec integrity failures
  visible as failed container state requiring operator action.

Near-term mitigation: pattern for operator-supplied prerequisites
-----------------------------------------------------------------

Until the two architectural items above are addressed, any DSL container
whose ability to spawn depends on an **operator-supplied prerequisite**
must use `restart: :temporary`. The prerequisite remains fail-closed
and visible as `failed`-state, but the runtime does not retry-storm
through repeated spawn attempts, and the shared demo binary is not
crash-loop-quarantined for unrelated workloads.

Triggers (each is a fail-closed pre-exec gate that depends on operator
setup outside the DSL itself):

- `signature: :required` — needs trust-roots installed under
  `/etc/erlkoenig/trust/` plus a valid `.sig` next to the binary.
- `signature: "/explicit/path.sig"` — needs the named sig-file on disk.
- Unsigned demo binaries used in examples that demonstrate signature
  enforcement.
- `binary: "/operator/path"` references that are not part of the
  bundled `rt/demo/` set (e.g. `/opt/api/server` in
  `examples/stacks/signed_deployment.exs`).
- Any future admission / attestation gate that fails closed before exec
  unless the operator completed setup (TPM-bound keys, hardware
  attestation tokens, externally-issued capability tickets, etc.).

Why neither `:permanent` nor `:transient` is correct here:

- `:permanent` retries unconditionally. With a deterministic pre-exec
  failure this hits 5 spawns within 60 s and triggers
  `EK_RUNTIME_BINARY_QUARANTINED` on the binary's content hash. Any
  other container in the system that uses the same binary is then
  blocked — a Glasbox violation: one DSL/config error affects
  unrelated workloads.
- `:transient` retries on abnormal exit. The OTP definition of
  "abnormal" is "anything other than `:normal` or `:shutdown`". A
  pre-exec spawn failure is abnormal by that definition, so
  `:transient` retries it. Same crash-loop, same quarantine.
- `:temporary` is "never restart". The container stays `failed` until
  the operator fixes the prerequisite and explicitly redeploys.
  Visible, fail-closed, no cascade.

For production stacks where the prerequisite is provisioned and the
spawn is expected to succeed, `:permanent` remains the correct policy
— the failure mode there is genuine runtime crash, not pre-exec gate
failure.

When writing new examples or operator cookbooks: any container that
demonstrates a feature requiring operator-side setup should default to
`:temporary` with a comment explaining that production deployments
flip it to `:permanent` once the prerequisite is in place.

## Host Firewall Lockout Preflight

Observed during example start testing on 2026-04-29:
`examples/stacks/tutorial.exs`, `examples/stacks/three_tier_ipvlan.exs`, and
`examples/stacks/three_tier_ipvlan_fw.exs` all declare a full host firewall
takeover:

- `nft_host`
- `base_chain "input", hook: :input, type: :filter,
  priority: :filter, policy: :drop`
- explicit accepts for `ct_state: [:established, :related]`, loopback,
  ICMP, and SSH only on `tcp_dport: 22222`
- `guard` honeypot lists that include port 22

The current SSH session usually survives because it is already tracked
as established, but any reconnect to the normal SSH port is dropped.
For `tutorial.exs`, a reconnect to port 22 can also be treated as a
honeypot hit and ban the operator IP for the configured ban interval.
This creates a bootstrap deadlock: once the session is gone, the
operator cannot run `ek down` without out-of-band access.

Near-term mitigation:

- Keep the DSL explicit. Do not inject a hidden `tcp_dport: 22` accept
  rule; that would violate the Glasbox model and hide production
  behavior.
- Add prominent warnings to examples that take over the host firewall
  and do not preserve the default SSH port.

Backlog items:

- Add an `ek up` host-firewall preflight. If the stack applies an input
  chain with `policy: :drop`, detect the currently reachable SSH port(s)
  from local host state (`ss`/`systemd`/`sshd_config` best effort) and
  abort when none are explicitly accepted. The operator can override
  with an explicit flag such as `--allow-lockout`.
- Treat guard honeypots as part of the same preflight. If the current
  SSH port is in a honeypot list and the operator source is not
  allowlisted, the warning should be stronger because reconnects can
  produce time-bounded bans, not just dropped SYNs.
- Consider a DSL-level demo/test profile marker for examples. A marker
  such as `profile: :demo` could be explicit in the source and permit
  tutorial-friendly safety checks without adding hidden production
  firewall rules.

Rejected mitigation:

- A DSL default that always accepts SSH on port 22. It prevents one
  class of self-DOS, but it is anti-Glasbox: the source no longer shows
  the real host firewall, and production hosts that intentionally move
  or close SSH get surprising behavior.
