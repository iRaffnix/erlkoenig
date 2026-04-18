defmodule FwFlowtable do
  @moduledoc """
  Chapter 6 — Flowtable Offload Demo.

  Demonstrates nftables' native fast-path acceleration. Once a TCP
  connection is established, subsequent packets bypass the full
  nftables evaluation pipeline and are fast-pathed at the ingress
  hook. This is the kernel-native alternative to eBPF XDP for
  connection-oriented workloads.

  The flowtable attaches to eth0 (change to match your interface).
  Established forward-path connections are offloaded automatically.
  New connections still traverse the full chain for policy evaluation.

  Starten:
    ek dsl compile examples/fw_flowtable.exs -o /tmp/fw_flowtable.term
    ek config_load /tmp/fw_flowtable.term

  Verify:
    nft list ruleset
    # Should show: flowtable ft0 { hook ingress ... devices = { eth0 } }
    # And rule:    ct state established flow add @ft0
  """

  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    nft_table :inet, "filter" do
      nft_counter "offloaded"
      nft_counter "forward_drop"

      # ── Flowtable: fast-path for established connections ──
      nft_flowtable "ft0", devices: ["eth0"]

      # ── Input: standard hardened host ─────────────────────
      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22
        nft_rule :drop, log_prefix: "INPUT: "
      end

      # ── Forward: offload established, filter new ──────────
      base_chain "forward", hook: :forward, type: :filter,
                 priority: :filter, policy: :drop do

        # Established flows -> offload to flowtable (fast-path)
        nft_rule :flow_offload, flowtable: "ft0"

        # New connections: explicit allow
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
      end
    end
  end
end
