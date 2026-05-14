defmodule ResourceAdmissionDenialLab do
  @moduledoc """
  Resource-admission *denial* showcase stack.

  Two workers, each declaring 8 GiB of memory — together they
  always exceed any reasonable lab `containers_memory_max` ceiling.

  Where the rejection actually happens
  ====================================

  The cross-validation in `erlkoenig_config_validate` (statically)
  catches this overcommit at *config-load* time, **before** any
  spawn or runtime admission gate runs. So in normal operation the
  lab is rejected by `ek up` (or the equivalent), not by a runtime
  `EK_CT_RESOURCE_ADMISSION_DENIED` event. There is no live `ek
  admission denial worker-1` trace to capture.

  Two ways to look at the lab
  ===========================

  1. Topology only — what the operator declared:

         mix erlkoenig.showcase resource_admission_denial --format mermaid

  2. Synthesised runtime explanation — what the admission gate
     *would* have produced if the static check did not exist:

         mix erlkoenig.showcase resource_admission_denial \\
           --explain --format mermaid

     The `--explain` flag walks the lab's containers, picks the
     largest declared memory request as the rejected one, treats
     the rest as already-allocated holders, and renders the
     resulting causal world. This is the same shape the runtime
     would emit live — useful for documentation, dashboards, and
     making the explainer pipeline visible in CI.
  """
  use Erlkoenig.Stack

  host do
    ipvlan "denial",
      parent: {:dummy, "ek_denial"},
      subnet: {10, 73, 0, 0, 24}

    nft_host do
      base_chain "input",
        hook: :input,
        type: :filter,
        priority: :filter,
        policy: :drop do
        nft_rule(:accept, ct_state: [:established, :related])
        nft_rule(:accept, iifname: "lo")
        nft_rule(:accept, ip_protocol: :icmp)
        nft_rule(:accept, tcp_dport: 22)
      end

      base_chain "forward",
        hook: :forward,
        type: :filter,
        priority: :filter,
        policy: :drop do
        nft_rule(:accept, ct_state: [:established, :related])
        nft_rule(:accept, ip_protocol: :icmp)
      end
    end
  end

  pod "workers", strategy: :rest_for_one do
    for_each i <- 0..1 do
      container "worker-#{i}",
        binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
        args: ["909#{i}"],
        zone: "denial",
        restart: :temporary,
        # 8 GiB per replica — two replicas push declared memory to 16
        # GiB, which any sane lab ceiling will refuse.
        limits: %{
          memory: 8 * 1024 * 1024 * 1024,
          pids: 256,
          cpu: 50
        } do
        requires(:"dns.local")

        publish interval: 2000 do
          metric(:memory)
          metric(:pids)
        end

        nft do
          input policy: :drop do
            nft_rule(:accept, ct_state: [:established, :related])
            nft_rule(:accept, ip_protocol: :icmp)
            nft_rule(:accept, tcp_dport: 9090 + i)
          end

          output policy: :drop do
            nft_rule(:accept, ct_state: [:established, :related])
            nft_rule(:accept, ip_protocol: :icmp)
            nft_rule(:accept, ip_daddr: {10, 73, 0, 1}, udp_dport: 53)
          end
        end
      end
    end
  end
end
