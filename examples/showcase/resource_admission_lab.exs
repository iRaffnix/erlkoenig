defmodule ResourceAdmissionLab do
  @moduledoc """
  Resource-admission showcase stack.

  This file is meant to be run by an operator, not just read in a test.
  It keeps every container instance explicit so the cgroup budget is visible
  in the DSL:

      ek dsl compile examples/showcase/resource_admission_lab.exs -o /tmp/resource_admission_lab.term
      ek config validate /tmp/resource_admission_lab.term
      ek up /tmp/resource_admission_lab.term
      ek admission snapshot

  The matching ontology is available from Elixir:

      mix run -e 'Code.compile_file("examples/showcase/resource_admission_lab.exs"); IO.inspect(ResourceAdmissionLab.ontology().facts, limit: 3)'

  The stack intentionally uses small demo binaries and conservative limits so
  it is safe to install-smoke on a lab host. The point is the operator surface:
  declared kill factors (`memory`, `pids`), CPU as a hard quota hint, publish
  metrics, explicit firewall ownership, and enough ontology facts to draw an
  architecture diagram.
  """
  use Erlkoenig.Stack

  host do
    ipvlan "admission", parent: {:dummy, "ek_admission"},
                         subnet: {10, 72, 0, 0, 24}

    nft_host do
      nft_nflog_group 72, name: "admission_lab"
      nft_counter "admission_input_drop"
      nft_counter "admission_forward_drop"

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22
        nft_rule :drop, counter: "admission_input_drop",
                        log_prefix: "ADMISSION: ", nflog_group: 72
      end

      base_chain "forward", hook: :forward, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, ip_protocol: :icmp

        # Keep the live lab fast and predictable: cross-container
        # ownership is demonstrated by the host-owned forward chain,
        # while the runtime does not have to wait for every target IP
        # before applying the table.
        nft_rule :accept,
                 ip_saddr: {10, 72, 0, 0, 24},
                 ip_daddr: {10, 72, 0, 0, 24},
                 tcp_dport: 8080

        nft_rule :drop, counter: "admission_forward_drop",
                        log_prefix: "ADMISSION-FWD: ", nflog_group: 72
      end
    end
  end

  pod "frontdoor", strategy: :one_for_one do
    for_each i <- 0..1 do
      container "edge-#{i}",
        binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
        args: ["807#{i}"],
        zone: "admission",
        restart: :temporary,
        limits: %{
          memory: 96_000_000,
          pids: 64,
          cpu: 50
        } do

        requires :"dns.local"
        requires :"journal.local"

        publish interval: 2000 do
          metric :memory
          metric :cpu
          metric :pids
        end

        stream retention: {1, :days} do
          channel :stdout
          channel :stderr
        end

        nft do
          input policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, ip_protocol: :icmp
            nft_rule :accept, tcp_dport: 8070 + i
          end

          output policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, ip_protocol: :icmp
            nft_rule :accept, ip_daddr: {10, 72, 0, 1}, udp_dport: 53
            nft_rule :accept, tcp_dport: 8080
          end
        end
      end
    end
  end

  pod "workers", strategy: :rest_for_one do
    for_each i <- 0..1 do
      container "worker-#{i}",
        binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
        args: ["808#{i}"],
        zone: "admission",
        restart: :temporary,
        limits: %{
          memory: 128_000_000,
          pids: 96,
          cpu: 75
        } do

        requires :"dns.local"
        requires :"journal.local"

        publish interval: 1000 do
          metric :memory
          metric :cpu
          metric :pids
        end

        nft do
          input policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, ip_protocol: :icmp
            nft_rule :accept, tcp_dport: 8080 + i
          end

          output policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, ip_protocol: :icmp
            nft_rule :accept, ip_daddr: {10, 72, 0, 1}, udp_dport: 53
          end
        end
      end
    end
  end
end
