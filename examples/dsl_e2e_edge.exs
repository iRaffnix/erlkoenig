defmodule DslE2eEdge do
  @moduledoc """
  Minimal stack file used by the E2E DSL integration test (test 32).

  Exercises the two edge-primitives declared via the DSL that
  previous tests only checked via hand-rolled spawn opts:

    * `requires :"dns.allowlist", hosts: [...]` — container
      lifecycle must register the allowlist against the container
      IP in `erlkoenig_dns_filter`.
    * `conn_limit per_ip: N` INSIDE a chain block — must appear as
      a visible `ct count over N saddr drop` rule in the container
      netns.

  The test harness patches `binary:` to the repo's echo_server
  before loading, so this file can live with a placeholder.
  """
  use Erlkoenig.Stack

  host do
    ipvlan "e2e_edge", parent: {:dummy, "ek_e2e_edge"},
                      subnet: {10, 80, 0, 0, 24}

    nft_table :inet, "host" do
      nft_counter "input_drop"

      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        # Zone gateway DNS — container must reach the resolver.
        nft_rule :accept, ip_saddr: {10, 80, 0, 0, 24}, udp_dport: 53
        nft_rule :drop,   counter: "input_drop"
      end
    end
  end

  pod "e2e_edge", strategy: :one_for_one do
    container "web",
      binary: "/placeholder/patched/by/test/harness",
      args: ["7732"],
      zone: "e2e_edge",
      replicas: 1,
      restart: :permanent do

      # DSL-flow check #1: DNS L7 allowlist, chain-less capability.
      # Expected side effect: erlkoenig_dns_filter ETS gets a row
      # keyed by the container IP with compiled patterns for these
      # hostnames — and nothing else.
      requires :"dns.allowlist", hosts: [
        "api.example.com",
        "*.test.invalid"
      ]

      # Container-local nft. `conn_limit` lives at chain level after
      # the Glasbox refactor — the rule must appear exactly at the
      # line the operator wrote it, not via runtime synthesis.
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, tcp_dport: 7732
          # DSL-flow check #2: distinctive cap=7 so the post-spawn
          # nft ruleset dump unambiguously proves this rule made it
          # to the kernel.
          conn_limit per_ip: 7
        end
      end
    end
  end
end
