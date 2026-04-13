defmodule IpvlanSmoke do
  @moduledoc """
  Minimal IPVLAN smoke test — ein Container, kein nft, kein guard.

  Voraussetzung auf dem Host:
    ip link add ek_ipv0 type dummy
    ip addr add 10.50.0.1/24 dev ek_ipv0
    ip link set ek_ipv0 up
  """
  use Erlkoenig.Stack

  host do
    ipvlan "test",
      parent: {:dummy, "ek_ct0"},
      subnet: {10, 50, 100, 0, 24}
  end

  pod "echo", strategy: :one_for_one do
    container "server",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      restart: :always
  end

  attach "echo", to: "test", replicas: 1
end
