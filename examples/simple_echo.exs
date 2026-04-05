defmodule SimpleEcho do
  use Erlkoenig.Stack

  # Minimal-Beispiel: ein einzelner Echo-Server auf einer Bridge.

  host do
    bridge "echo", subnet: {10, 0, 0, 0, 24}
  end

  pod "echo" do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      restart: :on_failure
  end

  attach "echo", to: "echo", replicas: 1
end
