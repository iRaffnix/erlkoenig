defmodule SignedEcho do
  @moduledoc """
  Minimal signed container example.

  The binary must have a valid .sig file (Ed25519 + certificate chain).
  erlkoenig rejects unsigned or tampered binaries.

      # Sign the binary
      erlkoenig sign /opt/erlkoenig/rt/demo/test-erlkoenig-echo_server \\
        --cert chain.pem --key signing.key

      # Deploy
      erlkoenig compile signed_echo.exs
      erlkoenig spawn ...
  """
  use Erlkoenig.Stack

  # TODO: migrate signature enforcement when supported

  pod "echo" do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      ports: [{9080, 7777}],
      restart: :on_failure,
      health_check: [port: 7777, interval: 5000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, udp: 53
        rule :accept
      end
    end
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "echo", replicas: 1
  end
end
