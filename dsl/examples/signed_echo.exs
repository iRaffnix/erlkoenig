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
  use Erlkoenig.DSL

  container :echo do
    binary "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"
    signature :required
    ip {10, 0, 0, 5}
    args ["7777"]
    ports [{9080, 7777}]
    restart :on_failure
    health_check port: 7777, interval: 5000, retries: 3
    firewall do
      accept :established
      accept :icmp
      accept_udp 53
      accept :all
    end
  end
end
