defmodule SimpleEcho do
  use Erlkoenig.Stack

  pod "echo" do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      ports: [{9080, 7777}],
      restart: :on_failure
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :accept, udp: 53, oif: "ek_br_default"
      rule :drop
    end

    deploy "echo", replicas: 1
  end
end
