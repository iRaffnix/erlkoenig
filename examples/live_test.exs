defmodule LiveTest do
  use Erlkoenig.Stack

  pod "echo" do
    container "echo_a",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      restart: :on_failure do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, udp: 53
        rule :accept
      end
    end

    container "echo_b",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8888"],
      ports: [{9080, 8888}],
      restart: {:on_failure, 3} do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 8888
        rule :drop, log: "DROP: "
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
