# SSH-Bastion direkt am Internet (z.B. Port 2222 auf oeffentlicher IP)
#
# Szenario: Ein Jump-Host fuer Admins, kein Loadbalancer davor.
# Guard schuetzt gegen Brute-Force (conn_flood) und Reconnaissance (port_scan).
#
# Auf dem Host: iptables/nftables leitet 0.0.0.0:2222 -> Container
# Erlkoenig DNAT:  Host:2222 -> 10.0.0.20:22

defmodule PublicBastion do
  use Erlkoenig.Stack

  pod "bastion" do
    container "bastion",
      binary: "/usr/sbin/dropbear",
      args: ["-F", "-E", "-p", "22"],
      ports: [{2222, 22}],
      limits: %{memory: "128M", pids: 50},
      restart: :permanent,
      health_check: [port: 22, interval: 15_000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, udp: 53
        rule :drop, log: "DROP: "
      end
    end
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "bastion", replicas: 1
  end
end
