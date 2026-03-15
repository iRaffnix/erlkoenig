# SSH-Bastion direkt am Internet (z.B. Port 2222 auf oeffentlicher IP)
#
# Szenario: Ein Jump-Host fuer Admins, kein Loadbalancer davor.
# Guard schuetzt gegen Brute-Force (conn_flood) und Reconnaissance (port_scan).
#
# Auf dem Host: iptables/nftables leitet 0.0.0.0:2222 -> Container
# Erlkoenig DNAT:  Host:2222 -> 10.0.0.20:22

defmodule PublicBastion do
  use Erlkoenig.DSL

  container :bastion do
    binary "/usr/sbin/dropbear"
    ip {10, 0, 0, 20}
    args ["-F", "-E", "-p", "22"]
    ports [{2222, 22}]
    limits memory: "128M", pids: 50, pps: 1000
    restart :permanent
    health_check port: 22, interval: 15_000, retries: 3

    firewall do
      accept :established
      accept :icmp
      accept_udp 53
      log_and_drop "DROP: "
    end
  end

end
