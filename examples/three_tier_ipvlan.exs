defmodule ThreeTierIpvlan do
  @moduledoc """
  Three-Tier Web Architecture — IPVLAN L3S auf Dummy-Parent.

  Web → App → Database, alle drei in einem gemeinsamen IPVLAN-L3S-Netz
  auf einem Dummy-Parent. IP-basierte Firewall isoliert die Tiers
  voneinander; kein Masquerade (rein internes Netz), kein DNAT
  (für externen Zugang nutzt man WireGuard oder einen Reverse-Proxy
  davor).

  Topologie:

    ek_ct0 (dummy, 10.50.100.1/24)  ←  IPVLAN L3S Parent
       |
    ipv.web0ngin  10.50.100.2  ──→  app:4000
    ipv.web1ngin  10.50.100.3  ──→  app:4000
    ipv.web2ngin  10.50.100.4  ──→  app:4000
    ipv.app0api   10.50.100.5  ──→  data:5432
    ipv.data0post 10.50.100.6  ──→  (nichts)

  Erlaubte Pfade:
    web (*.2,*.3,*.4)  →  app (*.5):4000
    app (*.5)          →  data (*.6):5432
    Alle               →  established/related (Antworten)

  Voraussetzung:
    ip link add ek_ct0 type dummy
    ip addr add 10.50.100.1/24 dev ek_ct0
    ip link set ek_ct0 up
  """

  use Erlkoenig.Stack

  # ── 1. Container ─────────────────────────────────────
  #
  # Jeder Container bekommt eine eigene nft-Tabelle in seiner netns.
  # input-Chain regelt wer reindarf, output wer raus. IPVLAN-L3S
  # umgeht den Host-Forward-Hook — Tier-Isolation MUSS deshalb in
  # den Container-netns passieren, nicht auf dem Host.

  pod "three_tier", strategy: :one_for_one do
    container "nginx",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8443"],
      limits: %{memory: 268_435_456, pids: 100},
      zone: "containers",
      replicas: 3,
      restart: :permanent do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      stream retention: {30, :days} do
        channel :stdout
        channel :stderr
      end

      # Web-Tier: offen auf 8443 für jeden; nach außen nur zur API
      # und zum Gateway (DNS/Health). ICMP erlaubt für Diagnose.
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, tcp_dport: 8443
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_daddr: {10, 50, 100, 5}, tcp_dport: 4000
          nft_rule :accept, ip_daddr: {10, 50, 100, 1}
        end
      end
    end

    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      limits: %{memory: 536_870_912, pids: 200},
      zone: "containers",
      replicas: 1,
      restart: :transient do

      publish interval: 2000 do
        metric :memory
        metric :cpu
      end

      # App-Tier: akzeptiert 4000 nur aus dem Web-Tier
      # (*.2, *.3, *.4). Spricht selbst nur mit Postgres
      # und dem Gateway.
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_saddr: {10, 50, 100, 2}, tcp_dport: 4000
          nft_rule :accept, ip_saddr: {10, 50, 100, 3}, tcp_dport: 4000
          nft_rule :accept, ip_saddr: {10, 50, 100, 4}, tcp_dport: 4000
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_daddr: {10, 50, 100, 6}, tcp_dport: 5432
          nft_rule :accept, ip_daddr: {10, 50, 100, 1}
        end
      end
    end

    container "postgres",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["5432"],
      limits: %{memory: 1_073_741_824, pids: 50},
      zone: "containers",
      replicas: 1,
      restart: :permanent do

      publish interval: 5000 do
        metric :memory
        metric :pids
      end

      # Data-Tier: akzeptiert 5432 nur von der API (*.5),
      # spricht selbst mit niemandem außer dem Gateway
      # (NTP/DNS/Health).
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_saddr: {10, 50, 100, 5}, tcp_dport: 5432
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_daddr: {10, 50, 100, 1}
        end
      end
    end
  end

  # ── 2. Bedrohungserkennung ───────────────────────────

  guard do
    detect do
      flood over: 50, within: s(10)
      port_scan over: 20, within: m(1)
      slow_scan over: 5, within: h(1)
      honeypot [21, 22, 23, 445, 1433, 1521, 3306,
                3389, 5900, 6379, 8080, 8888, 9200, 27017]
    end

    respond do
      suspect after: 3, distinct: :ports
      ban_for h(1)
      honeypot_ban_for h(24)
      escalate [h(1), h(6), h(24), d(7)]
      observe_after_unban m(2)
      forget_after m(5)
    end

    allowlist [
      {127, 0, 0, 1},
      {10, 50, 100, 1}
    ]
  end

  # ── 3. Netzwerk + Firewall ──────────────────────────
  #
  # Ein IPVLAN-Segment auf Dummy-Parent. Alle Container
  # im selben /24. Firewall regelt wer mit wem reden darf.

  host do
    interface "eth0", zone: :wan

    ipvlan "containers",
      parent: {:dummy, "ek_ct0"},
      subnet: {10, 50, 100, 0, 24}

    # ── Host-Firewall ────────────────────────────────

    nft_table :inet, "host" do
      nft_set "ban", :ipv4_addr
      nft_counter "input_drop"
      nft_counter "input_ban"

      base_chain "prerouting", hook: :prerouting, type: :filter,
        priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "input_ban"
      end

      base_chain "input",
        hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22222
        nft_rule :accept, tcp_dport: 9100
        nft_rule :drop, counter: "input_drop", log_prefix: "HOST: "
      end
    end
  end

end
