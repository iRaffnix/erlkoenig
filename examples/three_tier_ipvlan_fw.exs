defmodule ThreeTierIpvlanFw do
  @moduledoc """
  Three-Tier Web Architecture — IPVLAN L3S mit Firewall.

  Wie three_tier_ipvlan.exs, aber mit nft-Regeln die den
  Traffic zwischen den Tiers auf das Noetige beschraenken:

    web (*.2,*.3,*.4)  →  app (*.5):4000     ✓
    app (*.5)          →  data (*.6):5432     ✓
    web → data                                ✗
    data → web                                ✗
    data → app                                ✗
    alles andere                              ✗

  Topologie:

    ek_ct0 (dummy, 10.50.100.1/24)  ←  IPVLAN L3S Parent
       |
    ipv.web0ngin  10.50.100.2  ──→  app:4000
    ipv.web1ngin  10.50.100.3  ──→  app:4000
    ipv.web2ngin  10.50.100.4  ──→  app:4000
    ipv.app0api   10.50.100.5  ──→  data:5432
    ipv.data0post 10.50.100.6  ──→  (nichts)

  Firewall-Modell:
    Kein VMap-Dispatch (Slaves unsichtbar im Host-Netns).
    Stattdessen IP-basierte Forward-Regeln:
      ip saddr <web-ips> ip daddr <app-ip> tcp dport 4000 accept
      ip saddr <app-ip>  ip daddr <data-ip> tcp dport 5432 accept
    Default: drop + counter.
  """

  use Erlkoenig.Stack

  # ── 1. Container ─────────────────────────────────────

  pod "web", strategy: :one_for_one do
    container "nginx",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8443"],
      limits: %{memory: 268_435_456, pids: 100},
      restart: :always do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      stream retention: {30, :days} do
        channel :stdout
        channel :stderr
      end

      # nginx darf nur api erreichen, empfängt auf :8443
      nft do
        output policy: :drop do
          nft_rule :accept, iifname: "lo"
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_daddr: {10, 50, 100, 5}, tcp_dport: 4000
        end
        input policy: :drop do
          nft_rule :accept, iifname: "lo"
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, tcp_dport: 8443
        end
      end
    end
  end

  pod "app", strategy: :one_for_one do
    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      limits: %{memory: 536_870_912, pids: 200},
      restart: {:on_failure, 5} do

      publish interval: 2000 do
        metric :memory
        metric :cpu
      end

      # api darf nur postgres erreichen, empfängt auf :4000
      nft do
        output policy: :drop do
          nft_rule :accept, iifname: "lo"
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_daddr: {10, 50, 100, 6}, tcp_dport: 5432
        end
        input policy: :drop do
          nft_rule :accept, iifname: "lo"
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_saddr: {10, 50, 100, 2}, tcp_dport: 4000
          nft_rule :accept, ip_saddr: {10, 50, 100, 3}, tcp_dport: 4000
          nft_rule :accept, ip_saddr: {10, 50, 100, 4}, tcp_dport: 4000
        end
      end
    end
  end

  pod "data", strategy: :one_for_one do
    container "postgres",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["5432"],
      limits: %{memory: 1_073_741_824, pids: 50},
      restart: :always do

      publish interval: 5000 do
        metric :memory
        metric :pids
      end

      # postgres darf nichts initiieren, empfängt nur von api auf :5432
      nft do
        output policy: :drop do
          nft_rule :accept, iifname: "lo"
          nft_rule :accept, ct_state: [:established, :related]
        end
        input policy: :drop do
          nft_rule :accept, iifname: "lo"
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_saddr: {10, 50, 100, 5}, tcp_dport: 5432
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

    # ── Container-Firewall (IP-basiert) ──────────────
    #
    # IPVLAN-Slaves sind im Host-Netns nicht sichtbar,
    # deshalb kein iifname/oifname Matching moeglich.
    # Stattdessen: IP-basierte Forward-Policy.
    #
    # IPs (deterministisch, Pool startet bei .2):
    #   web-0-nginx:    10.50.100.2
    #   web-1-nginx:    10.50.100.3
    #   web-2-nginx:    10.50.100.4
    #   app-0-api:      10.50.100.5
    #   data-0-postgres: 10.50.100.6

    nft_table :inet, "erlkoenig" do
      nft_counter "forward_drop"

      # Forward-Policy (priority 0)
      #
      # Erlaubte Pfade:
      #   web (*.2,*.3,*.4) → app (*.5):4000
      #   app (*.5)         → data (*.6):5432
      #   Antworten         → established/related
      #   alles andere      → drop

      base_chain "forward",
        hook: :forward, type: :filter,
        priority: :filter, policy: :drop do

        # 1. Antworten auf bestehende Verbindungen
        nft_rule :accept, ct_state: [:established, :related]

        # 2. web → app:4000
        nft_rule :accept,
          ip_saddr: {10, 50, 100, 2},
          ip_daddr: {10, 50, 100, 5},
          tcp_dport: 4000
        nft_rule :accept,
          ip_saddr: {10, 50, 100, 3},
          ip_daddr: {10, 50, 100, 5},
          tcp_dport: 4000
        nft_rule :accept,
          ip_saddr: {10, 50, 100, 4},
          ip_daddr: {10, 50, 100, 5},
          tcp_dport: 4000

        # 3. app → data:5432
        nft_rule :accept,
          ip_saddr: {10, 50, 100, 5},
          ip_daddr: {10, 50, 100, 6},
          tcp_dport: 5432

        # 4. ICMP nur in erlaubten Richtungen
        #    (Antwort-Pings laufen ueber ct_state established/related)
        nft_rule :accept,
          ip_saddr: {10, 50, 100, 2}, ip_daddr: {10, 50, 100, 5},
          ip_protocol: :icmp
        nft_rule :accept,
          ip_saddr: {10, 50, 100, 3}, ip_daddr: {10, 50, 100, 5},
          ip_protocol: :icmp
        nft_rule :accept,
          ip_saddr: {10, 50, 100, 4}, ip_daddr: {10, 50, 100, 5},
          ip_protocol: :icmp
        nft_rule :accept,
          ip_saddr: {10, 50, 100, 5}, ip_daddr: {10, 50, 100, 6},
          ip_protocol: :icmp

        # 5. Default: drop + log
        nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
      end
    end
  end

  # ── 4. Deployment ────────────────────────────────────

  attach "web",  to: "containers", replicas: 3
  attach "app",  to: "containers", replicas: 1
  attach "data", to: "containers", replicas: 1
end
