defmodule ThreeTierNft do
  @moduledoc """
  Three-Tier Web Architecture (web/app/data).

  nft-nahe DSL mit deploy-time expandierten Referenzen:
  - {:veth_of, Pod, Ct}      -> Veth-Name aus attach-Konfiguration
  - {:replica_ips, Pod, Ct}   -> Container-IPs aus attach + replicas

  Topologie:

    Internet (:8443)
       |
    Bridge "dmz"  (10.0.0.0/24)  --  web/nginx  (replicas: 3)
       |
    Bridge "app"  (10.0.1.0/24)  --  app/api
       |
    Bridge "data" (10.0.2.0/24)  --  data/postgres

  Erlaubte Pfade:
    Internet -> web:8443 (DNAT, jhash-sticky)
    web -> app:4000
    app -> data:5432
    dmz -> Internet (Updates)
  """

  use Erlkoenig.Stack

  # ── 1. Was laeuft ────────────────────────────────────

  pod "web", strategy: :one_for_one do
    container "nginx",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8443"],
      limits: %{memory: 268_435_456, pids: 100},
      seccomp: :default,
      restart: :always do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      publish interval: 10_000 do
        metric :pressure
        metric :oom_events
      end

      stream retention: {30, :days} do
        channel :stdout
        channel :stderr
      end
    end
  end

  pod "app", strategy: :one_for_one do
    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      limits: %{memory: 536_870_912, pids: 200},
      seccomp: :default,
      restart: {:on_failure, 5} do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      stream retention: {90, :days} do
        channel :stderr
      end
    end
  end

  pod "data", strategy: :one_for_one do
    container "postgres",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["5432"],
      limits: %{memory: 1_073_741_824, pids: 50},
      seccomp: :default,
      restart: :always do

      publish interval: 5000 do
        metric :memory
        metric :pids
      end

      publish interval: 30_000 do
        metric :pressure
        metric :oom_events
      end

      stream retention: {90, :days} do
        channel :stdout
        channel :stderr
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
      {10, 0, 0, 1}
    ]
  end

  # ── 3. Wo laeuft es + Firewall ───────────────────────
  #
  # Policy-Absicht (was die nft-Bloecke unten implementieren):
  #
  #   expose "web", port: 8443, lb: :jhash
  #   allow "web" -> "app", port: 4000
  #   allow "app" -> "data", port: 5432
  #   allow "dmz" -> :internet

  host do
    interface "eth0", zone: :wan

    bridge "dmz",  subnet: {10, 0, 0, 0, 24}, uplink: "eth0"
    bridge "app",  subnet: {10, 0, 1, 0, 24}
    bridge "data", subnet: {10, 0, 2, 0, 24}

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

    # ── Container-Firewall ───────────────────────────

    nft_table :inet, "erlkoenig" do
      nft_counter "forward_drop"
      nft_counter "web_nginx_drop"
      nft_counter "app_api_drop"
      nft_counter "data_postgres_drop"

      # Loadbalancing: saddr-Hash -> Container-IP
      nft_map "web_jhash", :mark, :ipv4_addr,
        entries: {:replica_ips, "web", "nginx"}

      # DNAT (priority -100)
      base_chain "prerouting_nat", hook: :prerouting, type: :nat,
        priority: :dstnat, policy: :accept do

        nft_rule :dnat_jhash,
          iifname: "eth0", tcp_dport: 8443,
          map: "web_jhash", mod: 3, port: 8443
      end

      # Egress Dispatch: iifname -> jump Egress-Chain
      nft_vmap "egress_dispatch", :ifname, [
        {{:veth_of, "web", "nginx"},    {:jump, "from-web-nginx"}},
        {{:veth_of, "app", "api"},      {:jump, "from-app-api"}},
        {{:veth_of, "data", "postgres"}, {:jump, "from-data-postgres"}}
      ]

      # Egress: Port-Vorfilter pro Container
      nft_chain "from-web-nginx" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 4000
        nft_rule :drop, counter: "web_nginx_drop"
      end

      nft_chain "from-app-api" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 5432
        nft_rule :drop, counter: "app_api_drop"
      end

      nft_chain "from-data-postgres" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, counter: "data_postgres_drop"
      end

      # Forward-Policy: src . dst . port -> verdict
      nft_vmap "fwd_policy",
        fields: [:ipv4_addr, :ipv4_addr, :inet_service],
        entries: [
          {{10, 0, 0, 2}, {10, 0, 1, 2}, 4000, :accept},
          {{10, 0, 0, 3}, {10, 0, 1, 2}, 4000, :accept},
          {{10, 0, 0, 4}, {10, 0, 1, 2}, 4000, :accept},
          {{10, 0, 1, 2}, {10, 0, 2, 2}, 5432, :accept}
        ]

      # Forward (priority 0, nach DNAT)
      base_chain "forward",
        hook: :forward, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :vmap_lookup, vmap: "egress_dispatch", type: :ifname
        nft_rule :accept,
          iifname: "eth0",
          ip_daddr: {:replica_ips, "web", "nginx"},
          tcp_dport: 8443
        nft_rule :vmap_lookup, vmap: "fwd_policy"
        nft_rule :accept, iifname: "dmz", oifname: "eth0"
        nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
      end

      # Masquerade (priority +100)
      base_chain "postrouting",
        hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do

        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "dmz"
        nft_rule :masquerade, ip_saddr: {10, 0, 1, 0, 24}, oifname_ne: "app"
        nft_rule :masquerade, ip_saddr: {10, 0, 2, 0, 24}, oifname_ne: "data"
      end
    end
  end

  # ── 4. Deployment ────────────────────────────────────

  attach "web",  to: "dmz",  replicas: 3
  attach "app",  to: "app",  replicas: 1
  attach "data", to: "data", replicas: 1
end
