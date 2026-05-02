defmodule Tutorial.Firewall do
  @moduledoc """
  ### Datei 3/6 — nft-Firewall in voller Breite

  Zeigt alle wichtigen nftables-Primitives die die DSL dir gibt.
  Zweck: als Nachschlagewerk. Jeder Block ist für sich verständlich
  und zeigt einen konkreten Use-Case.

  Abgedeckt:
    * `nft_set`          — Basic-Set (IPs/Ports)
    * `nft_cidr_set`     — typisierte CIDR-Allowlist (Sugar, Glasbox-sauber)
    * `nft_counter`      — named counter, wird gepollt → AMQP-Event
    * `nft_map`          — Key → Value (Daten-Lookup)
    * `nft_vmap`         — Key → Verdict (Dispatch)
    * `nft_flowtable`    — HW-Fastpath für established flows
    * base_chain hooks:   prerouting, input, forward, output, postrouting
    * chain priorities:   :raw, :mangle, :filter, :nat
    * actions:            accept, drop, reject, jump, return, masquerade,
                          snat, dnat, ct_mark_set, flow_offload
    * `conn_limit`        — SPEC-EK-028 chain-level sugar (NICHT container-level!)
  """
  use Erlkoenig.Stack

  host do
    ipvlan "fw", parent: {:dummy, "ek_fw"},
                 subnet: {10, 30, 0, 0, 24}

    nft_host do

      # ══════════════════════════════════════════════════════════
      # SETS — Runtime-mutable Listen von Werten
      # ══════════════════════════════════════════════════════════

      # Basic set ohne vorbefüllung. Der Threat-Mesh füllt "ban"
      # zur Laufzeit; Regeln die auf das Set matchen droppen
      # sofort ohne conntrack-state zu allocaten.
      nft_set "ban", :ipv4_addr

      # CIDR-Allowlist — SPEC-AS-009 §3.3 Sugar.
      # Compile-time validiert, wird als nft interval-Set geladen.
      # Das Set kann in Regeln via `set: "name"` referenziert werden.
      nft_cidr_set "trusted_cidrs", [
        "10.0.0.0/8",          # RFC1918 internal
        "192.168.0.0/16",      # RFC1918 internal
        "203.0.113.0/24",      # TEST-NET-3 (im Beispiel stellvertretend)
        "198.51.100.42"        # single host is OK too
      ]

      # ══════════════════════════════════════════════════════════
      # COUNTERS — Observability
      # ══════════════════════════════════════════════════════════
      # Jeder Named-Counter wird alle 2s gepollt; rate>0 erzeugt
      # einen `firewall.<chain>.<action>`-AMQP-Event mit
      # pps+bps-Daten. Einer pro sinnvoller Observation.

      nft_counter "input_drop"
      nft_counter "input_ban"
      nft_counter "forward_drop"

      # ══════════════════════════════════════════════════════════
      # MAPS — Key → Data Lookup
      # ══════════════════════════════════════════════════════════
      #
      # Statisches Key-Value-Mapping. Bei jhash-DNAT wird der Map
      # als Backend-Pool benutzt (SRC-Hash → Backend-IP).
      nft_map "lb_backends", :ipv4_addr, :ipv4_addr, [
        {{10, 30, 0, 10}, {10, 30, 0, 100}},
        {{10, 30, 0, 11}, {10, 30, 0, 101}}
      ]

      # ══════════════════════════════════════════════════════════
      # VMAPS — Key → Verdict Dispatch
      # ══════════════════════════════════════════════════════════
      #
      # Effizientes Multi-Target-Dispatch. Statt N sequentieller
      # Regeln eine Lookup-Operation; Kernel verwendet eine
      # Hashtable unter der Haube. Lohnt ab ~5 Zielen.
      #
      # Wichtig: jeder jump-target MUSS als `nft_chain` (oder
      # base_chain) im gleichen nft_table deklariert sein — sonst
      # lehnt der Kernel das vmap-Element mit ENOENT ab und rollt
      # den gesamten atomaren Batch zurück. Der DSL-Validator
      # (Erlkoenig.Nft.TableBuilder.validate!/1) fängt das jetzt
      # zur Compile-Zeit ab.
      nft_vmap "port_dispatch", :inet_service, [
        {22,   {:jump, "ssh_handler"}},
        {80,   {:jump, "http_handler"}},
        {443,  {:jump, "https_handler"}},
        {5432, {:jump, "postgres_handler"}}
      ]

      # ── Handler-Chains für die vmap ──
      # Reguläre (non-base) Chains. Kein hook → werden nur per
      # jump/goto aus anderen Chains erreicht.
      nft_chain "ssh_handler" do
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 8}
        nft_rule :drop
      end

      nft_chain "http_handler" do
        nft_rule :accept
      end

      nft_chain "https_handler" do
        nft_rule :accept
      end

      nft_chain "postgres_handler" do
        nft_rule :accept, ip_saddr: {10, 30, 0, 0, 24}
        nft_rule :drop
      end

      # ══════════════════════════════════════════════════════════
      # FLOWTABLES — Software Fastpath
      # ══════════════════════════════════════════════════════════
      #
      # Offloaded forwarding für established flows. Erste Pakete
      # gehen normal durch die Chain; sobald der Kernel "diesen
      # flow sehe ich wieder" erkennt, wird der Rest im ingress-
      # hook direkt gematcht und gebridged. Reduziert CPU drastisch
      # für proxy-style workloads.
      nft_flowtable "ft0", devices: ["eth0"]

      # ══════════════════════════════════════════════════════════
      # CHAINS — Hooks, Prioritäten, Policies
      # ══════════════════════════════════════════════════════════

      # ── PREROUTING @ raw priority (-300) ──
      # Wird VOR conntrack ausgeführt. Bans hier kosten null
      # conntrack-entry + null NAT-lookup pro gebanntem Paket —
      # der schnellstmögliche Weg ein Paket zu killen.
      base_chain "prerouting_raw", hook: :prerouting, type: :filter,
                 priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "input_ban"
      end

      # ── INPUT — Pakete an den Host ──
      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp

        # SSH vom Trusted-Subnet
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 8}, tcp_dport: 22

        # VMap-Dispatch — alles was als TCP/dport reinkommt geht
        # durch die Port-Map (siehe nft_vmap oben). Die Jumps
        # landen in benannten chains die man mit nft_chain
        # deklarieren könnte (hier ausgelassen).
        nft_rule :vmap_dispatch, vmap: "port_dispatch"

        nft_rule :drop, counter: "input_drop",
                        log_prefix: "host/drop: "
      end

      # ── FORWARD — Pakete die weiter geroutet werden ──
      # Wichtig für Container-to-Container via Hub, oder masquerade
      # outbound.
      base_chain "forward", hook: :forward, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]

        # Flowtable-offload für established flows: markiert den
        # flow für ingress-fastpath.
        nft_rule :flow_offload, flowtable: "ft0"

        # Trusted-CIDR darf durch (INBOUND zur Container-Zone).
        nft_rule :accept, set: "trusted_cidrs",
                          ip_daddr: {10, 30, 0, 0, 24}

        nft_rule :drop, counter: "forward_drop"
      end

      # ── POSTROUTING — NAT ──
      # :srcnat priority für masquerade.
      base_chain "postrouting", hook: :postrouting, type: :nat,
                 priority: :srcnat, policy: :accept do
        # Alles was nicht durch eth0 rausgeht (also: container-
        # traffic via ipvlan) braucht kein NAT. Nur eth0-egress
        # wird masqueraded für internet-gateway.
        nft_rule :masquerade, oifname: "eth0"
      end
    end
  end

  # ══════════════════════════════════════════════════════════════════
  # Container-lokale nft: conn_limit + jhash-DNAT-LB
  # ══════════════════════════════════════════════════════════════════
  pod "web", strategy: :one_for_one do
    container "edge",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      zone: "fw",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 256_000_000, pids: 128} do

      # Container-eigene nft-Tabelle (lebt in der Container-netns).
      # Identische Syntax wie host nft_table, aber scoped auf den
      # Container.
      nft do

        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp

          # ── conn_limit per_ip — SPEC-EK-028 phase 1 ──
          # CHAIN-scoped Sugar. Expandiert zu einer
          # `ct count over N saddr drop`-Regel GENAU hier, exact
          # where the operator wrote it. KEINE auto-synthesis mehr
          # (alter container-level-Pfad wurde wegen Glasbox-
          # Verletzung entfernt).
          conn_limit per_ip: 100

          # Port 8080 frei für eingehende HTTP-Verbindungen, alles
          # andere default-drop.
          nft_rule :accept, tcp_dport: 8080
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp

          # DNS zur Zone-GW.
          nft_rule :accept, ip_daddr: {10, 30, 0, 1}, udp_dport: 53
        end
      end
    end
  end
end
