defmodule Tutorial.Overview do
  @moduledoc """
  ### Datei 1/6 — Minimal-Overview

  Das absolute Minimum: eine IPVLAN-Zone, ein Pod mit einem Container,
  eine Host-Firewall. Alles was ein running erlkoenig-Stack braucht —
  nichts mehr.

  Nächste Dateien (02…06) bauen einzelne Aspekte tiefer aus.
  """
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════════════════
  # host — Netzwerk-Topologie und Host-weite Firewall
  # ══════════════════════════════════════════════════════════════════
  #
  # Alles was die Host-Maschine tut, bevor ein einziger Container
  # läuft. Zwei Dinge: die Zone (Netzwerk-Segment) und die
  # Firewall-Tabelle.
  host do
    # ── Was:   IPVLAN-Zone "demo"
    # ── Wann:  einmal pro logischer Netzwerk-Domäne
    # ── Wieso: Jede Zone ist ein eigenes netns-übergreifendes
    #           L3-Segment. Container bekommen IPs aus `subnet`;
    #           `.1` wird der Gateway auf dem Host-Side-Slave.
    #           `{:dummy, "ek_demo"}` = parent ist ein virtueller
    #           Interface den erlkoenig erzeugt (kein physisches
    #           Gerät nötig).
    ipvlan "demo", parent: {:dummy, "ek_demo"},
                   subnet: {10, 10, 0, 0, 24}

    # ── Was:   nft-Table "erlkoenig_host"
    # ── Wann:  jede erlkoenig-Node hat genau eine Host-Tabelle
    # ── Wieso: Hier lebt die Firewall die den Host selbst schützt.
    #           Container haben ihre EIGENEN Tabellen (in ihrer
    #           eigenen netns) — siehe Datei 3.
    nft_host do

      # Named counter — wird alle 2s automatisch gepollt und als
      # AMQP-Event emittiert wenn rate > 0. Einer pro Drop-Chain
      # ist üblich, mehr sind OK.
      nft_counter "input_drop"

      # Base-chain mit hook=input = Pakete AN den Host. policy=drop
      # macht das zur default-deny Firewall. Explizite Accepts
      # folgen.
      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        # Conntrack — Antworten auf ausgehende Verbindungen.
        # Ohne das sterben AMQP-Reply, DNS-Reply, apt-Reply, ...
        nft_rule :accept, ct_state: [:established, :related]

        # Loopback — BEAM distribution, epmd, lokale Services.
        nft_rule :accept, iifname: "lo"

        # ICMP — Ping, MTU-Discovery, Path-Probes.
        nft_rule :accept, ip_protocol: :icmp

        # SSH — Admin.
        nft_rule :accept, tcp_dport: 22

        # Default-Drop mit Counter für Telemetrie.
        nft_rule :drop, counter: "input_drop"
      end
    end
  end

  # ══════════════════════════════════════════════════════════════════
  # pod — eine Gruppe Container mit gemeinsamer Supervision
  # ══════════════════════════════════════════════════════════════════
  #
  # Strategy:
  #   :one_for_one  — einer crasht, nur der restartet
  #   :one_for_all  — einer crasht, alle restarten
  #   :rest_for_one — einer crasht, alle NACH ihm restarten
  #
  # Für eigenständige Container ist :one_for_one der Standard;
  # für zusammengehörige Multi-Container-Pods (z.B. sidecar die
  # zusammen hoch müssen) sind die anderen zwei sinnvoll.
  pod "hello", strategy: :one_for_one do

    # ── Was:   ein Container namens "web" im Pod "hello"
    # ── Wann:  wann immer du ein Binary in eine eigene netns+
    #          cgroup+mount-namespace stecken willst
    # ── Wieso: Der finale Name wird "hello-0-web" (Pod + Replica-
    #          Index + Container-Name). Replicas: 1 = eine Instanz.
    container "web",
      # absolute Pfad zum statischen Binary. Wird vom Test-Harness
      # oder in Production aus einem verifizierten Artefakt kommen.
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      # CLI-Argumente an das Binary
      args: ["7777"],
      # welche Zone (= welche IPVLAN aus `host do ipvlan ... end`)
      zone: "demo",
      # Anzahl Instanzen — horizontale Skalierung
      replicas: 1,
      # OTP-restart policy:
      #   :permanent — immer restart
      #   :transient — restart nur bei crash (nicht bei normal exit)
      #   :temporary — nie restart
      restart: :permanent,
      # Ressourcen-Limits. Kernel enforcet via cgroup v2.
      limits: %{memory: 128_000_000, pids: 64} do

      # ── Optionaler Block mit container-spezifischen Settings.
      #    Hier könnten publish/stream/nft/volume/requires stehen
      #    — siehe weitere Tutorial-Dateien.
      #
      #    Für das minimal-Beispiel bewusst leer: ein Container
      #    ohne anything extra.
    end
  end
end
