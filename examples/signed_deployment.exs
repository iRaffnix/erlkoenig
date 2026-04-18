defmodule SignedDeployment do
  use Erlkoenig.Stack

  # ── Signed Binary Deployment ─────────────────────────────
  #
  # Zeigt den vollständigen PKI-Flow:
  #
  #   1. Binaries signieren (Build-Pipeline):
  #
  #      erlkoenig pki create-root-ca --cn "Acme Root CA" \
  #        --out ca/root.pem --key-out ca/root.key
  #
  #      erlkoenig pki create-sub-ca --cn "Acme Pipeline CA" \
  #        --ca ca/root.pem --ca-key ca/root.key \
  #        --out ca/sub-ca.pem --key-out ca/sub-ca.key
  #
  #      erlkoenig pki create-signer --cn "ci-deploy" \
  #        --ca ca/sub-ca.pem --ca-key ca/sub-ca.key \
  #        --out ca/signing.pem --key-out ca/signing.key
  #
  #      erlkoenig sign /opt/api/server \
  #        --cert ca/signing.pem --key ca/signing.key
  #
  #   2. sys.config auf dem Host:
  #
  #      {signature, #{
  #          mode => on,
  #          trust_roots => ["/etc/erlkoenig/ca/root.pem"],
  #          min_chain_depth => 2
  #      }}
  #
  #   3. Deploy: erlkoenig_config:load("/path/to/signed_deployment.term")
  #      → Container startet NUR wenn server.sig valide ist
  #      → Ungültiger/fehlender .sig → Container bleibt in failed State
  #
  # Testen:
  #
  #   # Valide Signatur → Container startet
  #   erlkoenig ps
  #   → api-0-server  running  pid=12345
  #
  #   # Signatur entfernen → Container rejected
  #   rm /opt/api/server.sig
  #   → container api-0-server failed: {signature_rejected, sig_not_found}
  #
  #   # Binary manipulieren → Tamper detected
  #   echo "x" >> /opt/api/server
  #   → container api-0-server failed: {signature_rejected, {sha256_mismatch, ...}}

  host do
    interface "eth0", zone: :wan
    ipvlan "secure", parent: {:device, "eth0"}, subnet: {10, 0, 0, 0, 24}

    nft_table :inet, "host" do
      nft_set "ban", :ipv4_addr
      nft_counter "input_drop"
      nft_counter "input_ban"

      # Raw: drop gebannte IPs vor conntrack (priority -300)
      base_chain "prerouting", hook: :prerouting, type: :filter,
        priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "input_ban"
      end

      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        # ── Standard-Härtung ──────────────────────────────
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22
        nft_rule :accept, tcp_dport: 9100

        # ── Runtime-Services ──────────────────────────────
        # erlkoenig DNS-Resolver pro Zone auf der Gateway-IP.
        # Ohne diese Regel timeoutet jedes getaddrinfo() im
        # Container. Glasbox: explizit, kein Magic-Inject
        # (Kapitel 6 Service-Catalogue).
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 24}, udp_dport: 53

        nft_rule :drop, counter: "input_drop", log_prefix: "HOST: "
      end
    end

    nft_table :inet, "erlkoenig" do
      nft_counter "forward_drop"

      # ── 1. Forward: priority 0 ──────────────────────
      # IPVLAN slaves sind nicht als iifname sichtbar — dispatch per IP.
      base_chain "forward", hook: :forward, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]

        # Ingress ins secure-Segment auf TCP 8443 (statt DNAT — Container
        # sind L3-erreichbar direkt).
        nft_rule :accept,
          iifname: "eth0",
          ip_daddr: {10, 0, 0, 0, 24},
          tcp_dport: 8443

        nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
      end

      # ── 2. Masquerade: priority +100 ────────────────
      base_chain "postrouting", hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do
        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "eth0"
      end
    end
  end

  pod "api", strategy: :one_for_one do
    container "server",
      binary: "/opt/api/server",
      args: ["--port", "8443", "--tls"],
      limits: %{memory: 536_870_912, pids: 100},
      seccomp: :default,
      zone: "secure",
      replicas: 2,
      restart: :transient do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      publish interval: 10_000 do
        metric :pressure
        metric :oom_events
      end

      # stderr mit 90 Tagen Retention — für Forensik nach
      # Sicherheitsvorfällen. Wann genau hat der Container
      # eine verdächtige Meldung geschrieben?
      stream retention: {90, :days} do
        channel :stderr
      end
    end
  end
end
