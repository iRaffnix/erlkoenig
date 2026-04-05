defmodule ParanoidPayment do
  @moduledoc """
  PCI-DSS-compliant payment stack with signature enforcement.

  Every binary is cryptographically signed. erlkoenig verifies the
  full certificate chain (Root CA → Sub-CA → Signing Cert) before
  starting any container. Unsigned or tampered binaries are rejected.

  Setup:

      # 1. Create PKI (once)
      erlkoenig pki create-root-ca --cn "Corp Root CA" \\
        --out root.pem --key-out root.key --validity 10y
      erlkoenig pki create-sub-ca --cn "Payment Team" \\
        --ca root.pem --ca-key root.key \\
        --out team.pem --key-out team.key
      erlkoenig pki create-signing-cert --cn "ci-pipeline" \\
        --ca team.pem --ca-key team.key \\
        --out sign.pem --key-out sign.key

      # 2. Sign binaries (in CI/CD)
      cat sign.pem team.pem > chain.pem
      erlkoenig sign /opt/erlkoenig/rt/proxy --cert chain.pem --key sign.key
      erlkoenig sign /opt/erlkoenig/rt/api   --cert chain.pem --key sign.key

      # 3. Configure trust root
      cp root.pem /etc/erlkoenig/ca/root.pem
      # sys.config: {signature, \#{mode => on, trust_roots => ["/etc/erlkoenig/ca/root.pem"]}}

      # 4. Deploy
      erlkoenig compile paranoid_payment.exs

  Security properties:
    - No shell, no package manager, no shared libraries
    - Per-container firewall (nftables)
    - Ed25519 signature verified at exec() time
    - Certificate chain must reach trusted Root CA
    - Every action in audit log
    - Tampered binary → rejected (SHA256 mismatch)
    - Unsigned binary → rejected (sig_not_found)
    - Wrong CA → rejected (untrusted_root)
  """
  use Erlkoenig.Stack

  # TODO: migrate signature enforcement when supported

  # === DMZ: reverse proxy (public-facing) ===

  pod "proxy" do
    container "proxy",
      binary: "/opt/erlkoenig/rt/proxy",
      ports: [{443, 8443}],
      limits: %{memory: "128M", pids: 50},
      seccomp: :strict,
      restart: :always,
      health_check: [port: 8443, interval: 5000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 443
        rule :drop, log: "DROP: "
      end
    end
  end

  # === App: payment API (internal) ===

  pod "api" do
    container "api",
      binary: "/opt/erlkoenig/rt/api",
      limits: %{memory: "256M", pids: 100},
      seccomp: :network,
      restart: {:on_failure, 5},
      health_check: [port: 8080, interval: 10_000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 8080
        rule :drop, log: "DROP: "
      end
    end
  end

  # === Data: database (isolated, no outbound) ===

  pod "db" do
    container "db",
      binary: "/opt/erlkoenig/rt/rqlited",
      args: ["-node-id", "1", "-http-addr", "10.0.3.10:4001",
             "-raft-addr", "10.0.3.10:4002", "/tmp/data"],
      limits: %{memory: "512M", pids: 50},
      seccomp: :standard,
      restart: :always,
      health_check: [port: 4001, interval: 5000, retries: 5] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 4001
        rule :accept, tcp: 4002
        rule :drop, log: "DROP: "
      end
    end
  end

  zone "dmz", subnet: {10, 0, 1, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "proxy", replicas: 1
  end

  zone "app", subnet: {10, 0, 2, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "api", replicas: 1
  end

  zone "data", subnet: {10, 0, 3, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "db", replicas: 1
  end
end
