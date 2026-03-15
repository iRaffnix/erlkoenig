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
  use Erlkoenig.DSL

  # === DMZ: reverse proxy (public-facing) ===

  container :proxy do
    binary "/opt/erlkoenig/rt/proxy"
    signature :required
    ip {10, 0, 1, 10}
    ports [{443, 8443}]
    zone :dmz
    limits cpu: 2, memory: "128M", pids: 50
    seccomp :strict
    caps [:net_bind_service]           # only cap needed: bind port < 1024
    restart :always
    health_check port: 8443, interval: 5000, retries: 3
    firewall do
      accept :established
      accept :icmp
      accept_tcp 443
      log_and_drop "DROP: "
    end
  end

  # === App: payment API (internal) ===

  container :api do
    binary "/opt/erlkoenig/rt/api"
    signature :required
    ip {10, 0, 2, 10}
    zone :app
    limits cpu: 4, memory: "256M", pids: 100
    seccomp :network                   # needs socket syscalls
    caps []                            # no caps needed (port > 1024)
    restart {:on_failure, 5}
    health_check port: 8080, interval: 10_000, retries: 3

    firewall do
      accept :established
      accept :icmp
      accept_tcp 8080
      log_and_drop "DROP: "
    end
  end

  # === Data: database (isolated, no outbound) ===

  container :db do
    binary "/opt/erlkoenig/rt/rqlited"
    signature :required
    ip {10, 0, 3, 10}
    zone :data
    args ["-node-id", "1", "-http-addr", "10.0.3.10:4001",
          "-raft-addr", "10.0.3.10:4002", "/tmp/data"]
    limits cpu: 2, memory: "512M", pids: 50
    seccomp :standard
    restart :always
    health_check port: 4001, interval: 5000, retries: 5

    firewall do
      accept :established
      accept :icmp
      accept_tcp 4001
      accept_tcp 4002
      log_and_drop "DROP: "
    end
  end
end
