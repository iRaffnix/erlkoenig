#!/usr/bin/env elixir
#
# Sichere Dokumentensignierung
#
# Drei Container, komplett voneinander isoliert.
# Jeder Container läuft in eigenen Linux-Namespaces (PID, NET, MNT, UTS, IPC).
# Die einzige Verbindung ist über das Netzwerk — kontrolliert durch die Firewall.
#
# Jeder Port der nicht explizit geöffnet ist, ist eine Falle (Honeypot).
# Ein einziges Paket am falschen Port → IP wird sofort für 24h gesperrt.
# Die Erkennung passiert in Echtzeit über Kernel-Conntrack-Events.
#
# Deployment:
#   erlkoenig deploy stack.exs
#
# Testen:
#   curl http://10.0.0.10:8080/sign -d '{"document":"Vertrag","signer":"Name"}'
#   curl http://10.0.0.10:8080/archive

defmodule SecureDocSign do
  use Erlkoenig.DSL

  # ════════════════════════════════════════════════════════════
  # Web-Gateway — öffentlich erreichbar, hat KEINEN Schlüssel
  # ════════════════════════════════════════════════════════════
  #
  # Nimmt HTTP-Anfragen entgegen und leitet sie an den Signer
  # weiter. Kann den Signaturschlüssel nicht sehen — der ist
  # in einem anderen Container, einem anderen Namespace.

  container :web do
    # Das statische Go-Binary (5.8 MB, keine Abhängigkeiten)
    binary "/opt/erlkoenig/rt/demo/doc-sign-web"

    # Nur signierte Binaries dürfen starten (Ed25519 + X.509-Kette)
    signature :required

    # Eigene IP-Adresse im Container-Netzwerk
    ip {10, 0, 0, 10}

    # Startargumente für das Binary:
    #   "8080"                      → Port auf dem das Binary lauscht
    #   "http://10.0.0.20:8081"    → Adresse des Signers (nächster Container)
    args ["8080", "http://10.0.0.20:8081"]

    # Port-Weiterleitung vom Host ins Container-Netzwerk:
    #   Host-Port 8080 → Container-Port 8080
    #   So ist der Dienst von außen erreichbar: curl http://HOST:8080/sign
    ports [{8080, 8080}]

    # Seccomp: nur ~60 Syscalls erlaubt (Netzwerk-Server-Profil)
    # Alles andere wird vom Kernel blockiert (KILL_PROCESS)
    seccomp :network

    # Capabilities: ALLE entfernt (Drop All)
    # Dieser Container braucht keine Root-Rechte
    caps []

    # Ressourcen-Limits via cgroups v2
    limits memory: "64M", pids: 20

    # Bei Crash automatisch neu starten
    # (durchläuft dabei erneut die Signaturprüfung!)
    restart :always

    # Alle 5 Sekunden prüfen ob der Container noch antwortet
    # Nach 3 Fehlversuchen: Neustart
    health_check port: 8080, interval: 5000, retries: 3

    # Firewall (eigene nftables-Chain, policy: DROP)
    # Jeder Port außer 8080 ist eine Falle (Honeypot).
    firewall do
      counters [:http, :trap]

      accept :established             # Bestehende Verbindungen durchlassen
      accept :loopback                # localhost erlauben
      connlimit_drop 100              # Max 100 gleichzeitige Verbindungen pro IP
      accept_tcp 8080, counter: :http # HTTP — der EINZIGE offene Port
      accept :icmp                    # Ping erlauben
      log_and_drop "TRAP: ", counter: :trap  # Alles andere ist eine Falle
    end

    # Echtzeit-Angriffserkennung:
    # Ein Paket am falschen Port → IP sofort 24h gesperrt.
    # Erkennung via Kernel-Conntrack-Events in Millisekunden.
    guard do
      detect :conn_flood, threshold: 50, window: 10  # 50 Verbindungen in 10s
      detect :port_scan, threshold: 1, window: 60    # 1 falscher Port = Ban
      ban_duration 86400                               # 24 Stunden
    end
  end

  # ════════════════════════════════════════════════════════════
  # Signer — isoliert, HAT den Signaturschlüssel
  # ════════════════════════════════════════════════════════════
  #
  # Hält den Ed25519-Privatschlüssel im Arbeitsspeicher.
  # Kein Internet. Nur vom Web-Gateway erreichbar.
  # Selbst wenn jemand den Web-Container hackt, kommt er
  # nicht an den Schlüssel — anderer Namespace, andere IP,
  # Firewall erlaubt nur Verbindungen von 10.0.0.10.

  container :signer do
    binary "/opt/erlkoenig/rt/demo/doc-sign-signer"
    signature :required
    ip {10, 0, 0, 20}

    # Startargumente:
    #   "8081"                      → Port auf dem der Signer lauscht
    #   "http://10.0.0.30:8082"    → Adresse des Archivs (nächster Container)
    args ["8081", "http://10.0.0.30:8082"]

    seccomp :network
    caps []
    limits memory: "32M", pids: 10
    restart :on_failure
    health_check port: 8081, interval: 5000, retries: 3

    # Firewall: NUR der Web-Gateway darf auf Port 8081 zugreifen.
    # Alles andere — jeder Port, jede andere IP — ist eine Falle.
    firewall do
      counters [:sign_req, :trap]

      accept :established
      accept_from {10, 0, 0, 10}                     # NUR von der Web-Gateway IP
      accept_tcp 8081, counter: :sign_req             # EINZIGER offener Port
      log_and_drop "TRAP: ", counter: :trap           # Alles andere → Falle
    end

    # Ein einziges Paket am falschen Port → 24h Ban
    guard do
      detect :port_scan, threshold: 1, window: 60
      ban_duration 86400
    end
  end

  # ════════════════════════════════════════════════════════════
  # Archiv — append-only, KEIN ausgehender Netzwerkverkehr
  # ════════════════════════════════════════════════════════════
  #
  # Speichert jedes signierte Dokument mit Hash und Zeitstempel.
  # Nur vom Signer erreichbar. Kann selbst niemanden kontaktieren.
  # Dateisystem ist schreibgeschützt — nur /tmp (RAM) ist beschreibbar.

  container :archive do
    binary "/opt/erlkoenig/rt/demo/doc-sign-archive"
    signature :required
    ip {10, 0, 0, 30}

    # Startargument: nur der Port
    args ["8082"]

    seccomp :network
    caps []
    limits memory: "32M", pids: 10
    restart :always
    health_check port: 8082, interval: 5000, retries: 3

    # Firewall: NUR der Signer darf auf Port 8082 zugreifen.
    # Das Archiv ist die letzte Festung — nur eine IP, ein Port.
    firewall do
      counters [:log_req, :trap]

      accept :established
      accept_from {10, 0, 0, 20}                     # NUR von der Signer IP
      accept_tcp 8082, counter: :log_req              # EINZIGER offener Port
      log_and_drop "TRAP: ", counter: :trap           # Alles andere → Falle
    end

    # Ein einziges Paket am falschen Port → 24h Ban
    guard do
      detect :port_scan, threshold: 1, window: 60
      ban_duration 86400
    end
  end
end
