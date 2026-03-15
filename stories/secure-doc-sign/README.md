# Sichere Dokumentensignierung

Ein Dienst aus drei Containern, der Dokumente digital signiert.
Der Signaturschlüssel verlässt niemals seinen isolierten Container.

## Das Problem

In Deutschland und der EU müssen Verträge, Rechnungen und Bescheide
zunehmend digital signiert werden (eIDAS-Verordnung). Die digitale
Unterschrift muss drei Dinge garantieren:

- **Integrität** — das Dokument wurde nach der Signierung nicht verändert
- **Authentizität** — die Signatur stammt von einer identifizierbaren Person
- **Nicht-Abstreitbarkeit** — der Unterzeichner kann nicht bestreiten, signiert zu haben

Der Signaturschlüssel ist das wertvollste Asset im ganzen System.
Wer den Schlüssel besitzt, kann im Namen des Unternehmens Verträge
unterschreiben.

In der Praxis liegt dieser Schlüssel oft auf einem Server, der gleichzeitig
E-Mails empfängt, im Internet erreichbar ist und hunderte Abhängigkeiten
installiert hat. Eine einzige Schwachstelle — und der Schlüssel ist weg.

## Die Lösung

Drei Container. Drei Netzwerkzonen. Der Signaturschlüssel existiert
ausschließlich im mittleren Container, der keinen Internetzugang hat.

```
                Internet
                   │
    Zone: dmz      │      Zone: sign         Zone: store
    ┌──────────┐   │   ┌──────────────┐   ┌──────────────┐
    │   web    │◄──┘   │   signer     │   │   archive    │
    │          │──────►│              │──►│              │
    │ Port 8080│       │ Port 8081    │   │ Port 8082    │
    │ KEIN     │       │ HAT DEN     │   │ Nur          │
    │ SCHLÜSSEL│       │ SCHLÜSSEL    │   │ Anhängen     │
    │ Öffentl. │       │ Isoliert     │   │ Kein Netz    │
    └──────────┘       └──────────────┘   └──────────────┘
```

**web** — Nimmt Anfragen aus dem Internet entgegen. Leitet sie an den
Signer weiter. Hat keinen Zugriff auf den Signaturschlüssel.

**signer** — Hält den Ed25519-Privatschlüssel. Signiert Dokument-Hashes.
Ist nur vom Web-Gateway aus erreichbar (Firewall). Kein Internetzugang.

**archive** — Unveränderliches Protokoll. Speichert jedes signierte
Dokument mit Hash und Zeitstempel. Nur vom Signer aus erreichbar.

## Was ein Angreifer NICHT tun kann

| Angriff | Warum er scheitert |
|---------|-------------------|
| Web hacken → Schlüssel stehlen | Schlüssel ist in einem anderen Container, einer anderen Zone |
| Schlüssel über Internet exfiltrieren | Signer hat kein Internet (Firewall blockiert ausgehenden Verkehr) |
| Signierte Dokumente verändern | Archiv ist append-only, Dateisystem ist schreibgeschützt |
| Hintertür-Binary deployen | Ed25519-Signaturprüfung schlägt fehl → Container startet nicht |
| Shell im Container öffnen | Keine Shell vorhanden — statisches Binary, sonst nichts |
| Tools installieren (curl, nc) | Kein Paketmanager, keine Bibliotheken |

## Voraussetzungen

- erlkoenig installiert (`sudo sh install.sh --version v0.1.0`)
- Go-Compiler (zum Bauen der Demo-Binaries)

## Schritt 1: Binaries bauen

```bash
cd stories/secure-doc-sign

CGO_ENABLED=0 go build -ldflags="-s -w" -o web     ./src/web/
CGO_ENABLED=0 go build -ldflags="-s -w" -o signer  ./src/signer/
CGO_ENABLED=0 go build -ldflags="-s -w" -o archive ./src/archive/

ls -lh web signer archive
# web      5,8 MB  (statisch, keine Abhängigkeiten)
# signer   6,1 MB  (statisch, keine Abhängigkeiten)
# archive  5,3 MB  (statisch, keine Abhängigkeiten)
```

Alle drei sind statisch gelinkt. Keine libc, keine Bibliotheken, keine Shell.

## Schritt 2: Signaturidentität erstellen

```bash
# Root-CA erstellen (in Produktion: Ihre Unternehmens-CA)
erlkoenig pki create-root-ca \
  --cn "Document Services Root CA" \
  --out root-ca.pem \
  --key-out root-ca.key \
  --validity 10y

# Signaturzertifikat für die CI/CD-Pipeline erstellen
erlkoenig pki create-signing-cert \
  --cn "doc-sign-pipeline" \
  --ca root-ca.pem \
  --ca-key root-ca.key \
  --out signing.pem \
  --key-out signing.key
```

## Schritt 3: Binaries signieren

Jedes Binary bekommt eine kryptographische Signatur. erlkoenig weigert
sich, ein Binary ohne gültige Signatur zu starten.

```bash
erlkoenig sign web     --cert signing.pem --key signing.key
erlkoenig sign signer  --cert signing.pem --key signing.key
erlkoenig sign archive --cert signing.pem --key signing.key
```

Überprüfen:

```bash
erlkoenig verify web     --trust-root root-ca.pem
erlkoenig verify signer  --trust-root root-ca.pem
erlkoenig verify archive --trust-root root-ca.pem
```

Jedes sollte `Result: OK` zeigen.

## Schritt 4: Deployen

Binaries und Signaturen ins Laufzeitverzeichnis kopieren:

```bash
sudo cp web     /opt/erlkoenig/rt/demo/doc-sign-web
sudo cp signer  /opt/erlkoenig/rt/demo/doc-sign-signer
sudo cp archive /opt/erlkoenig/rt/demo/doc-sign-archive
sudo cp web.sig     /opt/erlkoenig/rt/demo/doc-sign-web.sig
sudo cp signer.sig  /opt/erlkoenig/rt/demo/doc-sign-signer.sig
sudo cp archive.sig /opt/erlkoenig/rt/demo/doc-sign-archive.sig
sudo chmod 755 /opt/erlkoenig/rt/demo/doc-sign-*
```

Root-CA als Vertrauensanker installieren:

```bash
sudo cp root-ca.pem /etc/erlkoenig/ca/root-ca.pem
```

Container starten (Reihenfolge beachten — von hinten nach vorne):

```bash
erlkoenig spawn /opt/erlkoenig/rt/demo/doc-sign-archive \
  --ip 10.0.0.30 --args 8082

erlkoenig spawn /opt/erlkoenig/rt/demo/doc-sign-signer \
  --ip 10.0.0.20 --args "8081,http://10.0.0.30:8082"

erlkoenig spawn /opt/erlkoenig/rt/demo/doc-sign-web \
  --ip 10.0.0.10 --args "8080,http://10.0.0.20:8081"
```

Prüfen ob alle drei laufen:

```bash
erlkoenig ps
```

## Schritt 5: Dokument signieren

```bash
curl http://localhost:8080/sign \
  -d '{"document":"Kaufvertrag Grundstück Berlin-Mitte Nr. 2026-001",
       "signer":"Dr. Anna Schmidt"}'
```

Antwort:

```json
{
  "id": "DOC-2026-0001",
  "hash": "sha256:857d63b8...",
  "signature": "ed25519:OJU7NCAg...",
  "signer": "Dr. Anna Schmidt",
  "timestamp": "2026-03-15T18:00:00Z",
  "seq": 1,
  "archived": true
}
```

Noch ein Dokument signieren:

```bash
curl http://localhost:8080/sign \
  -d '{"document":"Arbeitsvertrag Max Mustermann","signer":"HR Abteilung"}'
```

## Schritt 6: Archiv einsehen

```bash
curl http://localhost:8080/archive
```

Jedes signierte Dokument ist mit Hash, Signatur und Zeitstempel gespeichert.

## Schritt 7: Audit-Log prüfen

```bash
erlkoenig audit
```

Zeigt jede Aktion: PKI geladen, Binaries verifiziert, Container gestartet.

## Schritt 8: Angriff simulieren

Ein unsigniertes Binary deployen:

```bash
# Signatur entfernen
sudo rm /opt/erlkoenig/rt/demo/doc-sign-web.sig

# Versuch es zu starten
erlkoenig spawn /opt/erlkoenig/rt/demo/doc-sign-web \
  --ip 10.0.0.40 --args "9090,http://10.0.0.20:8081"

# Audit-Log prüfen
erlkoenig audit
# → binary_reject: sig_not_found
```

Der Container startet nicht. Das Audit-Log dokumentiert die Ablehnung.

## Verzeichnisstruktur

```
stories/secure-doc-sign/
├── README.md          Diese Datei
├── src/
│   ├── web/           HTTP-Gateway (Go, ~70 Zeilen)
│   │   └── main.go
│   ├── signer/        Ed25519-Dokumentensignierer (Go, ~130 Zeilen)
│   │   └── main.go
│   └── archive/       Unveränderliches Protokoll (Go, ~80 Zeilen)
│       └── main.go
├── stack.exs          Erlkoenig-DSL-Definition
└── go.mod             Go-Moduldatei
```

## Firewall-Konfiguration

Jeder Container bekommt eine eigene nftables-Chain mit `policy: drop` —
nur explizit erlaubter Verkehr kommt durch. Die `stack.exs` zeigt die
vollständige Konfiguration mit der erlkoenig_nft DSL:

**Web-Gateway** — öffentlich, aber geschützt:
```elixir
chain "inbound", hook: :input, policy: :drop do
  accept :established
  accept :loopback
  connlimit_drop 100                    # max 100 Verbindungen pro IP
  accept_tcp 8080, counter: :http
  accept :icmp
  log_and_drop "WEB-DROP: ", counter: :dropped
end
```

**Signer** — nur vom Web-Gateway erreichbar:
```elixir
chain "inbound", hook: :input, policy: :drop do
  accept :established
  accept_from {10, 0, 0, 10}           # NUR vom Web-Gateway
  accept_tcp 8081, counter: :sign_req
  log_and_drop "SIGN-DROP: ", counter: :dropped
end
```

**Archiv** — nur vom Signer erreichbar:
```elixir
chain "inbound", hook: :input, policy: :drop do
  accept :established
  accept_from {10, 0, 0, 20}           # NUR vom Signer
  accept_tcp 8082, counter: :log_req
  log_and_drop "ARCH-DROP: ", counter: :dropped
end
```

Zusätzlich: automatische Angriffserkennung und Echtzeit-Monitoring:

```elixir
# Angriffe erkennen und blockieren
guard do
  detect :conn_flood, threshold: 50, window: 10   # 50 Verbindungen in 10s → Sperre
  detect :port_scan, threshold: 10, window: 30    # 10 Ports in 30s → Sperre
  ban_duration 3600                                # 1 Stunde
end

# Firewall-Counter beobachten
watch "doc-sign" do
  counter :http, :pps, threshold: 500              # Alarm bei > 500 req/s
  counter :sign_req, :pps, threshold: 100          # Alarm bei > 100 Signaturen/s
  counter :dropped, :pps, threshold: 50            # Alarm bei > 50 drops/s
  interval 2000
  on_alert :log
end
```

## Sicherheitsschichten pro Container

| Schicht | web | signer | archive |
|---------|-----|--------|---------|
| Binary-Signatur | Ed25519 + X.509-Kette | Ed25519 + X.509-Kette | Ed25519 + X.509-Kette |
| Seccomp | network (60 Syscalls) | network (60 Syscalls) | network (60 Syscalls) |
| Capabilities | keine (alle entfernt) | keine (alle entfernt) | keine (alle entfernt) |
| Firewall | TCP 8080, connlimit 100 | TCP 8081, nur von web | TCP 8082, nur von signer |
| IP-Blocklist | ja (nftables set) | — | — |
| Flood-Erkennung | 50 conn/10s → ban | — | — |
| Port-Scan-Erkennung | 10 ports/30s → ban | — | — |
| Counter-Monitoring | http, dropped | sign_req, dropped | log_req, dropped |
| Dateisystem | schreibgeschützt | schreibgeschützt | schreibgeschützt |
| /proc | maskiert | maskiert | maskiert |
| Neustart | automatisch | bei Fehler | automatisch |
| Healthcheck | Port 8080, 5s | Port 8081, 5s | Port 8082, 5s |
