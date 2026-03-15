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

Drei Container. Komplett voneinander isoliert. Jeder in eigenen
Linux-Namespaces (PID, NET, MNT, UTS, IPC). Der Signaturschlüssel
existiert ausschließlich im mittleren Container, der keinen
Internetzugang hat.

```
                Internet
                   │
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

## Honeypot-Firewall

Jeder Port der nicht explizit geöffnet ist, ist eine Falle.
Ein einziges Paket am falschen Port — und die IP wird sofort
für 24 Stunden gesperrt.

```elixir
firewall do
  counters [:sign_req, :trap]

  accept :established
  accept_from {10, 0, 0, 10}             # NUR vom Web-Gateway
  accept_tcp 8081, counter: :sign_req    # EINZIGER offener Port
  log_and_drop "TRAP: ", counter: :trap  # Alles andere ist eine Falle
end

guard do
  detect :port_scan, threshold: 1, window: 60  # 1 Paket = Ban
  ban_duration 86400                             # 24 Stunden
end
```

Was passiert wenn jemand Port 22 auf dem Signer versucht:

```
1. accept_from 10.0.0.10  → nein (andere IP)
2. accept_tcp 8081         → nein (Port 22)
3. log_and_drop "TRAP: "   → geloggt, DROP
4. Guard: port_scan         → threshold 1 erreicht
5. IP → blocklist           → 24h gesperrt
6. Alle weiteren Pakete     → DROP (Kernel, Millisekunden)
```

Die Erkennung passiert in Echtzeit. Kein Polling, kein Cronjob.
Der Linux-Kernel meldet den Verbindungsversuch über Conntrack-Netlink,
der Guard reagiert sofort — in Millisekunden, nicht in Sekunden.

## Was ein Angreifer NICHT tun kann

| Angriff | Warum er scheitert |
|---------|-------------------|
| Web hacken → Schlüssel stehlen | Schlüssel ist in einem anderen Container, einem anderen Namespace |
| Schlüssel über Internet exfiltrieren | Signer hat kein Internet (Firewall blockiert) |
| Port-Scan auf Signer | 1 Paket am falschen Port = 24h Ban (Honeypot) |
| Signierte Dokumente verändern | Archiv ist append-only, Dateisystem schreibgeschützt |
| Hintertür-Binary deployen | Ed25519-Signaturprüfung schlägt fehl → startet nicht |
| Shell im Container öffnen | Keine Shell — statisches Binary, sonst nichts |
| Tools installieren (curl, nc) | Kein Paketmanager, keine Bibliotheken |

## Voraussetzungen

- erlkoenig installiert (`sudo sh install.sh --version v0.1.0`)
- Go >= 1.21 (zum Bauen der Demo-Binaries)

## Schritt 1: Binaries bauen

```bash
cd stories/secure-doc-sign
sh build.sh
```

Alle drei sind statisch gelinkt. Keine libc, keine Bibliotheken, keine Shell.

## Schritt 2: Signaturidentität erstellen

```bash
erlkoenig pki create-root-ca \
  --cn "Document Services Root CA" \
  --out root-ca.pem --key-out root-ca.key --validity 10y

erlkoenig pki create-signing-cert \
  --cn "doc-sign-pipeline" \
  --ca root-ca.pem --ca-key root-ca.key \
  --out signing.pem --key-out signing.key
```

## Schritt 3: Binaries signieren

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

## Schritt 4: Installieren

```bash
sudo cp web     /opt/erlkoenig/rt/demo/doc-sign-web
sudo cp signer  /opt/erlkoenig/rt/demo/doc-sign-signer
sudo cp archive /opt/erlkoenig/rt/demo/doc-sign-archive
sudo cp web.sig     /opt/erlkoenig/rt/demo/doc-sign-web.sig
sudo cp signer.sig  /opt/erlkoenig/rt/demo/doc-sign-signer.sig
sudo cp archive.sig /opt/erlkoenig/rt/demo/doc-sign-archive.sig
sudo chmod 755 /opt/erlkoenig/rt/demo/doc-sign-*
sudo cp root-ca.pem /etc/erlkoenig/ca/root-ca.pem
```

## Schritt 5: Deployen

Ein Befehl. Drei Container.

```bash
erlkoenig deploy stack.exs
```

Ausgabe:

```
Compiling stack.exs ...
  3 container(s) found

Deploying archive (10.0.0.30) ...
  Started: archive
Deploying signer (10.0.0.20) ...
  Started: signer
Deploying web (10.0.0.10) ...
  Started: web

3/3 containers running.
```

## Schritt 6: Dokument signieren

```bash
curl http://10.0.0.10:8080/sign \
  -d '{"document":"Kaufvertrag Grundstück Berlin-Mitte Nr. 2026-001",
       "signer":"Dr. Anna Schmidt"}'
```

Antwort:

```json
{
  "id": "DOC-2026-0001",
  "hash": "sha256:d9d61c0e...",
  "signature": "ed25519:lRSNnsIF...",
  "signer": "Dr. Anna Schmidt",
  "timestamp": "2026-03-15T18:00:00Z",
  "seq": 1,
  "archived": true
}
```

## Schritt 7: Archiv und Audit

```bash
curl http://10.0.0.10:8080/archive

erlkoenig audit
```

## Schritt 8: Angriff simulieren

```bash
sudo cp web /opt/erlkoenig/rt/demo/doc-sign-fake
sudo chmod 755 /opt/erlkoenig/rt/demo/doc-sign-fake
erlkoenig spawn /opt/erlkoenig/rt/demo/doc-sign-fake --ip 10.0.0.40 --args "9090,x"
erlkoenig audit
# → binary_reject: sig_not_found
```

## Verzeichnisstruktur

```
stories/secure-doc-sign/
├── README.md              Diese Datei
├── SICHERHEITSKONZEPT.md  Technisches Expertendokument
├── build.sh               Baut die drei Go-Binaries
├── stack.exs              erlkoenig deploy-Definition (kommentiert)
├── go.mod                 Go-Moduldatei
└── src/
    ├── web/main.go        HTTP-Gateway (~70 Zeilen)
    ├── signer/main.go     Ed25519-Dokumentensignierer (~130 Zeilen)
    └── archive/main.go    Unveränderliches Protokoll (~80 Zeilen)
```

## Sicherheitsschichten pro Container

| Schicht | web | signer | archive |
|---------|-----|--------|---------|
| Binary-Signatur | Ed25519 + X.509 | Ed25519 + X.509 | Ed25519 + X.509 |
| Seccomp | 60 Syscalls | 60 Syscalls | 60 Syscalls |
| Capabilities | alle entfernt | alle entfernt | alle entfernt |
| Firewall | TCP 8080, connlimit | TCP 8081, nur von web | TCP 8082, nur von signer |
| Honeypot | jeder andere Port = Ban | jeder andere Port = Ban | jeder andere Port = Ban |
| Guard | flood + scan | scan (threshold 1) | scan (threshold 1) |
| Namespaces | PID, NET, MNT, UTS, IPC | PID, NET, MNT, UTS, IPC | PID, NET, MNT, UTS, IPC |
| Dateisystem | schreibgeschützt | schreibgeschützt | schreibgeschützt |
| /proc | maskiert | maskiert | maskiert |
