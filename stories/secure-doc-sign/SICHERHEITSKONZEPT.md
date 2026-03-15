# Sicherheitskonzept — Dokumentensignierdienst mit erlkoenig

## Zusammenfassung

Dieses Dokument beschreibt die technischen Sicherheitsmaßnahmen eines
Dokumentensignierdienstes, der auf der erlkoenig Container-Runtime
betrieben wird. Die Architektur setzt auf mehrere unabhängige
Verteidigungsschichten (Defense in Depth), die auch dann schützen,
wenn eine einzelne Schicht kompromittiert wird.

## 1. Architekturprinzip: Schlüsselisolation

Das zentrale Schutzziel ist die Isolation des Signaturschlüssels.
Der Ed25519-Privatschlüssel existiert ausschließlich im Arbeitsspeicher
eines dedizierten Containers (`signer`), der:

- keinen Internetzugang hat (Egress-Firewall)
- nur von einem einzigen anderen Container erreichbar ist (Ingress-Firewall)
- keine Shell, keinen Paketmanager und keine Bibliotheken enthält
- bei jedem Start kryptographisch verifiziert wird

Jeder Container läuft in eigenen Linux-Namespaces (PID, NET, MNT, UTS, IPC).
Die Container können sich gegenseitig nicht sehen — keine gemeinsamen
Prozesse, kein gemeinsames Netzwerk, kein gemeinsames Dateisystem. Die
einzige Verbindung ist über TCP, kontrolliert durch die Firewall.

Selbst bei vollständiger Kompromittierung des öffentlich erreichbaren
Web-Gateways hat ein Angreifer keinen Zugriff auf den Signaturschlüssel.

## 2. Supply-Chain-Sicherheit

### 2.1 Binary-Signierung

Jedes der drei Binaries (web, signer, archive) wird vor dem Deployment
mit Ed25519 signiert. Die Signatur umfasst:

- SHA-256-Hash des Binaries
- Git-Commit-Hash des Quellcodes (Rückverfolgbarkeit)
- Zeitstempel der Signierung
- Identität des Signierers (Common Name aus dem X.509-Zertifikat)

### 2.2 Zertifikatskette

Die Signatur wird nicht mit einem einzelnen Schlüssel erstellt, sondern
mit einem Zertifikat, das Teil einer Kette ist:

```
Root CA (Vertrauensanker)
  └── Signing Certificate (CI/CD-Pipeline)
        └── Signiert: web, signer, archive
```

Die erlkoenig-Runtime prüft bei **jedem Start** eines Containers —
auch bei automatischen Neustarts nach einem Absturz — die vollständige
Kette bis zum konfigurierten Vertrauensanker.

### 2.3 Prüfung bei exec(), nicht bei Deployment

Die meisten Container-Runtimes (Docker, containerd, Podman) prüfen
Signaturen beim Herunterladen des Images aus einer Registry oder über
einen Admission-Controller beim Deployment. erlkoenig prüft die Signatur
im Moment der Ausführung (`exec()`). Das bedeutet:

- Ein Binary, das nach dem Download verändert wurde, wird erkannt
- Ein automatischer Neustart nach einem Crash durchläuft die gleiche Prüfung
- Kein Registry-Server nötig — das Binary und seine `.sig`-Datei genügen

### 2.4 Statische Binaries

Alle Binaries sind statisch gelinkt (Go, `CGO_ENABLED=0`). Im Container
existiert ausschließlich das Binary — keine Shell, kein Interpreter,
keine dynamischen Bibliotheken, kein Paketmanager.

Die Angriffsfläche beschränkt sich auf den Code des Binaries selbst.
Es gibt keine Möglichkeit, zur Laufzeit weitere Software nachzuladen.

## 3. Laufzeit-Isolation

### 3.1 Linux-Namespaces

Jeder Container läuft in fünf eigenen Namespaces:

| Namespace | Wirkung |
|-----------|---------|
| PID | Container sieht nur eigene Prozesse |
| NET | Eigenes Netzwerk-Interface, eigene IP |
| MNT | Eigenes Dateisystem (schreibgeschützt) |
| UTS | Eigener Hostname |
| IPC | Eigene Interprozesskommunikation |

Im Gegensatz zu Kubernetes, wo Container in einem Pod den Netzwerk-
und IPC-Namespace teilen, sind bei erlkoenig alle Namespaces vollständig
getrennt. Ein kompromittierter Container kann den Traffic des Nachbarn
nicht mitlesen.

### 3.2 Schreibgeschütztes Dateisystem

Nach `pivot_root` ist das Root-Dateisystem des Containers schreibgeschützt.
Nur `/tmp` ist beschreibbar (tmpfs im RAM). Ein Angreifer kann keine
Systemdateien, Konfigurationen oder Binaries verändern.

### 3.3 /proc-Maskierung

Das `/proc`-Dateisystem im Container ist maskiert (OCI-konform).
Sensible Informationen über den Host (andere Prozesse, Kernel-Parameter,
Netzwerkkonfiguration) sind nicht einsehbar.

## 4. Kernel-Enforcement

### 4.1 Seccomp (Secure Computing)

Jeder Container hat ein Seccomp-Profil, das festlegt, welche
Systemaufrufe (Syscalls) an den Linux-Kernel erlaubt sind.

Für die Binaries in diesem Dienst wird das Profil `network` verwendet,
das etwa 60 Syscalls erlaubt — ausschließlich die, die ein
Netzwerk-Serverprogramm benötigt:

- Netzwerk: `socket`, `bind`, `listen`, `accept`, `sendto`, `recvfrom`
- Datei: `openat`, `read`, `write`, `close`
- Speicher: `mmap`, `mprotect`, `brk`
- Prozess: `exit`, `futex`, `clock_gettime`

Alle anderen Syscalls (über 300) sind blockiert. Ein Verstoß führt
zum sofortigen Abbruch des Container-Prozesses (`SECCOMP_RET_KILL_PROCESS`).

### 4.2 Capabilities

Linux-Capabilities unterteilen die Root-Rechte in einzelne Berechtigungen.
erlkoenig entfernt standardmäßig **alle 41 Capabilities**.

Keiner der drei Container in diesem Dienst benötigt Capabilities.
Selbst wenn ein Angreifer durch einen Exploit Root-Rechte im Container
erlangt, kann er weder das Netzwerk manipulieren noch Kernel-Module
laden noch das Dateisystem verändern.

### 4.3 Zusammenwirken

Seccomp und Capabilities ergänzen sich:

- Capabilities beschränken, **welche Operationen** ein Prozess mit
  Root-Rechten ausführen darf
- Seccomp beschränken, **welche Kernel-Schnittstellen** ein Prozess
  überhaupt ansprechen darf

## 5. Honeypot-Firewall

### 5.1 Prinzip: Jeder Port ist eine Falle

Jeder Container hat eine eigene nftables-Chain mit `policy: drop`.
Nur der eine Port der geöffnet ist, lässt Traffic durch. Alles
andere ist eine Falle.

```elixir
firewall do
  counters [:sign_req, :trap]

  accept :established
  accept_from {10, 0, 0, 10}             # NUR vom Web-Gateway
  accept_tcp 8081, counter: :sign_req    # EINZIGER offener Port
  log_and_drop "TRAP: ", counter: :trap  # Alles andere → Falle
end
```

### 5.2 Echtzeit-Reaktion

Die Erkennung passiert nicht über Polling oder Cronjobs, sondern
über den Linux-Kernel selbst. Der Ablauf:

```
1. Angreifer sendet Paket an Port 22 des Signers
2. nftables-Chain: kein match → log_and_drop, counter :trap +1
3. Kernel-Conntrack meldet neuen Verbindungsversuch über Netlink
4. erlkoenig_nft Guard empfängt Conntrack-Event in Echtzeit
5. Guard: port_scan threshold 1 erreicht
6. Guard: schreibt IP in nftables-Set "blocklist"
7. Alle weiteren Pakete von dieser IP: DROP (in prerouting, vor der Chain)
```

**Zeitraum: Millisekunden.** Nicht Sekunden, nicht Minuten.

Die meisten Sicherheitssysteme (Fail2ban, Kubernetes NetworkPolicies,
Cloud-WAFs) arbeiten mit Polling-Intervallen von 5-60 Sekunden. In
dieser Zeit kann ein Angreifer tausende Requests senden. Bei erlkoenig
reicht ein einziges Paket für den Ban.

### 5.3 Konfiguration pro Container

| Container | Offener Port | Guard |
|-----------|-------------|-------|
| web | TCP 8080 + connlimit 100 | flood: 50 conn/10s, scan: threshold 1 |
| signer | TCP 8081, nur von 10.0.0.10 | scan: threshold 1 |
| archive | TCP 8082, nur von 10.0.0.20 | scan: threshold 1 |

Der Signer und das Archiv sind besonders streng: nur eine einzige
IP-Adresse darf zugreifen, auf genau einem Port. Alles andere führt
zum sofortigen Ban.

### 5.4 Atomare Firewall-Regeln

Die nftables-Regeln werden atomar in einer einzigen Netlink-Transaktion
angelegt. Es gibt keinen Moment, in dem ein Container ohne Firewall
läuft. Beim Stopp werden die Regeln ebenso atomar entfernt.

## 6. Audit-Protokollierung

### 6.1 Aufgezeichnete Ereignisse

Jede sicherheitsrelevante Aktion wird im Audit-Log festgehalten:

| Ereignis | Wann |
|----------|------|
| `pki_loaded` | Systemstart — Root-CAs geladen, Modus angezeigt |
| `ctl_started` | Systemstart — Management-Socket bereit |
| `ctl_spawn` | Container-Start angefordert |
| `binary_verify` | Signaturprüfung bestanden |
| `binary_reject` | Signaturprüfung fehlgeschlagen |
| `ctl_stop` | Container gestoppt |

### 6.2 Format

JSON Lines — ein JSON-Objekt pro Zeile, maschinenlesbar:

```json
{"seq":4,"ts":"2026-03-15T17:00:07Z","type":"binary_verify",
 "subject":"529a0f69-...","result":"ok",
 "sha256":"80fca813...","signer_cn":"doc-sign-pipeline"}
```

### 6.3 Zugang

```bash
erlkoenig audit                        # alle Ereignisse
erlkoenig audit --type binary_reject   # nur Ablehnungen
```

## 7. Management-Schnittstelle

### 7.1 Unix-Socket

Die Verwaltung erfolgt ausschließlich über einen Unix-Socket:

```
/run/erlkoenig/ctl.sock    root:erlkoenig    0660
```

- Kein TCP-Port, kein Netzwerkzugang
- Berechtigungen werden vom Linux-Kernel erzwungen
- Nur root und Mitglieder der Gruppe `erlkoenig` können verbinden
- Jeder Befehl wird im Audit-Log protokolliert

### 7.2 Kein Erlang-Distribution-Protokoll

erlkoenig verwendet weder `epmd` (Erlang Port Mapper Daemon) noch
das Erlang-Distribution-Protokoll. Es gibt keinen offenen TCP-Port
für die Verwaltung.

### 7.3 Deploy-Command

Alle Container werden über eine einzige Konfigurationsdatei deployt:

```bash
erlkoenig deploy stack.exs
```

Die Datei definiert alle Container mit ihren Firewall-Regeln,
Seccomp-Profilen und Signaturanforderungen. Ein Befehl startet
den gesamten Stack.

## 8. Fehlerbehandlung

### 8.1 Crash-Erkennung in Mikrosekunden

erlkoenig basiert auf Erlang/OTP. Die Container werden als Prozesse
in einem Supervision-Tree überwacht. Ein Container-Absturz wird in
Mikrosekunden erkannt — nicht über periodische Healthchecks (typisch
30 Sekunden in Kubernetes), sondern über Erlang-Prozess-Links.

### 8.2 Signaturprüfung bei Neustart

Ein abgestürzter Container durchläuft bei jedem automatischen Neustart
die vollständige Signaturprüfung. Ein Angreifer, der einen Container
zum Absturz bringt, um ihn durch eine manipulierte Version zu ersetzen,
scheitert an der Signaturprüfung.

## 9. Zusammenfassung der Verteidigungsschichten

```
Schicht 1: Supply Chain
  ├── Ed25519-Signatur auf jedem Binary
  ├── X.509-Zertifikatskette bis zum Vertrauensanker
  └── Prüfung bei jedem exec(), auch nach Crash-Restart

Schicht 2: Container-Isolation
  ├── 5 Linux-Namespaces (PID, NET, MNT, UTS, IPC)
  ├── Vollständige Namespace-Trennung (kein Pod-Sharing)
  ├── Schreibgeschütztes Root-Dateisystem
  ├── /proc-Maskierung
  └── Statische Binaries (keine Shell, keine Bibliotheken)

Schicht 3: Kernel-Enforcement
  ├── Seccomp-Whitelist (~60 von 300+ Syscalls)
  └── Capabilities: alle 41 entfernt

Schicht 4: Honeypot-Firewall
  ├── Per-Container nftables-Chain (policy: drop)
  ├── Jeder Port außer dem einen ist eine Falle
  ├── Echtzeit-Erkennung via Kernel-Conntrack (Millisekunden)
  ├── Automatisches Banning (threshold: 1 Paket)
  └── Atomare Firewall-Regeln (kein Moment ohne Schutz)

Schicht 5: Betrieb
  ├── Audit-Log für jede sicherheitsrelevante Aktion
  ├── Unix-Socket-Verwaltung (kein TCP, kein epmd)
  ├── Crash-Erkennung in Mikrosekunden
  └── Signaturprüfung bei jedem Neustart
```

Keine dieser Schichten ist allein ausreichend. Zusammen stellen sie
sicher, dass ein Angreifer mehrere unabhängige Sicherheitsmechanismen
gleichzeitig überwinden müsste — auf Kernel-Ebene, Netzwerk-Ebene
und kryptographischer Ebene.

Die Echtzeit-Reaktivität der Honeypot-Firewall (Schicht 4) in Kombination
mit der Signaturprüfung bei exec() (Schicht 1) und der vollständigen
Namespace-Trennung (Schicht 2) ist nach unserem Kenntnisstand in keiner
anderen Container-Runtime in dieser Form implementiert.
