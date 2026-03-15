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

### 2.3 Unterschied zu bestehenden Lösungen

Die meisten Container-Runtimes (Docker, containerd, Podman) prüfen
Signaturen beim Herunterladen des Images aus einer Registry. erlkoenig
prüft die Signatur im Moment der Ausführung (`exec()`). Das bedeutet:

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

Insbesondere sind blockiert:
- `execve` (im Profil `strict`) — kein Starten weiterer Programme
- `mount`, `pivot_root` — kein Verändern des Dateisystems
- `ptrace` — kein Debuggen anderer Prozesse
- `bpf`, `perf_event_open` — kein eBPF-Laden, kein Profiling
- `init_module`, `finit_module` — kein Laden von Kernel-Modulen

### 4.2 Capabilities

Linux-Capabilities unterteilen die Root-Rechte in einzelne Berechtigungen.
erlkoenig entfernt standardmäßig **alle** Capabilities:

```
cap_chown, cap_dac_override, cap_fowner, cap_kill, cap_setgid,
cap_setuid, cap_net_admin, cap_sys_admin, cap_sys_ptrace, ...
(41 Capabilities, alle entfernt)
```

Keiner der drei Container in diesem Dienst benötigt Capabilities.
Falls ein Container einen Port unter 1024 binden müsste, könnte
gezielt `cap_net_bind_service` erlaubt werden — alle anderen blieben
entfernt.

### 4.3 Zusammenwirken

Seccomp und Capabilities ergänzen sich:

- Capabilities beschränken, **welche Operationen** ein Prozess mit
  Root-Rechten ausführen darf
- Seccomp beschränkt, **welche Kernel-Schnittstellen** ein Prozess
  überhaupt ansprechen darf

Ein Angreifer, der durch einen Exploit Root-Rechte im Container erlangt,
kann trotzdem weder das Netzwerk manipulieren (keine `cap_net_admin`)
noch einen Kernel-Syscall wie `mount` ausführen (Seccomp blockiert).

## 5. Netzwerk-Isolation

### 5.1 Zonen

Die drei Container laufen in getrennten Netzwerkzonen:

| Zone | Subnetz | Zweck |
|------|---------|-------|
| dmz | 10.0.1.0/24 | Öffentlich erreichbar |
| sign | 10.0.2.0/24 | Nur von dmz erreichbar |
| store | 10.0.3.0/24 | Nur von sign erreichbar |

### 5.2 Per-Container-Firewall

Jeder Container erhält eine eigene nftables-Chain. Die Regeln werden
atomar beim Start des Containers angelegt und beim Stopp entfernt.

```
Container web (10.0.1.10):
  ✓ Eingehend TCP 8080 (HTTP-Anfragen)
  ✓ Bestehende Verbindungen (ct state established)
  ✓ ICMP (Ping)
  ✗ Alles andere → DROP

Container signer (10.0.2.10):
  ✓ Eingehend TCP 8081 (nur von 10.0.1.0/24)
  ✓ Bestehende Verbindungen
  ✗ Ausgehend ins Internet → DROP
  ✗ Alles andere → DROP

Container archive (10.0.3.10):
  ✓ Eingehend TCP 8082 (nur von 10.0.2.0/24)
  ✓ Bestehende Verbindungen
  ✗ Ausgehend → DROP (keinerlei Netzwerkzugang)
  ✗ Alles andere → DROP
```

### 5.3 Unterschied zu bestehenden Lösungen

In Kubernetes werden Netzwerkrichtlinien über CNI-Plugins (Calico, Cilium)
umgesetzt. Diese arbeiten auf Pod-Ebene und erfordern einen separaten
Netzwerk-Stack.

erlkoenig setzt Firewall-Regeln direkt über nftables, das im
Linux-Kernel integrierte Nachfolgesystem von iptables. Die Regeln
werden atomar in einer einzigen Netlink-Transaktion angelegt — es
gibt keinen Moment, in dem ein Container ohne Firewall läuft.

## 6. Audit-Protokollierung

### 6.1 Aufgezeichnete Ereignisse

Jede sicherheitsrelevante Aktion wird im Audit-Log festgehalten:

| Ereignis | Wann | Was wird protokolliert |
|----------|------|----------------------|
| `pki_loaded` | Systemstart | Anzahl geladener Root-CAs, Modus |
| `ctl_started` | Systemstart | Socket-Pfad |
| `ctl_spawn` | Container-Start | Binary-Pfad, Parameter, Absender |
| `binary_verify` | Signaturprüfung OK | SHA-256, Git-SHA, Signer, Kette |
| `binary_reject` | Signaturprüfung fehlgeschlagen | Binary-Pfad, Fehlgrund |
| `ctl_stop` | Container-Stopp | Container-ID, Absender |

### 6.2 Format

Das Audit-Log wird als JSON Lines geschrieben — ein JSON-Objekt pro
Zeile, maschinenlesbar:

```json
{"seq":4,"ts":"2026-03-15T17:00:07Z","type":"binary_verify",
 "subject":"529a0f69-...","result":"ok",
 "sha256":"80fca813...","signer_cn":"doc-sign-pipeline"}
```

### 6.3 Zugang

Das Log liegt unter `/var/log/erlkoenig/audit.jsonl` und kann über
die CLI oder direkt von SIEM-Systemen ausgelesen werden:

```bash
erlkoenig audit                    # alle Ereignisse
erlkoenig audit --type binary_reject  # nur Ablehnungen
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
für die Verwaltung. Der Daemon kommuniziert ausschließlich über den
Unix-Socket und systemd-Signale (SIGTERM für Shutdown).

## 8. Fehlerbehandlung

### 8.1 Crash-Erkennung

erlkoenig basiert auf Erlang/OTP. Die Container werden als Prozesse
in einem Supervision-Tree überwacht. Ein Container-Absturz wird in
Mikrosekunden erkannt — nicht über periodische Healthchecks (typisch
30 Sekunden in Kubernetes), sondern über Erlang-Prozess-Links.

### 8.2 Automatischer Neustart

Je nach Konfiguration wird ein abgestürzter Container automatisch
neu gestartet. Dabei durchläuft er erneut die vollständige
Signaturprüfung. Ein Angreifer, der einen Container zum Absturz
bringt, um ihn durch eine manipulierte Version zu ersetzen, scheitert
an der Signaturprüfung beim Neustart.

## 9. Zusammenfassung der Verteidigungsschichten

```
Schicht 1: Supply Chain
  ├── Ed25519-Signatur auf jedem Binary
  ├── X.509-Zertifikatskette bis zum Vertrauensanker
  └── Prüfung bei jedem exec(), auch nach Crash-Restart

Schicht 2: Container-Isolation
  ├── 5 Linux-Namespaces (PID, NET, MNT, UTS, IPC)
  ├── Schreibgeschütztes Root-Dateisystem
  ├── /proc-Maskierung
  └── Statische Binaries (keine Shell, keine Bibliotheken)

Schicht 3: Kernel-Enforcement
  ├── Seccomp-Whitelist (~60 von 300+ Syscalls)
  ├── Capabilities: alle 41 entfernt
  └── Per-Container-nftables-Firewall

Schicht 4: Netzwerk-Isolation
  ├── Drei getrennte Zonen (dmz, sign, store)
  ├── Atomare Firewall-Regeln pro Container
  └── Kein ausgehender Verkehr für signer und archive

Schicht 5: Betrieb
  ├── Audit-Log für jede sicherheitsrelevante Aktion
  ├── Unix-Socket-Verwaltung (kein TCP)
  ├── Crash-Erkennung in Mikrosekunden
  └── Signaturprüfung bei jedem Neustart
```

Keine dieser Schichten ist allein ausreichend. Zusammen stellen sie
sicher, dass ein Angreifer mehrere unabhängige Sicherheitsmechanismen
gleichzeitig überwinden müsste — auf Kernel-Ebene, Netzwerk-Ebene
und kryptographischer Ebene.
