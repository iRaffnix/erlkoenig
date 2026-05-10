# Quickstart

Operator-Walkthrough für eine frische erlkoenig-Installation. Jeder Schritt
zeigt den exakten Befehl und den erwarteten Output. Wenn ein Schritt nicht
genau so reagiert, hast du den Punkt gefunden, an dem etwas anders ist.

Vorausgesetzt: erlkoenig ist über `install.sh` installiert
(siehe README für Install-Optionen) und der Service läuft (`systemctl
status erlkoenig`).

## 1. Liveness — antwortet die Runtime?

```sh
ek node ping
```

Erwartet:

```
pong
```

Wenn nicht: Service prüfen (`systemctl status erlkoenig`), Cookie-Pfad
verifizieren (`ek doctor` Schritt 3), ggf. journalctl.

## 2. Version + Health

```sh
ek node version
ek node health
```

Erwartet:

```
0.9.0

uptime_ms     1063408
sup_children  15
```

`sup_children` zeigt die top-level Supervisor-Kinder. Drop bei einem
Restart sichtbar. Genauere Lifecycle-Informationen in
[ERROR_CODES.md](ERROR_CODES.md), Component `runtime`.

## 3. Doctor — Host & Install Diagnose

```sh
ek doctor
```

Erwartet (alle grün):

```
check             status  code     detail
runtime_binary    ok      -        /opt/erlkoenig/rt/erlkoenig_rt
cookie            ok      -        /etc/erlkoenig/cookie
socket_dir        ok      -        /run/erlkoenig/containers
cgroup_v2         ok      -        /sys/fs/cgroup/cgroup.controllers
nft               ok      -        /usr/sbin/nft
protocol_vectors  warn    EK_HOST_PROTOCOL_VECTORS_MISSING ...
doctor: no blocking local issues found
```

`protocol_vectors` als `warn` ist erwartbar — das ist eine
CI/Development-Variable, nicht für Produktivbetrieb.

Jeder fail/warn-Code ist in der Catalog-Reference dokumentiert
und über `ek explain <CODE>` greifbar.

## 4. Container starten — Lifecycle

DSL-Beispiel kompilieren. Das Repository enthält die lesbare
`examples/tutorial/01_overview.exs`; die `.term`-Datei ist ein lokal
generiertes Artefakt des Compile-Schritts und muss nicht vorher existieren:

```sh
ek dsl compile examples/tutorial/01_overview.exs
```

Erwartet:

```
compiled examples/tutorial/01_overview.exs -> examples/tutorial/01_overview.term
```

Vor dem Deploy genau dieses generierte `.term` validieren:

```sh
ek config validate examples/tutorial/01_overview.term
```

Erwartet:

```
ok: examples/tutorial/01_overview.term validates
```

Apply:

```sh
ek up examples/tutorial/01_overview.term
```

Erwartet:

```
up: 1 container(s) running
  hello-0-web
```

## 5. Status — was läuft

```sh
ek ps
```

Erwartet:

```
name         state    ip         zone  restart_count
-----------  -------  ---------  ----  -------------
hello-0-web  running  10.10.0.2  demo  0
```

Dichte Tabelle: name, state, IP, zone, Restart-Counter.

## 6. Inspect — alles über einen Container

```sh
ek ct inspect hello-0-web
```

Erwartet:

```
args           7777
binary         /opt/erlkoenig/rt/demo/test-erlkoenig-echo_server
id             d85302ff-2a43-446e-9478-b552aa4204e6
name           hello-0-web
os_pid         239804
ports
restart        always
state          running
stats          #{cpu_usec => 2839, memory_bytes => 921600,
                 pids_current => 3, memory_peak => 1404928}
zone           demo
restart_count  0
net_info       #{netmask => 24, ip => {10,10,0,2},
                 zone => demo, ...}
seccomp        default
limits         #{memory => 128000000, pids => 64}
caps
volumes
netns_path     /proc/239804/ns/net

Timeline
  runtime_socket   unknown
  handshake        unknown
  spawn            spawned
  network          configured
```

Vollständiger State plus Lifecycle-Timeline am Ende. Cgroup-Stats sind
live (cpu_usec, memory_bytes, pids_current).

## 7. Volumes

```sh
ek vol list                              # alle
ek vol list --container hello-0-web      # gefiltert
ek vol inspect <uuid>                    # Details eines Volumes
```

## 8. Wenn ein Code im Log auftaucht

Realistisch: `journalctl -u erlkoenig` zeigt einen `EK_*`-Code. Ohne
Doku-Suche erklärt:

```sh
ek explain EK_RUNTIME_HANDSHAKE_FAILED
```

Erwartet:

```
EK_RUNTIME_HANDSHAKE_FAILED  [since 0.9.0]
component: runtime
severity:  error

description:
  runtime rejected reconnect handshake reply

operator action:
  verify BEAM and runtime protocol versions match and capture
  the raw handshake reply

evidence fields you will see:
  reason, reply

related:
  SPEC-PROTO-001
```

Bei `critical`-Codes erscheint zusätzlich die `iron rule` — der
Architektur-Grundsatz, der erklärt warum der Code hart fail-closed ist.

Filter nach Component:

```sh
ek explain --component audit       # alle Audit-Codes mit Severity
ek explain --component nft         # alle nftables-Codes
ek explain --list                  # alles, gekürzt
```

Für Tooling/Alertmanager:

```sh
ek --format json explain EK_AUDIT_CHAIN_BROKEN | jq '.severity'
```

Vollständige Catalog-Reference: [ERROR_CODES.md](ERROR_CODES.md).

## 9. Stoppen

Deklarativ — alles aus dem zuvor generierten `.term`-File:

```sh
ek down examples/tutorial/01_overview.term
```

Erwartet:

```
down: stopped 1/1 container(s)
```

Einzeln:

```sh
ek ct stop hello-0-web
```

## Was du jetzt kannst

- Status, Health, Diagnose vor jedem Deploy
- Deploy mit Validate-First-Pattern (`validate` → `up`)
- Inspection mit voller Cgroup-/Netz-Information
- Codes verstehen ohne externe Doku
- Cleanly herunterfahren

## Wo es nach diesem Quickstart weitergeht

- **Deeper architecture**: [README](../README.md) → Architektur-Sektion
- **CLI reference**: [CLI.md](CLI.md)
- **Error codes komplett**: [ERROR_CODES.md](ERROR_CODES.md)
- **Install layout**: [INSTALL_LAYOUT.md](INSTALL_LAYOUT.md)
- **AMQP events**: [AMQP_EVENTS.md](AMQP_EVENTS.md)
- **Contributor pattern**: [CONTRIBUTING](../CONTRIBUTING.md) — speziell die "Error Handling Contract" Sektion bei Modifikationen
