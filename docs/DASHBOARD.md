# erlkoenig Dashboard — Technischer Plan

## Vision

Ein Echtzeit-Dashboard im Browser das zeigt was in erlkoenig passiert.
Keine Seiten-Refreshes, keine Polling-Intervalle. Container starten,
Firewall-Counter zählen hoch, Audit-Events erscheinen — alles live.

```
┌─────────────────────────────────────────────────────────┐
│  erlkoenig Dashboard                    [status: active] │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Containers (3 running)                                 │
│  ┌──────────┬──────────┬───────────┬────────┬────────┐  │
│  │ Name     │ IP       │ State     │ Memory │ CPU    │  │
│  ├──────────┼──────────┼───────────┼────────┼────────┤  │
│  │ web      │ 10.0.0.10│ ● running │ 4.4 MB │ 16 ms │  │
│  │ signer   │ 10.0.0.20│ ● running │ 5.7 MB │  9 ms │  │
│  │ archive  │ 10.0.0.30│ ● running │ 1.2 MB │  3 ms │  │
│  └──────────┴──────────┴───────────┴────────┴────────┘  │
│                                                         │
│  Firewall Counters (live)                               │
│  ┌──────────┬────────┬──────┬────────────────────────┐  │
│  │ Container│ Counter│ pkts │ ▁▂▃▅▇█▇▅▃▂▁ (10s)    │  │
│  ├──────────┼────────┼──────┼────────────────────────┤  │
│  │ web      │ http   │ 1247 │ ▂▃▅▇▇▅▃▂▁▁           │  │
│  │ web      │ trap   │    3 │ ▁▁▁▁▁▁▁▁▁█           │  │
│  │ signer   │ sign   │  842 │ ▂▃▅▇▅▃▂▁▁▁           │  │
│  │ signer   │ trap   │    0 │ ▁▁▁▁▁▁▁▁▁▁           │  │
│  │ archive  │ log    │  842 │ ▂▃▅▇▅▃▂▁▁▁           │  │
│  └──────────┴────────┴──────┴────────────────────────┘  │
│                                                         │
│  Audit Log (live stream)                                │
│  ┌──────────────────────────────────────────────────┐   │
│  │ 20:18:31 binary_verify  web     OK doc-sign-pipe │   │
│  │ 20:18:30 binary_verify  signer  OK doc-sign-pipe │   │
│  │ 20:18:29 binary_verify  archive OK doc-sign-pipe │   │
│  │ 20:17:34 pki_loaded     pki     roots=1 mode=on  │   │
│  │ 20:17:34 ctl_started    ctl     /run/.../ctl.sock│   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  Binary Trust                                           │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Root CA: Document Services Root CA               │   │
│  │ Mode: on (enforce)                               │   │
│  │                                                  │   │
│  │ web      ✓ doc-sign-pipeline  sha256:fc07ec...  │   │
│  │ signer   ✓ doc-sign-pipeline  sha256:29dc8c...  │   │
│  │ archive  ✓ doc-sign-pipeline  sha256:598aca...  │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  Guard Events                                           │
│  ┌──────────────────────────────────────────────────┐   │
│  │ 20:19:05 BAN 192.168.1.42 → port_scan on signer │   │
│  │          expires: 2026-03-16T20:19:05Z           │   │
│  │ 20:18:55 FLOOD 10.0.0.99 → 52 conn/10s on web   │   │
│  │          expires: 2026-03-16T20:18:55Z           │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  Blocked IPs (2)                                        │
│  ┌──────────────┬───────────┬──────────┬─────────────┐  │
│  │ IP           │ Reason    │ Since    │ Expires     │  │
│  ├──────────────┼───────────┼──────────┼─────────────┤  │
│  │ 192.168.1.42 │ port_scan │ 20:19:05 │ +24h        │  │
│  │ 10.0.0.99    │ conn_flood│ 20:18:55 │ +24h        │  │
│  └──────────────┴───────────┴──────────┴─────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Technologie: Phoenix LiveView

### Warum LiveView

- **Echtzeit ohne JavaScript**: Server rendert HTML, schickt Diffs
  über WebSocket. Browser aktualisiert DOM. Kein React, kein npm.
- **Läuft auf dem BEAM**: Gleicher Cluster wie erlkoenig. Direkter
  Zugriff auf erlkoenig_core, erlkoenig_audit, erlkoenig_nft APIs.
- **Elixir schon im Stack**: DSL ist Elixir, Dashboard ist Elixir.
- **Leichtgewichtig**: ~15 MB RAM für Phoenix. Kein separater Prozess.

### Datenfluss

```
Browser ──WebSocket──► Phoenix LiveView
                           │
                           ├── erlkoenig_core:list()       → Container-Tabelle
                           ├── erlkoenig_core:inspect(Pid) → Container-Details
                           ├── erlkoenig_audit:query(#{})   → Audit-Log
                           ├── erlkoenig_pki:mode()         → Trust-Status
                           ├── erlkoenig_nft:counters()     → Firewall-Counter
                           ├── erlkoenig_nft:blocklist()    → Gebannte IPs
                           └── pg:monitor(erlkoenig_cts)    → Live Container-Events
```

**Kein Polling.** LiveView subscribt sich auf:
- `pg` Gruppen-Events (Container start/stop)
- `erlkoenig_events` gen_event Bus (Lifecycle-Events)
- erlkoenig_nft Watch-Events (Counter-Schwellwerte)
- erlkoenig_nft Guard-Events (Ban/Unban)

Wenn ein Container startet oder ein Counter hochzählt, pusht der
Server den Diff zum Browser. Latenz: Millisekunden.

## Architektur

### Wo lebt das Dashboard?

**Option A: Im erlkoenig Release (empfohlen)**

```
erlkoenig_sup
├── ... (bestehende Module)
└── erlkoenig_web (Phoenix-App als OTP-Application)
    ├── Endpoint (Cowboy HTTP auf localhost:4000)
    ├── Router
    └── LiveViews
```

Phoenix wird als Dependency in rebar.config (via mix) eingebunden.
Läuft im selben BEAM — direkter Funktionsaufruf, kein RPC.

**Option B: Separates Release (erlkoenig_ex)**

```
erlkoenig (BEAM 1)  ◄──Unix Socket──► erlkoenig_ex (BEAM 2)
Container Runtime                      Dashboard + Phoenix
```

Entkoppelt, aber braucht Socket-Kommunikation statt direktem Aufruf.

### Empfehlung: Option A

Ein BEAM, ein Release. Phoenix als Application im Umbrella.
Der Overhead ist minimal (~15 MB RAM, ~2 MB Dependency).

## LiveView Pages

### 1. Dashboard (Hauptseite)

Zeigt alles auf einen Blick:
- Container-Tabelle mit Live-Stats (Memory, CPU, PIDs)
- Firewall-Counter mit Sparklines
- Audit-Stream (letzte 20 Events)
- Trust-Status (Root CAs, Mode)
- Guard-Events (Bans)

Updates: **Echtzeit** via PubSub.

### 2. Container Detail

Klick auf einen Container:
- Alle Spawn-Optionen (binary, ip, args, seccomp, caps)
- Live-Stats (Memory-Graph, CPU-Graph, PID-Count)
- Firewall-Regeln (Chain mit allen Rules)
- Signatur-Info (SHA256, Signer, Timestamp, Chain)
- Logs (stdout/stderr Stream)
- Netzwerk (IP, veth, Bridge, Gateway)
- Namespace-Info (PID, netns_path)

### 3. Firewall

Volle nftables-Übersicht:
- Alle Tabellen und Chains
- Counter pro Chain (live, mit Rate/s)
- Blocklist (alle gebannten IPs, Grund, Ablauf)
- Conntrack (aktive Verbindungen, Top-Sources)
- Guard-Status (aktive Detektoren, Schwellwerte)

### 4. Audit

Filterbares Event-Log:
- Typ-Filter (binary_verify, binary_reject, ctl_spawn, etc.)
- Zeitraum-Filter
- Suche nach Container-ID oder Binary-Name
- Export als JSON Lines

### 5. PKI / Trust

Zertifikatskette visualisiert:
- Root CAs (geladen, Ablaufdatum)
- Signierte Binaries (SHA256, Signer, Chain-Depth)
- Verifikations-Historie

## Daten-APIs (existieren schon)

| Was | Erlang-API | Status |
|-----|-----------|--------|
| Container-Liste | `erlkoenig_core:list()` | Existiert |
| Container-Details | `erlkoenig_core:inspect(Pid)` | Existiert |
| Container-Stats | `erlkoenig_core:stats(Pid)` | Existiert |
| Container-Start/Stop | `erlkoenig_sup:start_container/2` | Existiert |
| Audit-Log | `erlkoenig_audit:query(Opts)` | Existiert |
| PKI-Mode | `erlkoenig_pki:mode()` | Existiert |
| Firewall-Counter | `erlkoenig_nft_srv:dump_counters()` | Existiert (nft Repo) |
| Blocklist | `erlkoenig_nft_firewall:blocklist()` | Existiert (nft Repo) |
| Conntrack | `erlkoenig_nft_ct:connections()` | Existiert (nft Repo) |
| Guard-Events | `pg:monitor(ct_events)` | Existiert (nft Repo) |
| Container-Events | `pg:monitor(erlkoenig_cts)` | Existiert |

**Alle Daten-APIs existieren bereits.** Das Dashboard ist nur eine
Visualisierung — kein neues Backend nötig.

## Implementation

### Dependencies (mix.exs)

```elixir
{:phoenix, "~> 1.7"},
{:phoenix_live_view, "~> 1.0"},
{:phoenix_html, "~> 4.0"},
{:heroicons, "~> 0.5"},     # Icons
```

Kein Ecto (keine Datenbank). Kein npm (LiveView braucht kein JS-Build).

### Sicherheit

- Dashboard hört nur auf `127.0.0.1:4000` (kein Internet)
- Zugang über SSH-Tunnel: `ssh -L 4000:localhost:4000 erlk-ubuntu`
- Optional: Basic Auth über Phoenix Plugs
- Keine Datenbank, keine Sessions, kein Cookie-Problem

### Schritte

```
Step 1: Phoenix-App als neue OTP-Application
        apps/erlkoenig_web/ mit mix.exs
        Endpoint auf localhost:4000

Step 2: Dashboard LiveView
        Container-Tabelle + Live-Stats
        PubSub subscription auf pg-Events

Step 3: Firewall LiveView
        Counter-Tabelle mit Sparklines
        Blocklist + Guard-Events

Step 4: Audit LiveView
        Event-Stream + Filter

Step 5: Container Detail LiveView
        Stats-Graphen + Logs + Signatur-Info

Step 6: PKI LiveView
        Zertifikatskette + Verifikations-Historie
```

## Mockup: Container-Tabelle (LiveView)

```elixir
defmodule ErlkoenigWeb.DashboardLive do
  use ErlkoenigWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      # Subscribe auf Container-Events
      :pg.monitor(:erlkoenig_pg, :erlkoenig_cts)
      # Refresh Stats alle 2 Sekunden
      :timer.send_interval(2000, :refresh_stats)
    end

    containers = erlkoenig_core:list()
    pki_mode = erlkoenig_pki:mode()

    {:ok, assign(socket,
      containers: containers,
      pki_mode: pki_mode,
      audit: erlkoenig_audit:query(%{limit: 20})
    )}
  end

  @impl true
  def handle_info(:refresh_stats, socket) do
    containers = erlkoenig_core:list()
    {:noreply, assign(socket, containers: containers)}
  end

  # Container gestartet/gestoppt → automatisch aktualisiert
  def handle_info({:pg, :erlkoenig_cts, _event}, socket) do
    containers = erlkoenig_core:list()
    {:noreply, assign(socket, containers: containers)}
  end
end
```

**Keine JavaScript-Zeile.** LiveView rendert HTML, schickt Diffs
über WebSocket, Browser aktualisiert DOM.
