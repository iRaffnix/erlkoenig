# erlkoenig DSL — Tutorial Set

Sechs progressive Beispiel-Stack-Files die zusammen die (fast) komplette
DSL-Oberfläche von `Erlkoenig.Stack` abdecken. Jede Datei fokussiert eine
Feature-Gruppe; oben steht der Zweck, im Code stehen `Was / Wann / Wieso`-
Kommentare pro Block.

Lesefreundlich von oben nach unten:

| # | Datei | Zweck | Features |
|---|-------|-------|----------|
| 1 | `01_overview.exs` | Minimal-Skelett. Das absolute Minimum — ein Container in einer Zone, mit host-firewall. Einstiegspunkt. | `host`, `ipvlan`, `nft_table`, `base_chain`, `nft_rule`, `pod`, `container` |
| 2 | `02_capabilities.exs` | Service-Capabilities (`requires`). DNS, Journal, Postgres, DNS-Allowlist — mit der Glasbox-Regel: operator sieht alle Effekte. | `requires :"...local"`, `requires ... hosts: [...]` |
| 3 | `03_firewall.exs` | nft-Vollbild: sets, cidr_set, counter, vmap, flowtable, conn_limit inside chain. Host- und Container-Firewall. | `nft_set`, `nft_cidr_set`, `nft_counter`, `nft_vmap`, `nft_flowtable`, `conn_limit`, alle action-verbs |
| 4 | `04_threat_detection.exs` | Reactive Firewall. Port-scan, flood, slow-scan, honeypot-Detektoren + Escalation-Ladder. | `guard`, `detect`, `respond`, `allowlist` |
| 5 | `05_storage_and_pki.exs` | Persistente Volumes, ephemeral storage, mount-options, PKI-signierte Container. | `volume`, `read_only`, `opts`, `signature`, `files` |
| 6 | `06_multi_tier.exs` | Drei-Tier-Workload. Frontend + API + DB als Pods, Replicas, cross-tier nft via `{:replica_ips, pod, ct}`, jhash-LB. | `replicas`, `pod strategy`, replica-IP refs, `dnat_lb`, `dnat_jhash` |

Jede Datei ist lauffähig (soweit die Binaries existieren). Kompilieren
zum Term:

```bash
cd dsl
mix run -e 'mod = List.first(Code.compile_file("../examples/tutorial/01_overview.exs")) |> elem(0); mod.write!("/tmp/01.term")'
```

Loaden:

```bash
ek config load /tmp/01.term
```

## Philosophie-Punkte die durch alle Files durchziehen

1. **Glasbox**: Was die DSL deklariert entspricht 1:1 dem Kernel-State.
   Keine Magie, keine Auto-Injection — siehe `feedback_no_magic_inject`.
2. **Zero-Trust Default**: Jeder Container hat seine eigene nft-Tabelle,
   seine eigene netns; Host-Firewall ist default-drop, Container-Policies
   sind explizit.
3. **Kernel-native**: Edge-Protections (rate limit, conn limit, DNS filter)
   laufen im Kernel (nft/netfilter/XDP) nicht in userspace Proxies.
4. **Observability baked-in**: Jeder Container kann Metriken via AMQP,
   jeder Drop-Counter wird periodisch gepollt, Audit-Events signiert.
