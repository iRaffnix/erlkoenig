# The Erlkoenig Book

Erlkoenig is a container runtime for Linux, built on Erlang/OTP 28 and a
168 KB static C binary. This book is the canonical documentation: from your
first container down to the mechanics of Netlink, ELF analysis, and the
kernel-native storage model.

The chapters are grouped into three arcs. **Part I — Getting Started** walks
a new reader to a running container in under an hour. **Part II — DSL
Reference** explains every block of the Elixir DSL in detail. **Part III —
Internals & Operations** lifts the lid: C runtime, wire protocol, kernel
integration, operator procedures.

## Contents

### Part I — Getting Started

1. [Overview](01-overview.md) — What erlkoenig is and how the layers fit together
2. [Installation](02-installation.md) — Prerequisites, installing a release, enabling the systemd service
3. [Your First Container](03-first-container.md) — From `.exs` to a running sleeper in ten minutes

### Part II — DSL Reference

4. [Containers & Pods](04-containers.md) — Lifecycle, restart policies, limits, capabilities
5. [Networking](05-networking.md) — IPVLAN L3S, zones, host-side slave, DNS
6. [Firewall](06-firewall.md) — nftables pure in Erlang, host vs. container tables
7. [Threat Detection](07-threat-detection.md) — Per-IP state machines, guard blocks, honeypots
8. [Persistent Volumes](08-persistent-volumes.md) — Bind-mounts with mount options, ephemeral, quota
9. [Observability](09-observability.md) — AMQP event bus, `publish` blocks, routing keys
10. [PKI & Signatures](10-pki-signatures.md) — Ed25519 signatures, trust roots, verification modes
11. [Logging](11-logging.md) — Container stdout/stderr over RabbitMQ streams

### Part III — Internals & Operations

12. [Runtime Architecture](12-runtime-architecture.md) — C binary, TLV wire, namespaces, memfd self-protect
13. [ELF Analysis & Seccomp](13-elf-analysis.md) — Language inference, syscall detection, generated profiles
14. [Netlink Transport](14-netlink-transport.md) — AF_NETLINK direct, batch semantics, drain discipline
15. [Volume Backing Operations](15-volume-backing-ops.md) — XFS-on-loop setup, reflink, migration
16. [Supervision & Admission](16-supervision-and-admission.md) — Fail-closed firewall, crashloop quarantine, admission gate
17. [Property-Based Testing](17-property-based-testing.md) — PropEr invariants covering the runtime's state machines
18. [Operator CLI](18-operator-cli.md) — `erlkoenigctl` for everyday operations

## How to read

A new reader reads Part I linearly, then jumps into Part II on demand. An
operator setting up a fresh node needs Chapters 2 and 15 plus the
cross-references. Anyone who wants to know why a container can't `execve()`
from a compromised upload directory should read Chapters 8 and 12.

Cross-references use the form `→ Chapter N` and are load-bearing — the
structure is meant to be stable.

## Conventions

- All code samples are verified against the current tree.
- DSL syntax is Elixir; runtime orchestration is Erlang.
- Paths are relative to the repository root unless noted otherwise.
- Specifications (architecture decisions, `SPEC-EK-*` documents) live in a
  separate repository at `erlkoenigin/` — this book is the reader-facing
  layer on top.
