# Erlkoenig Tutorials

Hands-on, sequential walkthroughs. Each tutorial is **copy-paste
runnable** from a fresh checkout — no production VM, no sudo, no
network access required (unless explicitly stated). The book under
`doc/book/` is the reference layer; tutorials are the "play through
it yourself" layer.

## How to read

A tutorial is one Markdown file with numbered steps. Every code
block is something you actually run. Expected output is shown right
underneath. If a step fails, that's a real bug — open an issue.

## Available

1. [Audit chain + `:journal.local` from scratch](01-audit-and-journal-local.md)
   — SHA-256 hash chain, Ed25519 signing, daily HMAC seal, and the
   first service capability streaming through it. ~20 minutes.
