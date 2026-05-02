# Erlkoenig examples

This directory is split by audience and purpose:

- `stacks/` contains runnable operator stack files for normal `ek up` and
  `ek dsl compile` workflows.
- `tutorial/` contains the chapter-by-chapter tutorial examples used by the
  book and integration tests.
- `firewall/` contains focused nftables and host-firewall examples.
- `dev/` contains development, diagnostics, and verifier demos.
- `scenarios/` contains nft VM fixtures used by tests. These are not operator
  stack examples.
- `agents/` contains demo workload source code used by showcase flows.
- `showcase/` contains opt-in showcase stack files plus `showcase/bin/`, the
  ignored local output directory created by `make agents-build`. Showcase
  stacks require their setup flow; they are not default runnable stack files.

Runtime test binaries named `test-erlkoenig-*` are not examples. Some are
intentionally destructive or resource-heavy and belong to the runtime test
artifact set, not this examples tree.

Generated `.term` files from compiling examples should stay local unless they
are deliberate fixtures under `scenarios/`.
