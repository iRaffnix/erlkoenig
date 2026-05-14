# Erlkoenig Makefile
# ==================
#
# The C runtime (erlkoenig_rt) lives in its own repo. Build it there or
# download a release tarball; point RT_BIN at the resulting binary if you
# want `make install` to pick it up:
#   make install RT_BIN=../erlkoenig_rt/build/release/erlkoenig_rt
#
# Build:
#   make              — BEAM compile, tests, and OTP release tarball
#   make check        — Alle Tests ohne Root (eunit + dialyzer + dsl)
#   make erl          — Erlang kompilieren
#   make test         — eunit Tests (kein Root)
#   make dialyzer     — Dialyzer Typanalyse
#   make integration  — Integrationstests (braucht sudo)
#   make release      — OTP Release-Tarball (BEAM + ERTS, ohne C-Runtime)
#   make dsl          — Elixir-DSL kompilieren
#   make docs         — ExDoc Dokumentation generieren
#   make test-dsl     — Elixir-DSL Tests
#
# Install:
#   sudo sh install.sh --version vX.Y.Z
#   sudo sh install.sh --local /tmp/artifacts
#   sudo make install [RT_BIN=/path/to/erlkoenig_rt]
#   sudo make uninstall   — Remove installation
#   make fetch-artifacts  — Download CI artifacts via gh
#
# Release:
#   make tag VERSION=0.2.0
#
#   make clean        — Alles aufraeumen

.PHONY: all check erl test dialyzer dsl-dialyzer integration release \
        dsl dsl-bundle dsl-escript test-dsl docs docs-erlang docs-error-codes \
        ontology-showcase go-demos \
        fmt fmt-check xref lint error-catalog-check \
        verifier verifier-xcheck agents-build showcase showcase-verify \
        live-lab-firewall live-lab-lifecycle live-lab-lifecycle-two \
        live-lab-observability live-lab-crash live-lab-logs \
        live-lab-volumes-persistent live-lab-volumes-ephemeral \
        live-lab-admission-denial live-lab-quarantine-crashloop \
        install uninstall fetch-artifacts install-smoke \
        tag clean clean-erl clean-dsl

PREFIX          ?= /opt/erlkoenig
SERVICE_USER    ?= erlkoenig

# Path to the pre-built C runtime binary (produced by the erlkoenig_rt
# repo's `cmake --build` target). Override on the command line or via env
# if your checkout lives elsewhere. Only consulted by `install`.
RT_BIN          ?= ../erlkoenig_rt/build/release/erlkoenig_rt
BUILD_DIR       := build/release
INT_TESTS       := tests/integration

# ── Hauptziel ─────────────────────────────────────────────

all: erl check release

# ── Alle Tests (kein Root) ──────────────────────────────

check: lint error-catalog-check test dialyzer test-dsl

# ── Quality ──────────────────────────────────────────────

fmt:
	rebar3 fmt

fmt-check:
	rebar3 fmt --check

xref: erl
	rebar3 xref

lint: fmt-check xref dialyzer

error-catalog-check: erl
	rebar3 eunit --module=erlkoenig_error_catalog_check_tests

# ── Erlang ───────────────────────────────────────────────

erl:
	rebar3 compile

# ── Tests ────────────────────────────────────────────────

test: erl
	rebar3 eunit

dialyzer: erl dsl-dialyzer
	@RESULT=$$(rebar3 dialyzer 2>&1); RC=$$?; echo "$$RESULT" | tail -20; \
	if echo "$$RESULT" | grep -q "no_return\|will never be called\|invalid_contract\|has no local return"; then \
		echo ""; echo "ERROR: Dialyzer found real type errors"; exit 1; \
	fi; \
	echo "Dialyzer: OK"

dsl-dialyzer:
	cd dsl && mix deps.get && mix dialyzer

integration: erl
	@echo ""
	@echo "==> Integration Tests (braucht sudo)"
	@echo ""
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "ERROR: Integration tests need root. Run: sudo make integration"; \
		exit 1; \
	fi
	@if [ ! -x "$(RT_BIN)" ]; then \
		echo "ERROR: C runtime binary not found at $(RT_BIN)"; \
		echo "Build erlkoenig_rt separately or override RT_BIN=..."; \
		exit 1; \
	fi
	erlc -o $(INT_TESTS) $(INT_TESTS)/test_helper.erl
	@RT_BIN=$(RT_BIN) bash $(INT_TESTS)/run_all.sh

# ── Elixir DSL ──────────────────────────────────────────

dsl:
	cd dsl && mix deps.get && mix compile

dsl-bundle:
	cd dsl && MIX_ENV=prod mix deps.get --only prod && MIX_ENV=prod mix compile
	@ELIXIR_BIN=$$(readlink -f "$$(command -v elixir)"); \
	ELIXIR_HOME=$$(cd "$$(dirname "$$ELIXIR_BIN")/.." && pwd); \
	rm -rf dist/elixir; \
	mkdir -p dist/elixir/bin dist/elixir/lib; \
	cp "$$ELIXIR_HOME/bin/elixir" dist/elixir/bin/elixir; \
	for app in elixir eex logger; do \
		test -d "$$ELIXIR_HOME/lib/$$app/ebin" || { echo "missing Elixir app ebin: $$app" >&2; exit 1; }; \
		mkdir -p "dist/elixir/lib/$$app"; \
		cp -R "$$ELIXIR_HOME/lib/$$app/ebin" "dist/elixir/lib/$$app/ebin"; \
	done
	mkdir -p dist/elixir/lib/erlkoenig_dsl/ebin
	cp dsl/_build/prod/lib/erlkoenig_dsl/ebin/* dist/elixir/lib/erlkoenig_dsl/ebin/

dsl-escript: dsl
	cd dsl && mix escript.build

docs: dsl
	cd dsl && mix docs

# Erlang-side ExDoc: HTML reference for all OTP modules + extras
# (README, QUICKSTART, ERROR_CODES, CONTRIBUTING). Always rebuild
# the catalog markdown first so it stays in sync with the live
# error_catalog.term.
docs-erlang: docs-error-codes erl
	rebar3 ex_doc

# Render priv/error_catalog.term as docs/ERROR_CODES.md. Idempotent;
# stays in sync with the live catalog because it is regenerated on
# every docs-erlang invocation.
docs-error-codes: docs/ERROR_CODES.md

docs/ERROR_CODES.md: apps/erlkoenig/priv/error_catalog.term tools/render-error-catalog.escript
	@mkdir -p docs
	escript tools/render-error-catalog.escript > $@
	@echo "  generated: $@ ($$(wc -l < $@) lines)"

test-dsl:
	cd dsl && mix test

ontology-showcase:
	@mkdir -p docs/generated/ontology
	cd dsl && mix erlkoenig.showcase resource_admission --format mermaid > ../docs/generated/ontology/resource_admission_topology.mmd
	cd dsl && mix erlkoenig.showcase resource_admission --format text > ../docs/generated/ontology/resource_admission_topology.txt
	cd dsl && mix erlkoenig.showcase resource_admission --format json > ../docs/generated/ontology/resource_admission_topology.json
	cd dsl && mix erlkoenig.showcase resource_admission --debug --format text > ../docs/generated/ontology/resource_admission_debug.txt
	cd dsl && mix erlkoenig.showcase resource_admission_denial --explain --format mermaid > ../docs/generated/ontology/resource_admission_denial_explain.mmd
	cd dsl && mix erlkoenig.showcase resource_admission_denial --explain --format text > ../docs/generated/ontology/resource_admission_denial_explain.txt
	cd dsl && mix erlkoenig.showcase resource_admission_denial --explain --format json > ../docs/generated/ontology/resource_admission_denial_explain.json
	@printf '# Erlkoenig Ontology Showcase\n\nGenerated by `make ontology-showcase`.\n\n## Resource Admission Topology\n\n```mermaid\n' > docs/generated/ontology/showcase.md
	@cat docs/generated/ontology/resource_admission_topology.mmd >> docs/generated/ontology/showcase.md
	@printf '\n```\n\n## Resource Admission Denial Explanation\n\n```mermaid\n' >> docs/generated/ontology/showcase.md
	@cat docs/generated/ontology/resource_admission_denial_explain.mmd >> docs/generated/ontology/showcase.md
	@printf '\n```\n\n## Resource Admission Debug Report\n\n```text\n' >> docs/generated/ontology/showcase.md
	@cat docs/generated/ontology/resource_admission_debug.txt >> docs/generated/ontology/showcase.md
	@printf '\n```\n\n## Files\n\n- `resource_admission_topology.mmd`\n- `resource_admission_topology.txt`\n- `resource_admission_topology.json`\n- `resource_admission_debug.txt`\n- `resource_admission_denial_explain.mmd`\n- `resource_admission_denial_explain.txt`\n- `resource_admission_denial_explain.json`\n' >> docs/generated/ontology/showcase.md
	@echo "generated docs/generated/ontology/showcase.md"

live-lab-firewall:
	tools/live_lab_runner.py firewall-host-counters

live-lab-lifecycle:
	tools/live_lab_runner.py lifecycle-minimal

live-lab-lifecycle-two:
	tools/live_lab_runner.py lifecycle-two-containers

live-lab-observability:
	tools/live_lab_runner.py observability-stats

live-lab-crash:
	tools/live_lab_runner.py controlled-crash

live-lab-logs:
	tools/live_lab_runner.py log-stream

live-lab-volumes-persistent:
	tools/live_lab_runner.py volumes-persistent

live-lab-volumes-ephemeral:
	tools/live_lab_runner.py volumes-ephemeral

live-lab-admission-denial:
	tools/live_lab_runner.py admission-denial

live-lab-quarantine-crashloop:
	tools/live_lab_runner.py quarantine-crashloop

# ── Release ──────────────────────────────────────────────
#
# OTP Release: BEAM + ERTS + erlkoenig + erlkoenig_nft
# Kein Erlang auf dem Zielserver noetig.
# C-Runtime ist NICHT enthalten — wird separat via install.sh installiert.
# Discovery: {rt_path, auto} findet /opt/erlkoenig/rt/erlkoenig_rt

release: erl dsl-bundle
	rebar3 release
	@# rebar3 version-filters lib/ and releases/ when packaging the
	@# tar (only the active version is shipped), but NOT bin/. Older
	@# per-version wrappers (bin/erlkoenig-X.Y.Z) accumulate in the
	@# release tree across builds and get packaged into every
	@# subsequent tarball. Once installed, the systemd entrypoint
	@# bin/erlkoenig globs `erlkoenig-*` and picks the FIRST match
	@# alphabetically — which can be older than the active release.
	@# Strip stale wrappers before tar so we ship exactly one.
	@find _build/default/rel/erlkoenig/bin -maxdepth 1 -name 'erlkoenig-*' \
		-not -name 'erlkoenig-$(CURRENT_VERSION)' -delete
	rebar3 tar
	@# Manifest-only audit gates the artefact before it leaves the
	@# build directory. Catches the build-side bug classes documented
	@# in docs/INSTALL_LAYOUT.md (stale per-version wrapper, empty
	@# elixir/{elixir,eex,logger}/ebin, leaked examples/*.term, missing
	@# required files, OTP-dep gap). The audit runs against the source
	@# tarball in _build/, *before* the cp into dist/ — a failure here
	@# blocks the `make release` target without ever publishing the
	@# broken artefact under dist/.
	@tools/release-tarball-audit.sh \
		_build/default/rel/erlkoenig/erlkoenig-$(CURRENT_VERSION).tar.gz
	@mkdir -p dist
	@# Copy ONLY the audited tarball, not a glob over `_build/`. Older
	@# version tarballs accumulate in `_build/default/rel/erlkoenig/`
	@# across builds; a glob would publish them too, bypassing the
	@# audit gate which only inspects $(CURRENT_VERSION).
	cp _build/default/rel/erlkoenig/erlkoenig-$(CURRENT_VERSION).tar.gz dist/
	@echo ""
	@echo "==> dist/$$(cd dist && ls erlkoenig-*.tar.gz)"

# ── Audit verifier (customer-deliverable) ──────────────────────────
# SPEC-AS-005 stage 4. Statically-linked Go binary that recomputes
# the chain + signatures + seal from first principles, independent
# of the producing runtime. Customer hands this to their auditor.

verifier:
	@mkdir -p dist
	cd tools/audit-verifier && \
	  CGO_ENABLED=0 go build -ldflags="-s -w" \
	  -o ../../dist/audit-verifier .
	@echo "==> dist/audit-verifier ($$(du -h dist/audit-verifier | cut -f1))"

# Cross-language regression: Erlang produces a signed+sealed audit
# log; the Go verifier then walks it through 4 happy-path modes and
# 3 tamper exercises. Either side drifting on canonical-JSON, hash,
# signature, or seal format breaks this loud and fast.
verifier-xcheck: erl verifier
	cd dsl && mix run ../examples/dev/audit_verifier_demo.exs

# ── case_mgmt showcase (book ch21) ─────────────────────────────
# End-to-end demo: build the two Go agents, deploy to a remote
# erlkoenig host (SHOWCASE_HOST, default erlkoenig-2__root), wipe +
# re-seed Postgres, spawn the pod, print the URL the operator
# can curl. Idempotent — run again to reset.

SHOWCASE_HOST ?= erlkoenig-2__root
SHOWCASE_RT_DEMO ?= /opt/erlkoenig/rt/demo
SHOWCASE_BIN_DIR ?= examples/showcase/bin

agents-build:
	mkdir -p $(SHOWCASE_BIN_DIR)
	cd examples/agents/case_mgmt && \
	  CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../showcase/bin/case_mgmt .
	cd examples/agents/deadline_worker && \
	  CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../showcase/bin/deadline_worker .

showcase: agents-build
	@echo "==> deploying agents + schema to $(SHOWCASE_HOST)"
	scp $(SHOWCASE_BIN_DIR)/case_mgmt          $(SHOWCASE_HOST):$(SHOWCASE_RT_DEMO)/
	scp $(SHOWCASE_BIN_DIR)/deadline_worker    $(SHOWCASE_HOST):$(SHOWCASE_RT_DEMO)/
	scp examples/agents/case_mgmt/schema.sql         $(SHOWCASE_HOST):/tmp/
	scp examples/agents/case_mgmt/seed.sql           $(SHOWCASE_HOST):/tmp/
	@echo "==> resetting cases db (DROP + CREATE + seed)"
	ssh $(SHOWCASE_HOST) 'sudo -u postgres psql -d cases -f /tmp/schema.sql > /dev/null && \
	                     sudo -u postgres psql -d cases -f /tmp/seed.sql > /dev/null && \
	                     echo "    seeded $$(sudo -u postgres psql -d cases -t -c "SELECT COUNT(*) FROM tasks;" | xargs) tasks"'
	@echo "==> deploying showcase pod runner"
	scp tests/integration/showcase_case_mgmt.escript $(SHOWCASE_HOST):/root/erlkoenig/tests/integration/
	@echo ""
	@echo "==> showcase ready"
	@echo "    start the pod (long-running):"
	@echo "      ssh $(SHOWCASE_HOST) /root/erlkoenig/tests/integration/showcase_case_mgmt.escript"
	@echo ""
	@echo "    or run the one-shot integration test:"
	@echo "      ssh $(SHOWCASE_HOST) /root/erlkoenig/tests/integration/45_case_mgmt.escript"

# Verify the showcase audit log offline with the Go verifier.
showcase-verify: verifier
	@AUDIT=$$(ssh $(SHOWCASE_HOST) ls -1t /var/log/erlkoenig/case_mgmt_audit.jsonl 2>/dev/null); \
	  if [ -z "$$AUDIT" ]; then echo "no audit log on $(SHOWCASE_HOST) — start the showcase pod first"; exit 1; fi; \
	  echo "==> pulling $$AUDIT from $(SHOWCASE_HOST)"; \
	  scp $(SHOWCASE_HOST):$$AUDIT /tmp/case_mgmt_audit.jsonl; \
	  echo "==> verifying chain"; \
	  dist/audit-verifier verify-chain /tmp/case_mgmt_audit.jsonl

# ── Go-Demos (statisch gelinkt) ────────────────────────────────────

GO_DEMOS := $(BUILD_DIR)/echo-server $(BUILD_DIR)/reverse-proxy $(BUILD_DIR)/api-server

go-demos: $(GO_DEMOS)

$(BUILD_DIR)/echo-server: demos/echo-server/main.go
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $@ $<

$(BUILD_DIR)/reverse-proxy: demos/reverse-proxy/main.go
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $@ $<

$(BUILD_DIR)/api-server: demos/api-server/main.go
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $@ $<

# ── Install (local build) ──────────────────────────────
#
# Installs from a local build. For production, use install.sh
# which handles downloads, upgrades, and architecture detection.

install: release
	@if [ ! -x "$(RT_BIN)" ]; then \
	    echo "ERROR: RT_BIN=$(RT_BIN) not found or not executable."; \
	    echo "  Build erlkoenig_rt separately (cmake --build) or pass"; \
	    echo "  RT_BIN=/path/to/erlkoenig_rt on the command line."; \
	    exit 1; \
	fi
	@echo "Installing to $(PREFIX) ..."
	@# Service user (idempotent)
	id -u $(SERVICE_USER) >/dev/null 2>&1 || \
		useradd --system --no-create-home --shell /usr/sbin/nologin $(SERVICE_USER)
	@# Directories
	mkdir -p $(PREFIX) $(PREFIX)/rt $(PREFIX)/rt/demo /etc/erlkoenig /var/lib/erlkoenig/volumes
	@# Extract OTP release
	tar xzf dist/erlkoenig-*.tar.gz -C $(PREFIX)
	@# C runtime
	install -m 755 $(RT_BIN) $(PREFIX)/rt/erlkoenig_rt
	chown root:root $(PREFIX)/rt/erlkoenig_rt
	setcap cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,cap_setpcap,cap_setuid,cap_setgid,cap_dac_override,cap_bpf,cap_sys_resource+ep $(PREFIX)/rt/erlkoenig_rt
	@# Ownership: root owns files, service user can read
	chown -R root:$(SERVICE_USER) $(PREFIX)
	chmod 750 $(PREFIX)
	[ -f $(PREFIX)/bin/erlkoenig_run ] && chmod 755 $(PREFIX)/bin/erlkoenig_run || true
	[ -f $(PREFIX)/dist/erlkoenig.service ] && chmod 644 $(PREFIX)/dist/erlkoenig.service || true
	@# RT dir owned by root (file capabilities)
	chown -R root:root $(PREFIX)/rt
	@# Volume dir owned by service user
	chown $(SERVICE_USER):$(SERVICE_USER) /var/lib/erlkoenig/volumes
	@# Systemd symlink
	@if [ -d /etc/systemd/system ] && [ -f $(PREFIX)/dist/erlkoenig.service ]; then \
		ln -sf $(PREFIX)/dist/erlkoenig.service /etc/systemd/system/erlkoenig.service; \
		systemctl daemon-reload; \
		echo "  Systemd unit symlinked"; \
	fi
	@echo ""
	@echo "Done. Next steps:"
	@echo "  1. Start:  sudo systemctl start erlkoenig"
	@echo "  2. Status: sudo systemctl status erlkoenig"
	@echo "  3. Logs:   journalctl -u erlkoenig -f"

uninstall:
	@echo "Uninstalling erlkoenig ..."
	-systemctl stop erlkoenig 2>/dev/null || true
	-systemctl disable erlkoenig 2>/dev/null || true
	rm -f /etc/systemd/system/erlkoenig.service
	-systemctl daemon-reload 2>/dev/null || true
	rm -rf $(PREFIX)
	@echo "Done."
	@echo "  Note: User '$(SERVICE_USER)' not removed. Run: userdel $(SERVICE_USER)"
	@echo "  Note: /var/lib/erlkoenig/volumes/ not removed (persistent data)."
	@echo "  Note: /etc/erlkoenig/ not removed (configuration)."

# ── CI artifact download ─────────────────────────────────

fetch-artifacts:
ifdef RUN_ID
	gh run download $(RUN_ID) -D /tmp/erlkoenig-artifacts
else
	gh run download -D /tmp/erlkoenig-artifacts
endif
	@echo "Artifacts in /tmp/erlkoenig-artifacts/"
	@echo "Install with: sudo sh install.sh --local /tmp/erlkoenig-artifacts"

# ── Install smoke gate ───────────────────────────────────
#
# Builds the release tarball, deploys it to HOST via install.sh, and
# probes the minimum operator surface that must work before further
# integration tests are meaningful. Designed to catch the regressions
# we have hit in this area: stale per-version wrappers, vm.args path
# drift, daemon failing to come back online after upgrade.
#
# Usage:  make install-smoke HOST=erlkoenig-2__root
# Optional: PREFIX=, RT_BIN=, ARTIFACT=, KEEP=1 (see tools/install-smoke.sh)
install-smoke:
ifndef HOST
	@echo "Usage: make install-smoke HOST=user@host"
	@exit 2
endif
	@# Only forward RT_BIN if the caller set it explicitly on the
	@# command line — otherwise tools/install-smoke.sh picks its own
	@# remote-side default (/opt/erlkoenig/rt/erlkoenig_rt). The
	@# top-level RT_BIN ?= is a *local* path used by `make install`
	@# and would not exist on the target host.
	bash tools/install-smoke.sh HOST=$(HOST) \
	  $(if $(filter command,$(origin PREFIX)),PREFIX=$(PREFIX)) \
	  $(if $(filter command,$(origin RT_BIN)),RT_BIN=$(RT_BIN)) \
	  $(if $(filter command,$(origin ARTIFACT)),ARTIFACT=$(ARTIFACT)) \
	  $(if $(filter command,$(origin KEEP)),KEEP=$(KEEP))

# ── Version Tag ─────────────────────────────────────────
CURRENT_VERSION = $(shell grep -oP '(?<=\{release, \{erlkoenig, ")[^"]+' rebar.config)
VERSION_FILES = rebar.config apps/erlkoenig/src/erlkoenig.app.src dsl/mix.exs install.sh dist/ek.escript

tag:
ifndef VERSION
	$(error Usage: make tag VERSION=X.Y.Z)
endif
	@if ! echo "$(VERSION)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "Error: VERSION must be semver (e.g., 0.2.0)" >&2; exit 1; \
	fi
	@BRANCH=$$(git branch --show-current); \
	if [ "$$BRANCH" != "main" ]; then \
		echo "Error: tags are only allowed from main (currently on $$BRANCH)" >&2; \
		echo "  git checkout main && git merge dev-rudi && make tag VERSION=$(VERSION)" >&2; \
		exit 1; \
	fi
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "Error: working tree is dirty — commit or stash first" >&2; exit 1; \
	fi
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "Error: tag v$(VERSION) already exists" >&2; exit 1; \
	fi
	@echo "Bumping version: $(CURRENT_VERSION) -> $(VERSION)"
	sed -i 's/{release, {erlkoenig, "[^"]*"}/{release, {erlkoenig, "$(VERSION)"}/' rebar.config
	sed -i 's/{vsn, "[^"]*"}/{vsn, "$(VERSION)"}/' apps/erlkoenig/src/erlkoenig.app.src
	sed -i 's/version: "[^"]*"/version: "$(VERSION)"/' dsl/mix.exs
	sed -i 's/--version v[0-9]*\.[0-9]*\.[0-9]*/--version v$(VERSION)/' install.sh
	sed -i 's/-define(EK_VERSION, "[^"]*")/-define(EK_VERSION, "$(VERSION)")/' dist/ek.escript
	git add $(VERSION_FILES)
	git commit -m "chore: bump version to $(VERSION)"
	git tag -a "v$(VERSION)" -m "$(if $(MSG),$(MSG),v$(VERSION))"
	@echo ""
	@echo "Tagged v$(VERSION). Push with:"
	@echo "  git push origin main v$(VERSION)"

# ── Clean ────────────────────────────────────────────────

clean: clean-erl clean-dsl
	rm -rf build dist

clean-erl:
	rebar3 clean
	rm -rf _build
	rm -f $(INT_TESTS)/test_helper.beam

clean-dsl:
	cd dsl && mix clean
	rm -rf dsl/_build
