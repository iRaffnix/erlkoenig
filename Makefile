# Erlkoenig Makefile
# ==================
#
# Build:
#   make              — Alles: bauen, testen, Release
#   make check        — Alle Tests ohne Root (eunit + dialyzer + dsl)
#   make rt           — C-Runtime (static musl)
#   make rt-san       — C-Runtime mit ASan+UBSan (Entwicklung)
#   make test-rt      — C-Runtime Unit Tests (braucht libcheck, sudo fuer alle)
#   make erl          — Erlang kompilieren
#   make test         — eunit Tests (kein Root)
#   make dialyzer     — Dialyzer Typanalyse
#   make integration  — Integrationstests (braucht sudo)
#   make release      — OTP Release-Tarball (BEAM + ERTS, ohne C-Runtime)
#   make dsl          — Elixir-DSL kompilieren
#   make dsl-escript  — Standalone erlkoenig-dsl Binary (1.4 MB, braucht nur erl)
#   make test-dsl     — Elixir-DSL Tests
#
# Install:
#   sudo sh install.sh --version vX.Y.Z
#   sudo sh install.sh --local /tmp/artifacts
#   sudo make install     — Install from local build
#   sudo make uninstall   — Remove installation
#   make fetch-artifacts  — Download CI artifacts via gh
#
# Release:
#   make tag VERSION=0.2.0
#
#   make clean        — Alles aufraeumen

.PHONY: all check rt rt-san erl test test-rt dialyzer integration release \
        dsl dsl-escript test-dsl go-demos \
        fmt fmt-check xref lint \
        install uninstall fetch-artifacts \
        tag clean clean-rt clean-erl clean-dsl

PREFIX          ?= /opt/erlkoenig
SERVICE_USER    ?= erlkoenig

BUILD_DIR       := build/release
BUILD_SAN       := build/san
RT_BIN          := $(BUILD_DIR)/erlkoenig_rt
RT_BIN_SAN      := $(BUILD_SAN)/erlkoenig_rt
INT_TESTS       := integration-tests

# ── Hauptziel ─────────────────────────────────────────────

all: rt erl check release

# ── Alle Tests (kein Root) ──────────────────────────────

check: lint test dialyzer test-dsl

# ── C-Runtime (static musl) ──────────────────────────────

rt: $(RT_BIN)

$(RT_BIN): $(BUILD_DIR)/Makefile $(wildcard c-runtime/*.c c-runtime/*.h)
	cmake --build $(BUILD_DIR) -j$$(nproc)

$(BUILD_DIR)/Makefile:
	CC=musl-gcc cmake -B $(BUILD_DIR) \
		-DERLKOENIG_BUILD_DEMOS=ON \
		-DCMAKE_BUILD_TYPE=Release

# ── C-Runtime (Sanitizer) ────────────────────────────────

rt-san: $(RT_BIN_SAN)

$(RT_BIN_SAN): $(BUILD_SAN)/Makefile $(wildcard c-runtime/*.c c-runtime/*.h)
	cmake --build $(BUILD_SAN) -j$$(nproc)

$(BUILD_SAN)/Makefile:
	cmake -B $(BUILD_SAN) \
		-DERLKOENIG_SANITIZE=ON \
		-DERLKOENIG_BUILD_DEMOS=ON \
		-DCMAKE_BUILD_TYPE=Debug

# ── C-Runtime Unit Tests (libcheck) ─────────────────────
#
# Tests mit echten Kernel-Ops (minijail-Stil).
# Ohne Root laufen nur die unprivilegierten Tests (rlimits, seccomp, signals).
# Mit sudo laufen alle 12 Tests (namespaces, mounts, pivot_root, caps).

BUILD_TEST      := build/test
TEST_BIN        := $(BUILD_TEST)/test/test_container_setup

test-rt: $(TEST_BIN)
	@echo ""
	@echo "==> C-Runtime Unit Tests"
	@echo ""
	$(TEST_BIN)

$(TEST_BIN): $(BUILD_TEST)/Makefile $(wildcard c-runtime/*.c c-runtime/*.h c-runtime/test/*.c)
	cmake --build $(BUILD_TEST) -j$$(nproc)

$(BUILD_TEST)/Makefile:
	cmake -B $(BUILD_TEST) \
		-DERLKOENIG_BUILD_TESTS=ON \
		-DERLKOENIG_BUILD_DEMOS=OFF \
		-DCMAKE_BUILD_TYPE=Debug

# ── Quality ──────────────────────────────────────────────

fmt:
	rebar3 fmt

fmt-check:
	rebar3 fmt --check

xref: erl
	rebar3 xref

lint: fmt-check xref dialyzer

# ── Erlang ───────────────────────────────────────────────

erl:
	rebar3 compile

# ── Tests ────────────────────────────────────────────────

test: erl
	rebar3 eunit

dialyzer: erl
	@RESULT=$$(rebar3 dialyzer 2>&1); RC=$$?; echo "$$RESULT" | tail -20; \
	if echo "$$RESULT" | grep -q "no_return\|will never be called\|invalid_contract\|has no local return"; then \
		echo ""; echo "ERROR: Dialyzer found real type errors"; exit 1; \
	fi; \
	echo "Dialyzer: OK"

integration: rt erl dsl-escript
	@echo ""
	@echo "==> Integration Tests (braucht sudo)"
	@echo ""
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "ERROR: Integration tests need root. Run: sudo make integration"; \
		exit 1; \
	fi
	erlc -o $(INT_TESTS) $(INT_TESTS)/test_helper.erl
	@bash $(INT_TESTS)/run_all.sh

# ── Elixir DSL ──────────────────────────────────────────

dsl:
	cd dsl && mix deps.get && mix compile

dsl-escript: dsl
	cd dsl && mix escript.build
	@echo ""
	@echo "==> dsl/erlkoenig-dsl"

test-dsl:
	cd dsl && mix test

# ── Release ──────────────────────────────────────────────
#
# OTP Release: BEAM + ERTS + erlkoenig_core + erlkoenig_nft
# Kein Erlang auf dem Zielserver noetig.
# C-Runtime ist NICHT enthalten — wird separat via install.sh installiert.
# Discovery: {rt_path, auto} findet /opt/erlkoenig/rt/erlkoenig_rt

release: erl dsl-escript
	rebar3 release
	rebar3 tar
	@mkdir -p dist
	cp _build/default/rel/erlkoenig/erlkoenig-*.tar.gz dist/
	cp dsl/erlkoenig-dsl dist/
	@echo ""
	@echo "==> dist/$$(cd dist && ls erlkoenig-*.tar.gz)"
	@echo "==> dist/erlkoenig-dsl"

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

install: release rt
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
	@# DSL escript (if built)
	@[ -f dsl/erlkoenig-dsl ] && install -m 755 dsl/erlkoenig-dsl $(PREFIX)/bin/erlkoenig-dsl || true
	@# Ownership: root owns files, service user can read
	chown -R root:$(SERVICE_USER) $(PREFIX)
	chmod 750 $(PREFIX)
	[ -f $(PREFIX)/bin/erlkoenig_run ] && chmod 755 $(PREFIX)/bin/erlkoenig_run || true
	[ -f $(PREFIX)/bin/erlkoenig-dsl ] && chmod 755 $(PREFIX)/bin/erlkoenig-dsl || true
	[ -f $(PREFIX)/dist/erlkoenig.service ] && chmod 644 $(PREFIX)/dist/erlkoenig.service || true
	@# RT dir owned by root (file capabilities)
	chown -R root:root $(PREFIX)/rt
	@# Volume dir owned by service user
	chown $(SERVICE_USER):$(SERVICE_USER) /var/lib/erlkoenig/volumes
	@# Fix escript shebang to bundled ERTS
	@ERTS_BIN=$$(ls -d $(PREFIX)/erts-*/bin 2>/dev/null | head -1); \
	if [ -n "$$ERTS_BIN" ] && [ -f $(PREFIX)/bin/erlkoenig-dsl ]; then \
		sed -i "1s|.*|#!$$ERTS_BIN/escript|" $(PREFIX)/bin/erlkoenig-dsl; \
		echo "  DSL shebang: $$ERTS_BIN/escript"; \
	fi
	@# CLI symlink
	@[ -f $(PREFIX)/bin/erlkoenig-dsl ] && ln -sf $(PREFIX)/bin/erlkoenig-dsl /usr/local/bin/erlkoenig-dsl || true
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
	rm -f /usr/local/bin/erlkoenig-dsl
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

# ── Version Tag ─────────────────────────────────────────
CURRENT_VERSION = $(shell grep -oP '(?<=\{release, \{erlkoenig, ")[^"]+' rebar.config)
VERSION_FILES = rebar.config apps/erlkoenig_core/src/erlkoenig_core.app.src dsl/mix.exs install.sh

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
	sed -i 's/{vsn, "[^"]*"}/{vsn, "$(VERSION)"}/' apps/erlkoenig_core/src/erlkoenig_core.app.src
	sed -i 's/version: "[^"]*"/version: "$(VERSION)"/' dsl/mix.exs
	sed -i 's/--version v[0-9]*\.[0-9]*\.[0-9]*/--version v$(VERSION)/' install.sh
	git add $(VERSION_FILES)
	git commit -m "chore: bump version to $(VERSION)"
	git tag -a "v$(VERSION)" -m "$(if $(MSG),$(MSG),v$(VERSION))"
	@echo ""
	@echo "Tagged v$(VERSION). Push with:"
	@echo "  git push origin main v$(VERSION)"

# ── Clean ────────────────────────────────────────────────

clean: clean-rt clean-erl clean-dsl
	rm -rf dist

clean-rt:
	rm -rf build

clean-erl:
	rebar3 clean
	rm -rf _build
	rm -f $(INT_TESTS)/test_helper.beam

clean-dsl:
	cd dsl && mix clean
	rm -rf dsl/_build
