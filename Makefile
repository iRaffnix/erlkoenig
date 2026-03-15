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
#
# Release:
#   make tag VERSION=0.2.0
#
#   make clean        — Alles aufraeumen

.PHONY: all check rt rt-san erl test test-rt dialyzer integration release \
        dsl dsl-escript test-dsl go-demos \
        tag clean clean-rt clean-erl clean-dsl

BUILD_DIR       := build/release
BUILD_SAN       := build/san
RT_BIN          := $(BUILD_DIR)/erlkoenig_rt
RT_BIN_SAN      := $(BUILD_SAN)/erlkoenig_rt
INT_TESTS       := integration-tests

# ── Hauptziel ─────────────────────────────────────────────

all: rt erl check release

# ── Alle Tests (kein Root) ──────────────────────────────

check: test dialyzer test-dsl

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
