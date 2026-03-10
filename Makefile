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
# Deploy:
#   make deploy-rt    — C-Runtime auf Zielserver (scp + setcap)
#   make deploy-erl   — OTP Release auf Zielserver
#   make deploy       — Beides (rt zuerst, dann erl)
#   make verify       — Post-Deploy Smoke Tests (SSH)
#
# Deploy braucht zwei SSH-Hosts (gleicher Server, zwei User):
#   HOST_ROOT=root@server        — setcap, systemctl
#   HOST_ERL=erlkoenig@server    — Release-Dateien, Config
#
#   make clean        — Alles aufraeumen

.PHONY: all check rt rt-san erl test test-rt dialyzer integration release \
        dsl dsl-escript test-dsl go-demos \
        deploy deploy-rt deploy-erl verify clean clean-rt clean-erl clean-dsl

BUILD_DIR       := build/release
BUILD_SAN       := build/san
RT_BIN          := $(BUILD_DIR)/erlkoenig_rt
RT_BIN_SAN      := $(BUILD_SAN)/erlkoenig_rt
INT_TESTS       := integration-tests
RT_INSTALL_DIR  := /usr/lib/erlkoenig
ERL_INSTALL_DIR := /opt/erlkoenig

# Deploy-Hosts: root fuer privilegierte Ops, erlkoenig fuer den Rest.
# Beide muessen im SSH-Config definiert sein (gleicher Server, anderer User).
#   make deploy HOST_ROOT=root@server HOST_ERL=erlkoenig@server
HOST_ROOT       := erlk-trixie__root
HOST_ERL        := erlk-trixie__erlkoenig
# Rueckwaerts-kompatibel: HOST setzt beide
ifdef HOST
HOST_ROOT       := $(HOST)
endif

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
# C-Runtime ist NICHT enthalten — wird separat via deploy-rt installiert.
# Discovery: {rt_path, auto} findet /usr/lib/erlkoenig/erlkoenig_rt

release: erl dsl-escript
	rebar3 release
	rebar3 tar
	@mkdir -p dist
	cp _build/default/rel/erlkoenig/erlkoenig-*.tar.gz dist/
	cp dsl/erlkoenig-dsl dist/
	@echo ""
	@echo "==> dist/$$(cd dist && ls erlkoenig-*.tar.gz)"
	@echo "==> dist/erlkoenig-dsl"

# ── Deploy ───────────────────────────────────────────────
#
# deploy-rt:  Statisches Binary via scp + setcap (root)
# deploy-erl: OTP Release via scp + tar + systemd
#             Dateien als erlkoenig, privilegierte Ops als root.
# deploy:     Beides, in der richtigen Reihenfolge.
#
# Zwei SSH-Hosts:
#   HOST_ROOT  — root@server (setcap, systemctl, systemd-Unit)
#   HOST_ERL   — erlkoenig@server (Release-Dateien, Config, Cookie)
#
# Ueberschreibbar:
#   make deploy HOST_ROOT=root@server HOST_ERL=erlkoenig@server

deploy: deploy-rt deploy-erl

# ── Go-Demos (statisch gelinkt) ────────────────────────────────────

GO_DEMOS := $(BUILD_DIR)/echo-server $(BUILD_DIR)/reverse-proxy $(BUILD_DIR)/api-server

go-demos: $(GO_DEMOS)

$(BUILD_DIR)/echo-server: demos/echo-server/main.go
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $@ $<

$(BUILD_DIR)/reverse-proxy: demos/reverse-proxy/main.go
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $@ $<

$(BUILD_DIR)/api-server: demos/api-server/main.go
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $@ $<

# ── deploy-rt: Braucht root (setcap, /usr/lib ownership) ──────────

deploy-rt: rt go-demos
	@echo ""
	@echo "==> Deploy C-Runtime to $(HOST_ROOT):$(RT_INSTALL_DIR)"
	ssh $(HOST_ROOT) 'mkdir -p $(RT_INSTALL_DIR)/demo'
	scp $(RT_BIN) $(HOST_ROOT):$(RT_INSTALL_DIR)/erlkoenig_rt
	scp $(BUILD_DIR)/demo/test-erlkoenig-* $(HOST_ROOT):$(RT_INSTALL_DIR)/demo/
	scp $(BUILD_DIR)/echo-server $(BUILD_DIR)/reverse-proxy $(BUILD_DIR)/api-server $(HOST_ROOT):$(RT_INSTALL_DIR)/
	ssh $(HOST_ROOT) '\
		chown root:root $(RT_INSTALL_DIR)/erlkoenig_rt && \
		chmod 755 $(RT_INSTALL_DIR)/erlkoenig_rt && \
		setcap cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,cap_setpcap,cap_setuid,cap_setgid,cap_dac_override,cap_bpf,cap_sys_resource+ep \
			$(RT_INSTALL_DIR)/erlkoenig_rt && \
		if [ -f $(ERL_INSTALL_DIR)/bin/erlkoenig_rt ]; then \
			cp $(RT_INSTALL_DIR)/erlkoenig_rt $(ERL_INSTALL_DIR)/bin/erlkoenig_rt && \
			setcap cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,cap_setpcap,cap_setuid,cap_setgid,cap_dac_override,cap_bpf,cap_sys_resource+ep \
				$(ERL_INSTALL_DIR)/bin/erlkoenig_rt; \
		fi && \
		chmod 755 $(RT_INSTALL_DIR)/echo-server $(RT_INSTALL_DIR)/reverse-proxy $(RT_INSTALL_DIR)/api-server && \
		chown -R root:root $(RT_INSTALL_DIR)/demo && \
		chmod 700 $(RT_INSTALL_DIR)/demo/*'
	@echo "==> erlkoenig_rt installed on $(HOST_ROOT)"

# ── deploy-erl: Dateien als erlkoenig, dann root fuer systemd ────

deploy-erl: release
	@echo ""
	@echo "==> Deploy OTP Release (erlkoenig@) to $(ERL_INSTALL_DIR)"
	@# ── Phase 1: Dateien als erlkoenig (kein root noetig) ──
	scp dist/erlkoenig-*.tar.gz $(HOST_ERL):~/erlkoenig-release.tar.gz
	scp dist/erlkoenig-dsl $(HOST_ERL):~/erlkoenig-dsl
	ssh $(HOST_ERL) '\
		mkdir -p $(ERL_INSTALL_DIR) && \
		tar xzf ~/erlkoenig-release.tar.gz -C $(ERL_INSTALL_DIR) && \
		mv ~/erlkoenig-dsl $(ERL_INSTALL_DIR)/bin/erlkoenig-dsl && \
		chmod 755 $(ERL_INSTALL_DIR)/bin/erlkoenig-dsl && \
		ERTS_DIR=$$(ls -d $(ERL_INSTALL_DIR)/erts-*/bin | head -1) && \
		sed -i "1s|.*|#!$$ERTS_DIR/escript|" \
			$(ERL_INSTALL_DIR)/bin/erlkoenig-dsl && \
		rm ~/erlkoenig-release.tar.gz'
	scp -r dsl/examples $(HOST_ERL):$(ERL_INSTALL_DIR)/examples
	@# ── Phase 2: Cookie + vm.args als erlkoenig ──
	ssh $(HOST_ERL) '\
		if [ ! -f /etc/erlkoenig/vm.args ]; then \
			COOKIE=$$(openssl rand -base64 32 | tr -d "/+=" | head -c 32) && \
			sed "s/erlkoenig_dev/$$COOKIE/" \
				$(ERL_INSTALL_DIR)/releases/0.1.0/vm.args \
				> /etc/erlkoenig/vm.args && \
			chmod 600 /etc/erlkoenig/vm.args && \
			echo "==> Generated new cookie in /etc/erlkoenig/vm.args"; \
		else \
			echo "==> Keeping existing /etc/erlkoenig/vm.args"; \
		fi && \
		if grep -q "erlkoenig_dev" /etc/erlkoenig/vm.args 2>/dev/null; then \
			echo "WARNING: /etc/erlkoenig/vm.args still has default cookie!"; \
		fi'
	@# ── Phase 3: Nur diese Schritte brauchen root ──
	@echo "==> Activating service (root@)"
	ssh $(HOST_ROOT) '\
		$(ERL_INSTALL_DIR)/bin/erlkoenig-dsl --completions bash \
			> /etc/bash_completion.d/erlkoenig-dsl 2>/dev/null || true && \
		cp $(ERL_INSTALL_DIR)/erlkoenig.service /usr/lib/systemd/system/ && \
		systemctl daemon-reload && \
		pkill -x epmd 2>/dev/null; sleep 1; \
		systemctl restart erlkoenig'
	@echo "==> OTP Release deployed to $(ERL_INSTALL_DIR)"

# ── Verify (Post-Deploy) ───────────────────────────────
#
# Smoke Tests via SSH: Security, ek-Shell, DSL, Completion, Vim, Container.
# Laeuft auf dem Zielserver, prueft ob alles funktioniert.

verify:
	@echo ""
	@echo "==> Verify deployment on $(HOST_ROOT)"
	ssh $(HOST_ROOT) 'bash -s' < scripts/verify-deploy.sh

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
