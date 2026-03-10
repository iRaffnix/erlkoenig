#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#!/bin/bash
# verify-deploy.sh — Post-Deploy Smoke Tests
#
# Prueft ob alle Features auf dem Server funktionieren.
# Usage: make verify HOST=root@server
#        oder: ssh root@server 'bash -s' < scripts/verify-deploy.sh

set -euo pipefail

PASS=0
FAIL=0
ERL="/opt/erlkoenig/bin/erlkoenig"
DSL="/opt/erlkoenig/bin/erlkoenig-dsl"

# CLI-Befehle brauchen den gleichen Cookie wie der laufende Node
export VMARGS_PATH=/etc/erlkoenig/vm.args

pass() { echo "  OK   $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL $1: $2"; FAIL=$((FAIL + 1)); }

echo ""
echo "=== Erlkoenig Post-Deploy Verification ==="
echo ""

# ── 1. Service ──────────────────────────────────────────

echo "--- Service ---"

if systemctl is-active --quiet erlkoenig; then
    pass "systemd service running"
else
    fail "systemd service running" "not active"
fi

if systemctl show erlkoenig --property=MainPID --value | grep -qv '^0$'; then
    pass "BEAM process alive"
else
    fail "BEAM process alive" "PID=0"
fi

# ── 2. Privilege Separation ────────────────────────────

echo ""
echo "--- Privilege Separation ---"

# BEAM laeuft als erlkoenig, nicht root
BEAM_USER=$(ps -o user= -p "$(systemctl show erlkoenig --property=MainPID --value)" 2>/dev/null || echo "unknown")
if [ "$BEAM_USER" = "erlkoenig" ]; then
    pass "BEAM runs as user erlkoenig"
elif [ "$BEAM_USER" = "root" ]; then
    fail "BEAM runs as user erlkoenig" "running as root"
else
    fail "BEAM runs as user erlkoenig" "running as $BEAM_USER"
fi

# systemd User=erlkoenig
if systemctl show erlkoenig --property=User --value | grep -q 'erlkoenig'; then
    pass "systemd User=erlkoenig"
else
    fail "systemd User=erlkoenig" "$(systemctl show erlkoenig --property=User --value)"
fi

# /opt/erlkoenig owned by erlkoenig
OPT_OWNER=$(stat -c '%U' /opt/erlkoenig 2>/dev/null || echo "missing")
if [ "$OPT_OWNER" = "erlkoenig" ]; then
    pass "/opt/erlkoenig owned by erlkoenig"
else
    fail "/opt/erlkoenig owned by erlkoenig" "owned by $OPT_OWNER"
fi

# /etc/erlkoenig owned by erlkoenig
ETC_OWNER=$(stat -c '%U' /etc/erlkoenig 2>/dev/null || echo "missing")
if [ "$ETC_OWNER" = "erlkoenig" ]; then
    pass "/etc/erlkoenig owned by erlkoenig"
else
    fail "/etc/erlkoenig owned by erlkoenig" "owned by $ETC_OWNER"
fi

# erlkoenig_rt owned by root (nicht durch erlkoenig user aenderbar)
RT_OWNER=$(stat -c '%U' /usr/lib/erlkoenig/erlkoenig_rt 2>/dev/null || echo "missing")
if [ "$RT_OWNER" = "root" ]; then
    pass "erlkoenig_rt owned by root (immutable)"
else
    fail "erlkoenig_rt owned by root" "owned by $RT_OWNER"
fi

# ── 3. Security ───────────────────────────────────────

echo ""
echo "--- Security ---"

# Cookie nicht der Default
if grep -q 'erlkoenig_dev' /etc/erlkoenig/vm.args 2>/dev/null; then
    fail "cookie randomized" "still using default cookie 'erlkoenig_dev'"
elif grep -q 'setcookie' /etc/erlkoenig/vm.args 2>/dev/null; then
    pass "cookie randomized"
else
    fail "cookie randomized" "/etc/erlkoenig/vm.args not found or no cookie"
fi

# vm.args Permissions
PERMS=$(stat -c '%a' /etc/erlkoenig/vm.args 2>/dev/null || echo "missing")
if [ "$PERMS" = "600" ]; then
    pass "vm.args permissions (600)"
else
    fail "vm.args permissions (600)" "got $PERMS"
fi

# vm.args owned by erlkoenig
VMARGS_OWNER=$(stat -c '%U' /etc/erlkoenig/vm.args 2>/dev/null || echo "missing")
if [ "$VMARGS_OWNER" = "erlkoenig" ]; then
    pass "vm.args owned by erlkoenig"
else
    fail "vm.args owned by erlkoenig" "owned by $VMARGS_OWNER"
fi

# /etc/erlkoenig Permissions
DIR_PERMS=$(stat -c '%a' /etc/erlkoenig 2>/dev/null || echo "missing")
if [ "$DIR_PERMS" = "700" ]; then
    pass "/etc/erlkoenig permissions (700)"
else
    fail "/etc/erlkoenig permissions (700)" "got $DIR_PERMS"
fi

# EPMD nur auf localhost
if systemctl show erlkoenig --property=Environment --value | grep -q 'ERL_EPMD_ADDRESS=127.0.0.1'; then
    pass "EPMD bound to 127.0.0.1"
else
    fail "EPMD bound to 127.0.0.1" "ERL_EPMD_ADDRESS not set in systemd"
fi

# Distribution auf localhost
if grep -q 'inet_dist_use_interface' /etc/erlkoenig/vm.args 2>/dev/null; then
    pass "distribution bound to 127.0.0.1"
else
    fail "distribution bound to 127.0.0.1" "inet_dist_use_interface not in vm.args"
fi

# Distribution Ports gepinnt
if grep -q 'inet_dist_listen_min' /etc/erlkoenig/vm.args 2>/dev/null; then
    pass "distribution ports pinned"
else
    fail "distribution ports pinned" "inet_dist_listen_min not in vm.args"
fi

# EPMD nicht von aussen erreichbar (127.0.0.1 und [::1] sind ok)
if ! ss -tlnp 2>/dev/null | grep ':4369' | grep -Ev '127\.0\.0\.1|\[::1\]' | grep -q .; then
    pass "EPMD not exposed to network"
else
    fail "EPMD not exposed to network" "listening on non-localhost"
fi

# ── 4. C-Runtime ──────────────────────────────────────

echo ""
echo "--- C-Runtime ---"

if [ -x /usr/lib/erlkoenig/erlkoenig_rt ]; then
    pass "erlkoenig_rt installed"
else
    fail "erlkoenig_rt installed" "not found or not executable"
fi

if getcap /usr/lib/erlkoenig/erlkoenig_rt 2>/dev/null | grep -q 'cap_sys_admin'; then
    pass "erlkoenig_rt capabilities set"
else
    fail "erlkoenig_rt capabilities set" "missing capabilities"
fi

# ── 5. Operator Shell (ek) ────────────────────────────

echo ""
echo "--- Operator Shell ---"

# ek module geladen? (eval laeuft auf dem laufenden Node via erl_call)
# WICHTIG: </dev/null verhindert, dass erl_call den bash-stdin (das Script) frisst.
if $ERL eval 'erlang:function_exported(ek, help, 0).' </dev/null 2>/dev/null | grep -q 'true'; then
    pass "ek module loaded"
else
    fail "ek module loaded" "module not found"
fi

# Pruefe ob zentrale ek-Funktionen exportiert sind.
# ek:ps() / ek:health() / ek:zones() nutzen io:format und blockieren in erl_call.
if $ERL eval 'erlang:function_exported(ek, ps, 0).' </dev/null 2>/dev/null | grep -q 'true'; then
    pass "ek:ps/0 exported"
else
    fail "ek:ps/0 exported" "function not found"
fi

if $ERL eval 'erlang:function_exported(ek, health, 0).' </dev/null 2>/dev/null | grep -q 'true'; then
    pass "ek:health/0 exported"
else
    fail "ek:health/0 exported" "function not found"
fi

if $ERL eval 'erlang:function_exported(ek, zones, 0).' </dev/null 2>/dev/null | grep -q 'true'; then
    pass "ek:zones/0 exported"
else
    fail "ek:zones/0 exported" "function not found"
fi

# ── 6. DSL Escript ────────────────────────────────────

echo ""
echo "--- DSL Escript ---"

if [ -x "$DSL" ]; then
    pass "erlkoenig-dsl installed"
else
    fail "erlkoenig-dsl installed" "not found or not executable"
fi

# --help exits with 1 (escript convention), pipefail wuerde das als Fehler werten
if ($DSL --help </dev/null 2>/dev/null || true) | grep -q 'compile\|validate'; then
    pass "erlkoenig-dsl --help works"
else
    fail "erlkoenig-dsl --help" "no output"
fi

# Beispiel validieren
if [ -d /opt/erlkoenig/examples ]; then
    EXAMPLE=$(ls /opt/erlkoenig/examples/*.exs 2>/dev/null | head -1)
    if [ -n "$EXAMPLE" ]; then
        if $DSL validate "$EXAMPLE" </dev/null 2>/dev/null; then
            pass "erlkoenig-dsl validate example"
        else
            fail "erlkoenig-dsl validate example" "validation failed"
        fi
    else
        fail "examples installed" "no .exs files in /opt/erlkoenig/examples/"
    fi
else
    fail "examples installed" "/opt/erlkoenig/examples/ not found"
fi

# Beispiel kompilieren
if [ -n "${EXAMPLE:-}" ]; then
    TMPTERM=$(mktemp /tmp/verify-XXXXXX.term)
    if $DSL compile "$EXAMPLE" -o "$TMPTERM" </dev/null 2>/dev/null; then
        pass "erlkoenig-dsl compile example"
        rm -f "$TMPTERM"
    else
        fail "erlkoenig-dsl compile example" "compilation failed"
        rm -f "$TMPTERM"
    fi
fi

# ── 7. Shell Completion ──────────────────────────────

echo ""
echo "--- Shell Completion ---"

if $DSL --completions bash </dev/null 2>/dev/null | grep -q 'complete\|_erlkoenig'; then
    pass "bash completion generates output"
else
    fail "bash completion" "no output"
fi

if [ -f /etc/bash_completion.d/erlkoenig-dsl ]; then
    pass "bash completion installed"
else
    fail "bash completion installed" "/etc/bash_completion.d/erlkoenig-dsl not found"
fi

# ── 8. Vim Plugin ────────────────────────────────────

echo ""
echo "--- Vim Plugin ---"

if [ -f /opt/erlkoenig/share/vim/syntax/erlkoenig.vim ]; then
    pass "vim syntax file deployed"
else
    fail "vim syntax file" "not found"
fi

if [ -f /opt/erlkoenig/share/vim/ftdetect/erlkoenig.vim ]; then
    pass "vim ftdetect file deployed"
else
    fail "vim ftdetect file" "not found"
fi

# ── 9. Live Container Test ───────────────────────────

echo ""
echo "--- Live Container Test ---"

# Demo-Binary vorhanden?
DEMO="/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
if [ -x "$DEMO" ]; then
    pass "demo binary available"

    # Container spawnen, pruefen, stoppen
    # eval laeuft auf dem laufenden Node (kein halt!), ek:ps() Output
    # geht auf den Server-stdout. Wir pruefen nur ob spawn/stop ohne Crash laeuft.
    RESULT=$($ERL eval '
        {ok, Pid} = erlkoenig_core:spawn(<<"/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server">>, #{
            ip => {10, 0, 0, 250},
            args => [<<"7777">>],
            name => <<"verify_test">>
        }),
        timer:sleep(1000),
        Info = erlkoenig_core:inspect(Pid),
        erlkoenig_core:stop(Pid),
        timer:sleep(500),
        binary_to_list(maps:get(name, Info)).
    ' </dev/null 2>&1) || true

    if echo "$RESULT" | grep -q 'verify_test'; then
        pass "container spawn + info + stop"
    else
        fail "container spawn + info + stop" "got: $RESULT"
    fi
else
    fail "demo binary available" "$DEMO not found"
    fail "container spawn + ek:ps()" "skipped (no demo binary)"
fi

# ── Ergebnis ──────────────────────────────────────────

echo ""
echo "==========================================="
TOTAL=$((PASS + FAIL))
echo "  $TOTAL checks: $PASS passed, $FAIL failed"
echo "==========================================="
echo ""

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
