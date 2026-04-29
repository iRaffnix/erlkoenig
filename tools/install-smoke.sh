#!/usr/bin/env bash
# tools/install-smoke.sh — install-and-probe smoke gate for an
# erlkoenig release.
#
# Builds the release tarball locally, deploys it via the bundled
# install.sh on a target host, restarts the daemon, then probes the
# minimum operator surface that must work before any further test
# is meaningful:
#
#   ek --version         (matches the version we just built)
#   ek node ping         (daemon reachable)
#   ek doctor            (no blocking issues)
#   ek ct list           (valid JSON, empty array is OK)
#   ek pod list          (valid JSON, empty array is OK)
#   ek vol list          (valid JSON, current store)
#
# Catches the class of bugs we hit during this session:
#   - stale per-version wrapper /opt/erlkoenig/bin/erlkoenig-X.Y.Z
#     left behind, systemd picks the wrong version
#   - vm.args path mismatch after partial install
#   - daemon not coming up at all
#
# Usage:
#
#   tools/install-smoke.sh HOST=erlkoenig-2__root
#
#   make install-smoke HOST=erlkoenig-2__root
#
# Optional environment:
#
#   KEEP=1            Skip the final "summary OK" echo, leave host
#                     in installed state for further probing.
#   PREFIX=/opt/erlkoenig
#                     Prefix on the target host (passed to install.sh).
#   RT_BIN=/opt/erlkoenig/rt/erlkoenig_rt
#                     Path to the runtime binary on the target host.
#                     Default: reuse the existing one already installed.
#                     Override if you also want to refresh the runtime.
#   ARTIFACT=path/to/erlkoenig-X.Y.Z.tar.gz
#                     Skip `make release` and use this artifact instead.
#
# Exit codes:
#   0  — install succeeded and all probes passed
#   1  — install failed, version mismatch, or any probe failed
#   2  — usage / setup error

set -eu

HOST="${HOST:-}"
PREFIX="${PREFIX:-/opt/erlkoenig}"
RT_BIN="${RT_BIN:-/opt/erlkoenig/rt/erlkoenig_rt}"
ARTIFACT="${ARTIFACT:-}"
KEEP="${KEEP:-0}"

# Allow `HOST=foo` style positional invocation (e.g. via Make).
for arg in "$@"; do
    case "$arg" in
        HOST=*)     HOST="${arg#HOST=}"     ;;
        PREFIX=*)   PREFIX="${arg#PREFIX=}" ;;
        RT_BIN=*)   RT_BIN="${arg#RT_BIN=}" ;;
        ARTIFACT=*) ARTIFACT="${arg#ARTIFACT=}" ;;
        KEEP=*)     KEEP="${arg#KEEP=}"     ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "install-smoke: unknown argument '$arg'" >&2
            exit 2
            ;;
    esac
done

if [ -z "$HOST" ]; then
    echo "install-smoke: HOST=... is required" >&2
    exit 2
fi

# --- Pretty output ----------------------------------------------------

GREEN=$'\e[32m'
RED=$'\e[31m'
DIM=$'\e[2m'
RESET=$'\e[0m'

info() { printf '  %s[*]%s %s\n' "$DIM" "$RESET" "$*"; }
ok()   { printf '  %s[OK]%s %s\n' "$GREEN" "$RESET" "$*"; }
fail() { printf '  %s[FAIL]%s %s\n' "$RED" "$RESET" "$*" >&2; }

step_pass=0
step_fail=0

run_step() {
    local name="$1"; shift
    if "$@"; then
        ok "$name"
        step_pass=$((step_pass + 1))
    else
        fail "$name"
        step_fail=$((step_fail + 1))
    fi
}

# --- 1. Build (or reuse) the release artifact ------------------------

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [ -z "$ARTIFACT" ]; then
    info "make release (this may take a minute)"
    if ! make release >/tmp/install-smoke-build.log 2>&1; then
        fail "make release failed; see /tmp/install-smoke-build.log"
        exit 1
    fi
fi

if [ -z "$ARTIFACT" ]; then
    ARTIFACT="$(ls -t dist/erlkoenig-*.tar.gz 2>/dev/null | head -1 || true)"
fi

if [ -z "$ARTIFACT" ] || [ ! -f "$ARTIFACT" ]; then
    fail "release artifact not found (looked for dist/erlkoenig-*.tar.gz)"
    exit 1
fi

ARTIFACT_BASE="$(basename "$ARTIFACT")"
EXPECTED_VERSION="$(echo "$ARTIFACT_BASE" \
                      | sed -E 's/^erlkoenig-(.+)\.tar\.gz$/\1/')"
info "artifact: $ARTIFACT_BASE  (expected version: $EXPECTED_VERSION)"

# Pre-flight the tarball manifest. `make release` already runs this
# gate, but install-smoke also accepts an externally-supplied
# ARTIFACT= — for those, this is the only place that catches a
# build-side defect before the host install starts.
#
# Also passes --expected-version: install-smoke derives EXPECTED_VERSION
# from the filename, the audit derives its version from start_erl.data
# inside the tarball. Without this cross-check, a misnamed or repackaged
# tarball could pass both the smoke-side filename probe and the audit's
# own internal-consistency probe, then explode at `ek --version` post-install.
info "audit tarball manifest"
if ! "$REPO_ROOT/tools/release-tarball-audit.sh" --quiet \
        --expected-version "$EXPECTED_VERSION" "$ARTIFACT"; then
    fail "tarball manifest audit failed for $ARTIFACT — re-run audit without --quiet for detail"
    exit 1
fi
ok "tarball manifest clean"

# --- 2. Stage artifacts on the target ---------------------------------

REMOTE_TMP="/tmp/install-smoke-$$"

cleanup_remote() {
    ssh "$HOST" "rm -rf '$REMOTE_TMP'" >/dev/null 2>&1 || true
}
trap cleanup_remote EXIT

info "stage artifacts on $HOST in $REMOTE_TMP"
ssh "$HOST" "mkdir -p '$REMOTE_TMP'" >/dev/null
scp -q "$ARTIFACT" "$HOST:$REMOTE_TMP/" >/dev/null
scp -q "$REPO_ROOT/install.sh" "$HOST:$REMOTE_TMP/install.sh" >/dev/null

# --- 3. Run install.sh on the target ---------------------------------

info "run install.sh on $HOST (this stops, replaces, restarts the daemon)"

INSTALL_LOG="/tmp/install-smoke-install-$$.log"
if ! ssh "$HOST" "
    set -e
    cd '$REMOTE_TMP'
    sh install.sh \
        --erlkoenig-tar '$REMOTE_TMP/$ARTIFACT_BASE' \
        --rt-bin '$RT_BIN' \
        --prefix '$PREFIX' \
        --force
" >"$INSTALL_LOG" 2>&1; then
    fail "install.sh failed on $HOST (log: $INSTALL_LOG)"
    sed -n '1,40p' "$INSTALL_LOG" >&2
    echo "..." >&2
    tail -n 40 "$INSTALL_LOG" >&2
    exit 1
fi
ok "install.sh completed"

info "ensure erlkoenig service is running"
if ! ssh "$HOST" "systemctl start erlkoenig" >/dev/null 2>&1; then
    fail "systemctl start erlkoenig failed on $HOST"
    ssh "$HOST" "systemctl status erlkoenig --no-pager -l || true" >&2
    exit 1
fi
ok "erlkoenig service started"

# --- 4. Probes ---------------------------------------------------------

# Stale-wrapper guard — the bug we hit twice during this session: an
# old `erlkoenig-OLD.VERSION` wrapper in $PREFIX/bin causes the
# version-discovery loop in /opt/erlkoenig/bin/erlkoenig to pick the
# wrong release. install.sh --force should clean it up; verify.
check_no_stale_wrapper() {
    local out
    out="$(ssh "$HOST" "ls '$PREFIX'/bin/erlkoenig-* 2>/dev/null || true")"
    local count
    count="$(printf '%s\n' "$out" | grep -c '/erlkoenig-' || true)"
    if [ "$count" -le 1 ]; then
        return 0
    fi
    fail "found multiple per-version wrappers in $PREFIX/bin:"
    printf '%s\n' "$out" >&2
    return 1
}

# Wait for the daemon to come back online after restart.
wait_ping() {
    local i
    for i in $(seq 1 30); do
        if ssh "$HOST" "PATH=$PREFIX/bin:\$PATH ek node ping" \
              >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# `ek --version` matches the freshly-installed version.
check_version_match() {
    local out
    out="$(ssh "$HOST" "PATH=$PREFIX/bin:\$PATH ek --version 2>&1" || true)"
    case "$out" in
        *"$EXPECTED_VERSION"*) return 0 ;;
        *) fail "version mismatch: got '$out', expected '$EXPECTED_VERSION'"
           return 1 ;;
    esac
}

# `ek doctor` returns no blocking issues. Warn-level findings are fine.
check_doctor_no_block() {
    local rc
    ssh "$HOST" "PATH=$PREFIX/bin:\$PATH ek doctor" \
        >/tmp/install-smoke-doctor-$$.log 2>&1 || rc=$?
    rc="${rc:-0}"
    if [ "$rc" -eq 0 ]; then
        return 0
    fi
    fail "ek doctor reported blocking issues (exit=$rc)"
    cat /tmp/install-smoke-doctor-$$.log >&2
    return 1
}

# JSON-shape probe: must be valid JSON, must be an array (possibly empty).
check_json_list() {
    local cmd="$1"
    local out
    if ! out="$(ssh "$HOST" "PATH=$PREFIX/bin:\$PATH ek --format json $cmd 2>/dev/null")"; then
        fail "ek --format json $cmd failed"
        return 1
    fi

    if printf '%s' "$out" | python3 -c '
import json
import sys

try:
    value = json.load(sys.stdin)
except Exception as exc:
    print(f"invalid JSON: {exc}", file=sys.stderr)
    sys.exit(1)

if not isinstance(value, list):
    print(f"expected JSON array, got {type(value).__name__}", file=sys.stderr)
    sys.exit(1)
' >/tmp/install-smoke-json-$$.log 2>&1; then
        return 0
    fi

    fail "ek --format json $cmd did not return a valid JSON array"
    cat /tmp/install-smoke-json-$$.log >&2
    printf 'output: %s\n' "$out" >&2
    return 1
}

check_tutorial_06_compile() {
    ssh "$HOST" "PATH=$PREFIX/bin:\$PATH ek dsl compile \
        $PREFIX/examples/tutorial/06_multi_tier.exs \
        -o /tmp/erlkoenig_install_smoke_06.term >/tmp/erlkoenig_install_smoke_06.log 2>&1"
}

# --- 5. Run the probes ------------------------------------------------

run_step "no stale per-version wrapper in bin/"  check_no_stale_wrapper
run_step "ek node ping reachable"                wait_ping
run_step "ek --version matches $EXPECTED_VERSION" check_version_match
run_step "ek doctor — no blocking issues"        check_doctor_no_block
run_step "ek dsl compile tutorial 06"            check_tutorial_06_compile
run_step "ek --format json ct list is valid"     check_json_list "ct list"
run_step "ek --format json pod list is valid"    check_json_list "pod list"
run_step "ek --format json vol list is valid"    check_json_list "vol list"

# Layout audit — assert installed file tree matches docs/INSTALL_LAYOUT.md.
# Skipped when LAYOUT_AUDIT=0 is set (e.g. on hosts with known long-lived
# drift that has not been cleaned up yet, where install-smoke is being
# used purely for the daemon-level probes).
check_layout_audit() {
    HOST="$HOST" PREFIX="$PREFIX" "$REPO_ROOT/tools/install-layout-audit.sh" \
        --quiet >/tmp/install-smoke-layout-$$.log 2>&1
}
if [ "${LAYOUT_AUDIT:-1}" = "1" ]; then
    if run_step "install layout audit (no drift under $PREFIX)" \
            check_layout_audit; then
        :
    else
        info "layout drift details:"
        cat /tmp/install-smoke-layout-$$.log >&2 || true
    fi
fi

# --- 6. Summary -------------------------------------------------------

echo ""
if [ "$step_fail" -eq 0 ]; then
    if [ "$KEEP" != "1" ]; then
        ok "install-smoke PASSED (${step_pass}/${step_pass} probes)"
    fi
    exit 0
else
    fail "install-smoke FAILED (${step_fail} probe(s) of $((step_pass + step_fail)) failed)"
    exit 1
fi
