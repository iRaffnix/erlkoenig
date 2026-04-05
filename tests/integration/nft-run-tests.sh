#!/bin/bash
#
# erlkoenig_nft Dual-Namespace Integration Tests
#
# Compares our Netlink encoding against nft CLI output.
# Each test has a .term (our config) and .nft (reference) file.
# Both are applied in separate network namespaces, then
# nft -j list ruleset output is compared after sanitization.
#
# Usage:
#   ./run-tests.sh                     # Run all tests
#   ./run-tests.sh testcases/basic     # Run one category
#   ./run-tests.sh testcases/basic/tcp_accept  # Run one test
#   VERBOSE=1 ./run-tests.sh           # Show diffs on failure
#
# Requirements:
#   - Linux with unshare -n (network namespace support)
#   - Root (or user namespace support)
#   - nft CLI installed
#   - erlkoenig_nft release built (rebar3 as prod release)
#     OR installed at /opt/erlkoenig_nft
#
# Exit codes:
#   0 — all tests passed
#   1 — at least one test failed
#   77 — skipped (missing requirements)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERBOSE="${VERBOSE:-0}"

# ── Find erlkoenig_nft release ──────────────────────────────────

find_release() {
    # 1. Explicit env var
    if [ -n "${ERLKOENIG_NFT_DIR:-}" ] && [ -d "$ERLKOENIG_NFT_DIR/lib" ]; then
        echo "$ERLKOENIG_NFT_DIR"
        return
    fi
    # 2. Local build (_build/prod/rel)
    local local_rel="$SCRIPT_DIR/../../_build/prod/rel/erlkoenig_nft"
    if [ -d "$local_rel/lib" ]; then
        echo "$(cd "$local_rel" && pwd)"
        return
    fi
    # 3. System install
    if [ -d "/opt/erlkoenig_nft/lib" ]; then
        echo "/opt/erlkoenig_nft"
        return
    fi
    echo ""
}

ROOTDIR=$(find_release)
if [ -z "$ROOTDIR" ]; then
    echo "ERROR: erlkoenig_nft release not found." >&2
    echo "  Build: rebar3 as prod release" >&2
    echo "  Or set: ERLKOENIG_NFT_DIR=/path/to/release" >&2
    exit 77
fi

# Find erts bin directory (no glob in subshell)
ERTS_BIN=$(ls -d "$ROOTDIR"/erts-*/bin 2>/dev/null | head -1)
if [ -z "$ERTS_BIN" ]; then
    echo "ERROR: ERTS not found in $ROOTDIR" >&2
    exit 77
fi

# Check nft CLI
if ! command -v nft >/dev/null 2>&1; then
    echo "ERROR: nft CLI not found" >&2
    exit 77
fi

# Check unshare works
if ! unshare -n true 2>/dev/null; then
    echo "ERROR: unshare -n not available (need root or user namespace support)" >&2
    exit 77
fi

# Check escript
ESCRIPT="$SCRIPT_DIR/lib/nfnl_apply.escript"
if [ ! -f "$ESCRIPT" ]; then
    echo "ERROR: $ESCRIPT not found" >&2
    exit 1
fi

echo "Release:  $ROOTDIR"
echo "ERTS:     $ERTS_BIN"
echo ""

# ── Sanitize JSON ───────────────────────────────────────────────

SANITIZE_PY='
import json, sys
def sanitize(data):
    for o in data.get("nftables", []):
        if "metainfo" in o:
            o["metainfo"] = {"json_schema_version": 1}
        for key in ("table","chain","rule","set","map","counter","quota","flowtable"):
            if key in o and "handle" in o[key]:
                o[key]["handle"] = 0
    return data
data = sanitize(json.load(sys.stdin))
json.dump(data, sys.stdout, indent=2, sort_keys=True)
'

sanitize() {
    python3 -c "$SANITIZE_PY" < "$1"
}

# ── Find tests ──────────────────────────────────────────────────

find_tests() {
    local search="${1:-$SCRIPT_DIR/testcases}"

    # Resolve to absolute path — the escript runs in a different cwd (cd /tmp)
    # so relative paths would break inside the unshare namespace.
    if [ -d "$search" ]; then
        search="$(cd "$search" && pwd)"
    elif [ -f "$search.term" ]; then
        search="$(cd "$(dirname "$search")" && pwd)/$(basename "$search")"
    fi

    if [ -f "$search.term" ] && [ -f "$search.nft" ]; then
        # Single test specified
        echo "$search"
        return
    fi

    # Find all .term files that have a matching .nft
    find "$search" -name "*.term" -print0 2>/dev/null | while IFS= read -r -d '' term; do
        local base="${term%.term}"
        if [ -f "${base}.nft" ]; then
            echo "$base"
        fi
    done | sort
}

# ── Run single test ─────────────────────────────────────────────

TMPDIR_BASE=$(mktemp -d)
trap "rm -rf $TMPDIR_BASE" EXIT

run_one_test() {
    local base="$1"
    local name="${base#$SCRIPT_DIR/testcases/}"
    local nft_file="${base}.nft"
    local term_file="${base}.term"
    local ref_json="$TMPDIR_BASE/ref.json"
    local ours_json="$TMPDIR_BASE/ours.json"
    local ref_san="$TMPDIR_BASE/ref_san.json"
    local ours_san="$TMPDIR_BASE/ours_san.json"

    # Namespace A: nft CLI (reference)
    if ! unshare -n sh -c "nft -f '$nft_file' && nft -j list ruleset" > "$ref_json" 2>/dev/null; then
        echo "  SKIP: $name (nft -f failed)"
        return 77
    fi

    # Namespace B: erlkoenig_nft (our code)
    rm -f /tmp/etc/firewall.term 2>/dev/null
    if ! unshare -n sh -c "
        export PATH=$ERTS_BIN:\$PATH
        cd /tmp
        escript '$ESCRIPT' '$ROOTDIR' '$term_file' >/dev/null 2>&1
        nft -j list ruleset
    " > "$ours_json" 2>/dev/null; then
        echo "  FAIL: $name (erlkoenig_nft apply failed)"
        return 1
    fi

    # Check we got actual content (not just metainfo)
    local ours_size
    ours_size=$(wc -c < "$ours_json")
    if [ "$ours_size" -lt 200 ]; then
        echo "  FAIL: $name (erlkoenig_nft produced empty ruleset)"
        if [ "$VERBOSE" = "1" ]; then
            echo "    ours.json ($ours_size bytes):"
            cat "$ours_json" | head -5
        fi
        return 1
    fi

    # Sanitize both
    sanitize "$ref_json" > "$ref_san" 2>/dev/null
    sanitize "$ours_json" > "$ours_san" 2>/dev/null

    # Compare kernel output
    if diff -q "$ref_san" "$ours_san" >/dev/null 2>&1; then
        echo "  PASS: $name (kernel)"
    else
        echo "  FAIL: $name (kernel DIFF)"
        if [ "$VERBOSE" = "1" ]; then
            diff --unified "$ref_san" "$ours_san" | head -40
        fi
        return 1
    fi

    # DSL verification: if .exs exists, compile it and compare with checked-in .term
    local exs_file="${base}.exs"
    if [ -f "$exs_file" ]; then
        local dsl_compiled="$TMPDIR_BASE/dsl_compiled.term"
        local dsl_cli="$ERTS_BIN/escript"

        # Find the DSL escript
        local dsl_escript=""
        for candidate in \
            "$ROOTDIR/bin/erlkoenig-dsl" \
            "$ROOTDIR/bin/erlkoenig" \
            "$SCRIPT_DIR/../../dsl/erlkoenig"; do
            if [ -x "$candidate" ]; then
                dsl_escript="$candidate"
                break
            fi
        done

        if [ -z "$dsl_escript" ]; then
            echo "  SKIP: $name (dsl) — no DSL escript found"
        else
            # Compile .exs to temp .term
            local exs_copy="$TMPDIR_BASE/test_dsl.exs"
            cp "$exs_file" "$exs_copy"
            if "$dsl_escript" compile "$exs_copy" >/dev/null 2>&1; then
                local compiled_term="$TMPDIR_BASE/test_dsl.term"
                if [ -f "$compiled_term" ]; then
                    # Normalize whitespace for comparison (erlang term formatting may differ)
                    local norm_compiled="$TMPDIR_BASE/norm_compiled"
                    local norm_reference="$TMPDIR_BASE/norm_reference"
                    tr -s '[:space:]' ' ' < "$compiled_term" > "$norm_compiled"
                    tr -s '[:space:]' ' ' < "$term_file" > "$norm_reference"

                    if diff -q "$norm_compiled" "$norm_reference" >/dev/null 2>&1; then
                        echo "  PASS: $name (dsl)"
                    else
                        echo "  FAIL: $name (dsl DIFF — .exs compiled .term differs from checked-in .term)"
                        if [ "$VERBOSE" = "1" ]; then
                            diff --unified "$term_file" "$compiled_term" | head -20
                        fi
                        return 1
                    fi
                else
                    echo "  FAIL: $name (dsl — compile produced no output)"
                    return 1
                fi
            else
                echo "  FAIL: $name (dsl — compile failed)"
                return 1
            fi
        fi
    fi

    return 0
}

# ── Main ────────────────────────────────────────────────────────

TESTS=$(find_tests "${1:-}")
if [ -z "$TESTS" ]; then
    echo "No tests found."
    exit 1
fi

TOTAL=0
PASS=0
FAIL=0
SKIP=0

echo "══════════════════════════════════════════════"
echo "  erlkoenig_nft Dual-Namespace Tests"
echo "══════════════════════════════════════════════"
echo ""

while IFS= read -r test_base; do
    TOTAL=$((TOTAL + 1))
    rc=0
    run_one_test "$test_base" || rc=$?
    case $rc in
        0)  PASS=$((PASS + 1)) ;;
        77) SKIP=$((SKIP + 1)) ;;
        *)  FAIL=$((FAIL + 1)) ;;
    esac
done <<< "$TESTS"

echo ""
echo "══════════════════════════════════════════════"
echo "  $TOTAL tests: $PASS passed, $FAIL failed, $SKIP skipped"
echo "══════════════════════════════════════════════"

[ "$FAIL" -gt 0 ] && exit 1
exit 0
