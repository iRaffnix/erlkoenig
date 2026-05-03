#!/usr/bin/env bash
# tools/leak_check.sh — operator-facing leak audit for erlkoenig
# integration tests.
#
# Categories audited:
#   link            — ipv. / h. / i. interfaces left from container nets
#   parent-dummy    — test-only dummy parents (ek_*, by name prefix)
#   nft             — erlkoenig-owned nft tables (inet/host, inet/erlkoenig)
#   cgroup          — container cgroups under erlkoenig.service/containers
#   volume-orphan   — disk-orphan volume dirs reported by `ek vol orphans`
#
# Usage:
#
#   tools/leak_check.sh report
#       Print one line per detected leak (LEAK <category> <id>).
#       Always exit 0.
#
#   tools/leak_check.sh strict
#       Print + exit non-zero if any unexpected leak is detected.
#
# Options (apply to both subcommands):
#
#   --parent NAME           Allow this dummy parent to remain (repeat).
#   --baseline-orphans N    Tolerate up to N pre-existing volume orphans.
#                           Default: 0 (every orphan is reported as a leak).
#   --ek PATH               Path to the `ek` binary. Default: search PATH
#                           and /opt/erlkoenig/bin/ek.
#   --quiet                 Suppress LEAK lines (useful in scripts that
#                           only care about the exit code under strict).
#
# Each detected leak emits a single line:
#
#   LEAK <category> <identifier>
#
# Exit codes:
#   0 — report mode, or strict mode with no unexpected leaks
#   1 — strict mode found unexpected leaks
#   2 — usage error / setup problem
#
# This script is intentionally self-contained and does NOT require
# helper modules or test fixtures.

set -u

mode=""
parents=()
baseline_orphans=""
ek_bin=""
quiet=0

# ---------------------------------------------------------------------
# Option parsing
# ---------------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        report|strict)
            mode="$1"; shift
            ;;
        --parent)
            parents+=("$2"); shift 2
            ;;
        --baseline-orphans)
            baseline_orphans="$2"; shift 2
            ;;
        --ek)
            ek_bin="$2"; shift 2
            ;;
        --quiet)
            quiet=1; shift
            ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "leak_check: unknown argument '$1'" >&2
            exit 2
            ;;
    esac
done

if [ -z "$mode" ]; then
    echo "leak_check: missing subcommand (report|strict)" >&2
    exit 2
fi

# ---------------------------------------------------------------------
# Resolve `ek` binary (best-effort; volume-orphan check is skipped if
# unreachable rather than reported as a missing-tool failure).
# ---------------------------------------------------------------------

if [ -z "$ek_bin" ]; then
    if command -v ek >/dev/null 2>&1; then
        ek_bin="$(command -v ek)"
    elif [ -x /opt/erlkoenig/bin/ek ]; then
        ek_bin=/opt/erlkoenig/bin/ek
    fi
fi

# ---------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------

leaks_found=0

emit() {
    if [ "$quiet" -eq 0 ]; then
        echo "LEAK $1 $2"
    fi
    leaks_found=$((leaks_found + 1))
}

# Match a name against the --parent allowlist.
is_allowed_parent() {
    local name="$1"
    local p
    for p in "${parents[@]:-}"; do
        [ "$name" = "$p" ] && return 0
    done
    return 1
}

# 1. Container-side ipvlan/veth interfaces (ipv.*, h.*, i.*)
audit_links() {
    local line name
    while read -r line; do
        # Format: "<idx>: <name>@<peer>: ..."
        name="${line#*: }"
        name="${name%%:*}"
        name="${name%%@*}"
        case "$name" in
            ipv.*|h.*|i.*)
                emit link "$name"
                ;;
        esac
    done < <(ip -o link show 2>/dev/null)
}

# 2. Test-only dummy parents (ek_cliXX etc).
audit_parent_dummies() {
    local line name
    while read -r line; do
        name="${line#*: }"
        name="${name%%:*}"
        name="${name%%@*}"
        case "$name" in
            ek_cli*|ek_test*|ek_demo*|ek_smoke*)
                if ! is_allowed_parent "$name"; then
                    emit parent-dummy "$name"
                fi
                ;;
        esac
    done < <(ip -o link show 2>/dev/null)
}

# 3. Legacy test-specific nft tables. The daemon-managed tables are
# `inet erlkoenig_host`, `inet erlkoenig_zone`, and `inet erlkoenig_ct`;
# old `inet host` / `inet erlkoenig` tables are stale migration drift.
audit_nft_tables() {
    local line family name
    while read -r line; do
        # Format: "table <family> <name>"
        set -- $line
        family="$2"
        name="$3"
        case "$family $name" in
            "inet host"|"inet erlkoenig")
                emit nft "$family/$name"
                ;;
        esac
    done < <(nft list tables 2>/dev/null)
}

# 4. Container cgroup directories left over after teardown.
audit_cgroups() {
    local root=/sys/fs/cgroup/system.slice/erlkoenig.service/containers
    [ -d "$root" ] || return 0
    local d name
    for d in "$root"/*/; do
        [ -d "$d" ] || continue
        name="$(basename "$d")"
        emit cgroup "$name"
    done
}

# 5. Volume orphans (disk-orphan volume dirs without metadata).
audit_volume_orphans() {
    if [ -z "$ek_bin" ]; then
        emit volume-orphan-audit "ek-not-found"
        return 0
    fi
    if [ ! -x "$ek_bin" ]; then
        emit volume-orphan-audit "ek-not-executable:$ek_bin"
        return 0
    fi

    local out rc
    out="$("$ek_bin" --format json vol orphans 2>/dev/null)"
    rc=$?

    # Distinguish "no orphans" from "couldn't audit" (daemon
    # unreachable, missing tables, JSON path off). A successful
    # response is a JSON array starting with `['; anything else
    # means the audit itself failed and the operator should see
    # that explicitly rather than silently assuming clean state.
    if [ "$rc" -ne 0 ] || [ -z "$out" ]; then
        emit volume-orphan-audit "ek-call-failed:exit=$rc"
        return 0
    fi
    case "$out" in
        \[*) ;;
        *)
            emit volume-orphan-audit "non-json-output"
            return 0
            ;;
    esac

    # Extract `"uuid":"..."` substrings and count them.
    local current_count=0
    while IFS= read -r uuid; do
        [ -n "$uuid" ] && current_count=$((current_count + 1))
    done < <(printf '%s\n' "$out" \
              | grep -o '"uuid":"[^"]*"' \
              | sed 's/^"uuid":"//; s/"$//')

    # If a baseline was provided, only emit the count above that.
    local tolerated="${baseline_orphans:-0}"
    if [ "$current_count" -le "$tolerated" ]; then
        return 0
    fi

    # Emit each individual orphan over the threshold.
    local idx=0
    while IFS= read -r uuid; do
        [ -n "$uuid" ] || continue
        idx=$((idx + 1))
        if [ "$idx" -gt "$tolerated" ]; then
            emit volume-orphan "$uuid"
        fi
    done < <(printf '%s\n' "$out" \
              | grep -o '"uuid":"[^"]*"' \
              | sed 's/^"uuid":"//; s/"$//')
}

# ---------------------------------------------------------------------
# Run all audits
# ---------------------------------------------------------------------

audit_links
audit_parent_dummies
audit_nft_tables
audit_cgroups
audit_volume_orphans

if [ "$mode" = "strict" ] && [ "$leaks_found" -gt 0 ]; then
    exit 1
fi
exit 0
