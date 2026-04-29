#!/usr/bin/env bash
# tools/release-tarball-audit.sh — manifest-only audit for an
# erlkoenig release tarball.
#
# Validates structural assumptions about a `dist/erlkoenig-X.Y.Z.tar.gz`
# *before* it is shipped: stale per-version wrapper, incomplete elixir
# bundle, accidentally-bundled DSL artefacts, missing required files.
# Pure offline check — operates on `tar tzf` output and selective tar
# extracts; no remote host, no install, no daemon.
#
# Catches the build-side bug classes:
#
#   B-1  multiple `bin/erlkoenig-X.Y.Z` entries (poisoned wrapper glob)
#   B-2  `examples/**/*.term` operator artefacts leaking into tarball
#   B-3  `elixir/lib/{elixir,eex,logger}/ebin` empty (only .app files,
#        no .beam) — `ek dsl compile` would silently break on a fresh
#        prefix because the runtime modules are not in the bundle
#
# Usage:
#
#   tools/release-tarball-audit.sh dist/erlkoenig-0.9.0.tar.gz
#   tools/release-tarball-audit.sh --json dist/erlkoenig-0.9.0.tar.gz
#
# Exit codes:
#   0  — tarball passes all checks
#   1  — at least one check failed (release should NOT ship)
#   2  — usage / setup error

set -eu

JSON=0
QUIET=0
TARBALL=""
EXPECTED_VERSION_OVERRIDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --json)   JSON=1;   shift ;;
        --quiet)  QUIET=1;  shift ;;
        --expected-version)
            EXPECTED_VERSION_OVERRIDE="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        --*)
            echo "release-tarball-audit: unknown flag '$1'" >&2
            exit 2
            ;;
        *)
            if [ -n "$TARBALL" ]; then
                echo "release-tarball-audit: multiple tarballs given" >&2
                exit 2
            fi
            TARBALL="$1"
            shift
            ;;
    esac
done

if [ -z "$TARBALL" ]; then
    echo "release-tarball-audit: TARBALL argument required" >&2
    exit 2
fi
if [ ! -f "$TARBALL" ]; then
    echo "release-tarball-audit: tarball not found: $TARBALL" >&2
    exit 2
fi

# ---- Pretty output --------------------------------------------------

if [ "$JSON" -eq 1 ]; then
    GREEN=""; RED=""; YELLOW=""; DIM=""; RESET=""
else
    GREEN=$'\e[32m'
    RED=$'\e[31m'
    YELLOW=$'\e[33m'
    DIM=$'\e[2m'
    RESET=$'\e[0m'
fi

CHECKS_FILE="$(mktemp)"
FINDINGS_FILE="$(mktemp)"
trap 'rm -f "$CHECKS_FILE" "$FINDINGS_FILE"' EXIT

emit_check() {
    local name="$1" status="$2" detail="${3:-}"
    printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >>"$CHECKS_FILE"
    [ "$JSON" -eq 1 ] && return
    case "$status" in
        ok)
            [ "$QUIET" -eq 1 ] || printf '  %s[OK]%s   %s\n' \
                "$GREEN" "$RESET" "$name"
            ;;
        fail)
            printf '  %s[FAIL]%s %s\n' "$RED" "$RESET" "$name" >&2
            [ -n "$detail" ] && printf '         %s%s%s\n' \
                "$DIM" "$detail" "$RESET" >&2
            ;;
        warn)
            printf '  %s[WARN]%s %s\n' "$YELLOW" "$RESET" "$name" >&2
            [ -n "$detail" ] && printf '         %s%s%s\n' \
                "$DIM" "$detail" "$RESET" >&2
            ;;
    esac
}

emit_drift() {
    local category="$1" path="$2" detail="$3"
    printf '%s\t%s\t%s\n' "$category" "$path" "$detail" >>"$FINDINGS_FILE"
}

# ---- Pre-flight: read tarball manifest ------------------------------

# Listing once is much cheaper than `tar tzf` per check. Strip leading
# "./" so callers don't have to handle both "./bin/x" and "bin/x" forms.
MANIFEST="$(mktemp)"
trap 'rm -f "$CHECKS_FILE" "$FINDINGS_FILE" "$MANIFEST"' EXIT

if ! tar tzf "$TARBALL" 2>/dev/null \
        | sed 's@^\./@@' \
        | sort -u >"$MANIFEST"; then
    if [ "$JSON" -eq 1 ]; then
        printf '{"error":"tarball-unreadable","tarball":"%s"}\n' "$TARBALL"
    else
        echo "release-tarball-audit: tar tzf failed for $TARBALL" >&2
    fi
    exit 1
fi
N_ENTRIES="$(wc -l <"$MANIFEST" | tr -d ' ')"
if [ "$N_ENTRIES" -eq 0 ]; then
    if [ "$JSON" -eq 1 ]; then
        printf '{"error":"tarball-empty","tarball":"%s"}\n' "$TARBALL"
    else
        echo "release-tarball-audit: tarball is empty" >&2
    fi
    exit 1
fi

manifest_grep() {
    grep -E "$1" "$MANIFEST" || true
}

manifest_has() {
    grep -q -E "$1" "$MANIFEST"
}

# ---- Detect declared version from start_erl.data --------------------

VSN_LINE="$(tar xzf "$TARBALL" -O ./releases/start_erl.data 2>/dev/null \
              || tar xzf "$TARBALL" -O releases/start_erl.data 2>/dev/null \
              || true)"
EXPECTED_VERSION="$(printf '%s' "$VSN_LINE" | awk '{print $2}')"

if [ -z "$EXPECTED_VERSION" ]; then
    emit_check "releases/start_erl.data exists and parses" fail \
        "could not read version from start_erl.data"
    emit_drift "missing-start-erl-data" "releases/start_erl.data" \
        "tarball does not contain a parseable start_erl.data"
    EXPECTED_VERSION="?"
else
    emit_check "releases/start_erl.data declares version $EXPECTED_VERSION" ok
fi

# Cross-check against caller-supplied expected version (typically the
# version the install-smoke / Makefile thought it was shipping, often
# parsed from the tarball *filename*). A mismatch means the tarball is
# misnamed or repackaged from a different release — the install would
# silently install the wrong version.
if [ -n "$EXPECTED_VERSION_OVERRIDE" ]; then
    if [ "$EXPECTED_VERSION_OVERRIDE" = "$EXPECTED_VERSION" ]; then
        emit_check "tarball version matches caller --expected-version $EXPECTED_VERSION_OVERRIDE" ok
    else
        emit_check "tarball version matches caller --expected-version $EXPECTED_VERSION_OVERRIDE" fail \
            "manifest declares $EXPECTED_VERSION but caller expected $EXPECTED_VERSION_OVERRIDE"
        emit_drift "version-mismatch" "releases/start_erl.data" \
            "manifest=$EXPECTED_VERSION caller=$EXPECTED_VERSION_OVERRIDE"
    fi
fi

if [ "$JSON" -ne 1 ] && [ "$QUIET" -ne 1 ]; then
    echo "Erlkoenig release tarball audit"
    echo "  tarball: $TARBALL"
    echo "  version: $EXPECTED_VERSION"
    echo "  entries: $N_ENTRIES"
    echo ""
fi

# ---- Checks ---------------------------------------------------------

check_required_files() {
    # Files that must be present for any erlkoenig release. Per-version
    # paths are filled in once we know EXPECTED_VERSION. erts-* matched
    # by glob since the OTP version is decoupled from the release version.
    local missing=""
    local p
    local required=(
        "bin/ek"
        "bin/erlkoenig"
        "bin/install_upgrade.escript"
        "bin/nodetool"
        "bin/no_dot_erlang.boot"
        "share/ek.escript"
        "share/error_catalog.term"
        "dist/erlkoenig.service"
        "releases/start_erl.data"
        "releases/RELEASES"
    )
    for p in "${required[@]}"; do
        manifest_has "^${p}$" || missing="${missing}${p} "
    done

    # Per-version paths.
    if [ "$EXPECTED_VERSION" != "?" ]; then
        local vsn_required=(
            "bin/erlkoenig-$EXPECTED_VERSION"
            "releases/$EXPECTED_VERSION/sys.config"
            "releases/$EXPECTED_VERSION/vm.args.src"
            "releases/$EXPECTED_VERSION/start.boot"
            "releases/$EXPECTED_VERSION/start_clean.boot"
            "releases/$EXPECTED_VERSION/erlkoenig.rel"
            "lib/erlkoenig-$EXPECTED_VERSION/ebin/erlkoenig.app"
        )
        for p in "${vsn_required[@]}"; do
            manifest_has "^${p}$" || missing="${missing}${p} "
        done
    fi

    # erts-*/bin/erl must exist (relx packs the VM).
    manifest_has '^erts-[0-9].*/bin/erl$' \
        || missing="${missing}erts-*/bin/erl "

    if [ -z "$missing" ]; then
        emit_check "required release files present" ok
        return 0
    fi
    emit_check "required release files present" fail "missing: $missing"
    for p in $missing; do
        emit_drift "missing-required" "$p" "absent from tarball"
    done
    return 1
}

check_per_version_wrapper_uniqueness() {
    # bin/erlkoenig-X.Y.Z must appear exactly once and must match
    # EXPECTED_VERSION. Stale wrappers cause the systemd entrypoint
    # `bin/erlkoenig` glob loop to pick the first alphabetically — see
    # B-1 in docs/INSTALL_LAYOUT.md.
    local wrappers
    wrappers="$(manifest_grep '^bin/erlkoenig-[0-9]')"
    local count
    count="$(printf '%s\n' "$wrappers" | grep -c . || true)"

    if [ "$count" -eq 0 ]; then
        emit_check "exactly one per-version wrapper bin/erlkoenig-$EXPECTED_VERSION" fail \
            "no per-version wrapper found"
        emit_drift "missing-wrapper" "bin/erlkoenig-$EXPECTED_VERSION" \
            "no per-version wrapper in tarball"
        return 1
    fi
    if [ "$count" -gt 1 ]; then
        emit_check "exactly one per-version wrapper bin/erlkoenig-$EXPECTED_VERSION" fail \
            "found $count: $(printf '%s' "$wrappers" | tr '\n' ' ')"
        printf '%s\n' "$wrappers" | while read -r w; do
            [ -z "$w" ] && continue
            if [ "$w" != "bin/erlkoenig-$EXPECTED_VERSION" ]; then
                emit_drift "stale-wrapper" "$w" \
                    "version-suffix does not match start_erl.data ($EXPECTED_VERSION)"
            fi
        done
        return 1
    fi
    # count == 1: must match expected version.
    local sole
    sole="$(printf '%s' "$wrappers" | tr -d '\n')"
    if [ "$sole" = "bin/erlkoenig-$EXPECTED_VERSION" ]; then
        emit_check "exactly one per-version wrapper bin/erlkoenig-$EXPECTED_VERSION" ok
        return 0
    fi
    emit_check "exactly one per-version wrapper bin/erlkoenig-$EXPECTED_VERSION" fail \
        "got $sole, expected bin/erlkoenig-$EXPECTED_VERSION"
    emit_drift "wrong-wrapper" "$sole" \
        "version-suffix does not match start_erl.data ($EXPECTED_VERSION)"
    return 1
}

check_elixir_bundle_complete() {
    # The DSL compile path (dist/ek.escript:dsl_compile) requires a real
    # Elixir runtime in the bundle: bin/elixir + lib/{elixir,eex,logger}/ebin
    # populated with .beam files. Only .app skeletons mean `ek dsl compile`
    # would silently break on a fresh prefix where no leftover Elixir runs.
    local bundle_root="elixir"
    local fail=0

    if ! manifest_has "^${bundle_root}/bin/elixir$"; then
        emit_check "$bundle_root/bin/elixir present in bundle" fail \
            "missing — \`ek dsl compile\` cannot launch"
        emit_drift "elixir-bin-missing" "$bundle_root/bin/elixir" \
            "elixir launcher absent from tarball"
        fail=1
    else
        emit_check "$bundle_root/bin/elixir present in bundle" ok
    fi

    # Per-app .beam thresholds. The exact counts can vary across Elixir
    # patch versions (1.18 vs 1.19), but each app must have at least
    # *some* compiled modules — empty ebin/ means the app metadata was
    # copied without the runtime.
    local app expected_min
    for spec in "elixir:200" "eex:3" "logger:5" "erlkoenig_dsl:10"; do
        app="${spec%:*}"
        expected_min="${spec#*:}"
        local n
        n="$(manifest_grep "^${bundle_root}/lib/${app}/ebin/.*\.beam$" | wc -l | tr -d ' ')"
        if [ "$n" -lt "$expected_min" ]; then
            emit_check "$bundle_root/lib/$app/ebin/ has >=${expected_min} .beam files" fail \
                "got $n .beam files (expected >=$expected_min)"
            emit_drift "elixir-app-empty" "$bundle_root/lib/$app/ebin/" \
                "$n .beam files (need >=$expected_min)"
            fail=1
        else
            emit_check "$bundle_root/lib/$app/ebin/ has >=${expected_min} .beam files" ok
        fi
    done

    return "$fail"
}

check_no_compiled_dsl_artefacts() {
    # `ek dsl compile` writes .term next to its source by default. Any
    # .term under examples/ in a release tarball is operator-generated
    # and should not ship — see B-2 in docs/INSTALL_LAYOUT.md.
    local found
    found="$(manifest_grep '^examples/.*\.term$')"
    if [ -z "$found" ]; then
        emit_check "no compiled DSL artefacts (*.term) under examples/" ok
        return 0
    fi
    local n
    n="$(printf '%s' "$found" | grep -c . || true)"
    emit_check "no compiled DSL artefacts (*.term) under examples/" fail \
        "$n file(s)"
    printf '%s\n' "$found" | while read -r p; do
        [ -z "$p" ] && continue
        emit_drift "operator-dsl-output" "$p" \
            "ek dsl compile output, must not be in release tarball"
    done
    return 1
}

check_no_backup_files() {
    # No editor swap files, OS metadata, or mid-build backups in a
    # release artefact. Allow `share/error_catalog.term` (legitimate)
    # but flag anything matching backup-style names.
    local found
    found="$(manifest_grep '\.bak$|~$|\.tmp$|\.orig$|\.swp$|/\.DS_Store$|/Thumbs\.db$')"
    if [ -z "$found" ]; then
        emit_check "no backup/swap/OS-metadata files in tarball" ok
        return 0
    fi
    emit_check "no backup/swap/OS-metadata files in tarball" fail \
        "$(printf '%s' "$found" | grep -c . || true) file(s)"
    printf '%s\n' "$found" | while read -r p; do
        [ -z "$p" ] && continue
        emit_drift "stale-backup" "$p" \
            "backup-style filename, must not be in release tarball"
    done
    return 1
}

check_no_release_subtree() {
    # A `release/` directory inside the tarball is the kind of phantom
    # second-copy that produced the 92 MB stale tree on erlkoenig-2. It
    # should never originate from the build path; if it does, something
    # is recursively packaging a previous install.
    local found
    found="$(manifest_grep '^release/')"
    if [ -z "$found" ]; then
        emit_check "no phantom release/ subtree in tarball" ok
        return 0
    fi
    emit_check "no phantom release/ subtree in tarball" fail \
        "$(printf '%s' "$found" | grep -c . || true) entries"
    emit_drift "phantom-release" "release/" \
        "release/ must not exist in the tarball"
    return 1
}

check_otp_deps_present() {
    # rebar.config declares: kernel, stdlib, sasl, crypto, ssl,
    # public_key, compiler, amqp_client (+ erlkoenig itself). A relx
    # build that's missing one of these would not boot. Cheap glob
    # check: each app must have at least one ebin entry under lib/.
    local missing=""
    local app
    for app in kernel stdlib sasl crypto ssl public_key compiler amqp_client; do
        manifest_has "^lib/${app}-[0-9].*/ebin/" \
            || missing="${missing}${app} "
    done
    if [ -z "$missing" ]; then
        emit_check "OTP/dep apps present (kernel/stdlib/sasl/crypto/ssl/public_key/compiler/amqp_client)" ok
        return 0
    fi
    emit_check "OTP/dep apps present" fail "missing: $missing"
    for app in $missing; do
        emit_drift "missing-otp-app" "lib/${app}-*/ebin/" \
            "release dependency app not packaged"
    done
    return 1
}

# ---- Run all checks --------------------------------------------------

check_required_files                || true
check_per_version_wrapper_uniqueness || true
check_elixir_bundle_complete         || true
check_no_compiled_dsl_artefacts      || true
check_no_backup_files                || true
check_no_release_subtree             || true
check_otp_deps_present               || true

# ---- Summary --------------------------------------------------------

n_pass="$(grep -cP '\tok\t' "$CHECKS_FILE" || true)"
n_fail="$(grep -cP '\tfail\t' "$CHECKS_FILE" || true)"
n_warn="$(grep -cP '\twarn\t' "$CHECKS_FILE" || true)"
n_drift="$(wc -l <"$FINDINGS_FILE" | tr -d ' ')"

if [ "$JSON" -eq 1 ]; then
    # Emit JSON via python3 (already a dependency) — sed-escaping
    # handles only double-quote, missing backslash and control chars.
    if [ "$n_fail" = "0" ]; then code=0; else code=1; fi
    python3 - "$CHECKS_FILE" "$FINDINGS_FILE" \
        "$TARBALL" "$EXPECTED_VERSION" "$N_ENTRIES" \
        "$n_pass" "$n_fail" "$n_warn" "$n_drift" "$code" <<'PYEOF'
import json, sys

(_, checks_file, findings_file,
 tarball, version, entries,
 n_pass, n_fail, n_warn, n_drift, code) = sys.argv

def read_tsv(path, fields):
    out = []
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < len(fields):
                parts += [""] * (len(fields) - len(parts))
            out.append(dict(zip(fields, parts[:len(fields)])))
    return out

doc = {
    "tarball": tarball,
    "version": version,
    "entries": int(entries),
    "checks":  read_tsv(checks_file,   ["name", "status", "detail"]),
    "drift":   read_tsv(findings_file, ["category", "path", "detail"]),
    "summary": {
        "pass":      int(n_pass),
        "fail":      int(n_fail),
        "warn":      int(n_warn),
        "drift":     int(n_drift),
        "exit_code": int(code),
    },
}
sys.stdout.write(json.dumps(doc))
sys.stdout.write("\n")
PYEOF
else
    echo ""
    if [ "$n_drift" -gt 0 ] && [ "$QUIET" -eq 0 ]; then
        echo "  Findings:"
        DRIFT_CAP=20
        cut -f1 "$FINDINGS_FILE" | sort -u | while read -r cat; do
            [ -z "$cat" ] && continue
            cat_count="$(grep -cP "^${cat}\t" "$FINDINGS_FILE" || true)"
            printf '    %s%s%s  (%s item(s))\n' \
                "$YELLOW" "$cat" "$RESET" "$cat_count"
            grep -P "^${cat}\t" "$FINDINGS_FILE" \
                | head -n "$DRIFT_CAP" \
                | while IFS=$'\t' read -r _ path detail; do
                    printf '      - %s\n' "$path"
                    [ -n "$detail" ] && printf '          %s%s%s\n' \
                        "$DIM" "$detail" "$RESET"
                done
            if [ "$cat_count" -gt "$DRIFT_CAP" ]; then
                printf '      %s... and %s more (use --json for full list)%s\n' \
                    "$DIM" "$((cat_count - DRIFT_CAP))" "$RESET"
            fi
        done
        echo ""
    fi
    if [ "$n_fail" = "0" ]; then
        printf '  %s[+]%s tarball clean — %s check(s) passed\n' \
            "$GREEN" "$RESET" "$n_pass"
    else
        printf '  %s[!]%s tarball NOT shippable — %s check(s) failed, %s drift item(s)\n' \
            "$RED" "$RESET" "$n_fail" "$n_drift"
    fi
fi

[ "$n_fail" = "0" ] && exit 0
exit 1
