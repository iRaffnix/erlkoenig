#!/usr/bin/env bash
# tools/install-layout-audit.sh — assert installed layout matches
# docs/INSTALL_LAYOUT.md.
#
# Walks $PREFIX (default /opt/erlkoenig) plus the documented out-of-
# prefix paths and emits one OK/FAIL per layout assertion. Catches the
# concrete drift categories observed during the 2026-04-29 audit:
#
#   - phantom $PREFIX/release/ subtree
#   - cookie.bak (or any *.bak / *~) under $PREFIX
#   - operator-generated *.term under examples/
#   - multiple per-version wrappers in bin/
#   - rt/erlkoenig_rt with wrong or missing file capabilities
#   - ownership drift under $PREFIX (anything not root:erlkoenig
#     except rt/* which is root:root)
#   - missing or wrong-target cookie / systemd symlinks
#   - $PREFIX permissions != 750
#
# Modes:
#
#   tools/install-layout-audit.sh                       # local, prefix=/opt/erlkoenig
#   HOST=erlkoenig-2__root tools/install-layout-audit.sh
#   tools/install-layout-audit.sh --prefix /opt/erlkoenig-clean
#   tools/install-layout-audit.sh --version 0.9.0
#   tools/install-layout-audit.sh --json
#   tools/install-layout-audit.sh --against-tarball dist/erlkoenig-0.9.0.tar.gz
#
# Exit codes:
#   0  — layout clean
#   1  — drift detected
#   2  — usage / setup error
#
# Optional environment / args:
#
#   HOST=user@host        Run all probes via ssh on this host.
#   PREFIX=/opt/erlkoenig Prefix to audit.
#   --version VSN         Expected release version. Default: read from
#                         $PREFIX/releases/start_erl.data.
#   --json                Emit single JSON object on stdout instead
#                         of human-readable lines. Useful in CI.
#   --against-tarball PATH
#                         Cross-check installed file list against the
#                         release tarball manifest. Files at $PREFIX
#                         not in the tarball (and not in the documented
#                         installer-generated / runtime-generated
#                         allowlist) become drift findings.
#   --quiet               Suppress per-check OK lines, only show FAILs
#                         and summary.

set -eu

HOST="${HOST:-}"
PREFIX="${PREFIX:-/opt/erlkoenig}"
EXPECTED_VERSION="${EXPECTED_VERSION:-}"
JSON=0
QUIET=0
AGAINST_TARBALL=""

# ---- Argument parsing -------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)            PREFIX="$2"; shift 2 ;;
        --version)           EXPECTED_VERSION="$2"; shift 2 ;;
        --against-tarball)   AGAINST_TARBALL="$2"; shift 2 ;;
        --json)              JSON=1; shift ;;
        --quiet)             QUIET=1; shift ;;
        HOST=*)              HOST="${1#HOST=}"; shift ;;
        PREFIX=*)            PREFIX="${1#PREFIX=}"; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "install-layout-audit: unknown argument '$1'" >&2
            exit 2
            ;;
    esac
done

# ---- Output helpers --------------------------------------------------

if [ "$JSON" -eq 1 ]; then
    # JSON mode silences human output; we accumulate findings instead.
    GREEN=""; RED=""; YELLOW=""; DIM=""; RESET=""
else
    GREEN=$'\e[32m'
    RED=$'\e[31m'
    YELLOW=$'\e[33m'
    DIM=$'\e[2m'
    RESET=$'\e[0m'
fi

# json_string VAL — emit JSON-encoded form of VAL (with surrounding
# quotes). Handles backslash, double-quote, and control characters
# (which a sed escape would miss). Pathnames typically don't contain
# any of those, but we don't want a single weird filename to corrupt
# CI-consumed JSON.
json_string() {
    python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.argv[1]))' -- "$1"
}

# Findings accumulator (JSON mode)
FINDINGS_FILE="$(mktemp)"
CHECKS_FILE="$(mktemp)"
trap 'rm -f "$FINDINGS_FILE" "$CHECKS_FILE" "${SSH_FAIL_SENTINEL:-}"' EXIT

emit_check() {
    # emit_check NAME STATUS [DETAIL]
    local name="$1" status="$2" detail="${3:-}"
    printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >>"$CHECKS_FILE"
    if [ "$JSON" -eq 1 ]; then return; fi
    case "$status" in
        ok)
            [ "$QUIET" -eq 1 ] || printf '  %s[OK]%s   %s\n' \
                "$GREEN" "$RESET" "$name"
            ;;
        fail)
            printf '  %s[FAIL]%s %s\n' "$RED" "$RESET" "$name" >&2
            if [ -n "$detail" ]; then
                printf '         %s%s%s\n' "$DIM" "$detail" "$RESET" >&2
            fi
            ;;
        warn)
            printf '  %s[WARN]%s %s\n' "$YELLOW" "$RESET" "$name" >&2
            if [ -n "$detail" ]; then
                printf '         %s%s%s\n' "$DIM" "$detail" "$RESET" >&2
            fi
            ;;
    esac
}

emit_drift() {
    # emit_drift CATEGORY PATH DETAIL
    local category="$1" path="$2" detail="$3"
    printf '%s\t%s\t%s\n' "$category" "$path" "$detail" >>"$FINDINGS_FILE"
}

# Count non-empty lines in a string. Robust against `$(...)` stripping
# the trailing newline (`wc -l` would then under-report by one).
count_lines() {
    printf '%s\n' "$1" | grep -c . || true
}

info() {
    [ "$JSON" -eq 1 ] && return
    [ "$QUIET" -eq 1 ] && return
    printf '  %s[*]%s %s\n' "$DIM" "$RESET" "$*"
}

# ---- Remote shell wrapper --------------------------------------------
# All probes go through r() — runs locally if HOST is empty, else over
# ssh. ssh failures are reported but never crash the script.

SSH_PROBE_OK=0
SSH_FAIL_SENTINEL="$(mktemp)"

r() {
    if [ -z "$HOST" ]; then
        sh -c "$1" </dev/null
    else
        # `-n` is critical: without it, ssh inherits the parent's stdin
        # and silently consumes one line per call when r() runs inside a
        # `while read -r p; do ... done` loop. That eats the loop's input
        # and aborts after the first iteration — silently undercounting
        # any per-path drift on hosts with substantial leftover.
        local rc=0
        ssh -n -o BatchMode=yes -o ConnectTimeout=5 "$HOST" "$1" || rc=$?
        # SSH itself uses exit code 255 to signal transport failure
        # (connection refused, timeout, host unreachable). After a
        # successful preflight we treat any 255 as an audit-killer:
        # later checks would silently get empty output and mis-classify
        # the missing data as drift.
        if [ "$rc" -eq 255 ] && [ "$SSH_PROBE_OK" -eq 1 ]; then
            printf '%s\n' "ssh transport failure (exit 255) on $HOST" \
                >"$SSH_FAIL_SENTINEL"
        fi
        return "$rc"
    fi
}

r_silent() {
    r "$1" 2>/dev/null || true
}

ssh_preflight() {
    [ -z "$HOST" ] && return 0
    local probe
    if ! probe="$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 "$HOST" \
                  'echo erlkoenig-audit-probe' 2>/dev/null)"; then
        if [ "$JSON" -eq 1 ]; then
            printf '{"error":"ssh-preflight-failed","host":"%s"}\n' "$HOST"
        else
            echo "install-layout-audit: ssh transport failed for HOST=$HOST" >&2
            echo "  hint: BatchMode=yes is on — verify ssh reachable + key auth works without password prompt" >&2
        fi
        exit 2
    fi
    if [ "$probe" != "erlkoenig-audit-probe" ]; then
        if [ "$JSON" -eq 1 ]; then
            printf '{"error":"ssh-preflight-malformed","host":"%s","got":"%s"}\n' \
                "$HOST" "$probe"
        else
            echo "install-layout-audit: ssh preflight returned unexpected output: $probe" >&2
        fi
        exit 2
    fi
    SSH_PROBE_OK=1
}

# ---- Pre-flight ------------------------------------------------------

# SSH transport must work *before* any other check. Without this, an
# unreachable host produces empty output for every probe, and the
# audit silently mis-classifies the missing data as drift.
ssh_preflight

if ! r "test -d '$PREFIX'" >/dev/null 2>&1; then
    if [ "$JSON" -eq 1 ]; then
        printf '{"error":"prefix-not-found","prefix":"%s","host":"%s"}\n' \
            "$PREFIX" "$HOST"
    else
        echo "install-layout-audit: prefix not found: $PREFIX (host=${HOST:-local})" >&2
    fi
    exit 2
fi

# Auto-detect installed version from start_erl.data if not given.
if [ -z "$EXPECTED_VERSION" ]; then
    EXPECTED_VERSION="$(r_silent "awk '{print \$2}' '$PREFIX/releases/start_erl.data' 2>/dev/null" | head -1)"
fi

if [ -z "$EXPECTED_VERSION" ]; then
    if [ "$JSON" -eq 1 ]; then
        printf '{"error":"version-not-detected","prefix":"%s","host":"%s"}\n' \
            "$PREFIX" "$HOST"
    else
        echo "install-layout-audit: cannot detect version (no $PREFIX/releases/start_erl.data, --version not given)" >&2
    fi
    exit 2
fi

if [ "$JSON" -ne 1 ] && [ "$QUIET" -ne 1 ]; then
    echo "Erlkoenig install layout audit"
    echo "  prefix:   $PREFIX"
    echo "  version:  $EXPECTED_VERSION"
    echo "  host:     ${HOST:-local}"
    if [ -n "$AGAINST_TARBALL" ]; then
        echo "  tarball:  $AGAINST_TARBALL"
    fi
    echo ""
fi

# ---- Expected capability set on rt/erlkoenig_rt ----------------------
# Source of truth: install.sh `setcap` invocation. Audit fails if either
# the cap set is missing or differs.

EXPECTED_CAPS="cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,cap_setpcap,cap_setuid,cap_setgid,cap_dac_override,cap_bpf,cap_sys_resource"

normalize_caps() {
    # Sort cap names alphabetically (getcap order varies by kernel).
    # Strip the =ep flag suffix; we assert it separately.
    printf '%s' "$1" | tr ',' '\n' | sort | tr '\n' ',' | sed 's/,$//'
}

EXPECTED_CAPS_SORTED="$(normalize_caps "$EXPECTED_CAPS")"

# ---- Checks ----------------------------------------------------------

check_required_release() {
    local missing=""
    local p
    for p in \
        "bin/ek" \
        "bin/erlkoenig" \
        "bin/erlkoenig-$EXPECTED_VERSION" \
        "releases/start_erl.data" \
        "releases/RELEASES" \
        "releases/$EXPECTED_VERSION/sys.config" \
        "releases/$EXPECTED_VERSION/vm.args" \
        "releases/$EXPECTED_VERSION/start.boot" \
        "lib/erlkoenig-$EXPECTED_VERSION/ebin" \
        "rt/erlkoenig_rt" \
        "share/ek.escript" \
        "share/error_catalog.term" \
        "dist/erlkoenig.service" \
        ; do
        if ! r "test -e '$PREFIX/$p'" >/dev/null 2>&1; then
            missing="${missing}${p} "
        fi
    done

    # erts-* directory (version varies by OTP release).
    local erts
    erts="$(r_silent "ls -d '$PREFIX'/erts-* 2>/dev/null | head -1")"
    if [ -z "$erts" ]; then
        missing="${missing}erts-*/ "
    fi

    if [ -z "$missing" ]; then
        emit_check "required release artefacts present" ok
        return 0
    fi
    emit_check "required release artefacts present" fail "missing: $missing"
    emit_drift "required-missing" "$PREFIX" "$missing"
    return 1
}

check_per_version_wrapper_count() {
    local found count
    found="$(r_silent "ls '$PREFIX'/bin/erlkoenig-* 2>/dev/null")"
    count="$(printf '%s\n' "$found" | grep -c '/erlkoenig-' || true)"

    # Allow erlkoenig-dsl* alongside the version wrapper (per install.sh).
    local non_dsl_count
    non_dsl_count="$(printf '%s\n' "$found" \
        | grep '/erlkoenig-' \
        | grep -v '/erlkoenig-dsl' \
        | wc -l \
        | tr -d ' ')"

    if [ "$non_dsl_count" -eq 1 ]; then
        emit_check "exactly one per-version wrapper (erlkoenig-$EXPECTED_VERSION)" ok
        return 0
    fi
    emit_check "exactly one per-version wrapper (erlkoenig-$EXPECTED_VERSION)" fail \
        "found $non_dsl_count: $(printf '%s' "$found" | tr '\n' ' ')"
    printf '%s\n' "$found" | grep '/erlkoenig-' | grep -v '/erlkoenig-dsl' | while read -r p; do
        case "$p" in
            "$PREFIX/bin/erlkoenig-$EXPECTED_VERSION") ;;
            "") ;;
            *) emit_drift "stale-wrapper" "$p" "wrapper for version != $EXPECTED_VERSION" ;;
        esac
    done
    return 1
}

check_capabilities() {
    local out
    out="$(r_silent "getcap '$PREFIX/rt/erlkoenig_rt' 2>/dev/null")"
    if [ -z "$out" ]; then
        emit_check "rt/erlkoenig_rt has expected file capabilities" fail \
            "getcap returned empty (capabilities missing or setcap not installed?)"
        emit_drift "missing-caps" "$PREFIX/rt/erlkoenig_rt" "no caps set"
        return 1
    fi

    # getcap output: "/path/to/binary cap_a,cap_b,...=ep"
    # Some versions use " = " with spaces. Normalise.
    local caps_part flag_part
    caps_part="$(printf '%s' "$out" | sed -E 's@^[^ ]+ +@@; s@[= ].*@@')"
    flag_part="$(printf '%s' "$out" | sed -E 's@.*=@@')"
    local caps_sorted
    caps_sorted="$(normalize_caps "$caps_part")"

    if [ "$caps_sorted" = "$EXPECTED_CAPS_SORTED" ] && [ "$flag_part" = "ep" ]; then
        emit_check "rt/erlkoenig_rt has expected file capabilities" ok
        return 0
    fi

    emit_check "rt/erlkoenig_rt has expected file capabilities" fail \
        "got: '$out'; expected caps: $EXPECTED_CAPS=ep"
    emit_drift "wrong-caps" "$PREFIX/rt/erlkoenig_rt" "got '$out'"
    return 1
}

check_prefix_mode() {
    local mode
    mode="$(r_silent "stat -c '%a' '$PREFIX'")"
    if [ "$mode" = "750" ]; then
        emit_check "$PREFIX permissions = 750" ok
        return 0
    fi
    emit_check "$PREFIX permissions = 750" fail "got mode $mode"
    emit_drift "prefix-mode" "$PREFIX" "mode=$mode (expected 750)"
    return 1
}

check_ownership() {
    # All files under $PREFIX should be root:erlkoenig EXCEPT rt/* which
    # is root:root (capability-bearing binary tree). Anything else is
    # operator-deposited or a tarball/extraction bug.
    #
    # One batched ssh round-trip rather than per-path: `find -printf`
    # emits `owner<TAB>group<TAB>path<NUL>` for every matching entry,
    # bash splits and validates locally.

    local bad
    bad="$(r_silent "find '$PREFIX' -mindepth 1 -path '$PREFIX/rt' -prune -o -printf '%u\\t%g\\t%p\\n' 2>/dev/null")"

    local bad_rt
    bad_rt="$(r_silent "find '$PREFIX/rt' -printf '%u\\t%g\\t%p\\n' 2>/dev/null")"

    local prefix_drift=0 rt_drift=0
    if [ -n "$bad" ]; then
        # Outside `rt/`, the only acceptable ownership is `root:erlkoenig`.
        # Two narrow allowlist exceptions:
        #
        #   - `$PREFIX/rt` itself is the prune-anchor directory and is
        #     printed by find before -prune takes effect.
        #   - `$PREFIX/cookie` is created by `install.sh` *after* the
        #     bulk `chown -R root:erlkoenig` step (install.sh:564-569),
        #     so the symlink itself ends up owned by `root:root`. The
        #     readlink path / target ownership is checked separately by
        #     check_cookie_symlink + check_cookie_file. This is a known
        #     install.sh quirk; relaxing the whole prefix tree to allow
        #     `root:root` would silently accept any operator-deposited
        #     drift and is rejected by spec. Tracked separately as a
        #     candidate install.sh fix (`chown -h root:erlkoenig
        #     $PREFIX/cookie`).
        while IFS=$'\t' read -r u g p; do
            [ -z "$p" ] && continue
            [ "$p" = "$PREFIX/rt" ] && continue
            if [ "$p" = "$PREFIX/cookie" ] && [ "$u" = "root" ] \
                    && { [ "$g" = "root" ] || [ "$g" = "erlkoenig" ]; }; then
                continue
            fi
            if [ "$u" = "root" ] && [ "$g" = "erlkoenig" ]; then
                continue
            fi
            emit_drift "ownership-prefix" "$p" \
                "owner=$u:$g (expected root:erlkoenig)"
            prefix_drift=$((prefix_drift + 1))
        done < <(printf '%s\n' "$bad")
    fi

    if [ -n "$bad_rt" ]; then
        while IFS=$'\t' read -r u g p; do
            [ -z "$p" ] && continue
            if [ "$u" = "root" ] && [ "$g" = "root" ]; then
                continue
            fi
            emit_drift "ownership-rt" "$p" \
                "owner=$u:$g (expected root:root)"
            rt_drift=$((rt_drift + 1))
        done < <(printf '%s\n' "$bad_rt")
    fi

    local total_bad=$((prefix_drift + rt_drift))
    if [ "$total_bad" -eq 0 ]; then
        emit_check "ownership: $PREFIX/* root:erlkoenig, $PREFIX/rt/* root:root" ok
        return 0
    fi
    emit_check "ownership: $PREFIX/* root:erlkoenig, $PREFIX/rt/* root:root" fail \
        "$total_bad path(s) with wrong owner"
    return 1
}

check_cookie_symlink() {
    local target
    target="$(r_silent "readlink '$PREFIX/cookie' 2>/dev/null")"
    if [ "$target" = "/etc/erlkoenig/cookie" ]; then
        emit_check "$PREFIX/cookie -> /etc/erlkoenig/cookie" ok
        return 0
    fi
    if [ -z "$target" ]; then
        if r "test -e '$PREFIX/cookie'" >/dev/null 2>&1; then
            emit_check "$PREFIX/cookie -> /etc/erlkoenig/cookie" fail \
                "is a regular file, not a symlink"
            emit_drift "cookie-not-symlink" "$PREFIX/cookie" "expected symlink to /etc/erlkoenig/cookie"
        else
            emit_check "$PREFIX/cookie -> /etc/erlkoenig/cookie" fail \
                "missing"
            emit_drift "cookie-missing" "$PREFIX/cookie" "expected symlink to /etc/erlkoenig/cookie"
        fi
        return 1
    fi
    emit_check "$PREFIX/cookie -> /etc/erlkoenig/cookie" fail \
        "points to $target instead of /etc/erlkoenig/cookie"
    emit_drift "cookie-wrong-target" "$PREFIX/cookie" "points to $target"
    return 1
}

check_systemd_symlink() {
    local target
    target="$(r_silent "readlink /etc/systemd/system/erlkoenig.service 2>/dev/null")"
    local expected="$PREFIX/dist/erlkoenig.service"
    if [ "$target" = "$expected" ]; then
        emit_check "/etc/systemd/system/erlkoenig.service -> $expected" ok
        return 0
    fi
    if [ -z "$target" ]; then
        if r "test -e /etc/systemd/system/erlkoenig.service" >/dev/null 2>&1; then
            emit_check "/etc/systemd/system/erlkoenig.service -> $expected" fail \
                "is a regular file, not a symlink"
            emit_drift "systemd-not-symlink" "/etc/systemd/system/erlkoenig.service" "expected symlink"
        else
            emit_check "/etc/systemd/system/erlkoenig.service -> $expected" warn \
                "absent (acceptable on hosts without systemd)"
        fi
        return 1
    fi
    emit_check "/etc/systemd/system/erlkoenig.service -> $expected" fail \
        "points to $target"
    emit_drift "systemd-wrong-target" "/etc/systemd/system/erlkoenig.service" "points to $target"
    return 1
}

check_cookie_file() {
    if ! r "test -f /etc/erlkoenig/cookie" >/dev/null 2>&1; then
        emit_check "/etc/erlkoenig/cookie present" fail "missing"
        emit_drift "cookie-file-missing" "/etc/erlkoenig/cookie" "installer should have created it"
        return 1
    fi
    local mode owner
    mode="$(r_silent "stat -c '%a' /etc/erlkoenig/cookie")"
    owner="$(r_silent "stat -c '%U:%G' /etc/erlkoenig/cookie")"
    if [ "$mode" = "440" ] && [ "$owner" = "root:erlkoenig" ]; then
        emit_check "/etc/erlkoenig/cookie mode 440, owner root:erlkoenig" ok
        return 0
    fi
    emit_check "/etc/erlkoenig/cookie mode 440, owner root:erlkoenig" fail \
        "got mode=$mode owner=$owner"
    emit_drift "cookie-perms" "/etc/erlkoenig/cookie" "mode=$mode owner=$owner"
    return 1
}

check_runtime_dirs() {
    local fails=0
    local p owner
    for p in /var/lib/erlkoenig/volumes /var/log/erlkoenig; do
        if ! r "test -d '$p'" >/dev/null 2>&1; then
            emit_check "$p exists, owned by erlkoenig:erlkoenig" fail "missing"
            emit_drift "runtime-dir-missing" "$p" "installer should have created"
            fails=$((fails + 1))
            continue
        fi
        owner="$(r_silent "stat -c '%U:%G' '$p'")"
        if [ "$owner" = "erlkoenig:erlkoenig" ]; then
            emit_check "$p exists, owned by erlkoenig:erlkoenig" ok
        else
            emit_check "$p exists, owned by erlkoenig:erlkoenig" fail \
                "owner=$owner"
            emit_drift "runtime-dir-owner" "$p" "owner=$owner"
            fails=$((fails + 1))
        fi
    done
    return "$fails"
}

check_no_phantom_release() {
    if ! r "test -e '$PREFIX/release'" >/dev/null 2>&1; then
        emit_check "no phantom $PREFIX/release/" ok
        return 0
    fi
    local size
    size="$(r_silent "du -sh '$PREFIX/release' 2>/dev/null | awk '{print \$1}'")"
    emit_check "no phantom $PREFIX/release/" fail \
        "exists (size $size); not part of any installer manifest"
    emit_drift "phantom-release" "$PREFIX/release" "size $size"
    return 1
}

check_no_backup_files() {
    local found
    found="$(r_silent "find '$PREFIX' -maxdepth 3 \\( -name '*.bak' -o -name '*~' -o -name '*.tmp' -o -name '*.orig' \\) -print 2>/dev/null")"
    if [ -z "$found" ]; then
        emit_check "no backup files (*.bak, *~, *.tmp, *.orig) under $PREFIX" ok
        return 0
    fi
    emit_check "no backup files (*.bak, *~, *.tmp, *.orig) under $PREFIX" fail \
        "$(count_lines "$found") file(s)"
    printf '%s\n' "$found" | while read -r p; do
        [ -z "$p" ] && continue
        emit_drift "stale-backup" "$p" "backup-style filename"
    done
    return 1
}

check_no_compiled_dsl() {
    local found
    found="$(r_silent "find '$PREFIX/examples' -name '*.term' -print 2>/dev/null")"
    if [ -z "$found" ]; then
        emit_check "no compiled DSL artefacts under $PREFIX/examples/" ok
        return 0
    fi
    emit_check "no compiled DSL artefacts under $PREFIX/examples/" fail \
        "$(count_lines "$found") *.term file(s)"
    printf '%s\n' "$found" | while read -r p; do
        [ -z "$p" ] && continue
        emit_drift "operator-dsl-output" "$p" "ek dsl compile output, should not be under \$PREFIX"
    done
    return 1
}

check_rt_demo_layout() {
    # rt/demo/ may legitimately be empty (default install) or contain
    # only specific filenames (--with-demo install). Anything else is drift.
    if ! r "test -d '$PREFIX/rt/demo'" >/dev/null 2>&1; then
        emit_check "rt/demo/ contents within allowed set" ok
        return 0
    fi
    local content_count unknown
    content_count="$(r_silent "find '$PREFIX/rt/demo' -mindepth 1 -maxdepth 1 -print 2>/dev/null | wc -l | tr -d ' '")"
    if [ "$content_count" = "0" ]; then
        emit_check "rt/demo/ contents within allowed set (empty)" ok
        return 0
    fi
    # Allowed names per docs/INSTALL_LAYOUT.md.
    unknown="$(r_silent "find '$PREFIX/rt/demo' -mindepth 1 -maxdepth 1 -printf '%f\\n' 2>/dev/null \
        | grep -v -E '^(test-erlkoenig-|case_mgmt$|deadline_worker$|echo-server$|reverse-proxy$|api-server$)' \
        || true")"
    if [ -z "$unknown" ]; then
        emit_check "rt/demo/ contents within allowed set ($content_count file(s))" ok
        return 0
    fi
    emit_check "rt/demo/ contents within allowed set" fail \
        "unexpected: $(printf '%s' "$unknown" | tr '\n' ' ')"
    printf '%s\n' "$unknown" | while read -r f; do
        [ -z "$f" ] && continue
        emit_drift "rt-demo-unknown" "$PREFIX/rt/demo/$f" "name not in allowed set"
    done
    return 1
}

# ---- Optional: tarball cross-check ----------------------------------

check_against_tarball() {
    [ -z "$AGAINST_TARBALL" ] && return 0

    if [ ! -f "$AGAINST_TARBALL" ]; then
        emit_check "tarball cross-check ($AGAINST_TARBALL)" fail "tarball not found"
        return 1
    fi

    # Build "what tarball provides" set (relative paths, no trailing /).
    local tar_list
    tar_list="$(tar tzf "$AGAINST_TARBALL" 2>/dev/null \
        | grep -v '/$' \
        | sed 's@^\./@@' \
        | sort -u)"

    if [ -z "$tar_list" ]; then
        emit_check "tarball cross-check ($AGAINST_TARBALL)" fail \
            "tarball is empty or unreadable"
        return 1
    fi

    # Build "what host has under PREFIX, ignoring runtime/installer-generated".
    local host_list
    host_list="$(r_silent "cd '$PREFIX' && find . -type f -o -type l 2>/dev/null \
        | sed 's@^\\./@@' \
        | sort -u")"

    # Allowlist for things that legitimately exist on host but not in tarball:
    #  - cookie (installer-generated symlink)
    #  - rt/erlkoenig_rt + rt/demo/* (separate artifact, not in release tarball)
    #  - releases/RELEASES (relx generates on first start)
    #  - releases/X/vm.args (rebar3 generates from vm.args.src at boot)
    #  - release/ (phantom subtree — already flagged by check_no_phantom_release;
    #    suppress here to avoid 1000-line fan-out)
    local allowlist='^cookie$|^rt/|^releases/RELEASES$|^releases/[^/]+/vm\.args$|^release/'

    local extras
    extras="$(printf '%s\n' "$host_list" \
        | grep -v -E "$allowlist" \
        | comm -23 - <(printf '%s' "$tar_list") 2>/dev/null \
        || true)"

    # Missing: items in tarball that are not anywhere on host.
    # Compare against the FULL host_list (no allowlist filter), otherwise
    # `releases/RELEASES` etc. appear as "missing" just because they were
    # excluded from the comparison side.
    local missing
    missing="$(printf '%s' "$tar_list" \
        | comm -13 <(printf '%s' "$host_list") - 2>/dev/null \
        || true)"

    local n_extras n_missing
    n_extras="$(printf '%s' "$extras" | grep -c . || true)"
    n_missing="$(printf '%s' "$missing" | grep -c . || true)"

    if [ "$n_extras" = "0" ] && [ "$n_missing" = "0" ]; then
        emit_check "tarball cross-check (manifest matches host)" ok
        return 0
    fi
    emit_check "tarball cross-check (manifest matches host)" fail \
        "$n_extras extra file(s) on host, $n_missing missing"
    printf '%s\n' "$extras" | while read -r p; do
        [ -z "$p" ] && continue
        emit_drift "tarball-extra" "$PREFIX/$p" "present on host but not in tarball"
    done
    printf '%s\n' "$missing" | while read -r p; do
        [ -z "$p" ] && continue
        emit_drift "tarball-missing" "$PREFIX/$p" "in tarball but not on host"
    done
    return 1
}

# ---- Run all checks --------------------------------------------------

# Each check function returns 0 on pass, non-zero on fail. We don't
# use $? for control flow — emit_check has already recorded the result.
# `|| true` keeps `set -e` from aborting after a failure.

check_required_release         || true
check_per_version_wrapper_count || true
check_capabilities              || true
check_prefix_mode               || true
check_ownership                 || true
check_cookie_symlink            || true
check_systemd_symlink           || true
check_cookie_file               || true
check_runtime_dirs              || true
check_no_phantom_release        || true
check_no_backup_files           || true
check_no_compiled_dsl           || true
check_rt_demo_layout            || true
check_against_tarball           || true

# ---- Summary ---------------------------------------------------------

n_pass="$(grep -cP '\tok\t' "$CHECKS_FILE" || true)"
n_fail="$(grep -cP '\tfail\t' "$CHECKS_FILE" || true)"
n_warn="$(grep -cP '\twarn\t' "$CHECKS_FILE" || true)"
n_drift="$(wc -l <"$FINDINGS_FILE" | tr -d ' ')"

if [ "$JSON" -eq 1 ]; then
    # Emit one JSON object — easier to consume from CI. Built in
    # python3 (already a dependency) for robust escaping.
    if [ "$n_fail" = "0" ]; then code=0; else code=1; fi
    [ -s "$SSH_FAIL_SENTINEL" ] && code=2
    python3 - "$CHECKS_FILE" "$FINDINGS_FILE" \
        "$PREFIX" "$EXPECTED_VERSION" "${HOST:-local}" \
        "$n_pass" "$n_fail" "$n_warn" "$n_drift" "$code" <<'PYEOF'
import json, sys

(_, checks_file, findings_file,
 prefix, version, host,
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
    "prefix":  prefix,
    "version": version,
    "host":    host,
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
        echo "  Drift report:"
        # Group by category, cap each category at 20 entries to keep the
        # output readable when a single drift class fans out (phantom
        # subtrees, tarball-extra over a 92 MB stale tree, etc.). The
        # full set is always preserved in JSON output.
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
        printf '  %s[+]%s layout clean — %s check(s) passed' \
            "$GREEN" "$RESET" "$n_pass"
        [ "$n_warn" != "0" ] && printf ', %s warn' "$n_warn"
        printf '\n'
    else
        printf '  %s[!]%s drift detected — %s check(s) failed, %s drift item(s), %s passed' \
            "$RED" "$RESET" "$n_fail" "$n_drift" "$n_pass"
        [ "$n_warn" != "0" ] && printf ', %s warn' "$n_warn"
        printf '\n'
    fi
fi

# Mid-audit ssh transport failure trumps any verdict — the data is
# unreliable. Don't dress it up as drift.
if [ -s "$SSH_FAIL_SENTINEL" ]; then
    if [ "$JSON" -eq 1 ]; then
        : # JSON mode already emitted the per-check structure; users
          # parsing the JSON should also check for empty/missing values
          # but we still abort with non-zero so callers know.
    else
        echo ""
        printf '  %s[!]%s ssh transport failed mid-audit — results unreliable, re-run when host is reachable\n' \
            "$RED" "$RESET" >&2
    fi
    exit 2
fi

if [ "$n_fail" = "0" ]; then
    exit 0
fi
exit 1
