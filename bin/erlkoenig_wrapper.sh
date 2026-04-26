#!/bin/sh
# erlkoenig wrapper — loads cookie, then delegates to the relx release script.
#
# foreground, daemon, eval, rpc, stop, remote_console, pid all work
# without requiring RELX_COOKIE to be set externally.
#
# Cookie resolution order:
#   1. RELX_COOKIE environment variable (explicit, e.g. from systemd)
#   2. ERLKOENIG_COOKIE_FILE
#   3. /etc/erlkoenig/cookie
#   4. ~/.config/erlkoenig/cookie

set -e

SCRIPT=$(readlink -f "$0" 2>/dev/null || echo "$0")
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT")" && pwd -P)"
RELEASE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

# ── Cookie ──────────────────────────────────────────────────────────

resolve_cookie_file() {
    if [ -n "${ERLKOENIG_COOKIE_FILE:-}" ]; then
        echo "$ERLKOENIG_COOKIE_FILE"
        return 0
    fi
    if [ -f /etc/erlkoenig/cookie ]; then
        echo /etc/erlkoenig/cookie
        return 0
    fi
    if [ -n "${HOME:-}" ] && [ -f "$HOME/.config/erlkoenig/cookie" ]; then
        echo "$HOME/.config/erlkoenig/cookie"
        return 0
    fi
    return 1
}

if [ -z "$RELX_COOKIE" ]; then
    if COOKIE_FILE="$(resolve_cookie_file)" && [ -r "$COOKIE_FILE" ]; then
        RELX_COOKIE="$(cat "$COOKIE_FILE")"
        export RELX_COOKIE
        echo "erlkoenig: using cookie file $COOKIE_FILE" >&2
    else
        echo "FATAL: No Erlang cookie found." >&2
        echo "" >&2
        echo "  Resolution order:" >&2
        echo "    ERLKOENIG_COOKIE_FILE" >&2
        echo "    /etc/erlkoenig/cookie" >&2
        echo "    ~/.config/erlkoenig/cookie" >&2
        exit 1
    fi
fi

# ── Delegate to relx release script ────────────────────────────────
# Find the versioned release script (e.g. erlkoenig-0.4.0)

RELEASE_SCRIPT=""
for f in "$RELEASE_ROOT"/bin/erlkoenig-*; do
    if [ -x "$f" ] && [ "$(basename "$f")" != "erlkoenig" ]; then
        RELEASE_SCRIPT="$f"
        break
    fi
done

if [ -z "$RELEASE_SCRIPT" ]; then
    echo "FATAL: No release script found in $RELEASE_ROOT/bin/" >&2
    exit 1
fi

exec "$RELEASE_SCRIPT" "$@"
