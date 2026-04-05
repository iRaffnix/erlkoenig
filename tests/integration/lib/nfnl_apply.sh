#!/bin/sh
# nfnl_apply.sh — Apply a .term config via erlkoenig_nft Netlink in the current namespace.
# Usage: nfnl_apply.sh <config.term>
#
# Starts a minimal BEAM, applies the config, exits.
# Must run inside an unshare -n namespace.

set -e

TERM_FILE="$1"
if [ -z "$TERM_FILE" ] || [ ! -f "$TERM_FILE" ]; then
    echo "Usage: nfnl_apply.sh <config.term>" >&2
    exit 1
fi

ROOTDIR="${ERLKOENIG_NFT_DIR:-/opt/erlkoenig_nft}"
ERL="$ROOTDIR/erts-*/bin/erl"
# Resolve glob
ERL=$(ls $ERL 2>/dev/null | head -1)

if [ -z "$ERL" ]; then
    echo "ERROR: erl not found in $ROOTDIR/erts-*/bin/" >&2
    exit 1
fi

# Collect all ebin paths
EBIN_ARGS=""
for d in "$ROOTDIR"/lib/*/ebin; do
    EBIN_ARGS="$EBIN_ARGS -pa $d"
done

BOOT=$(ls "$ROOTDIR"/releases/*/start_clean.boot 2>/dev/null | head -1)
BOOT="${BOOT%.boot}"

exec $ERL \
    -boot "$BOOT" \
    -boot_var SYSTEM_LIB_DIR "$ROOTDIR/lib" \
    $EBIN_ARGS \
    -noinput -noshell \
    -eval "
        {ok, [Config]} = file:consult(\"$TERM_FILE\"),
        application:ensure_all_started(crypto),
        {ok, Pid} = nfnl_server:start_link(),
        case erlkoenig_nft_firewall:apply_config(Pid, Config) of
            ok -> halt(0);
            {error, E} ->
                io:format(standard_error, \"apply error: ~p~n\", [E]),
                halt(1)
        end.
    "
