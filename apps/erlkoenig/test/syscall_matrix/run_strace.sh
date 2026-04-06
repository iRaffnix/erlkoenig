#!/bin/bash
# Run strace on all test binaries and capture syscall summaries.
# Incremental: skips if strace output is newer than binary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v strace &>/dev/null; then
    echo "Error: strace not found. Install with: apt install strace" >&2
    exit 1
fi

run_strace_dir() {
    local bin_dir="$1"
    local strace_dir="$2"
    local label="$3"

    [ -d "$bin_dir" ] || return 0
    mkdir -p "$strace_dir"

    local traced=0 skipped=0 failed=0

    for bin in "$bin_dir"/*; do
        [ -f "$bin" ] && [ -x "$bin" ] || continue
        base="$(basename "$bin")"
        out="$strace_dir/${base}.strace"

        # Incremental
        if [ -f "$out" ] && [ "$out" -nt "$bin" ]; then
            skipped=$((skipped + 1))
            continue
        fi

        if timeout 10 strace -f -c -S name -o "$out" "$bin" 2>/dev/null; then
            traced=$((traced + 1))
        else
            # Binary may exit non-zero (expected for many syscalls), strace still works
            if [ -f "$out" ] && [ -s "$out" ]; then
                traced=$((traced + 1))
            else
                failed=$((failed + 1))
                echo "  FAIL: $label/$base" >&2
            fi
        fi
    done

    echo "Strace $label: $traced traced, $skipped up-to-date, $failed failed"
}

run_strace_dir "$SCRIPT_DIR/bin/asm" "$SCRIPT_DIR/strace/asm" "asm"
run_strace_dir "$SCRIPT_DIR/bin/go"  "$SCRIPT_DIR/strace/go"  "go"
