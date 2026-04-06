#!/bin/bash
# Build assembly syscall test binaries.
# Each .S file is assembled and linked into a static binary.
# Incremental: skips if binary is newer than source.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ASM_DIR="$SCRIPT_DIR/asm"
BIN_DIR="$SCRIPT_DIR/bin/asm"

if ! command -v as &>/dev/null || ! command -v ld &>/dev/null; then
    echo "Error: binutils (as, ld) not found. Install with: apt install binutils" >&2
    exit 1
fi

mkdir -p "$BIN_DIR"

built=0
skipped=0
failed=0

for src in "$ASM_DIR"/syscall_*.S; do
    [ -f "$src" ] || continue
    base="$(basename "$src" .S)"
    bin="$BIN_DIR/$base"

    # Incremental: skip if binary is newer than source
    if [ -f "$bin" ] && [ "$bin" -nt "$src" ]; then
        skipped=$((skipped + 1))
        continue
    fi

    obj="$BIN_DIR/${base}.o"
    if as --64 -o "$obj" "$src" 2>/dev/null && \
       ld -s --static -o "$bin" "$obj" 2>/dev/null; then
        rm -f "$obj"
        built=$((built + 1))
    else
        rm -f "$obj" "$bin"
        failed=$((failed + 1))
        echo "  FAIL: $base" >&2
    fi
done

echo "Assembly binaries: $built built, $skipped up-to-date, $failed failed"
