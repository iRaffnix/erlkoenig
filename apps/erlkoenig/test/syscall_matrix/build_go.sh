#!/bin/bash
# Build Go syscall test binaries.
# Each .go file is compiled as a static binary with CGO disabled.
# Incremental: skips if binary is newer than source.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GO_DIR="$SCRIPT_DIR/go"
BIN_DIR="$SCRIPT_DIR/bin/go"

if ! command -v go &>/dev/null; then
    echo "Error: Go compiler not found. Install from https://go.dev/dl/" >&2
    exit 1
fi

mkdir -p "$BIN_DIR"

built=0
skipped=0
failed=0

for src in "$GO_DIR"/cat_*.go; do
    [ -f "$src" ] || continue
    base="$(basename "$src" .go)"
    bin="$BIN_DIR/$base"

    # Incremental
    if [ -f "$bin" ] && [ "$bin" -nt "$src" ]; then
        skipped=$((skipped + 1))
        continue
    fi

    if CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$bin" "$src" 2>/dev/null; then
        built=$((built + 1))
    else
        failed=$((failed + 1))
        echo "  FAIL: $base" >&2
    fi
done

echo "Go binaries: $built built, $skipped up-to-date, $failed failed"
