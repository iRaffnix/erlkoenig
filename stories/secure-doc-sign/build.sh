#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Building web proxy..."
CGO_ENABLED=0 go build -o web ./src/web

echo "Building signer..."
CGO_ENABLED=0 go build -o signer ./src/signer

echo "Building archive..."
CGO_ENABLED=0 go build -o archive ./src/archive

echo "Done. Binaries: web, signer, archive"
