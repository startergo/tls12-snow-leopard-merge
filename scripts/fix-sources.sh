#!/usr/bin/env bash
# fix-sources.sh — Rename the extracted tarball directory to the canonical name
# Run once: bash scripts/fix-sources.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
SRC="$ROOT/sources"

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
ok()  { echo -e "${GREEN}✓ $*${NC}"; }
die() { echo -e "${RED}✗ $*${NC}"; exit 1; }

ACTUAL="$SRC/libsecurity_ssl-libsecurity_ssl-55002"
CANONICAL="$SRC/libsecurity_ssl-55002"

[ -d "$ACTUAL" ] || die "Expected directory not found: $ACTUAL"

echo "Renaming:"
echo "  $ACTUAL"
echo "  → $CANONICAL"
mv "$ACTUAL" "$CANONICAL"

# Quick sanity check
C_COUNT=$(find "$CANONICAL/lib" -name "*.c" | wc -l | tr -d ' ')
ok "Done — $CANONICAL/lib has $C_COUNT .c files"
