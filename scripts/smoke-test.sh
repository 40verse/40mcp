#!/usr/bin/env bash
# smoke-test.sh — Packaged install smoke test
#
# Packs the current workspace into a tarball, installs it into a temp directory,
# and verifies the CLI works from a clean install (no source files, no node_modules).
#
# Usage:
#   npm run smoke-test        # via package.json
#   bash scripts/smoke-test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "==> Packing 40mcp..."
TARBALL="$(npm pack --pack-destination "$TMPDIR" --silent 2>/dev/null || npm pack 2>/dev/null | tail -1)"
# npm pack may emit the filename on stdout; locate it
TARBALL_PATH="$(ls "$TMPDIR"/*.tgz 2>/dev/null | head -1)"

if [ -z "$TARBALL_PATH" ]; then
  echo "ERROR: npm pack produced no tarball in $TMPDIR"
  exit 1
fi

echo "==> Installing from tarball: $TARBALL_PATH"
INSTALL_DIR="$TMPDIR/install"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

cat > package.json <<'JSON'
{ "name": "smoke-test", "version": "1.0.0", "type": "module" }
JSON

npm install --silent "$TARBALL_PATH"

echo "==> Running: 40mcp --version"
node_modules/.bin/40mcp --version

echo "==> Running: 40mcp validate (missing arg — expects error exit)"
if node_modules/.bin/40mcp validate 2>/dev/null; then
  echo "ERROR: 'validate' with no args should exit non-zero"
  exit 1
fi

echo "==> Running: 40mcp validate configs/github.json (package-relative fallback)"
# CWD is the install dir (no local configs/), so this exercises the
# package-relative config-resolution fallback in loadConfig().
if ! node_modules/.bin/40mcp validate configs/github.json > /dev/null; then
  echo "ERROR: 'validate configs/github.json' must work from an installed CWD"
  exit 1
fi

echo "==> Running: 40mcp inspect configs/github.json"
if ! node_modules/.bin/40mcp inspect configs/github.json > /dev/null; then
  echo "ERROR: 'inspect configs/github.json' must work from an installed CWD"
  exit 1
fi

echo "==> Verifying programmatic import"
node --input-type=module <<'EOF'
import { createRestBridge, loadOpenApiSpec, createMixer, executeChain } from '40mcp';
if (typeof createRestBridge !== 'function') throw new Error('createRestBridge not exported');
if (typeof loadOpenApiSpec !== 'function') throw new Error('loadOpenApiSpec not exported');
if (typeof createMixer !== 'function') throw new Error('createMixer not exported');
if (typeof executeChain !== 'function') throw new Error('executeChain not exported');
console.log('All core exports present.');
EOF

echo ""
echo "✓ Smoke test passed — packaged install works correctly."
