#!/usr/bin/env bash
# pre-commit.sh — Local CI gate for 40mcp
#
# Mirrors the full GitHub Actions CI workflow so you can verify quality
# locally without burning GA minutes. Run this before pushing.
#
# Usage:
#   bash scripts/pre-commit.sh           # run all checks
#   bash scripts/pre-commit.sh --fast    # skip smoke test (saves ~30s)
#   bash scripts/pre-commit.sh --hook    # install as git pre-commit hook
#   bash scripts/pre-commit.sh --unit    # unit tests only
#
# Install as git hook (runs automatically on every commit):
#   bash scripts/pre-commit.sh --hook

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ─── Options ─────────────────────────────────────────────────────────────────

FAST=0
UNIT_ONLY=0
INSTALL_HOOK=0

for arg in "$@"; do
  case "$arg" in
    --fast)       FAST=1 ;;
    --unit)       UNIT_ONLY=1 ;;
    --hook)       INSTALL_HOOK=1 ;;
    -h|--help)
      sed -n '3,10p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
  esac
done

# ─── Install hook mode ────────────────────────────────────────────────────────

if [ "$INSTALL_HOOK" = "1" ]; then
  HOOK_PATH="$ROOT/.git/hooks/pre-commit"
  cat > "$HOOK_PATH" <<'HOOK'
#!/usr/bin/env bash
# Auto-installed by: bash scripts/pre-commit.sh --hook
exec "$(git rev-parse --show-toplevel)/scripts/pre-commit.sh" --fast "$@"
HOOK
  chmod +x "$HOOK_PATH"
  echo "✓ pre-commit hook installed at $HOOK_PATH"
  echo "  Runs: scripts/pre-commit.sh --fast (skips smoke test for speed)"
  echo "  To uninstall: rm $HOOK_PATH"
  exit 0
fi

# ─── Helpers ─────────────────────────────────────────────────────────────────

BOLD=$'\e[1m'
RED=$'\e[31m'
GREEN=$'\e[32m'
YELLOW=$'\e[33m'
CYAN=$'\e[36m'
RESET=$'\e[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
STEP_TIMES=()

_time_start() { _STEP_START=$(date +%s%3N); }

_time_end() {
  local end
  end=$(date +%s%3N)
  echo $(( end - _STEP_START ))
}

step_pass() {
  local name="$1" ms="$2"
  printf "  ${GREEN}✓${RESET} %-35s ${CYAN}%dms${RESET}\n" "$name" "$ms"
  PASS_COUNT=$(( PASS_COUNT + 1 ))
  STEP_TIMES+=("${GREEN}✓${RESET} $name (${ms}ms)")
}

step_fail() {
  local name="$1" ms="$2"
  printf "  ${RED}✗${RESET} %-35s ${CYAN}%dms${RESET}\n" "$name" "$ms"
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
  STEP_TIMES+=("${RED}✗${RESET} $name (${ms}ms)")
}

step_skip() {
  local name="$1"
  printf "  ${YELLOW}−${RESET} %-35s skipped\n" "$name"
  SKIP_COUNT=$(( SKIP_COUNT + 1 ))
  STEP_TIMES+=("${YELLOW}−${RESET} $name (skipped)")
}

run_step() {
  local name="$1"
  shift
  _time_start
  local out
  if out=$("$@" 2>&1); then
    local ms; ms=$(_time_end)
    step_pass "$name" "$ms"
    return 0
  else
    local ms; ms=$(_time_end)
    step_fail "$name" "$ms"
    echo ""
    echo "${BOLD}  Output from: $name${RESET}"
    echo "$out" | sed 's/^/    /'
    echo ""
    return 1
  fi
}

# ─── Header ──────────────────────────────────────────────────────────────────

TOTAL_START=$(date +%s%3N)
echo ""
echo "${BOLD}${CYAN}40mcp local CI gate${RESET}"
echo "  $(node --version)  |  $(npm --version | sed 's/^/npm /')"
echo "  Branch: $(git branch --show-current 2>/dev/null || echo detached)"
echo "  Commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
[ "$FAST" = "1" ]      && echo "  Mode: --fast (smoke skipped)"
[ "$UNIT_ONLY" = "1" ] && echo "  Mode: --unit (lint+integration skipped)"
echo ""

OVERALL_PASS=1

# ─── Step: Lint ──────────────────────────────────────────────────────────────

if [ "$UNIT_ONLY" = "0" ]; then
  run_step "eslint" npx eslint src test examples || OVERALL_PASS=0
fi

# ─── Step: LOC check ─────────────────────────────────────────────────────────

if [ "$UNIT_ONLY" = "0" ]; then
  run_step "check:loc (file-size gate)" node scripts/check-loc.js || OVERALL_PASS=0
fi

# ─── Step: Unit tests ────────────────────────────────────────────────────────

run_step "unit tests (src/)" \
  bash -c 'find src -type f -name "*.test.js" | xargs node --test' \
  || OVERALL_PASS=0

# ─── Step: Integration tests ─────────────────────────────────────────────────

if [ "$UNIT_ONLY" = "0" ]; then
  run_step "integration tests (test/)" \
    bash -c 'node --test test/*.test.js' \
    || OVERALL_PASS=0
fi

# ─── Step: Config injection scan ─────────────────────────────────────────────

if [ "$UNIT_ONLY" = "0" ]; then
  run_step "lint-configs (injection scan)" \
    node scripts/lint-configs.js \
    || OVERALL_PASS=0
fi

# ─── Step: Pack dry-run ──────────────────────────────────────────────────────

if [ "$UNIT_ONLY" = "0" ] && [ "$FAST" = "0" ]; then
  run_step "npm pack --dry-run" \
    bash -c 'npm pack --dry-run 2>&1 | tail -5' \
    || OVERALL_PASS=0
fi

# ─── Step: Smoke test ────────────────────────────────────────────────────────

if [ "$UNIT_ONLY" = "0" ] && [ "$FAST" = "0" ]; then
  run_step "smoke test (packaged install)" \
    bash scripts/smoke-test.sh \
    || OVERALL_PASS=0
elif [ "$UNIT_ONLY" = "0" ] && [ "$FAST" = "1" ]; then
  step_skip "smoke test (packaged install)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

TOTAL_END=$(date +%s%3N)
TOTAL_MS=$(( TOTAL_END - TOTAL_START ))
TOTAL_S=$(echo "scale=1; $TOTAL_MS / 1000" | bc 2>/dev/null || echo "${TOTAL_MS}ms")

echo ""
echo "${BOLD}Results${RESET}  ${GREEN}${PASS_COUNT} passed${RESET}  ${RED}${FAIL_COUNT} failed${RESET}  ${YELLOW}${SKIP_COUNT} skipped${RESET}  (${TOTAL_S}s)"
echo ""

if [ "$OVERALL_PASS" = "1" ]; then
  echo "  ${GREEN}${BOLD}✓ All checks passed — safe to push.${RESET}"
else
  echo "  ${RED}${BOLD}✗ Checks failed — fix before pushing to avoid burning GA minutes.${RESET}"
fi
echo ""

exit $(( 1 - OVERALL_PASS ))
