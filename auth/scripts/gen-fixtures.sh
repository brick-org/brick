#!/usr/bin/env bash
# Regenerate the checked-in golden vectors under auth/testdata.
#
# Usage:
#   ./scripts/gen-fixtures.sh          # Go helpers only (hermetic, no network)
#   ./scripts/gen-fixtures.sh --ts     # also dump TS reference vectors via
#                                      # targeted vitest runs (opt-in; needs
#                                      # pnpm install in vendor/better-auth)
#
# The script never runs the full upstream suite: every vitest invocation is
# scoped to a single file plus `-t <pattern>`. See auth/testdata/README.md.
set -euo pipefail

cd "$(dirname "$0")/.."

PINNED="5468e6bfcdff799848537cf5ad06ebab15aad9dd"
VENDOR="../vendor/better-auth"

actual="$(git -C "$VENDOR" rev-parse HEAD 2>/dev/null || echo unknown)"
if [ "$actual" != "$PINNED" ]; then
  echo "gen-fixtures: vendor commit $actual != pinned $PINNED" >&2
  echo "gen-fixtures: refusing to regenerate against the wrong tree" >&2
  exit 1
fi

TS=0
for arg in "$@"; do
  case "$arg" in
    --ts) TS=1 ;;
    *) echo "gen-fixtures: unknown flag $arg (want --ts)" >&2; exit 1 ;;
  esac
done

if [ "$TS" = 1 ]; then
  if [ ! -d "$VENDOR/node_modules" ]; then
    echo "gen-fixtures: $VENDOR/node_modules missing; run 'pnpm install' in vendor/better-auth first" >&2
    exit 1
  fi
  echo "gen-fixtures: dumping TS reference vectors (targeted runs only)..."
  # Each run is scoped to one file and one pattern; the full suite is never
  # executed. Outputs are printed for human comparison against testdata —
  # the script does not auto-promote TS values into fixtures.
  pnpm --dir "$VENDOR" vitest run packages/better-auth/src/oauth2/state.test.ts -t 'state' 2>&1 | tail -n 5 || true
  pnpm --dir "$VENDOR" vitest run packages/better-auth/src/crypto -t 'secret rotation' 2>&1 | tail -n 5 || true
  pnpm --dir "$VENDOR" vitest run packages/core/src/social-providers -t 'kick' 2>&1 | tail -n 5 || true
  echo "gen-fixtures: compare the TS output above with testdata/ before promoting any value."
fi

echo "gen-fixtures: regenerating fixtures with the Go helpers..."
GOWORK=off go run ./scripts/genfixtures
echo "gen-fixtures: done. Review with: git status --short auth/testdata && git diff --stat auth/testdata"
