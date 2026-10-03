#!/usr/bin/env bash
# Build a Koha plugin KPZ (zip) with paths starting at Koha/Plugin/...
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODULE="Koha/Plugin/DFLiddle/OidcAuthenticationLogger.pm"
if [[ ! -f "$MODULE" ]]; then
  echo "error: missing $MODULE" >&2
  exit 1
fi

VERSION="$(perl -ne 'print $1 if /^our \$VERSION = ['\''"]([^'\''"]+)/' "$MODULE")"
VERSION="${VERSION:-0.0.0}"

NAME="koha-plugin-oidc-authentication-logger"
OUT_DIR="$ROOT/dist"
OUT_FILE="$OUT_DIR/${NAME}-v${VERSION}.kpz"

mkdir -p "$OUT_DIR"
rm -f "$OUT_FILE"

# Archive must contain Koha/ at the root (KPZ = zip).
zip -r "$OUT_FILE" Koha -x '*.DS_Store' '*/.git/*'

echo "Wrote $OUT_FILE"
unzip -l "$OUT_FILE"
