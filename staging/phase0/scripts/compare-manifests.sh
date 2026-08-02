#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 EXPECTED.json ACTUAL.json" >&2
  exit 2
fi

expected=$1
actual=$2
[ -f "$expected" ] || { echo "Missing expected manifest: $expected" >&2; exit 1; }
[ -f "$actual" ] || { echo "Missing actual manifest: $actual" >&2; exit 1; }

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
python3 "${SCRIPT_DIR}/validate-manifest.py" "$expected"
python3 "${SCRIPT_DIR}/validate-manifest.py" "$actual"

expected_normalized=$(mktemp)
actual_normalized=$(mktemp)
cleanup() {
  rm -f "$expected_normalized" "$actual_normalized"
}
trap cleanup EXIT

jq -S 'del(.generatedAt)' "$expected" >"$expected_normalized"
jq -S 'del(.generatedAt)' "$actual" >"$actual_normalized"
diff --unified "$expected_normalized" "$actual_normalized"
echo "Non-secret Phase 0 preservation manifests match."
