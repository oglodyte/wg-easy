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

comparison_epoch=$(date -u +%s)
normalize_filter='
  def expires_at_epoch:
    . | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
  del(.generatedAt) |
  .clients |= map(
    if .oneTimeLink != null and
      ((.oneTimeLink.expiresAt | expires_at_epoch) <= $comparison_epoch)
    then .oneTimeLink = null
    else .
    end
  )
'
jq -S --argjson comparison_epoch "$comparison_epoch" \
  "$normalize_filter" "$expected" >"$expected_normalized"
jq -S --argjson comparison_epoch "$comparison_epoch" \
  "$normalize_filter" "$actual" >"$actual_normalized"
diff --unified "$expected_normalized" "$actual_normalized"
echo "Non-secret Phase 0 preservation manifests match."
