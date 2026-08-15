#!/bin/sh
set -eu

if [ -n "${RETURN_ROUTE:-}" ] && [ -n "${RETURN_VIA:-}" ]; then
  ip route replace "$RETURN_ROUTE" via "$RETURN_VIA"
fi

exec python3 /usr/local/lib/wg-easy-lab/sink.py
