#!/usr/bin/env bash
# Reviewed local entry point. Do not pipe unreviewed downloads into a root shell.
set -euo pipefail
umask 077
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'ERROR: Python 3 is required (preinstalled on supported Ubuntu releases).' >&2
  exit 1
fi
exec python3 "$DIR/tunnel.py" "$@"