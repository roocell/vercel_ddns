#!/usr/bin/env bash
set -euo pipefail

BASE="/home/roocell/code/vercel_ddns"
LOGDIR="$BASE/logs"
mkdir -p "$LOGDIR"

cd "$BASE"

# Use venv python explicitly
"$BASE/.venv/bin/python" "$BASE/vercel_ddns.py" --once --verbose >> "$LOGDIR/ddns.log" 2>&1
