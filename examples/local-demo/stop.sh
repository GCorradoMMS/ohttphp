#!/usr/bin/env bash
# Stop the local demo servers started by start.sh.
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -f var/pids ]]; then
    echo "no running demo servers found."
    exit 0
fi

while read -r pid; do
    kill "$pid" 2>/dev/null || true
done < var/pids
rm -f var/pids
echo "demo servers stopped."