#!/usr/bin/env bash
# Start the local demo servers: target (8003), gateway (8002), relay (8001).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p var/logs

if [[ -f var/pids && -s var/pids ]]; then
    echo "demo servers appear to be running (see var/pids); run ./stop.sh first."
    exit 1
fi

php -S 127.0.0.1:8003 target/router.php > var/logs/target.log 2>&1 &
echo $! >> var/pids
php -S 127.0.0.1:8002 gateway/router.php > var/logs/gateway.log 2>&1 &
echo $! >> var/pids
php -S 127.0.0.1:8001 relay/router.php > var/logs/relay.log 2>&1 &
echo $! >> var/pids

sleep 1
echo "started:"
echo "  target  127.0.0.1:8003  (pid $(sed -n 1p var/pids))"
echo "  gateway 127.0.0.1:8002  (pid $(sed -n 2p var/pids))"
echo "  relay   127.0.0.1:8001  (pid $(sed -n 3p var/pids))"
echo "logs in var/logs/, stop with ./stop.sh"