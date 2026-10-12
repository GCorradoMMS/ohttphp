#!/usr/bin/env bash
# Initialize the local demo: create the key store and generate a gateway
# key pair if none exists yet.
set -euo pipefail
cd "$(dirname "$0")"

KEYS_DIR=var/keys

if compgen -G "$KEYS_DIR/key-*.json" > /dev/null; then
    echo "gateway keys already exist in $KEYS_DIR; nothing to do."
    echo "delete the directory to start over: rm -rf $KEYS_DIR"
    exit 0
fi

mkdir -p "$KEYS_DIR"
php "$(dirname "$0")/../../bin/ohttphp-gateway-keys" generate --store "$KEYS_DIR"
echo "key store initialized at $KEYS_DIR"