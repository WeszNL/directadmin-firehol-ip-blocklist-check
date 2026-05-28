#!/bin/sh
set -eu

PLUGIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$PLUGIN_DIR/data" "$PLUGIN_DIR/state"
chmod 750 "$PLUGIN_DIR/data" "$PLUGIN_DIR/state"
find "$PLUGIN_DIR/admin" "$PLUGIN_DIR/reseller" "$PLUGIN_DIR/user" "$PLUGIN_DIR/scripts" -type f -exec chmod 755 {} \;

exit 0

