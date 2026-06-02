#!/bin/sh
set -eu

PLUGIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"

CRON_FILE="/etc/cron.d/sernate-firehol-blocklist-check"
if [ -f "$CRON_FILE" ]; then
  rm -f "$CRON_FILE"
fi

if [ -f "$PLUGIN_DIR/state/check.lock" ]; then
  rm -f "$PLUGIN_DIR/state/check.lock"
fi

exit 0
