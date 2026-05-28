#!/bin/sh
set -eu

PLUGIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"

for CRON_FILE in \
  /etc/cron.d/sernate-firehol-blocklist-check \
  /etc/cron.d/sernate-ip-reputation
do
  if [ -f "$CRON_FILE" ]; then
    rm -f "$CRON_FILE"
  fi
done

if [ -f "$PLUGIN_DIR/state/check.lock" ]; then
  rm -f "$PLUGIN_DIR/state/check.lock"
fi

exit 0
