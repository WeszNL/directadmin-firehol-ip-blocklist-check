#!/bin/sh
set -eu

CRON_FILE="/etc/cron.d/sernate-firehol-blocklist-check"
if [ -f "$CRON_FILE" ] && [ -w /etc/cron.d ]; then
  rm -f "$CRON_FILE"
fi

exit 0

