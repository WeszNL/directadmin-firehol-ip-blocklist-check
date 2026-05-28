#!/bin/sh
set -eu

PLUGIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CRON_FILE="/etc/cron.d/sernate-firehol-blocklist-check"

mkdir -p "$PLUGIN_DIR/data" "$PLUGIN_DIR/state"
chmod 750 "$PLUGIN_DIR/data" "$PLUGIN_DIR/state"

if [ -w /etc/cron.d ]; then
  cat > "$CRON_FILE" <<EOF
*/15 * * * * root /usr/local/bin/php /usr/local/directadmin/plugins/sernate_firehol_blocklist_check/scripts/check.php >/dev/null 2>&1
EOF
  chmod 644 "$CRON_FILE"
fi

find "$PLUGIN_DIR/admin" "$PLUGIN_DIR/reseller" "$PLUGIN_DIR/user" "$PLUGIN_DIR/scripts" -type f -exec chmod 755 {} \;

exit 0

