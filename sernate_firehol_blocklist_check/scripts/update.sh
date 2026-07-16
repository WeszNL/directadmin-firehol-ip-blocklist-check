#!/bin/sh
set -eu

PLUGIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CRON_FILE="/etc/cron.d/sernate-firehol-blocklist-check"
PHP_BIN="/usr/local/bin/php"
MIN_PHP_VERSION_ID=70100
HOST_NAME="$(hostname 2>/dev/null || uname -n 2>/dev/null || echo directadmin)"
CRON_OFFSET="$(printf '%s' "$HOST_NAME-sernate-firehol-blocklist-check" | cksum | awk '{print $1 % 15}')"
CRON_MINUTES="$CRON_OFFSET,$((CRON_OFFSET + 15)),$((CRON_OFFSET + 30)),$((CRON_OFFSET + 45))"

if [ ! -x "$PHP_BIN" ]; then
  PHP_BIN="$(command -v php || true)"
fi

if [ -z "$PHP_BIN" ] || [ ! -x "$PHP_BIN" ]; then
  echo "PHP CLI was not found. This plugin needs PHP 7.1 or newer."
  exit 1
fi

PHP_VERSION_ID="$("$PHP_BIN" -r 'echo PHP_VERSION_ID;' 2>/dev/null || echo 0)"
if [ "$PHP_VERSION_ID" -lt "$MIN_PHP_VERSION_ID" ]; then
  PHP_VERSION="$("$PHP_BIN" -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)"
  echo "PHP $PHP_VERSION is too old. This plugin needs PHP 7.1 or newer."
  exit 1
fi

mkdir -p "$PLUGIN_DIR/data" "$PLUGIN_DIR/state"
chmod 755 "$PLUGIN_DIR/data" "$PLUGIN_DIR/state" || true

if [ -x "$PHP_BIN" ]; then
  PLUGIN_DIR="$PLUGIN_DIR" "$PHP_BIN" -r 'require_once getenv("PLUGIN_DIR") . "/lib/SernateFireholBlocklistCheck.php";' >/dev/null 2>&1 || true
  PLUGIN_DIR="$PLUGIN_DIR" "$PHP_BIN" -r 'require_once getenv("PLUGIN_DIR") . "/lib/SernateFireholBlocklistCheck.php"; SernateFireholBlocklistCheck::ensureDefaultConfigFile();' >/dev/null 2>&1 || true
fi

if id diradmin >/dev/null 2>&1; then
  chown -R diradmin:diradmin "$PLUGIN_DIR/data" "$PLUGIN_DIR/state" || true
  chmod 750 "$PLUGIN_DIR/data" "$PLUGIN_DIR/state" || true
fi
date -u '+update ran at %Y-%m-%dT%H:%M:%SZ' > "$PLUGIN_DIR/state/install_marker.txt" || true

if [ -w /etc/cron.d ]; then
  cat > "$CRON_FILE" <<EOF
$CRON_MINUTES * * * * diradmin $PHP_BIN /usr/local/directadmin/plugins/sernate_firehol_blocklist_check/scripts/check.php >/dev/null 2>&1
EOF
  chmod 644 "$CRON_FILE"
else
  echo "Warning: /etc/cron.d is not writable, automatic checks were not installed."
fi

find "$PLUGIN_DIR/admin" "$PLUGIN_DIR/reseller" "$PLUGIN_DIR/user" "$PLUGIN_DIR/scripts" -type f -exec chmod 755 {} \;

exit 0
