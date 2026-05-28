#!/bin/sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_DIR="$ROOT_DIR/sernate_firehol_blocklist_check"
DIST_DIR="$ROOT_DIR/dist"
VERSION="$(awk -F= '$1=="version"{print $2}' "$PLUGIN_DIR/plugin.conf")"

mkdir -p "$DIST_DIR"
find "$PLUGIN_DIR/admin" "$PLUGIN_DIR/reseller" "$PLUGIN_DIR/user" "$PLUGIN_DIR/scripts" -type f -exec chmod 755 {} \;

cd "$ROOT_DIR"
tar -C "$PLUGIN_DIR" -czf "$DIST_DIR/sernate_firehol_blocklist_check.tar.gz" .
cp "$DIST_DIR/sernate_firehol_blocklist_check.tar.gz" "$DIST_DIR/sernate_firehol_blocklist_check-$VERSION.tar.gz"
if command -v zip >/dev/null 2>&1; then
  rm -f "$DIST_DIR/sernate_firehol_blocklist_check-$VERSION.zip"
  (cd "$PLUGIN_DIR" && zip -qr "$DIST_DIR/sernate_firehol_blocklist_check-$VERSION.zip" .)
fi

printf '%s\n' "$DIST_DIR/sernate_firehol_blocklist_check.tar.gz"
