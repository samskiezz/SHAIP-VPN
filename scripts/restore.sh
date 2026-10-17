#!/usr/bin/env bash
# Restore a SHAIP control-plane database (and node keys) from a backup made
# by scripts/backup.sh. Usage: restore.sh <timestamp>
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/shaip}"
TIMESTAMP="${1:?usage: restore.sh <timestamp>}"
DB_URL="${DATABASE_URL:?DATABASE_URL is required}"
KEYS_DIR="${KEYS_DIR:-/etc/shaip}"

DB_FILE="$BACKUP_DIR/shaip-db-$TIMESTAMP.dump"
KEYS_FILE="$BACKUP_DIR/shaip-keys-$TIMESTAMP.tar.gz"

if [ ! -f "$DB_FILE" ]; then
    echo "missing $DB_FILE" >&2
    exit 1
fi

echo "[!] This will overwrite the current database and keys."
read -r -p "Type 'yes' to confirm: " confirm
[ "$confirm" = "yes" ] || exit 1

echo "[*] Stopping services"
systemctl stop shaipd 2>/dev/null || true
systemctl stop control-plane 2>/dev/null || true

echo "[*] Restoring database"
pg_restore --clean --if-exists --dbname="$DB_URL" "$DB_FILE"

if [ -f "$KEYS_FILE" ]; then
    echo "[*] Restoring keys"
    mkdir -p "$KEYS_DIR"
    tar -xzf "$KEYS_FILE" -C "$KEYS_DIR"
    chmod 600 "$KEYS_DIR"/*.key 2>/dev/null || true
fi

echo "[*] Starting services"
systemctl start control-plane 2>/dev/null || true
systemctl start shaipd 2>/dev/null || true

echo "[*] Restore complete: $TIMESTAMP"
