#!/usr/bin/env bash
# Back up the control-plane database and key material.
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/pqanon}"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
DB_URL="${DATABASE_URL:?DATABASE_URL is required}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

mkdir -p "$BACKUP_DIR"

echo "[*] Dumping database..."
pg_dump "$DB_URL" --format=custom --file="$BACKUP_DIR/pqanon-db-$TIMESTAMP.dump"

echo "[*] Archiving key material (if present)..."
tar -czf "$BACKUP_DIR/pqanon-keys-$TIMESTAMP.tar.gz" \
    /etc/pqanon/*.key /etc/pqanon/*.pub 2>/dev/null || true

echo "[*] Pruning backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -type f -mtime "+$RETENTION_DAYS" -delete

echo "[*] Backup complete."
