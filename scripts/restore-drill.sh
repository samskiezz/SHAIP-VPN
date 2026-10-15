#!/usr/bin/env bash
# Disaster-recovery drill: restore the latest backup into a scratch database
# and verify it is readable. Does not touch production. Run on a schedule.
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/pqanon}"
SCRATCH_DB="${SCRATCH_DB:-pqanon_restore_drill}"

LATEST=$(ls -1t "$BACKUP_DIR"/pqanon-db-*.dump 2>/dev/null | head -1)
if [ -z "$LATEST" ]; then
    echo "no backups found in $BACKUP_DIR" >&2
    exit 1
fi

echo "[*] Drilling on $LATEST"
dropdb --if-exists "$SCRATCH_DB"
createdb "$SCRATCH_DB"
pg_restore --dbname="$SCRATCH_DB" "$LATEST"

COUNT=$(psql -t -A -c "SELECT COUNT(*) FROM users" "$SCRATCH_DB")
echo "[*] Restored $COUNT users"

dropdb "$SCRATCH_DB"
echo "$(date -u +%FT%TZ) drill passed on $LATEST" >> "$BACKUP_DIR/drill.log"
echo "[*] Drill passed"
