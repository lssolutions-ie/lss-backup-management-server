#!/bin/bash
# lss-backup-server-db.sh — daily MySQL dump of the management server's own database.
#
# Backs up the lss_backup_server database (audit_log, anomalies, recordings metadata,
# nodes, sessions, the lot) to a rotating local file. Optionally ships off-host.
#
# It would be embarrassing if the box that audits everyone else's backups had
# none of its own.
#
# Install:
#   sudo cp install/lss-backup-server-db.sh /usr/local/bin/lss-backup-server-db.sh
#   sudo chmod 750 /usr/local/bin/lss-backup-server-db.sh
#   sudo chown root:root /usr/local/bin/lss-backup-server-db.sh
#   # Add to root's crontab:
#   sudo crontab -e
#     30 3 * * * /usr/local/bin/lss-backup-server-db.sh >> /var/log/lss-backup-server-db.log 2>&1
#
# Required env (override defaults via /etc/default/lss-backup-server-db):
#   LSS_BACKUP_DIR     — where to write dumps. Default /var/backups/lss-backup-server-db
#   LSS_BACKUP_DB      — database name. Default lss_backup_server
#   LSS_BACKUP_USER    — MySQL user. Default lss_backup_server
#   LSS_BACKUP_PASS    — MySQL password. REQUIRED. Use /etc/default/lss-backup-server-db
#                        with mode 600. Don't put it in the crontab.
#   LSS_BACKUP_KEEP    — how many daily dumps to keep locally. Default 14
#   LSS_BACKUP_REMOTE  — optional rsync/scp target like user@host:/path/. Empty disables.

set -euo pipefail

if [[ -f /etc/default/lss-backup-server-db ]]; then
    # shellcheck source=/dev/null
    . /etc/default/lss-backup-server-db
fi

BACKUP_DIR="${LSS_BACKUP_DIR:-/var/backups/lss-backup-server-db}"
DB_NAME="${LSS_BACKUP_DB:-lss_backup_server}"
DB_USER="${LSS_BACKUP_USER:-lss_backup_server}"
DB_PASS="${LSS_BACKUP_PASS:-}"
KEEP="${LSS_BACKUP_KEEP:-14}"
REMOTE="${LSS_BACKUP_REMOTE:-}"

if [[ -z "$DB_PASS" ]]; then
    echo "[$(date -Is)] ERROR: LSS_BACKUP_PASS not set. Put it in /etc/default/lss-backup-server-db (mode 600)." >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/lss_backup_server-$STAMP.sql.gz"

echo "[$(date -Is)] dumping $DB_NAME → $OUT"

mysqldump \
    --user="$DB_USER" \
    --password="$DB_PASS" \
    --single-transaction \
    --routines \
    --triggers \
    --events \
    --hex-blob \
    --default-character-set=utf8mb4 \
    "$DB_NAME" | gzip -9 > "$OUT"

chmod 600 "$OUT"

# Sanity: file must be > 1KB. mysqldump fails partway sometimes.
SIZE=$(stat -c %s "$OUT")
if (( SIZE < 1024 )); then
    echo "[$(date -Is)] ERROR: dump suspiciously small ($SIZE bytes). Removing." >&2
    rm -f "$OUT"
    exit 2
fi

echo "[$(date -Is)] dump ok ($SIZE bytes)"

# Rotation: keep newest $KEEP dumps locally.
ls -1t "$BACKUP_DIR"/lss_backup_server-*.sql.gz 2>/dev/null \
    | tail -n +"$((KEEP + 1))" \
    | xargs -r rm -f --

# Optional off-host shipment. Failure here is non-fatal — local copy is still good.
if [[ -n "$REMOTE" ]]; then
    echo "[$(date -Is)] shipping to $REMOTE"
    if rsync -a --quiet "$OUT" "$REMOTE"; then
        echo "[$(date -Is)] ship ok"
    else
        echo "[$(date -Is)] WARN: ship failed; local copy retained" >&2
    fi
fi

echo "[$(date -Is)] done"
