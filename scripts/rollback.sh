#!/usr/bin/env bash
# scripts/rollback.sh
#
# Production rollback script for subgate.
#
# Restores the previously working executable from `/usr/local/bin/subgate.bak`
# to `/usr/local/bin/subgate` atomically and restarts the service.

set -euo pipefail

INSTALL_DIR="${SUBGATE_INSTALL_DIR:-/usr/local/bin}"
CONFIG_FILE="${1:-/etc/subgate/config.json}"
TARGET_BINARY="$INSTALL_DIR/subgate"
BACKUP_FILE="${SUBGATE_BACKUP_FILE:-$INSTALL_DIR/subgate.bak}"
SKIP_SYSTEMD="${SUBGATE_SKIP_SYSTEMD:-0}"

echo "=== Subgate Rollback Procedure ==="
echo "Target binary:    $TARGET_BINARY"
echo "Backup binary:    $BACKUP_FILE"
echo "Config file:      $CONFIG_FILE"

# 1. Verify backup file exists
if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "Error: backup binary '$BACKUP_FILE' does not exist! Cannot rollback." >&2
    exit 1
fi
chmod +x "$BACKUP_FILE" 2>/dev/null || true

# 2. Pre-flight verification with backup binary
echo "[Step 1/3] Verifying configuration with backup binary..."
if "$BACKUP_FILE" --check "$CONFIG_FILE"; then
    echo "Configuration verified with backup binary."
else
    echo "Warning: configuration check failed with backup binary; proceeding with binary restoration." >&2
fi

# 3. Atomic restoration on the same filesystem
echo "[Step 2/3] Restoring previous binary atomically..."
TMP_FILE="$INSTALL_DIR/.subgate.rollback.$$"
cp -p "$BACKUP_FILE" "$TMP_FILE"
chmod 0755 "$TMP_FILE"
mv -f "$TMP_FILE" "$TARGET_BINARY"
echo "Restored $BACKUP_FILE to $TARGET_BINARY"

# 4. Restart service and verify health
echo "[Step 3/3] Restarting service..."
if [[ "$SKIP_SYSTEMD" != "1" ]]; then
    echo "Restarting subgate.service..."
    if ! systemctl restart subgate; then
        echo "Error: systemctl restart failed after rollback!" >&2
        exit 1
    fi

    sleep 2
    if ! systemctl is-active --quiet subgate; then
        echo "Error: subgate service failed after rollback!" >&2
        exit 1
    fi
    echo "Service successfully restored and active."
else
    echo "Skipped systemd restart (SUBGATE_SKIP_SYSTEMD=1)."
fi

echo "=== Subgate Rollback Completed Successfully ==="
exit 0
