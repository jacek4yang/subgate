#!/usr/bin/env bash
# scripts/upgrade.sh
#
# Production-grade, safe atomic upgrade script for subgate.
#
# Flow:
# 1. Pre-flight verification: runs `<new_binary> --check <config>` to guarantee
#    configuration compatibility before touching any running files.
# 2. Backup: creates a copy of the active executable to `/usr/local/bin/subgate.bak`.
# 3. Atomic replacement: copies to a temporary file on the same filesystem and
#    atomically renames (`mv -f`) to prevent `ETXTBSY` or running-binary corruption.
# 4. Service restart & health check: restarts systemd unit and monitors for 2 seconds.
# 5. Auto-rollback: if restart fails or service exits, immediately restores backup.

set -euo pipefail

NEW_BINARY="${1:-./target/release/subgate}"
CONFIG_FILE="${2:-/etc/subgate/config.json}"
INSTALL_DIR="${SUBGATE_INSTALL_DIR:-/usr/local/bin}"
TARGET_BINARY="$INSTALL_DIR/subgate"
BACKUP_FILE="${SUBGATE_BACKUP_FILE:-$INSTALL_DIR/subgate.bak}"
SKIP_SYSTEMD="${SUBGATE_SKIP_SYSTEMD:-0}"
DRY_RUN="${SUBGATE_DRY_RUN:-0}"

echo "=== Subgate Safe Upgrade Procedure ==="
echo "New binary:       $NEW_BINARY"
echo "Config file:      $CONFIG_FILE"
echo "Target binary:    $TARGET_BINARY"
echo "Backup binary:    $BACKUP_FILE"

# 1. Check new binary
if [[ ! -f "$NEW_BINARY" ]]; then
    echo "Error: new binary '$NEW_BINARY' does not exist." >&2
    exit 1
fi
chmod +x "$NEW_BINARY" 2>/dev/null || true

# 2. Pre-flight configuration validation with new binary
echo "[Step 1/4] Pre-flight configuration check with new binary..."
if ! "$NEW_BINARY" --check "$CONFIG_FILE"; then
    echo "Error: new binary rejected existing configuration! Aborting upgrade before modifying system." >&2
    exit 1
fi
echo "Configuration validated successfully."

if [[ "$DRY_RUN" == "1" ]]; then
    echo "[DRY-RUN] Pre-flight validation passed. No system files modified."
    exit 0
fi

# 3. Preserve existing executable
echo "[Step 2/4] Backing up existing executable..."
if [[ -f "$TARGET_BINARY" ]]; then
    cp -p "$TARGET_BINARY" "$BACKUP_FILE"
    chmod 0755 "$BACKUP_FILE"
    echo "Backup saved to: $BACKUP_FILE"
else
    echo "Note: No previous binary found at $TARGET_BINARY; initial installation."
fi

# 4. Atomic replacement on the same filesystem
echo "[Step 3/4] Installing new binary atomically..."
TMP_FILE="$INSTALL_DIR/.subgate.tmp.$$"
cp -p "$NEW_BINARY" "$TMP_FILE"
chmod 0755 "$TMP_FILE"
mv -f "$TMP_FILE" "$TARGET_BINARY"
echo "Atomically replaced $TARGET_BINARY"

# 5. Restart service and verify health
echo "[Step 4/4] Verifying service health..."
if [[ "$SKIP_SYSTEMD" != "1" ]]; then
    echo "Restarting subgate.service..."
    if ! systemctl restart subgate; then
        echo "Error: systemctl restart failed! Initiating automatic rollback..." >&2
        if [[ -f "$BACKUP_FILE" ]]; then
            mv -f "$BACKUP_FILE" "$TARGET_BINARY"
            systemctl restart subgate || true
            echo "Restored previous executable from backup." >&2
        fi
        exit 1
    fi

    # Wait briefly and verify service stays active
    sleep 2
    if ! systemctl is-active --quiet subgate; then
        echo "Error: subgate service failed after restart! Initiating automatic rollback..." >&2
        if [[ -f "$BACKUP_FILE" ]]; then
            mv -f "$BACKUP_FILE" "$TARGET_BINARY"
            systemctl restart subgate || true
            echo "Restored previous executable from backup." >&2
        fi
        exit 1
    fi
    echo "Service is active and healthy."
else
    echo "Skipped systemd restart (SUBGATE_SKIP_SYSTEMD=1)."
fi

echo "=== Subgate Upgrade Completed Successfully ==="
exit 0
