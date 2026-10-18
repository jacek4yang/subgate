#!/usr/bin/env bash
# tests/upgrade_rollback_test.sh
#
# Automated integration test for upgrade and rollback scripts.
# Runs in an isolated temporary directory without requiring root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TEST_DIR=$(mktemp -d /tmp/subgate-upg-test-XXXXXX)
trap 'rm -rf "$TEST_DIR"' EXIT

echo "=== Testing Upgrade & Rollback Scripts ==="
echo "Test directory: $TEST_DIR"

INSTALL_DIR="$TEST_DIR/bin"
mkdir -p "$INSTALL_DIR" "$TEST_DIR/etc"

export SUBGATE_INSTALL_DIR="$INSTALL_DIR"
export SUBGATE_BACKUP_FILE="$INSTALL_DIR/subgate.bak"
export SUBGATE_SKIP_SYSTEMD=1

# Find a working subgate binary
SUBGATE_BIN=""
if [[ -x "$REPO_DIR/target/linux/debug/subgate" ]]; then
    SUBGATE_BIN="$REPO_DIR/target/linux/debug/subgate"
elif [[ -x "$REPO_DIR/target/release/subgate" ]]; then
    SUBGATE_BIN="$REPO_DIR/target/release/subgate"
elif [[ -x "$REPO_DIR/target/debug/subgate" ]]; then
    SUBGATE_BIN="$REPO_DIR/target/debug/subgate"
fi

if [[ -z "$SUBGATE_BIN" ]]; then
    echo "Compiling subgate for test..."
    (cd "$REPO_DIR" && cargo build --target-dir target/linux)
    SUBGATE_BIN="$REPO_DIR/target/linux/debug/subgate"
fi

# Valid config
cat << "EOF" > "$TEST_DIR/etc/config.json"
{
  "listen": "127.0.0.1:8080",
  "nodes": [{"name": "n1", "address": "1.1.1.1", "port": 443, "uuid": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d", "public-key": "bK4PTQX5dwqSdVBzADrqhPtALBwj9b0uYjYR29lS4xE", "short-id": "", "server-name": "s"}],
  "groups": [{"token": "token1-0123456789abcdef", "name": "g1", "nodes": ["n1"]}]
}
EOF

# Create initial "installed" v1 binary
cp "$SUBGATE_BIN" "$INSTALL_DIR/subgate"

# Create a mock "v2" binary
V2_BIN="$TEST_DIR/v2_subgate"
cp "$SUBGATE_BIN" "$V2_BIN"

# 1. Test Dry-Run
echo "[Test 1] Testing Dry-run upgrade..."
export SUBGATE_DRY_RUN=1
bash "$REPO_DIR/scripts/upgrade.sh" "$V2_BIN" "$TEST_DIR/etc/config.json"
[[ ! -f "$INSTALL_DIR/subgate.bak" ]] || { echo "Dry-run should not create backup"; exit 1; }
export SUBGATE_DRY_RUN=0

# 2. Test Real Upgrade
echo "[Test 2] Testing Successful Upgrade..."
bash "$REPO_DIR/scripts/upgrade.sh" "$V2_BIN" "$TEST_DIR/etc/config.json"

[[ -f "$INSTALL_DIR/subgate" ]] || { echo "subgate executable missing after upgrade"; exit 1; }
[[ -f "$INSTALL_DIR/subgate.bak" ]] || { echo "subgate.bak missing after upgrade"; exit 1; }

# 3. Test Pre-flight Rejection on Incompatible Config
echo "[Test 3] Testing Pre-flight rejection on bad config..."
cat << "EOF" > "$TEST_DIR/etc/bad_config.json"
{ "invalid": json
EOF

if bash "$REPO_DIR/scripts/upgrade.sh" "$V2_BIN" "$TEST_DIR/etc/bad_config.json" 2>/dev/null; then
    echo "Upgrade should have been rejected by preflight check!"; exit 1;
else
    echo "Pre-flight check successfully rejected invalid config."
fi

# 4. Test Rollback Script
echo "[Test 4] Testing Rollback Script..."
bash "$REPO_DIR/scripts/rollback.sh" "$TEST_DIR/etc/config.json"

[[ -f "$INSTALL_DIR/subgate" ]] || { echo "subgate executable missing after rollback"; exit 1; }
echo "Rollback successfully completed."

echo "=== All Upgrade & Rollback Tests Passed! ==="
exit 0
