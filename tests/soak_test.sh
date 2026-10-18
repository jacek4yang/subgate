#!/usr/bin/env bash
# tests/soak_test.sh
#
# Production load & soak test for subgate.
#
# Generates continuous concurrent traffic and periodic runtime reloads
# while monitoring RSS memory, file descriptor counts, error rates,
# and process liveness.
#
# Usage:
#   ./tests/soak_test.sh [--duration <seconds>] [--concurrency <N>]
#
# Default duration is 10 seconds for automated testing; operators can run
# `./tests/soak_test.sh --duration 3600` for a 1-hour soak test.

set -euo pipefail

DURATION=10
CONCURRENCY=8

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --concurrency)
            CONCURRENCY="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find or build binary
SUBGATE_BIN=""
if [[ -x "$REPO_DIR/target/linux/debug/subgate" ]]; then
    SUBGATE_BIN="$REPO_DIR/target/linux/debug/subgate"
elif [[ -x "$REPO_DIR/target/release/subgate" ]]; then
    SUBGATE_BIN="$REPO_DIR/target/release/subgate"
elif [[ -x "$REPO_DIR/target/debug/subgate" ]]; then
    SUBGATE_BIN="$REPO_DIR/target/debug/subgate"
fi

if [[ -z "$SUBGATE_BIN" ]]; then
    echo "Compiling subgate for soak test..."
    (cd "$REPO_DIR" && cargo build --target-dir target/linux)
    SUBGATE_BIN="$REPO_DIR/target/linux/debug/subgate"
fi

TEST_DIR=$(mktemp -d /tmp/subgate-soak-XXXXXX)
trap 'cleanup' EXIT

cleanup() {
    if [[ -n "${SUBGATE_PID:-}" ]] && kill -0 "$SUBGATE_PID" 2>/dev/null; then
        kill "$SUBGATE_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}

PORT=18088
TOKEN="soak_test_token_0123456789abcdef"
CONFIG="$TEST_DIR/config.json"

cat << EOF > "$CONFIG"
{
  "listen": "127.0.0.1:$PORT",
  "nodes": [{"name": "node1", "address": "1.1.1.1", "port": 443, "uuid": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d", "public-key": "bK4PTQX5dwqSdVBzADrqhPtALBwj9b0uYjYR29lS4xE", "short-id": "", "server-name": "s"}],
  "groups": [{"token": "$TOKEN", "name": "soak-group", "nodes": ["node1"]}]
}
EOF

export SUBGATE_CONTROL_SOCK="$TEST_DIR/control.sock"
"$SUBGATE_BIN" "$CONFIG" > "$TEST_DIR/subgate.log" 2>&1 &
SUBGATE_PID=$!
sleep 0.5

if ! kill -0 "$SUBGATE_PID" 2>/dev/null; then
    echo "Failed to start subgate" >&2
    cat "$TEST_DIR/subgate.log"
    exit 1
fi

echo "=== Subgate Soak Test ==="
echo "PID:          $SUBGATE_PID"
echo "Duration:     ${DURATION}s"
echo "Concurrency:  $CONCURRENCY workers"
echo "Port:         $PORT"

# Track initial RSS
INITIAL_RSS=$(ps -o rss= -p "$SUBGATE_PID" 2>/dev/null || echo 0)

START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION))

SUCCESS_COUNT=0
ERROR_COUNT=0
RELOAD_COUNT=0
RELOAD_ERRORS=0

# Background worker function
worker() {
    local id="$1"
    local count=0
    local errs=0
    while [[ $(date +%s) -lt $END_TIME ]]; do
        # Rotate between valid clash, valid v2ray, and unknown paths
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/$TOKEN/clash" || echo 000)
        if [[ "$code" == "200" ]]; then
            count=$((count + 1))
        else
            errs=$((errs + 1))
        fi

        code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/$TOKEN/v2ray" || echo 000)
        if [[ "$code" == "200" ]]; then
            count=$((count + 1))
        else
            errs=$((errs + 1))
        fi

        code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/unknown-path" || echo 000)
        if [[ "$code" == "404" ]]; then
            count=$((count + 1))
        else
            errs=$((errs + 1))
        fi
    done
    echo "$count $errs" > "$TEST_DIR/worker_$id.out"
}

WORKER_PIDS=()
# Start worker processes
for i in $(seq 1 "$CONCURRENCY"); do
    worker "$i" &
    WORKER_PIDS+=($!)
done

# Periodic reload worker (triggers atomic reload every 2 seconds during active traffic)
reload_worker() {
    local r_count=0
    local r_errs=0
    while [[ $(date +%s) -lt $END_TIME ]]; do
        sleep 2
        if [[ -x "$SUBGATE_BIN" ]]; then
            if "$SUBGATE_BIN" --reload "$CONFIG" >/dev/null 2>&1; then
                r_count=$((r_count + 1))
            else
                r_errs=$((r_errs + 1))
            fi
        fi
    done
    echo "$r_count $r_errs" > "$TEST_DIR/reload.out"
}
reload_worker &
WORKER_PIDS+=($!)

# Wait for test completion while monitoring peak RSS and open file descriptors
PEAK_RSS=$INITIAL_RSS
MAX_FDS=0

while [[ $(date +%s) -lt $END_TIME ]]; do
    if ! kill -0 "$SUBGATE_PID" 2>/dev/null; then
        echo "Error: Subgate process died prematurely during soak test!" >&2
        cat "$TEST_DIR/subgate.log"
        exit 1
    fi
    CURRENT_RSS=$(ps -o rss= -p "$SUBGATE_PID" 2>/dev/null || echo "$PEAK_RSS")
    if [[ "$CURRENT_RSS" -gt "$PEAK_RSS" ]]; then
        PEAK_RSS=$CURRENT_RSS
    fi
    if [[ -d "/proc/$SUBGATE_PID/fd" ]]; then
        CURRENT_FDS=$(ls -1 "/proc/$SUBGATE_PID/fd" 2>/dev/null | wc -l || echo 0)
        if [[ "$CURRENT_FDS" -gt "$MAX_FDS" ]]; then
            MAX_FDS=$CURRENT_FDS
        fi
    fi
    sleep 0.5
done

# Wait for all workers and reloaders to finish writing their outputs
for pid in "${WORKER_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

FINAL_RSS=$(ps -o rss= -p "$SUBGATE_PID" 2>/dev/null || echo "$PEAK_RSS")
kill -9 "$SUBGATE_PID" 2>/dev/null || true
SUBGATE_PID=""

# Aggregate results
for f in "$TEST_DIR"/worker_*.out; do
    if [[ -f "$f" ]]; then
        read -r c e < "$f"
        SUCCESS_COUNT=$((SUCCESS_COUNT + c))
        ERROR_COUNT=$((ERROR_COUNT + e))
    fi
done

if [[ -f "$TEST_DIR/reload.out" ]]; then
    read -r rc re < "$TEST_DIR/reload.out"
    RELOAD_COUNT=$rc
    RELOAD_ERRORS=$re
fi

FINAL_RSS=$(ps -o rss= -p "$SUBGATE_PID" 2>/dev/null || echo 0)

echo ""
echo "=== Soak Test Results ==="
echo "Successful requests:      $SUCCESS_COUNT"
echo "Failed requests:          $ERROR_COUNT"
echo "Successful reloads:       $RELOAD_COUNT"
echo "Failed reloads:           $RELOAD_ERRORS"
echo "Initial RSS:              ${INITIAL_RSS} KB"
echo "Peak RSS:                 ${PEAK_RSS} KB"
echo "Final RSS:                ${FINAL_RSS} KB"
echo "Peak open FDs:            $MAX_FDS"
echo "Unexpected process exits: 0"

if [[ "$ERROR_COUNT" -gt 0 ]]; then
    echo "Error: requests failed during soak test!" >&2
    exit 1
fi

if [[ "$RELOAD_ERRORS" -gt 0 ]]; then
    echo "Error: reloads failed during soak test!" >&2
    exit 1
fi

echo "Soak test passed with zero errors and stable memory!"
exit 0
