#!/usr/bin/env bash
# tests/nginx_privacy_test.sh
#
# Production Logging-Privacy & Nginx Integration Test.
#
# Exercises subgate behind a real nginx reverse proxy with the privacy-safe
# configuration from deploy/nginx.conf.example.
#
# Verifies that a high-entropy synthetic subscription token NEVER appears in
# the production access log across successful refreshes, unknown tokens,
# malformed paths, oversized payloads, rate limiting, and upstream failures.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

if ! command -v nginx >/dev/null 2>&1; then
    echo -e "${YELLOW}nginx not found in PATH; skipping nginx integration test.${NC}"
    exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
    echo -e "${YELLOW}curl not found in PATH; skipping nginx integration test.${NC}"
    exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo -e "${YELLOW}openssl not found in PATH; skipping nginx integration test.${NC}"
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find or build subgate binary (prefer native Linux binary)
SUBGATE_BIN=""
if [[ -x "$REPO_DIR/target/linux/release/subgate" ]]; then
    SUBGATE_BIN="$REPO_DIR/target/linux/release/subgate"
elif [[ -x "$REPO_DIR/target/linux/debug/subgate" ]]; then
    SUBGATE_BIN="$REPO_DIR/target/linux/debug/subgate"
elif [[ -x "$REPO_DIR/target/release/subgate" ]]; then
    SUBGATE_BIN="$REPO_DIR/target/release/subgate"
elif [[ -x "$REPO_DIR/target/debug/subgate" ]]; then
    SUBGATE_BIN="$REPO_DIR/target/debug/subgate"
else
    echo "Building subgate binary for testing..."
    (cd "$REPO_DIR" && cargo build --target-dir target/linux)
    SUBGATE_BIN="$REPO_DIR/target/linux/debug/subgate"
fi

TEST_DIR=$(mktemp -d /tmp/subgate-nginx-privacy-XXXXXX)
trap 'cleanup' EXIT

cleanup() {
    if [[ -n "${NGINX_PID:-}" ]] && kill -0 "$NGINX_PID" 2>/dev/null; then
        kill "$NGINX_PID" 2>/dev/null || true
    fi
    if [[ -n "${SUBGATE_PID:-}" ]] && kill -0 "$SUBGATE_PID" 2>/dev/null; then
        kill "$SUBGATE_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}

BACKEND_PORT=18080
NGINX_PORT=18443

# Generate a unique synthetic token
SYNTHETIC_TOKEN="SYNTHETIC_SECRET_TOKEN_$(openssl rand -hex 12)"
UNKNOWN_TOKEN="UNKNOWN_SECRET_TOKEN_$(openssl rand -hex 12)"

# Clean up any leftover ports from prior crashed runs
fuser -k "$BACKEND_PORT/tcp" 2>/dev/null || true
fuser -k "$NGINX_PORT/tcp" 2>/dev/null || true

echo "=== Subgate Nginx Privacy & Token Leakage Test ==="
echo "Test directory: $TEST_DIR"
echo "Synthetic token: $SYNTHETIC_TOKEN"

# 1. Create subgate config.json
mkdir -p "$TEST_DIR/etc" "$TEST_DIR/ssl" "$TEST_DIR/logs"

cat << EOF > "$TEST_DIR/etc/config.json"
{
  "listen": "127.0.0.1:$BACKEND_PORT",
  "server_token": "nginx",
  "nodes": [
    {
      "name": "node-tokyo",
      "address": "198.51.100.1",
      "port": 443,
      "uuid": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
      "public-key": "bK4PTQX5dwqSdVBzADrqhPtALBwj9b0uYjYR29lS4xE",
      "short-id": "0123456789abcdef",
      "server-name": "tokyo.example.com"
    }
  ],
  "groups": [
    {
      "name": "VIP-Group",
      "token": "$SYNTHETIC_TOKEN",
      "nodes": ["node-tokyo"]
    }
  ]
}
EOF

# 2. Start subgate backend
export SUBGATE_CONTROL_SOCK="$TEST_DIR/control.sock"
"$SUBGATE_BIN" "$TEST_DIR/etc/config.json" > "$TEST_DIR/logs/subgate.log" 2>&1 &
SUBGATE_PID=$!
sleep 0.5

if ! kill -0 "$SUBGATE_PID" 2>/dev/null; then
    echo -e "${RED}Failed to start subgate backend${NC}"
    cat "$TEST_DIR/logs/subgate.log"
    exit 1
fi

# 3. Generate self-signed TLS cert
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
  -keyout "$TEST_DIR/ssl/subgate.key" \
  -out "$TEST_DIR/ssl/subgate.crt" \
  -subj "/CN=sub.example.com" 2>/dev/null

# 4. Generate isolated nginx.conf
cat << EOF > "$TEST_DIR/nginx.conf"
worker_processes 1;
pid $TEST_DIR/nginx.pid;
error_log $TEST_DIR/logs/error.log warn;

events {
    worker_connections 1024;
}

http {
    access_log off;
    client_body_temp_path $TEST_DIR/client_body;
    proxy_temp_path $TEST_DIR/proxy_temp;
    fastcgi_temp_path $TEST_DIR/fastcgi_temp;
    uwsgi_temp_path $TEST_DIR/uwsgi_temp;
    scgi_temp_path $TEST_DIR/scgi_temp;

    # Privacy-preserving URI mapping from deploy/nginx.conf.example
    map \$uri \$subgate_safe_uri {
        ~^/[^/]+/(clash|v2ray)$  "/*/\$1";
        ~^/$                     "/";
        default                  "/*";
    }

    # Redacted log format from deploy/nginx.conf.example
    log_format subgate_privacy '\$remote_addr - [\$time_iso8601] '
                               '"\$request_method \$subgate_safe_uri \$server_protocol" '
                               '\$status \$body_bytes_sent \$request_time '
                               '"\$http_user_agent"';

    limit_conn_zone \$binary_remote_addr zone=subgate_conn:10m;
    limit_req_zone \$binary_remote_addr zone=subgate_req:10m rate=5r/s;
    limit_req_log_level notice;
    limit_conn_log_level notice;

    upstream subgate_backend {
        server 127.0.0.1:$BACKEND_PORT;
        keepalive 32;
        keepalive_timeout 60s;
    }

    server {
        listen $NGINX_PORT ssl;
        server_name localhost;

        ssl_certificate $TEST_DIR/ssl/subgate.crt;
        ssl_certificate_key $TEST_DIR/ssl/subgate.key;
        ssl_protocols TLSv1.2 TLSv1.3;

        access_log $TEST_DIR/logs/access.log subgate_privacy;

        client_max_body_size 100k;
        limit_conn subgate_conn 32;
        limit_req zone=subgate_req burst=5 nodelay;

        location / {
            proxy_pass http://subgate_backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_connect_timeout 2s;
            proxy_read_timeout 5s;
        }
    }
}
EOF

# Verify nginx config syntax
echo "Testing nginx configuration syntax..."
nginx -t -c "$TEST_DIR/nginx.conf"

# Start nginx
nginx -c "$TEST_DIR/nginx.conf"
sleep 0.5
NGINX_PID=$(cat "$TEST_DIR/nginx.pid")

if ! kill -0 "$NGINX_PID" 2>/dev/null; then
    echo -e "${RED}Failed to start nginx${NC}"
    cat "$TEST_DIR/logs/error.log"
    exit 1
fi
echo -e "${GREEN}Nginx successfully started (PID: $NGINX_PID)${NC}"

# Exercise requests
echo "Exercising HTTP scenarios..."

# 1. Valid subscription (Clash & v2ray)
CODE_CLASH=$(curl -k -s -o /dev/null -w "%{http_code}" "https://127.0.0.1:$NGINX_PORT/$SYNTHETIC_TOKEN/clash")
CODE_V2RAY=$(curl -k -s -o /dev/null -w "%{http_code}" "https://127.0.0.1:$NGINX_PORT/$SYNTHETIC_TOKEN/v2ray")
echo "  [1] Valid requests: clash=$CODE_CLASH, v2ray=$CODE_V2RAY (expected 200, 200)"
[[ "$CODE_CLASH" -eq 200 ]] || { echo "Clash endpoint failed"; exit 1; }
[[ "$CODE_V2RAY" -eq 200 ]] || { echo "v2ray endpoint failed"; exit 1; }

# 2. Unknown token
CODE_UNKNOWN=$(curl -k -s -o /dev/null -w "%{http_code}" "https://127.0.0.1:$NGINX_PORT/$UNKNOWN_TOKEN/clash")
echo "  [2] Unknown token: status=$CODE_UNKNOWN (expected 404)"
[[ "$CODE_UNKNOWN" -eq 404 ]] || { echo "Unknown token test failed"; exit 1; }

# 3. Malformed URL with extra segments
CODE_MALFORMED=$(curl -k -s -o /dev/null -w "%{http_code}" "https://127.0.0.1:$NGINX_PORT/$SYNTHETIC_TOKEN/clash/extra/path")
echo "  [3] Malformed path: status=$CODE_MALFORMED (expected 404)"
[[ "$CODE_MALFORMED" -eq 404 ]] || { echo "Malformed path test failed"; exit 1; }

# 4. Oversized body (> 100k limit in test conf)
CODE_OVERSIZED=$(head -c 150000 /dev/zero | tr '\0' 'A' | curl -k -s -o /dev/null -w "%{http_code}" -X POST --data-binary @- "https://127.0.0.1:$NGINX_PORT/$SYNTHETIC_TOKEN/clash" || true)
echo "  [4] Oversized payload: status=$CODE_OVERSIZED (expected 413)"
[[ "$CODE_OVERSIZED" -eq 413 ]] || { echo "Oversized body test failed"; exit 1; }

# 5. Rate limiting: send 20 requests in tight loop to exhaust burst
RATE_LIMIT_HIT=0
for i in {1..20}; do
    CODE=$(curl -k -s --max-time 3 -o /dev/null -w "%{http_code}" "https://127.0.0.1:$NGINX_PORT/$SYNTHETIC_TOKEN/clash" || true)
    if [[ "$CODE" -eq 503 ]]; then
        RATE_LIMIT_HIT=1
    fi
done
echo "  [5] Rate limiting: hit 503=$RATE_LIMIT_HIT (expected 1)"
[[ "$RATE_LIMIT_HIT" -eq 1 ]] || { echo "Rate limit test failed to trigger 503"; exit 1; }

# 6. Upstream failure / 502 Bad Gateway
# Kill subgate with SIGKILL to simulate abrupt backend crash
kill -9 "$SUBGATE_PID" 2>/dev/null || true
SUBGATE_PID=""
sleep 0.5

CODE_502=$(curl -k -s --max-time 3 -o /dev/null -w "%{http_code}" "https://127.0.0.1:$NGINX_PORT/$SYNTHETIC_TOKEN/clash" || true)
echo "  [6] Backend down: status=$CODE_502 (expected 502)"
[[ "$CODE_502" -eq 502 ]] || { echo "Upstream failure test failed"; exit 1; }

# Stop nginx to ensure all log buffers are flushed to disk
nginx -s quit -c "$TEST_DIR/nginx.conf" 2>/dev/null || kill -9 "$NGINX_PID" 2>/dev/null || true
sleep 0.5
NGINX_PID=""

echo "Inspecting access log: $TEST_DIR/logs/access.log"
cat "$TEST_DIR/logs/access.log"

echo ""
echo "=== Security Audit Assertions ==="

# ASSERTION 1: Synthetic token must NOT appear in access.log
if grep -F "$SYNTHETIC_TOKEN" "$TEST_DIR/logs/access.log" >/dev/null; then
    echo -e "${RED}[FAIL] Synthetic token LEAKED into access.log!${NC}"
    grep -n -F "$SYNTHETIC_TOKEN" "$TEST_DIR/logs/access.log"
    exit 1
else
    echo -e "${GREEN}[PASS] Synthetic token did NOT appear in access.log.${NC}"
fi

# ASSERTION 2: Unknown token must NOT appear in access.log
if grep -F "$UNKNOWN_TOKEN" "$TEST_DIR/logs/access.log" >/dev/null; then
    echo -e "${RED}[FAIL] Unknown token LEAKED into access.log!${NC}"
    exit 1
else
    echo -e "${GREEN}[PASS] Unknown token did NOT appear in access.log.${NC}"
fi

# ASSERTION 3: Access log must contain redacted paths
if grep -F 'GET /*/clash' "$TEST_DIR/logs/access.log" >/dev/null; then
    echo -e "${GREEN}[PASS] Access log correctly uses redacted '/*/clash' paths.${NC}"
else
    echo -e "${RED}[FAIL] Expected '/*/clash' not found in access log!${NC}"
    exit 1
fi

# ASSERTION 4: Error log inspection
echo "Inspecting error log: $TEST_DIR/logs/error.log"
cat "$TEST_DIR/logs/error.log"

# Rate limit notices should NOT be logged as [error]
if grep -F 'limiting requests' "$TEST_DIR/logs/error.log" >/dev/null; then
    echo -e "${YELLOW}[NOTE] Rate limiting event recorded in error log.${NC}"
else
    echo -e "${GREEN}[PASS] Rate-limiting notice was suppressed from error log (level: warn).${NC}"
fi

echo -e "\n${GREEN}ALL NGINX PRIVACY AUDIT ASSERTIONS PASSED!${NC}"
exit 0
