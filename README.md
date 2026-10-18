# subgate

Production-ready single-binary subscription gateway for VLESS+Reality. Serves Mihomo (Clash) and v2rayN subscriptions while impersonating a default Ubuntu nginx 1.28.3 install for all other requests.

## Overview

- **Subscription endpoints**: Generates Mihomo / Clash Verge YAML profiles and v2rayN `vless://` base64 subscriptions.
- **Group isolation & display names**: Shared top-level node definitions with per-group display name overrides and token isolation.
- **Stealth front**: Byte-for-byte alignment with standard Ubuntu nginx static responses, status pages (404, 405, 412, 413, 416), header casing/ordering, ETag, and Range handling.
- **Token privacy**: Nginx log redaction prevents bearer subscription tokens from leaking into access logs.
- **Hardened HTTP/1.1 framing**: Strict RFC 9112 origin-form target verification, single `Host` header enforcement, rejection of request smuggling vectors (Transfer-Encoding, duplicate Content-Length, obsolete line folding).
- **Resource bounds**: Concurrency semaphores (`max_conns`), request head and body limits, distinct phase deadlines for idle, header, body, and write timeouts, and Range amplification bounds. Environment overrides are safely clamped against zero or pathological values.
- **Safe configuration lifecycle**: Atomic runtime swaps, generation tracking, synchronous reload acknowledgment via control socket (`subgate --reload`), failure tolerance retaining the last-known-good configuration, and CLI validation (`--check`).
- **Production deployment**: Hardened systemd unit with `DynamicUser=yes`, `RuntimeDirectory=subgate`, least-privilege permissions, automated upgrade/rollback scripts, and an nginx reverse proxy configuration.

## CLI Usage

```bash
# Validate configuration syntax, schema, and active listen compatibility (exit 0 on success, 1 on error):
subgate --check /etc/subgate/config.json

# Trigger a synchronous runtime reload against the active process via control socket:
subgate --reload /etc/subgate/config.json

# Query runtime metrics (PID, active listen address, generation, groups, nodes):
subgate --status

# Run gateway in production:
subgate /etc/subgate/config.json
```

## Security Model

### Token Security Policy

- **Token entropy**: Tokens act as the authorization secret protecting your node table. Production tokens must be generated using a cryptographically secure random generator with at least 128 bits of entropy.
  ```bash
  # Generate 192 bits of base64url entropy (24 bytes, 32 characters):
  openssl rand -base64 24 | tr '+/' '-_' | tr -d '='
  ```
- **Token validation**: Tokens must contain only ASCII alphanumeric characters, `-`, and `_`, with a length between 16 and 128 characters.
- **Constant-time comparison**: Token matching evaluates every character and iterates over all configured groups without early exits, preventing timing attacks.
- **Disproportionate computation guard**: Requests with token segments outside 16..=128 characters or containing invalid characters are rejected immediately in O(1) without group scanning.
- **Secret non-disclosure**: Tokens and secret keys are never emitted in application logs, error messages, or response headers. Error logs identify groups exclusively by `group.name`.
- **Cache control**: Subscription responses always emit `Cache-Control: no-store` to prevent intermediary or browser caching of subscription credentials.
- **Response shape invariance**: Unknown tokens, missing formats, unsupported methods, or non-existent paths return identical nginx 404 responses. Probing cannot disclose token existence.

### Logging Privacy & Reverse Proxy Boundary

Because subscription tokens are embedded in request URLs (`/<token>/clash`, `/<token>/v2ray`), standard reverse proxy configurations can accidentally record secret tokens in plain text. Subgate addresses this across the proxy boundary:

1. **Access log redaction**: [`deploy/nginx.conf.example`](deploy/nginx.conf.example) defines a privacy-preserving URI mapping and custom log format:
   ```nginx
   map $uri $subgate_safe_uri {
       ~^/[^/]+/(clash|v2ray)$  "/*/$1";
       ~^/$                     "/";
       default                  "/*";
   }

   log_format subgate_privacy '$remote_addr - [$time_iso8601] '
                              '"$request_method $subgate_safe_uri $server_protocol" '
                              '$status $body_bytes_sent $request_time '
                              '"$http_user_agent"';
   ```
   - Raw `$request` is replaced with sanitized `"$request_method $subgate_safe_uri $server_protocol"`.
   - Raw query strings, Authorization headers, and `Referer` headers are omitted from access logs.
   - The token is completely scrubbed from disk logs while preserving client IP, HTTP status, response size, and request duration.
2. **Error log considerations**: Nginx's internal error-log format is hardcoded in C and logs `$request` upon warning and error events.
   - Setting `limit_req_log_level notice;` and `limit_conn_log_level notice;` prevents rate-limit events from writing tokens to error logs.
   - In zero-leakage threat environments, setting `error_log /var/log/nginx/subgate.error.log crit;` suppresses upstream connection failure dumps (with the trade-off of reduced diagnostic visibility during backend downtime).
   - Ensure restrictive file permissions: `chmod 0640 /var/log/nginx/subgate.error.log`.
3. **Application logs**: Subgate's internal tracing logs only connection counts, listening addresses, reload generation results, and systemd notifications. URL paths and tokens are never logged.

## Configuration Format

```json
{
  "listen": "127.0.0.1:8080",
  "server_token": "nginx/1.28.3 (Ubuntu)",
  "nodes": [
    {
      "name": "hk-1",
      "address": "example.com",
      "port": 443,
      "uuid": "00000000-0000-0000-0000-000000000000",
      "public-key": "bK4PTQX5dwqSdVBzADrqhPtALBwj9b0uYjYR29lS4xE",
      "short-id": "0123456789abcdef",
      "server-name": "www.example.com",
      "flow": "xtls-rprx-vision",
      "fingerprint": "chrome",
      "alpn": ["h2", "http/1.1"],
      "spider-x": "/"
    }
  ],
  "groups": [
    {
      "token": "kQ7vT2xLm9pZr4sW8yB3nE6hJ5cD1fG0",
      "name": "main",
      "nodes": ["hk-1"]
    },
    {
      "token": "uX2wN8pQ4tK7vB1mZ5cR9dF3hJ6sL0aE",
      "name": "family",
      "nodes": [
        {
          "ref": "hk-1",
          "name": "Hong Kong Fast"
        }
      ]
    }
  ]
}
```

### Semantic Validation Rules

Validation occurs at startup and upon reload:
- **`listen`**: Valid IPv4 or IPv6 socket address (e.g. `127.0.0.1:8080`). Sockets are bound at boot; changing `listen` at runtime requires a process restart.
- **`uuid`**: Standard 8-4-4-4-12 hex UUID format.
- **`public-key`**: Base64 or base64url string decoding to exactly 32 bytes (X25519 public key).
- **`short-id`**: Even-length hexadecimal string up to 16 characters (or empty string if server performs no short-id matching).
- **`address`**: Valid hostname, IPv4, or bracketed IPv6 address without whitespace, `/`, `@`, `?`, or `#`.
- **`port`**: 1–65535 (port 0 rejected).
- **`server-name`**: Valid Reality SNI hostname without whitespace, `/`, or `:`.
- **`group.name`**: Non-empty, without control characters, commas, or YAML syntax characters that could corrupt Mihomo `MATCH,<group.name>` rules.
- **Display name uniqueness**: Every effective node display name within a single group must be unique.
- **Node references**: References in groups must resolve to valid node definitions. No node may be referenced twice within the same group.

## Resource Limits & DoS Controls

All network resource bounds are centralized in `src/limits.rs` and can be adjusted via environment variables. Values are strictly validated and clamped to prevent zero or pathological misconfigurations from taking down the gateway:

| Resource | Default | Clamped Range | Environment Override | Behavior on Limit |
|---|---|---|---|---|
| Concurrent connections | 512 | `1..=65535` | `SUBGATE_MAX_CONNS` | Excess accepted TCP streams dropped immediately (zero falls back to default) |
| Keepalive requests | 1000 | `1..=100000` | `SUBGATE_KEEPALIVE_REQUESTS` | Final request emits `Connection: close` and shuts down socket |
| Phase timeouts | 60–65s | `50..=600000ms` | `SUBGATE_TIMEOUT_MS` | Idle (65s), Header (60s), Body (60s), Write (10s); closes connection on elapse |
| Max request head size | 16 KiB | Hard limit | - | 400 Bad Request & Connection close |
| Max request headers | 100 | Hard limit | - | 400 Bad Request & Connection close |
| Max request body size | 8 MiB | Hard limit | - | 413 Request Entity Too Large & Connection close |
| Max multipart ranges | 100 | Hard limit | - | Capped; requests exceeding 100 ranges fall back to 200 OK full body |

## Subscription Endpoints

| Path | Format | Content-Type | Description |
|---|---|---|---|
| `/<token>/clash` | Mihomo / Clash Verge | `text/yaml; charset=utf-8` | Standalone profile with `proxies`, select group, and `MATCH` rule |
| `/<token>/v2ray` | v2rayN / v2rayNG | `text/plain; charset=utf-8` | Standard base64-encoded `vless://` share links |

Subscription responses carry `Cache-Control: no-store` and `Connection: keep-alive` (or `close`).

## Configuration Reload Lifecycle

To reload configuration without dropping active connections:

```bash
# Recommended: synchronous reload via systemd (calls subgate --reload via control socket)
sudo systemctl reload subgate

# Or directly via CLI:
subgate --reload /etc/subgate/config.json

# Or asynchronously via SIGHUP:
kill -HUP $(pidof subgate)
```

1. **Synchronous verification**: `subgate --reload` connects to the running daemon's Unix domain control socket (`/run/subgate/control.sock`), triggers the reload, and returns exit code 0 with the new generation counter (e.g. `config reloaded (generation=2)`), or exit code 1 with the exact validation error.
2. **Atomic swap**: The file is read (up to 1 MiB) and fully validated. A successful parse atomically replaces the running `Arc<Config>`. In-flight requests continue using their existing snapshot.
3. **Failure resilience**: If a reload fails (syntax error, file read failure, or semantic validation failure), subgate logs the failure and **retains the last-known-good configuration**, keeping service uninterrupted.
4. **Listen address lock**: Changing `listen` at runtime is rejected predictably and reports an error to the operator indicating that a restart is required.
5. **Runtime status inspection**: Operators can query `subgate --status` at any time to verify active PID, listen address, reload generation, and group counts.

## Production Deployment

### 1. File Permissions & DynamicUser

`systemd/subgate.service` uses `DynamicUser=yes` with strict sandbox isolation and `RuntimeDirectory=subgate`. Configuration files should be owned by root and readable by the `subgate` group:

```bash
# Create subgate system group if not present
sudo groupadd -r subgate

# Secure directory and configuration file
sudo mkdir -p /etc/subgate
sudo chown -R root:subgate /etc/subgate
sudo chmod 0750 /etc/subgate
sudo chmod 0640 /etc/subgate/config.json
```

### 2. Systemd Service Installation

```bash
# 1. Install binary
sudo install -m 0755 target/release/subgate /usr/local/bin/subgate

# 2. Install service unit
sudo cp systemd/subgate.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now subgate

# 3. Verify status
sudo systemctl status subgate
```

### 3. Nginx Reverse Proxy Setup

Subgate is designed to sit behind an nginx reverse proxy listening on loopback (`127.0.0.1:8080`).

Copy [`deploy/nginx.conf.example`](deploy/nginx.conf.example) to `/etc/nginx/conf.d/subgate.conf` (or `/etc/nginx/sites-available/subgate`), replace domain and certificate paths, and reload nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## Upgrade and Rollback Procedures

Subgate includes automated scripts under `scripts/` to ensure safe, atomic binary updates with pre-flight verification and automatic rollback.

### Automated Upgrades with `scripts/upgrade.sh`

```bash
# 1. Build new release binary
cargo build --release --locked

# 2. Dry-run pre-flight check (verifies configuration compatibility without modifying system)
SUBGATE_DRY_RUN=1 ./scripts/upgrade.sh ./target/release/subgate /etc/subgate/config.json

# 3. Perform live atomic upgrade
sudo ./scripts/upgrade.sh ./target/release/subgate /etc/subgate/config.json
```

The upgrade script executes the following safety guarantees:
1. Validates the configuration file against the new binary via `--check` before touching any system files.
2. Backs up the current running executable to `/usr/local/bin/subgate.bak`.
3. Atomically replaces `/usr/local/bin/subgate` via a temporary file on the same filesystem (`install` + `mv -f`), avoiding `ETXTBSY`.
4. Restarts `subgate.service` and verifies health.
5. If the new binary fails to start or exits within 2 seconds, **automatically restores the backup executable and restarts the service**.

### Manual or Emergency Rollback with `scripts/rollback.sh`

If an issue is detected after deployment:

```bash
sudo ./scripts/rollback.sh /etc/subgate/config.json
```

Or manually:
```bash
sudo cp -p /usr/local/bin/subgate.bak /usr/local/bin/subgate
sudo systemctl restart subgate
sudo systemctl status subgate
```
