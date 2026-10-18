# subgate

Production-ready single-binary subscription gateway for VLESS+Reality. Serves Mihomo (Clash) and v2rayN subscriptions while impersonating a default Ubuntu nginx 1.28.3 install for all other requests.

## Overview

- **Subscription endpoints**: Generates Mihomo / Clash Verge YAML profiles and v2rayN `vless://` base64 subscriptions.
- **Group isolation & display names**: Shared top-level node definitions with per-group display name overrides and token isolation.
- **Stealth front**: Byte-for-byte alignment with standard Ubuntu nginx static responses, status pages (404, 405, 412, 413, 416), header casing/ordering, ETag, and Range handling.
- **Hardened HTTP/1.1 framing**: Strict RFC 9112 origin-form target verification, single `Host` header enforcement, rejection of request smuggling vectors (Transfer-Encoding, duplicate Content-Length, obsolete line folding).
- **Resource bounds**: Concurrency semaphores (`max_conns`), request head and body limits, timeouts for idle/header/body/write phases, and Range amplification bounds.
- **Safe configuration lifecycle**: Atomic runtime swaps, failure tolerance retaining the last-known-good configuration, and CLI validation (`--check`).
- **Production deployment**: Hardened systemd unit with `DynamicUser=yes`, least-privilege permissions, and an nginx reverse proxy configuration.

## CLI Usage

```bash
# Validate configuration without starting network listener (exit 0 on success, 1 on error):
subgate --check /etc/subgate/config.json

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
- **`listen`**: Valid IPv4 or IPv6 socket address (e.g. `127.0.0.1:8080`). Cannot be changed across SIGHUP reloads without restart.
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

All network resource bounds are centralized in `src/limits.rs` and can be adjusted via environment variables:

| Resource | Default | Environment Override | Behavior on Limit |
|---|---|---|---|
| Concurrent connections | 512 | `SUBGATE_MAX_CONNS` | Excess accepted TCP streams dropped immediately |
| Keepalive requests | 1000 | `SUBGATE_KEEPALIVE_REQUESTS` | Final request emits `Connection: close` and shuts down socket |
| Phase timeouts | 60–65s | `SUBGATE_TIMEOUT_MS` | Idle (65s), Header (60s), Body (60s), Write (60s); closes connection on elapse |
| Max request head size | 16 KiB | Hard limit | 400 Bad Request & Connection close |
| Max request headers | 100 | Hard limit | 400 Bad Request & Connection close |
| Max request body size | 8 MiB | Hard limit | 413 Request Entity Too Large & Connection close |
| Max multipart ranges | 100 | Hard limit | Capped; requests exceeding 100 ranges fall back to 200 OK full body |

## Subscription Endpoints

| Path | Format | Content-Type | Description |
|---|---|---|---|
| `/<token>/clash` | Mihomo / Clash Verge | `text/yaml; charset=utf-8` | Standalone profile with `proxies`, select group, and `MATCH` rule |
| `/<token>/v2ray` | v2rayN / v2rayNG | `text/plain; charset=utf-8` | Standard base64-encoded `vless://` share links |

Subscription responses carry `Cache-Control: no-store` and `Connection: keep-alive` (or `close`).

## Configuration Reload Lifecycle

To reload configuration without dropping active connections:

```bash
systemctl reload subgate
# or
kill -HUP $(pidof subgate)
```

1. **Pre-flight verification**: When invoked via systemd, `subgate --check` validates the configuration before sending `SIGHUP`. If invalid, `systemctl reload` returns failure immediately.
2. **Atomic swap**: The file is read (up to 1 MiB) and fully validated. A successful parse atomically replaces the running `Arc<Config>`. In-flight requests continue using their existing snapshot.
3. **Failure resilience**: If a reload fails (syntax error, file read failure, or semantic validation failure), subgate logs the failure and **retains the last-known-good configuration**, keeping service available.
4. **Listen address lock**: Sockets are bound at process boot. Changing `listen` requires restarting the process.

## Production Deployment

### 1. File Permissions & DynamicUser

`systemd/subgate.service` uses `DynamicUser=yes` with strict sandbox isolation. Configuration files should be owned by root and readable by the `subgate` group:

```bash
# Create subgate system group if not present
groupadd -r subgate

# Secure directory and configuration file
mkdir -p /etc/subgate
chown -R root:subgate /etc/subgate
chmod 0750 /etc/subgate
chmod 0640 /etc/subgate/config.json
```

### 2. Systemd Service

Copy `systemd/subgate.service` to `/etc/systemd/system/subgate.service`:

```bash
cp target/release/subgate /usr/local/bin/subgate
cp systemd/subgate.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now subgate
```

### 3. Nginx Reverse Proxy

Subgate is designed to sit behind an nginx reverse proxy listening on loopback (`127.0.0.1:8080`).

See [`deploy/nginx.conf.example`](deploy/nginx.conf.example) for the complete configuration, including:
- TLS 1.2/1.3 termination and HTTP/2.
- Connection and rate limiting zones.
- Backend keepalive pool (`keepalive 32; keepalive_timeout 60s;`).
- Standard reverse-proxy header forwarding (`Host`, `X-Forwarded-For`).

## Upgrade and Rollback Procedure

### Upgrades

1. Build the release binary: `cargo build --release --locked`.
2. Validate new binary against existing configuration:
   ```bash
   ./target/release/subgate --check /etc/subgate/config.json
   ```
3. Install binary:
   ```bash
   install -m 0755 target/release/subgate /usr/local/bin/subgate.new
   mv /usr/local/bin/subgate.new /usr/local/bin/subgate
   ```
4. Restart service:
   ```bash
   systemctl restart subgate
   ```
5. Verify status and logs:
   ```bash
   systemctl status subgate
   journalctl -u subgate -n 20
   ```

### Rollback

1. Restore previous binary from backup or previous release:
   ```bash
   cp /usr/local/bin/subgate.bak /usr/local/bin/subgate
   systemctl restart subgate
   ```
2. If configuration needs to be rolled back:
   ```bash
   cp /etc/subgate/config.json.bak /etc/subgate/config.json
   systemctl reload subgate
   ```
