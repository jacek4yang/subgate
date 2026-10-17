# subgate

Single-binary subscription gateway for VLESS+Reality. Serves mihomo / v2rayN
subscriptions, and everything else looks like a default nginx install.

## Status

PR #1: nginx-compatible static front (no subscription routes yet).

## Run

```bash
cargo build --release
./target/release/subgate config.json
```

The config file is mandatory. A missing file, invalid JSON, or an unknown field
aborts startup with exit code 1.

```json
{
  "listen": "127.0.0.1:8080",
  "server_token": "nginx/1.28.3 (Ubuntu)"
}
```

- `listen` is required.
- `server_token` defaults to `nginx/1.28.3 (Ubuntu)`, the value a stock Ubuntu
  26.04 install emits. It drives both the `Server` header and the
  `<hr><center>...</center>` line of the error pages, so they can never drift
  apart — the same invariant real nginx maintains through `server_tokens`.

## Stealth model

The impersonation target is a default Ubuntu nginx 1.28.3 install. Every
behaviour below was captured from a real nginx running in WSL and stored under
`tests/golden/`; the test suite asserts on those bytes.

### Aligned

| Item | Behaviour |
|---|---|
| Home page body | Ubuntu's `index.nginx-debian.html`, 615 bytes, byte-identical |
| Header order | `Server → Date → Content-Type → Content-Length → Last-Modified → Connection → ETag → Accept-Ranges → Content-Range` |
| Header casing | Exactly as nginx writes it, including `ETag` (not `Etag`) |
| `Last-Modified` / `ETag` | Derived from the asset's size and mtime, same rule as `ngx_http_set_etag()` |
| 404 / 405 / 416 | nginx built-in pages with the `<hr><center>` tail; no `ETag`, `Last-Modified` or `Accept-Ranges` |
| 304 | Keeps `ETag` and `Last-Modified`, sends **no** `Content-Type`, `Content-Length` or `Accept-Ranges` |
| `If-Modified-Since` | Exact semantics: 304 only when the timestamp is **equal** |
| `If-None-Match` | Supports `W/` weak comparison, comma lists, and `*` |
| `If-Match` / `If-Unmodified-Since` | 412 when unsatisfied |
| `Range` | Single range 206, suffix `-N`, open-ended `start-`, clamping, 416 on invalid |
| Multi-range | `multipart/byteranges` with nginx's 20-digit zero-padded process-wide boundary counter |
| `If-Range` | Strong ETag match, or exact date match |
| `Connection` | HTTP/1.0 defaults to `close` unless `keep-alive` is requested; HTTP/1.1 defaults to `keep-alive` |
| `Keep-Alive` header | **Not sent** — Ubuntu's default config leaves the second `keepalive_timeout` argument unset |

### Known differences

| Item | Reason |
|---|---|
| Home page mtime | Derived from the asset at build time, so `Last-Modified` and `ETag` carry different values than the target machine's `index.nginx-debian.html` |

## Why no web framework

axum's `RouteFuture` unconditionally adds `Content-Length: 0` to empty-body
responses, and hyper normalises header names to `Etag` and reorders them. Both
are observable differences from real nginx, so request parsing and response
serialisation are hand-written in `src/server.rs` and `src/serialize.rs`.

TLS is terminated by a fronting nginx; subgate listens on `127.0.0.1` only.
