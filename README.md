# subgate

Single-binary subscription gateway for VLESS+Reality. Serves mihomo / v2rayN
subscriptions, and everything else looks like a default nginx install.

## Status

- PR #1: nginx-compatible static front.
- PR #2: decoupled node table, group references, per-group display names,
  and strict config validation (no routes yet).

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
- `nodes` and `groups` default to empty lists, which leaves every path a 404.

## Nodes and groups

Nodes are defined once in a top-level `nodes` table and referenced by name from
any number of groups. Editing a node updates every subscription that publishes
it, and nothing is duplicated.

```json
{
  "nodes": [
    {
      "name": "hk-1",
      "address": "example.com",
      "port": 443,
      "uuid": "00000000-0000-0000-0000-000000000000",
      "public-key": "REPLACE_WITH_X25519_PUBLIC_KEY",
      "short-id": "0123456789abcdef",
      "server-name": "www.example.com"
    }
  ],
  "groups": [
    { "token": "abc123", "name": "main",   "nodes": ["hk-1"] },
    { "token": "def456", "name": "family", "nodes": [{ "ref": "hk-1", "name": "Hong Kong 01" }] }
  ]
}
```

`group.nodes` holds **references**, and their order is the order clients
receive. A reference is either a bare node name or an object:

```json
{ "ref": "hk-1", "name": "Hong Kong 01" }
```

`ref` names a node in the top-level table. The optional `name` overrides the
label shown in the client, so the same node can be called something different
in each subscription that publishes it. Without an override the node's own
`name` is used.

A node may appear in several groups, but not twice within one group — even
under two different display names, since it is still the same node. An
unreferenced node is allowed, so nodes can be staged before assignment.

### Node fields

Every field below must appear in the config. A missing or misspelled key is a
startup error, not a silent default:

| Field | Rule |
|---|---|
| `name` | non-empty |
| `address` | non-empty |
| `port` | 1–65535 |
| `uuid` | non-empty |
| `public-key` | non-empty |
| `short-id` | **must be present**; an empty string is valid |
| `server-name` | **must be present and non-empty** |

`short-id` may be empty because a Reality server that performs no shortId
matching accepts any client. `server-name` is the SNI the handshake
impersonates; an empty value produces a node that renders without error and
then fails to connect, so it is rejected outright.

Optional, with the defaults a Reality client expects:

| Field | Default |
|---|---|
| `flow` | `xtls-rprx-vision` |
| `fingerprint` | `chrome` |
| `alpn` | `["h2", "http/1.1"]` |
| `spider-x` | `""` |

`flow` may be set to an empty string to omit flow control entirely.

Validation happens at load time. These are all fatal:

- an empty or non-ASCII-alphanumeric token (it becomes a URL path segment)
- duplicate tokens, group names, or node names
- a group referencing a node that does not exist, or an empty reference
- a group listing the same node twice, with or without a display-name override
- an empty or whitespace-only group name or display-name override
- an empty node name, address, uuid, or public-key
- a port of 0
- a control character in any group name, display name, or node field. These
  values are written verbatim into YAML and subscription links, so a newline
  would corrupt the output
- an empty ALPN entry, or one containing a comma, which would silently split
  into two entries when the list is joined
- any unknown field, at every level

Optional node fields (`flow`, `fingerprint`, `short-id`, `server-name`,
`spider-x`) may be left blank — that is how a client is told to omit them — but
they are still subject to the control-character rule.

Token comparison is constant-time, and every group is scanned even after a
match, so lookup cost does not depend on a token's position.

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

## Subscription endpoints

| Path | Output |
|---|---|
| `/<token>/clash` | mihomo / Clash Verge profile (`text/yaml`) |
| `/<token>/v2ray` | v2rayN subscription, base64 of `vless://` links (`text/plain`) |

Both send `Cache-Control: no-store`, so rotating a token takes effect at the
next refresh.

An unknown token, a token without a suffix, or any other suffix returns the
same 404 as every other unknown path, byte for byte. A token cannot be
discovered by comparing response shapes.

### Clash

A self-contained profile: `proxies`, a selector group named after the group, and
`MATCH` into it. Scalars are quoted only when YAML requires it, so the document
stays readable while names like `a: b`, `#hash`, or `true` still round-trip
exactly.

### v2ray

Standard base64 of newline-separated `vless://` links. Every value is
percent-encoded, so an `spider-x` of `/` or an ALPN list containing commas is
safe. IPv6 addresses are bracketed.

## Reloading

Send `SIGHUP` to re-read the config:

```bash
systemctl reload subgate
# or
kill -HUP $(pidof subgate)
```

The file is read and fully validated before anything is swapped, so a failed
reload never leaves a half-applied config. If validation fails:

- the process keeps running;
- the old config is **discarded**, so every request answers `503` with
  `Retry-After: 5` rather than continuing to serve a config that no longer
  matches the file;
- once a reload succeeds, service resumes without a restart.

There is no mtime polling: reload happens only on `SIGHUP`.

The swap is a single `RwLock` write of an `Arc`, and each request takes one
read lock, so reloading does not stall traffic.

## Deployment

`systemd/subgate.service` is a starting point:

```ini
ExecStart=/usr/local/bin/subgate /etc/subgate/config.json
ExecReload=/bin/kill -HUP $MAINPID
```

It runs as a `DynamicUser` with `ProtectSystem=strict` and
`ReadOnlyPaths=/etc/subgate`, so the config cannot be modified by the service
itself.

Because `/etc/subgate` is read-only to the service, write the config as root and
then reload.

## Source layout

| File | Responsibility |
|---|---|
| `server.rs` | HTTP/1.1 framing: parse a request, write bytes |
| `serialize.rs` | Response construction and header ordering |
| `routes.rs` | Routing and per-request response decisions |
| `condition.rs` | `If-*` evaluation |
| `range.rs` | `Range` parsing and multipart bodies |
| `stealth.rs` | HTTP dates and ETag derivation |
| `errors.rs` | nginx built-in error pages |
| `config.rs` | Load, index, and query the config |
| `validate.rs` | Every rule that decides what a config may contain |
| `model.rs` | `Node`, `Group`, `NodeRef`, `Format` |
| `state.rs` | Live config slot and SIGHUP reload semantics |
| `render/clash.rs` | Clash YAML |
| `render/v2ray.rs` | base64 `vless://` subscription |

Loading builds the node index first, then validates. That order keeps the
reference check a hash lookup instead of a scan of the node table for every
reference, which matters once a config carries thousands of nodes.

Token comparison folds the length into the result rather than returning early
on a length mismatch, so the number of rounds does not reveal the token's
length. Every group is still compared, so a match's position is not observable
either.

## Why no web framework

axum's `RouteFuture` unconditionally adds `Content-Length: 0` to empty-body
responses, and hyper normalises header names to `Etag` and reorders them. Both
are observable differences from real nginx, so request parsing and response
serialisation are hand-written in `src/server.rs` and `src/serialize.rs`.

TLS is terminated by a fronting nginx; subgate listens on `127.0.0.1` only.
