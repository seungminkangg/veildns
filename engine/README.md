# VeilDNS engine

An original, local HTTP proxy written in Rust. It resolves proxy destinations
through encrypted DNS and can divide an outgoing TLS ClientHello into separate
TLS records inside its visible SNI hostname. It never terminates the user's TLS
connection or installs a certificate authority.

Only applications configured to use this proxy send traffic through the engine.
Running the binary alone does **not** change macOS proxy settings, protect all
system DNS, or route UDP/QUIC traffic. See the project README for the macOS app
and its system-proxy lifecycle.

## Build and checks

```sh
cargo build --release --locked
cargo test --all-targets --locked
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
```

The project uses Rust edition 2024, Tokio, Hyper 1 and reqwest with rustls. The
committed Cargo.lock fixes the dependency graph. Unit and loopback tests require
no public network. `../scripts/smoke-proxy.py` separately checks real DoH, a
certificate-verified TLS connection, and HTTPS with fragmentation enabled.

## CLI and event contract

```sh
veildns-engine --config config.json
veildns-engine --config config.json --exit-on-stdin-close
veildns-engine --check-config config.json
veildns-engine --help
veildns-engine --version
```

`--config` is required for serving. `--check-config` parses and validates without
binding a socket or making network requests. Errors exit with status 1. Successful
checks and ordinary shutdown exit with status 0.

The optional `--exit-on-stdin-close` flag supports GUI supervision. The app gives
the child a dedicated stdin pipe and retains the write end. Closing that write
end, including on parent death, stops the engine and its active connections. Do
not use this flag with a closed stdin if the process should remain running.
Ctrl-C and Unix SIGTERM also stop it. Normal CLI usage does not monitor stdin.

Except for help/version output, stdout contains newline-delimited JSON:

```json
{"event":"config_valid"}
{"event":"ready","listen":"127.0.0.1:8080"}
{"event":"stopped","requests":8,"tunnels":6,"fragmented":3,"errors":0}
{"event":"error","code":"startup_failed","message":"Check configuration, port availability, and engine permissions"}
```

`ready` means the loopback listener and local resolver client were created. It
does not assert that a public resolver or destination is reachable. `stopped`
counts are cumulative process totals, not active connection counts; `errors`
includes rejected proxy requests and tunnel I/O failures. No domains, URLs,
credentials, packet contents, or TLS secrets are emitted. There is no telemetry
or on-disk query history.

## Configuration

See [config.example.json](config.example.json). Omitted fields use these defaults:

| Field | Default | Accepted values |
| --- | --- | --- |
| `listen_port` | `8080` | Integer, 1–65535 |
| `resolver` | `"google"` | `"cloudflare"`, `"google"` |
| `fragmentation` | `"all"` | `"selected"`, `"all"`, `"off"` |
| `domains` | `[]` | Up to 4096 exact or wildcard domain rules |
| `exclusions` | `[]` | Up to 4096 exact or wildcard domain rules |
| `fragment_delay_ms` | `5` | Integer, 0–100 |
| `allow_private` | `false` | Boolean; explicitly permits private/reserved destinations |

Unknown fields and malformed values are rejected. Configuration files are
limited to 256 KiB. Hostnames use ASCII or IDNA punycode, are case-insensitive,
and have an optional trailing dot removed. `example.com` matches only that name;
`*.example.com` matches its subdomains and does not match `example.com` itself.
IP addresses, URLs and arbitrary glob syntax are not domain rules.

Selected mode matches the **observed SNI** against `domains`. An exclusion on
either the CONNECT target name or observed SNI wins. All mode still respects
exclusions. Off disables fragmentation while retaining encrypted DNS resolution.
An empty selected list performs no SNI buffering.

## Network behavior and bounds

- The listener is always IPv4 loopback `127.0.0.1`. It cannot be configured to
  listen on LAN interfaces. Any local process with network access can use it;
  it is not an authenticated multi-user proxy.
- HTTPS uses HTTP/1 CONNECT. Plain HTTP requires an absolute `http://` URI.
  Host headers must identify the same destination, including the port when
  required. Hyper handles HTTP framing. Proxy credentials and hop-by-hop
  headers are stripped from forwarded headers and trailers.
- There are at most 128 HTTP client connections plus 256 established CONNECT
  tunnels. Excess connections are closed or receive HTTP 503. Headers are
  limited to 64 fields with a 32 KiB parser buffer and an explicit 32 KiB
  forwarded-header limit; request URIs are limited to 8 KiB. Header reading
  times out after 10 seconds.
- Outbound addresses come from the checked DoH result and are connected as IP
  addresses. There is no second hostname lookup or system-DNS fallback. By
  default, private, loopback, link-local, multicast, documentation and other
  reserved/transition ranges are rejected. `allow_private` is an explicit
  opt-in for private networks or loopback tests.
- Cloudflare uses `https://cloudflare-dns.com/dns-query` with bootstrap
  `1.1.1.1`. Google uses `https://dns.google/resolve` with bootstrap `8.8.8.8`.
  Both use their supported DNS JSON API with HTTPS certificate validation.
  Resolver requests ignore environment/system proxies, reject redirects and
  disable TLS key logging. There is no cross-provider fallback.
- A and AAAA queries run concurrently. Successful results from one address
  family can be used if the other query fails. Responses validate question,
  record type, success/truncation state and CNAME chain before accepting
  addresses. Responses are limited to 64 KiB, 128 answers and 16 CNAME steps.
  The in-memory cache has at most 1024 names and respects a maximum TTL of
  300 seconds; zero-TTL answers are not cached. The configured resolver can
  observe queries, and the engine does not independently validate DNSSEC.
- A DoH request has an 8-second total deadline and 5-second connect deadline.
  Target connection attempts have a 12-second total deadline, at most 16 IP
  addresses and 3 seconds per IP. HTTP response headers have a 30-second
  deadline, including request upload. Connections close after 5 minutes with
  no I/O; active long transfers remain open.
- SNI inspection waits at most 3 seconds and buffers at most 128 KiB, up to
  64 TLS records, an individual record up to 18 KiB, and a ClientHello body
  up to 64 KiB. ClientHello data can span TCP reads and multiple TLS records.
  Incomplete, malformed, unsupported or oversized input passes through
  unchanged. A successfully parsed hostname is split strictly inside one
  original TLS record, preserving all TLS handshake bytes and following data.

TLS record boundaries are **not** guaranteed TCP packet boundaries. The OS or
network may combine writes. Fragmentation effectiveness depends on the network
and destination and is not guaranteed. ECH hides the inner SNI; this engine can
only inspect a visible outer ClientHello name. QUIC/HTTP3, SOCKS, UDP forwarding,
transparent interception and plain-HTTP WebSocket upgrades are not implemented.
WebSockets inside a successful HTTPS CONNECT tunnel remain ordinary TLS traffic.
