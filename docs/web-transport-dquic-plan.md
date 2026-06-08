# Plan: Add `web-transport-dquic` backend crate

## Context

The workspace ships WebTransport (HTTP/3 over QUIC) on top of several interchangeable QUIC
backends, each as a standalone crate implementing the shared `web_transport_trait` interface:
`web-transport-quinn`, `-noq`, `-quiche`, and most recently `-s2n` (commit `42a4df1`).

We want to add the same support for [dquic](https://github.com/genmeta/dquic) — a native
async-Rust QUIC implementation (crates.io `dquic = "0.5"`, edition 2024, Apache-2.0). The goal
is a new `rs/web-transport-dquic` crate that mirrors `web-transport-s2n` file-for-file, swapping
only the QUIC-library touchpoints. No existing crate needs to change behaviour; the only wiring
is registering the new member.

Why dquic is a good fit: its `StreamReader`/`StreamWriter` implement tokio's `AsyncRead`/
`AsyncWrite` (which is exactly what `web-transport-proto`'s handshake helpers consume), it has
builder-based client/server APIs, ALPN configuration, and RFC 9221 datagrams enabled by default.

## Approach: clone `web-transport-s2n`, swap the QUIC layer

`web-transport-s2n` is **standalone** — it is NOT part of the `web-transport` router (which only
routes quinn↔wasm). So the work is confined to one new crate plus a one-line workspace edit.

Reference crate: `rs/web-transport-s2n/` (all paths below mirror it).
The protocol layer (`web-transport-proto`) and trait layer (`web-transport-trait`) are reused
**unchanged** — `proto` already uses tokio `AsyncRead`/`AsyncWrite`, which dquic streams satisfy.

### Files to create under `rs/web-transport-dquic/`

| File | Mirrors s2n's | dquic-specific changes |
|------|---------------|------------------------|
| `Cargo.toml` | same metadata | name `web-transport-dquic`, replace `s2n-quic`/`rustls`/datagram deps with `dquic = "0.5"`; keep `web-transport-proto`/`-trait` (workspace), `bytes`, `futures`, `http`, `tokio`, `thiserror`, `tracing`, `url`; dev-deps `rcgen`, `tokio` |
| `src/lib.rs` | module decls, `ALPN = "h3"`, re-exports, `app_error()`, datagram helper | re-export `pub use dquic;`; drop s2n datagram-endpoint builder; keep `app_error` mapping via `web_transport_proto::error_to_http3` |
| `src/client.rs` | `ClientBuilder` / `Client` | build a `dquic::QuicClient` via `QuicClient::builder().with_root_certificates(..).with_alpns([b"h3"]).build()`; `connect()` → `client.connect("host:port")` then `Session::connect(conn, request)` |
| `src/server.rs` | `ServerBuilder` / `Server` / `Request` | build `dquic::QuicListeners` via `builder()...listen(backlog)` + `add_server(name, cert, key, [addr], None)`; `accept()` loop drives `QuicListeners::accept()` (returns `(Connection, server_name, Pathway, Link)`) through `Request::accept` in a `FuturesUnordered` like s2n |
| `src/session.rs` | `Session` + `SessionAccept` | wrap `dquic::Connection` (see "Connection model" below); `open_bi/uni` via `Connection::open_bi_stream()/open_uni_stream()` (note: returns `Option<(StreamId, …)>`), `accept_*` via `accept_bi_stream/accept_uni_stream`; use returned `StreamId` for the session id; keep WebTransport header-prefix encoding, capsule background reader, `closed()` watch channel, graceful `close()` exactly as s2n |
| `src/send.rs` | `SendStream` wrapping `dquic::StreamWriter` | `write` via `AsyncWriteExt::write`; `finish` via `shutdown()`; `reset(code)`/`closed()` via dquic's writer API (verify — see risks); `set_priority` no-op (as s2n) |
| `src/recv.rs` | `RecvStream` wrapping `dquic::StreamReader` | `read`/`read_chunk` via `AsyncReadExt`; `stop(code)` via dquic's reader API (verify) |
| `src/connect.rs` | `Connecting` / `Connected` (HTTP/3 CONNECT) | **unchanged logic** — operates on generic `AsyncRead`/`AsyncWrite` streams; only the concrete stream types change to dquic's |
| `src/settings.rs` | `Settings` (HTTP/3 SETTINGS) | **unchanged logic**; opens/accepts dquic uni streams and runs `web_transport_proto::Settings::{read,write}` on them |
| `src/error.rs` | `SessionError`/`WriteError`/`ReadError` + `web_transport_trait::Error` impls | map `dquic` connection/stream error types instead of `s2n_quic::{connection,stream,application}::Error` |
| `src/tls.rs` / `src/crypto.rs` | rustls helpers | likely simpler — dquic consumes rustls roots directly via its builder typestate, so a custom `tls::Provider` may be unnecessary; keep `crypto.rs` SHA-256 helper only if cert-hash verification is kept |
| `tests/integration.rs` | the 4 e2e tests | identical: `bidirectional_echo`, `unidirectional`, `datagrams`, `graceful_close`, with a loopback self-signed `connect()` helper |

### Reused, unchanged (do not modify)
- `web_transport_proto`: `Settings`, `ConnectRequest`, `ConnectResponse`, `Capsule`,
  `Http3CapsuleReader`, `Frame`, `StreamUni`, `VarInt`, `error_to_http3` — all consumed as-is.
- `web_transport_trait`: implement `Session`, `SendStream`, `RecvStream`, `Error` (and default
  `Stats`/`set_priority` behaviour) exactly as s2n does.

### Connection model decision
s2n splits `Connection` into a `Clone` `Handle` + `StreamAcceptor`. dquic's `Connection` exposes
open/accept/close/datagram directly. The trait requires `Session: Clone`, so wrap the dquic
`Connection` in `Arc` inside `Session` (or rely on `Connection` being internally `Arc`-cloneable —
verify) and share the accept side behind a `Mutex` as s2n does for its acceptor.

### Workspace wiring (only out-of-crate change)
- `Cargo.toml` (root): add `"rs/web-transport-dquic"` to `[workspace] members` (alphabetical, after
  `-quinn`/`-s2n`).
- CI needs no change: `justfile` `check`/`test` use `--workspace`; `.github/workflows/pr.yml` runs
  those. `release-plz.toml` needs no entry unless we choose not to publish.

## Risks / verify against actual dquic source during implementation

The dquic API details below came from web research (README/docs.rs), not from reading dquic's
source. Confirm each against `docs.rs/dquic/0.5` / the repo before relying on it; where dquic lacks
an exact equivalent, degrade gracefully (the trait already tolerates this — e.g. `set_priority` is a
no-op in s2n).

1. **Stream reset/stop with error codes** — `AsyncWrite::shutdown` covers `finish`, but
   RESET_STREAM(`reset(code)`) and STOP_SENDING(`stop(code)`) need dquic's `send::Writer`/
   `recv::Reader` to expose code-carrying cancel/stop methods. If absent, fall back to plain
   shutdown/drop and document the gap.
2. **Datagrams** — trait `send_datagram` is **sync**, but dquic's `DatagramWriter::send` is async
   (and `datagram_writer()` is marked deprecated/stabilising). Bridge via a non-blocking try-send
   if available, else a small spawned forwarding task. Datagram support must be enabled via the
   `max_datagram_frame_size` transport parameter (`ClientParameters`/`ServerParameters`).
3. **TLS for `with_server_certificate_hashes` and `dangerous()`** — these need injecting a custom
   rustls `ServerCertVerifier`. dquic's client builder uses rustls typestate
   (`with_root_certificates`); confirm it allows a custom verifier / passing a built `ClientConfig`.
   If not exposed yet, implement `with_system_roots` + `with_server_certificates` and defer the
   cert-hash/dangerous variants (clearly documented).
4. **Server cert input** — `QuicListeners::add_server` takes `impl ToCertificate`/`ToPrivateKey`.
   Confirm these cover in-memory `Vec<CertificateDer>` / `PrivateKeyDer` (our `with_certificate`
   signature); otherwise adapt via dquic's `handy` traits.
5. **`open_bi_stream`/`open_uni_stream` return `Option`** — `None` (stream-limit/closing) must map
   to a `SessionError`, not a panic.
6. **Edition 2024** — dquic is edition 2024; the crate itself can stay `edition = "2021"` (matching
   the other backends) as long as the toolchain in `nix develop` is recent enough to build dquic.

## Verification

1. `cargo check -p web-transport-dquic` then `cargo clippy -p web-transport-dquic --all-targets --all-features -- -D warnings`.
2. `cargo test -p web-transport-dquic` — the four integration tests (bi echo, uni, datagrams,
   graceful close) must pass over a loopback self-signed session, exactly mirroring s2n's suite.
3. `just check` and `just test` (full workspace + feature powerset) to confirm the new member
   integrates cleanly with CI.
4. Run `just fix` before committing (auto fmt/clippy/sort), per CLAUDE.md.
