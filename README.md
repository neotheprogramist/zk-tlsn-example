# zk-tlsn-example

Browser-based TLSNotary attestation demo. A WASM prover running in Chromium runs MPC-TLS against a small fiat-transfer ledger and produces a selectively disclosed attestation that a native Rust verifier validates.

Proof of concept, not production code. Single flow, end-to-end, audit-friendly.

## Prerequisites

- Rust toolchain pinned in `rust-toolchain.toml` (nightly is required for the wasm build).
- `wasm-bindgen-cli` 0.2.118 on `PATH`.
- Node 20+ for the optional Playwright harness.

## Repo layout

| Crate        | Role                                                                                                                                 |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `core/`      | Reusable library (`zktlsn_core`). Native = Prover + Verifier. wasm32 = Prover only (verifier is `cfg`-gated). No `wasm-bindgen` dep. |
| `core-wasm/` | wasm32 JS shell (`zktlsn_core_wasm`). Wraps `core::Prover` for `wasm-bindgen`; owns `WebTransportIo` + `WasmRuntime`.                |
| `demo/`      | Native binary `zktlsn`: demo HTTPS ledger + WebTransport service with embedded verifier.                                             |

Dependency graph: `demo → core`, `core-wasm → core`. No cycles.

```
core/src/
  lib.rs           # public surface, target-gated re-exports
  error.rs         # Error enum + #[from] conversions
  attestation.rs   # FiatTransferAttestation codec
  flow.rs          # transfer-attestation request/reveal/TLS factories
  transport.rs     # Runtime trait, SmolRuntime (cfg native), FuturesIo
  verifier.rs      # cfg(not(wasm)); verify() + verify_transfer() wrapper
  parser/          # generic Pest parser (Body<V>: Range or Option<Range>)
  prover/          # Prover orchestrator + RevealConfig disclosure rules

core-wasm/src/
  lib.rs           # start / initialize entry points
  prover.rs        # #[wasm_bindgen] Prover wrapper + JSON boundary
  io.rs            # WebTransportIo
  runtime.rs       # WasmRuntime
  error.rs         # JS-boundary Error

demo/src/
  main.rs          # clap-derive Cli, spawns ledger + service
  tls.rs           # demo HTTPS certificate fixture
  ledger.rs        # demo HTTPS ledger (Salvo)
  service.rs       # WebTransport host + page rendering
  connect.rs       # WebTransport stream dispatcher + verifier handler
```

## Build the wasm artifact

`demo/assets/wasm/` is gitignored. Rebuild whenever `core/` or `core-wasm/` change. Three steps, all CLI:

```bash
cargo +nightly build -p zktlsn_core_wasm --lib --target wasm32-unknown-unknown --release

wasm-bindgen target/wasm32-unknown-unknown/release/zktlsn_core_wasm.wasm \
  --out-dir demo/assets/wasm --target web --out-name core

sed -i '' "s|'\.\./\.\./\.\.'|'\.\./\.\./\.\./core\.js'|g" demo/assets/wasm/snippets/*/js/spawn.js
```

What each step does:

1. **`cargo +nightly build`** — compiles `zktlsn_core_wasm` to `target/wasm32-unknown-unknown/release/zktlsn_core_wasm.wasm`. Nightly is required (the workspace `rust-toolchain.toml` pins stable for everything else; `+nightly` overrides it for this one invocation).
2. **`wasm-bindgen --target web`** — emits the JS glue (`core.js`, `core_bg.wasm`, plus `snippets/web-spawn-*/js/spawn.js`) into `demo/assets/wasm/`.
3. **`sed -i ''`** — rewrites `web-spawn`'s `import('../../..')` (a directory URL Chrome can't dynamically import) to `import('../../../core.js')`. The `|` delimiter avoids escaping the slashes; the `\.` escapes make the match literal. Two occurrences in `spawn.js` get rewritten.

The `sed` invocation shown is **macOS BSD sed**. On GNU sed (Linux), drop the `''` after `-i`.

## Run the demo

```bash
cargo run --release --bin zktlsn
```

That's it — every env var has a sensible default. The defaults are:

| Var                          | Default                 | Role                                                   |
| ---------------------------- | ----------------------- | ------------------------------------------------------ |
| `ZKTLSN_SERVER_LISTEN_ADDR`  | `[::]:8443`             | ledger socket bind (dual-stack)                        |
| `ZKTLSN_SERVICE_LISTEN_ADDR` | `[::]:8444`             | service socket bind (dual-stack)                       |
| `ZKTLSN_SERVER_ADDR`         | `localhost:8443`        | proxy dial target the service uses to reach the ledger |
| `ZKTLSN_SERVER_CERT_PATH`    | `.data/server/cert.pem` | ledger TLS cert (auto-created on first run)            |
| `ZKTLSN_SERVER_KEY_PATH`     | `.data/server/key.pem`  | ledger TLS key (auto-created on first run)             |

To override anything, drop a `.env` file at the repo root — `mise.toml` declares `_.file = ".env"`, so mise injects it automatically whenever you `cd` into the directory.

The two `*_LISTEN_ADDR`s use `[::]` (dual-stack) rather than `127.0.0.1` because Chrome's WebTransport (HTTP/3 over QUIC) prefers IPv6 when resolving `localhost`; a v4-only socket would refuse the QUIC handshake even though the TCP page fetch succeeds via Happy Eyeballs. macOS gives `IPV6_V6ONLY=0` by default, so one `[::]` socket serves both stacks.

Always run `--release`. MPC-TLS is heavily optimisation-sensitive; debug builds make a single attestation take ~30 s instead of ~3 s.

The single `zktlsn` process spawns the ledger on `ZKTLSN_SERVER_LISTEN_ADDR` and the WebTransport service (with verifier embedded) on `ZKTLSN_SERVICE_LISTEN_ADDR`.

## Manual e2e walkthrough

Run the full flow yourself in Chrome — no Playwright, no harness — to inspect every step.

1. **Build the wasm bundle** (once, or after any `core/` / `core-wasm/` change) — see [Build the wasm artifact](#build-the-wasm-artifact) above for the three commands.
2. **Start the binary** (`cargo run --release --bin zktlsn`). Wait for the two `listening` log lines (HTTP/3.0 and HTTP/1.1 on `:8444`).
3. **Open Chrome** at `https://localhost:8444/`. Accept the self-signed cert (Advanced → Proceed). The page renders one **Start attestation** button plus the configured transfer parameters. The cert's SAN covers `localhost`, `127.0.0.1`, and `::1` — any of them works; the page derives the WebTransport URL from `location.origin`, so it follows whichever you type.
4. **Open DevTools → Console** before clicking.
5. **Click Start attestation.** Chrome spawns a Worker, loads the wasm prover, opens two WebTransport bidi streams, and runs MPC-TLS against the ledger over the second stream while the verifier watches the first.
6. **Watch the console.** Both the on-page `<pre>` log and DevTools Console mirror the same lines. After MPC-TLS finishes (≈3–5 s) you'll see, in order:
   - `prover-view REQUEST (NN bytes, full): GET /api/attestations/1 …` — the full HTTP request the prover sent.
   - `prover-view RESPONSE (NN bytes, full): HTTP/1.1 200 OK …` — the full HTTP response the prover received over MPC-TLS.
   - `ZKTLSN_RESULT {"flow":"notarize-wasm","server_name":"localhost","to_username":"treasury","amount":25,"eligible_for_mint":true,"commitment_count":2}`
7. **Cross-check the binary log.** The terminal should show:
   - `verifier-view REQUEST (NN bytes; revealed = visible char, # = committed-not-revealed, · = redacted): …`
   - `verifier-view RESPONSE (…): …`
   - `Sending verification outcome success=true` from `demo::connect`.
     The legend distinguishes three byte states:
   - **visible char** — revealed: the verifier sees the actual byte.
   - **`#`** — committed but not revealed: the byte is pinned by a hash commitment, so the prover can't lie about its position or count, but the value is hidden. In the response you should see exactly **32 `#`** after `"attestation":` — that block is `ATTESTATION_LEN` (10 + 10 + 12) characters, matching `core::FiatTransferAttestation`.
   - **`·`** — neither revealed nor committed: the verifier has no information about this byte at all.
     Compare prover-view vs verifier-view: every revealed char matches the prover-view; every `#` and `·` was a `\0` in the underlying redacted transcript, with the distinction coming from `output.transcript.sent_authed()` / `received_authed()` (revealed ranges) and the `Hash` commitments in `output.transcript_commitments` (committed ranges).
8. **Failure mode to watch for:** if the page logs `ZKTLSN_ERROR …` instead of `ZKTLSN_RESULT …`, the prover or verifier rejected the run; the message contains the cause. The binary's stderr will have the matching server-side error (e.g. `RevealRuleNotMatched`, `policy rejected`, `tls handshake eof`).

The flow is fully deterministic — same `tx_id` every time, same disclosed fields, same commitment count.

## Automated e2e (optional)

For CI or quick sanity checks, the Playwright harness drives the same flow headlessly. Build the wasm bundle first ([Build the wasm artifact](#build-the-wasm-artifact)), then:

```bash
node scripts/run-attest.mjs
```

The harness spawns the binary, launches headed Chromium (Playwright is `npx`-installed on first run), reads `ZKTLSN_RESULT`, and asserts the same fields listed in step 6 above.

## Audit scope

| Component                       | Trust property enforced                                                                                    |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `core::verifier`                | Validates the MPC-TLS session, enforces transcript commitment policy, validates disclosed transfer fields. |
| `core::flow`                    | Canonical request, reveal config, and TLS config for the fixed transfer-attestation flow.                  |
| `core::FiatTransferAttestation` | 32-character zero-padded decimal attestation encoding shared by ledger and verifier.                       |

Out of scope: `core::prover`, `core::parser`, `demo/*`, `scripts/*.mjs`, Playwright. Those exercise the flow; they are not the trust boundary.

## Engineering standards

`GUIDELINES.md` is authoritative.
