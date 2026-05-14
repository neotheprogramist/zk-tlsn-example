# zk-tlsn-example

## Prerequisites

- Stable toolchain pinned in `rust-toolchain.toml` (1.95.0).
- `nightly-2025-07-14` for `zkp` and both wasm builds:

  ```bash
  rustup toolchain install nightly-2025-07-14 --target wasm32-unknown-unknown
  ```

- `wasm-bindgen-cli` 0.2.118 on `PATH`.

## Build

**1. Generate Poseidon2 circuit files from mpz**

```bash
cargo build -p demo
```

This triggers `build.rs` in `mpz-circuits-data` and writes `poseidon2_absorb.bin` and `poseidon2_permute.bin` into the mpz crate's local checkout directory.

**2. Copy circuits to `demo/assets/circuits/`**

```bash
mkdir -p demo/assets/circuits
find ~/.cargo/git/checkouts -path "*/circuits-data/data/poseidon2_absorb.bin" \
  -exec cp {} demo/assets/circuits/ \;
find ~/.cargo/git/checkouts -path "*/circuits-data/data/poseidon2_permute.bin" \
  -exec cp {} demo/assets/circuits/ \;
```

**3. Build WASM**

```bash
RUSTUP_TOOLCHAIN=nightly-2025-07-14 \
  cargo build -p zktls --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/zktls.wasm \
  --out-dir demo/assets/wasm --target web --out-name zktls
sed -i '' "s|'\.\./\.\./\.\.'|'\.\./\.\./\.\./zktls\.js'|g" \
  demo/assets/wasm/snippets/*/js/spawn.js

RUSTUP_TOOLCHAIN=nightly-2025-07-14 \
  cargo build -p zkp --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/zkp.wasm \
  --out-dir demo/assets/wasm --target web --out-name zkp
```

The `sed` patches `web-spawn`'s broken dynamic-import path; only `zktls` needs it. On GNU sed drop the `''` after `-i`. Always `--release` — debug builds make MPC-TLS take ~30 s instead of ~3 s.

## Run

```bash
cargo run --release --bin zktlsn
```

Binds on `[::]:8443` (ledger) and `[::]:8444` (HTTP/3 service) by default.
