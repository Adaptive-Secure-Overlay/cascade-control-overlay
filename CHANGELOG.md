# Changelog

All notable changes to `cascade-control-overlay` are documented in this file.

## [0.1.1] - 2026-11-26

### Changed & Fixed
- **Security:** Upgraded `rusqlite` (`0.32 -> 0.43`, bundled `libsqlite3-sys 0.40`) to resolve `RUSTSEC-2026-0459` (SQLite CVE-2026-119375).
- **Audit:** Added `.cargo/audit.toml` documenting the scoped offline benchmark exception (`RUSTSEC-2023-0071` in `cco-analytics` Table 4.6 RSA-3072 baseline) and switched CI security audit to `cargo-audit`.
- **CI / L3 Lab:** Added Ubuntu 24.04 AppArmor profile handling for ephemeral `ip netns` strongSwan verification and fixed `umask` scoping + failure diagnostics in `lab/scripts/netns_e2e.sh` (all 7/7 CI jobs passing).
- **Releases:** Added automated multi-platform GitHub Release workflow publishing binaries for Linux (`x86_64-musl`, `aarch64-musl`), Windows (`x86_64-msvc`), and macOS (`aarch64-apple-darwin`) with `SHA256SUMS.txt`.

## [0.1.0] - 2026-11-26

### Added
- **Workspace & Cryptography (`cco-crypto`):** Pure-Rust `X25519` (with contributory check), `HKDF-SHA256`, `AES-128-GCM` / `AES-256-GCM`, `Ed25519` (`verify_strict`), `ZeroizeOnDrop` wrappers, and wire-exact KDF/AAD contexts verified against Python golden vectors.
- **Trust Registry v2 (`cco-trust`):** Fail-closed verification against pinned external trust root, strict duplicate-free canonical JSON, monotonic anti-rollback store with atomic `fsync + rename` updates, `last-valid` recovery, offline provisioning helpers, and 12-test negative security matrix.
- **Protocol & Parsers (`cco-proto`):** All overlay message types (`MGMT_*`, `MCC_*`, `PRIV_*`, `CASCADE_*`, `LINK_FRAG`), `LinkFrag` UDP fragmentation (`<= 1200 B`, chunk 700 B, TTL 15 s), and zero-panic IKEv2 (UDP/500 & UDP/4500 Non-ESP) and WireGuard (`type 1/2/3` vs rejected `type 4`) parsers.
- **Sans-I/O State Machines (`cco-cascade`):**
  - Authenticated MCC with 4 selection modes (`first`, `window`, `adaptive`, `wait-all`), opaque privacy continuation tokens, move-only `LocalDeliveryProof`, and durable SQLite anti-replay ledger.
  - Generalized `UniversalCascade` (`H >= 2`) with cell-level privacy, `CASCADE_REJECT` rerouting, and `CASCADE_ABORT` recovery.
  - WireGuard Handshake Overlay engine and canonical 27-scenario verification matrix (`json`, `csv`, `eve-json`).
- **Analytics & Benchmarks (`cco-analytics`):** Exact `BigUint` Chapter 3 combinatorics (`F1/Tor`, `I2P`, `F3`, `F4`), exact compromise probabilities and `n50` thresholds, parallel `rayon` Monte Carlo simulator, and X25519 vs RSA-3072 benchmark (Table 4.6).
- **Async Transport & CLI (`cco-transport`, `cco-cli`):** Tokio UDP peer mesh, 4-step MGMT handshake with rekey/crossing overlap, sized UDP socket buffers, non-blocking session worker, unified `cco` CLI, localhost 4-node & 10-node UDP E2E suite, and live Rust↔Python UDP wire cross-compatibility test.
- **Linux Proxy & Verification Lab (`cco-linux-proxy`, `lab/`):** Linux `IP_TRANSPARENT` / `IP_RECVORIGDSTADDR` / `SO_MARK` / `SOCK_RAW` (`IP_HDRINCL`) backend, parameterized `nftables` / `ip xfrm` generators, lightweight multi-stage `Dockerfile` (~200 MB), `docker-compose.yml`, and standalone Linux `ip netns` strongSwan verification harness (`verify_no_direct_ike.sh`).
- **CI & Documentation:** GitHub Actions workflow (`fmt`, `clippy -D warnings`, Linux + Windows tests with Python cross-compat, static `musl` build, live `netns` strongSwan verification, security audit) and full EN/RU documentation.
