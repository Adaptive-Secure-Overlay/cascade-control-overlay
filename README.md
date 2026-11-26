# Cascade Control Overlay (`cco`)

[![CI](https://github.com/Adaptive-Secure-Overlay/cascade-control-overlay/actions/workflows/ci.yml/badge.svg)](https://github.com/Adaptive-Secure-Overlay/cascade-control-overlay/actions/workflows/ci.yml)
[![Org: Adaptive-Secure-Overlay](https://img.shields.io/badge/org-Adaptive--Secure--Overlay-166534.svg)](https://github.com/Adaptive-Secure-Overlay)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust MSRV 1.85+](https://img.shields.io/badge/MSRV-1.85%2B-orange.svg)](#quick-start)

> **[Русская версия документации (README.ru.md)](README.ru.md)**

**Cascade Control Overlay** is an open-source Rust implementation of a hybrid VPN control-plane architecture separating **multi-hop encrypted session establishment** from **direct data-plane transport** — without modifying the underlying VPN protocols (**IPsec/IKEv2** and **WireGuard**).

This repository ports and hardens the research software suite developed within a PhD (Candidate of Technical Sciences) dissertation in specialty **2.3.6 "Information Security Methods and Systems"**:

1. **Multiple Start Connections (MCC / МСС):** cascade fanout of `N` functionally equivalent handshake copies across `A -> X1 -> X2 -> B` with receiver-side branch selection (`first`, `window`, `adaptive`, `wait-all`), end-to-end Ed25519 signatures, X25519+HKDF-SHA256+AES-256-GCM hop/endpoint capsules, opaque continuation tokens (initiator `A` never learns selected `X2`), and a durable SQLite at-most-once anti-replay ledger.
2. **Unmodified VPN Control-Plane Overlay:** transparent Linux `nftables` + `IP_TRANSPARENT` + `SO_MARK` (`0x53`) + `SOCK_RAW` capture and injection for **IKEv2** (`IKE_SA_INIT` and `IKE_AUTH` over UDP/500 and UDP/4500 with Non-ESP Marker `00 00 00 00`) and **WireGuard handshakes** (`type 1/2/3`), while user traffic (**IPsec ESP** or **WireGuard `type 4`**) flows directly between endpoints.
3. **Universal H-Hop Privacy Cascade (`UniversalCascade`):** Sans-I/O state machine generalizing private relay routing to arbitrary hop count `H >= 2` with local-handle cell isolation, reroute on `CASCADE_REJECT`, and route rebuild on `CASCADE_ABORT`.
4. **Authenticated Trust Registry v2:** fail-closed Ed25519-signed node directory (`ipsec-ike-cascade-trust-registry/v2`) with separate `X25519` encryption and `Ed25519` verification keys per node, pinned external trust root, strict monotonic anti-rollback version state, SHA-256 integrity checks, and atomic `fsync` + `rename` backup recovery.
5. **Combinatorial & Monte Carlo Security Analytics:** exact arbitrary-precision route-space models (`F1/Tor`, `I2P`, `F3` without repetitions, `F4` with non-adjacent repetitions and endpoint transit), exact compromise probability and `n50` threshold computation, and multi-threaded `rayon` Monte Carlo verification (2.4M routes in ~6.5 ms).

---

## Workspace Architecture

All crates enforce `#![forbid(unsafe_code)]`, except `cco-linux-proxy`, where `unsafe` is strictly isolated to minimal `libc` socket wrappers under `#[cfg(target_os = "linux")]`. Only vetted RustCrypto / dalek primitives (`x25519-dalek`, `ed25519-dalek`, `hkdf`, `sha2`, `aes-gcm`, `zeroize`, `subtle`) are used; legacy password-based fallbacks are permanently removed.

| Crate | Purpose | Unsafe Policy |
| :--- | :--- | :--- |
| [`crates/cco-crypto`](crates/cco-crypto) | X25519 (low-order check), HKDF-SHA256, AES-128/256-GCM, Ed25519 (`verify_strict`), `ZeroizeOnDrop`, wire-exact KDF/AAD contexts | `#![forbid(unsafe_code)]` |
| [`crates/cco-trust`](crates/cco-trust) | Trust Registry v2 verifier, pinned trust root, strict duplicate-free JSON parser, monotonic anti-rollback store, offline keygen/signing | `#![forbid(unsafe_code)]` |
| [`crates/cco-proto`](crates/cco-proto) | Wire messages (`MGMT_*`, `MCC_*`, `PRIV_*`, `CASCADE_*`), `LinkFrag` UDP fragmentation (`<= 1200 B`), zero-panic IKEv2 & WireGuard parsers | `#![forbid(unsafe_code)]` |
| [`crates/cco-cascade`](crates/cco-cascade) | Pure Sans-I/O state machines: MCC (with move-only `LocalDeliveryProof` & SQLite ledger), `UniversalCascade` (`H >= 2`), WireGuard overlay + 27-scenario matrix | `#![forbid(unsafe_code)]` |
| [`crates/cco-transport`](crates/cco-transport) | Async Tokio UDP peer mesh, 4-step MGMT handshake with overlap window, non-blocking session worker, fail-closed trust gate | `#![forbid(unsafe_code)]` |
| [`crates/cco-linux-proxy`](crates/cco-linux-proxy) | Linux `IP_TRANSPARENT` / `IP_RECVORIGDSTADDR` / `SO_MARK` / `IP_HDRINCL` capture & raw injection + parameterized `nftables`/`xfrm` generators | Minimal isolated Linux syscalls |
| [`crates/cco-analytics`](crates/cco-analytics) | Exact `BigUint` route combinatorics (`F1`/`I2P`/`F3`/`F4`), `n50` threshold, `rayon` Monte Carlo simulator, X25519 vs RSA-3072 benchmark | `#![forbid(unsafe_code)]` |
| [`crates/cco-cli`](crates/cco-cli) | Unified `cco` binary (`node`, `trust-admin`, `wg-sim`, `analytics`, `bench`, `render-firewall`) | `#![forbid(unsafe_code)]` |

---

## Quick Start

```bash
# Build and run all unit, golden-vector, security-matrix, and localhost UDP E2E tests
cargo test --workspace

# Verify the bundled example Trust Registry v2 (RFC 5737 test fixture, public keys only)
cargo run --release -p cco-cli -- trust-admin verify \
  --registry examples/trust-registry.example.json \
  --trust-root examples/trust-root.example.json \
  --required-nodes A,X1,X2,B

# Exact Chapter 3 route space & compromise risk (n=10, m=2, j=3)
cargo run --release -p cco-cli -- analytics routes --n 10 --j 3 --m 2
cargo run --release -p cco-cli -- analytics n50 --m 2 --j 5

# Parallel rayon Monte Carlo verification (800,000 routes per model)
cargo run --release -p cco-cli -- bench monte-carlo --trials 800000 --n 10 --m 2 --j 3

# Cryptographic benchmark reproducing Table 4.6 (X25519+HKDF+AES-GCM vs RSA-3072 OAEP)
cargo run --release -p cco-cli -- bench crypto --iters 200 --rsa-iters 20 --include-rsa

# Canonical 27-scenario WireGuard handshake overlay matrix
cargo run --release -p cco-cli -- wg-sim --format csv
```

---

## Verification Pyramid (L1–L4)

No multi-gigabyte VM image is required to reproduce all experiments:

| Level | Scope | How to Run |
| :--- | :--- | :--- |
| **L1** | Crypto golden vectors (byte-exact vs Python), 12 Trust Registry v2 security-matrix tests, Sans-I/O MCC / UniversalCascade / WireGuard 27-scenario tests, Chapter 3 analytics | `cargo test --workspace` (Windows / Linux / macOS) |
| **L2** | Live localhost 4-node & 10-node UDP MCC mesh (5 concurrent routes × 9 copies, 100% delivery) + live Rust↔Python UDP wire cross-compatibility (`MGMT` + `LINK_FRAG`) | `cargo test -p cco-transport --test e2e_udp` |
| **L3** | Live Linux kernel `ip netns` (or Docker ~200 MB) 4-node lab with unmodified **strongSwan `charon` + `nftables` + `XFRM/ESP` + `tcpdump`** verifying `direct_ike == 0 && direct_esp > 0 && ping 100%` | `sudo CCO_BIN=./target/release/cco bash lab/scripts/netns_e2e.sh` |
| **L4** | Static `x86_64-unknown-linux-musl` drop-in binary for existing lab routers / EVE-NG topologies | Built in CI (`cco-linux-x86_64-musl`) |

### Highlighted Measurements

- **Live L3 strongSwan verification (`ip netns`, Linux 6.6 + strongSwan 5.9.5):** `IKE_SA_INIT` (462/470 B) and `IKE_AUTH` (288/224 B) established `CHILD_SA` tunnel through `A -> X1 -> X2 -> B` with **`direct_ike_total == 0`**, **`overlay_udp_packets == 324`**, **`direct_esp_proto50 == 10`**, and **5/5 ICMP replies (0% loss, 0.101 ms avg RTT)**.
- **Monte Carlo speedup (`800,000` trials, `n=10, m=2, j=3`):** **1.79 ms** in Rust (`rayon`) vs **1996.76 ms** in Python (**> 1,100× faster**), matching exact analytics within `<= 0.0004`.
- **Control-plane crypto (Table 4.6, 1024 B payload):** `X25519 + HKDF-SHA256 + AES-128-GCM` roundtrip **75.0 µs** vs `RSA-3072 OAEP + AES-128-GCM` **2505.7 µs** (**33.4× speedup**).

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for full methodology and raw numbers.

---

## Honest Scope & Threat Model Boundaries

- **Research prototype:** Experimental academic implementation; has not undergone an independent third-party cryptographic audit.
- **Threat model:** Protects VPN control-plane session initiation against local provider observation of direct `A <-> B` IKEv2/WG handshakes and against individual honest-but-curious or actively tampering intermediate relays (detected via Ed25519 + X25519 + SQLite anti-replay).
- **Non-goals:** Does **not** defend against a global passive adversary capable of correlating timings across all links, and does **not** hide the subsequent direct `A <-> B` IPsec ESP / WireGuard data plane. Not a replacement for Tor/I2P for general internet anonymization.

See [SECURITY.md](SECURITY.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for details.

---

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — System architecture, Sans-I/O separation, and crate dependencies
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — Exact wire framing, `LinkFrag`, KDF/AAD contexts, and Trust Registry v2 specification
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — Adversary assumptions, security invariants, and explicit limitations
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — Python vs Rust measurements, Table 4.6 crypto comparison, and Monte Carlo verification
- [docs/REPRODUCING-LAB.md](docs/REPRODUCING-LAB.md) — Step-by-step L1/L2/L3/L4 reproduction guide

## Related Repositories (`Adaptive-Secure-Overlay`)

This crate workspace is the standalone Rust core and verification suite within the [Adaptive Secure Overlay](https://github.com/Adaptive-Secure-Overlay) research organization, complementing the sibling Python prototypes and datasets:

- [Adaptive-Secure-Overlay/adaptive-ipsec-overlay](https://github.com/Adaptive-Secure-Overlay/adaptive-ipsec-overlay) — original Python IPsec/IKEv2 control-plane core (`universal_cascade`, Trust Registry, strongSwan/nftables) and platform integrations
- [Adaptive-Secure-Overlay/adaptive-wireguard-overlay](https://github.com/Adaptive-Secure-Overlay/adaptive-wireguard-overlay) — Python WireGuard handshake overlay (`v0.2.0`), Ed25519 trust registry, and MCC E2E authentication/privacy tracks
- [Adaptive-Secure-Overlay/adaptive-overlay-experiments](https://github.com/Adaptive-Secure-Overlay/adaptive-overlay-experiments) — reproducible EVE-NG test harnesses, cascade/threshold datasets, and empirical benchmarks

## Academic Context

Developed by **Vladislav Zyuzin** as part of a Candidate of Technical Sciences dissertation in specialty **2.3.6 "Information Security Methods and Systems"**.
This Rust version is an independent open-source port and evolution of the algorithms from the original Python prototypes previously registered with Rospatent (certificates of state registration of computer programs No. 2024610455 dated 10.01.2024 and No. 2025613326 dated 11.02.2025).

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
