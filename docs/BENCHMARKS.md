# Benchmarks & Verification Measurements

All measurements below were collected on the same host machine (Windows 11 x86_64 + WSL2 Linux `6.6.87.2-microsoft-standard-WSL2`, Rust `1.96.0` / `1.100.0` `--release`, Python `3.14.7` with `cryptography 48.0.0`). Commands to reproduce every number are listed below.

---

## 1. Cryptographic Primitives: X25519 + HKDF-SHA256 + AES-GCM vs RSA-3072 OAEP (Dissertation Table 4.6)

Command:
```bash
cargo run --release -p cco-cli -- bench crypto --iters 200 --rsa-iters 20 --include-rsa
```

| Operation (1024 B payload) | Python (`cryptography 48.0`, OpenSSL C) Median | Rust (`cco-crypto` / `cco-analytics`, pure Rust `--release`) Median | Rust Throughput | Notes |
| :--- | :---: | :---: | :---: | :--- |
| `X25519 + HKDF-SHA256 + AES-128-GCM` (seal + open) | `75.3 µs` | **`75.0 µs`** (p95 `84.9 µs`) | `12,931 ops/s` | Pure-Rust `x25519-dalek` + `aes-gcm` matches C/OpenSSL speed |
| `X25519 + HKDF-SHA256 + AES-256-GCM` (seal + open) | `76.1 µs` | **`75.6 µs`** (p95 `104.3 µs`) | `12,301 ops/s` | Production hop & MCC capsule cipher |
| `Ed25519` (sign + strict verify) | `86.5 µs` (`23.7` + `62.8`) | **`55.5 µs`** (p95 `66.6 µs`) | `17,493 ops/s` | **1.56× faster** than Python wrapper, with `verify_strict` |
| `RSA-3072 OAEP-SHA256 + AES-128-GCM` (seal + open) | `1147.0 µs` (OAEP only) | `2505.7 µs` (p95 `2695.7 µs`) | `392 ops/s` | Pure-Rust `rsa` baseline confirming Table 4.6 choice |
| **Speedup: X25519+HKDF+AES-128-GCM vs RSA-3072** | `15.2×` (OpenSSL) | **`33.4×`** (pure Rust) | — | Confirms engineering choice of X25519+HKDF+AES-GCM |

### Python `mcc_e2e.py` Reference Overhead (Single-Node, 512 B IKE Field, 200 Iters)
- `mcc_signed_message`: median `100.0 µs` (p95 `201.6 µs`)
- `mcc_verify_signed`: median `173.8 µs` (p95 `258.0 µs`)
- `mcc_seal_endpoint_capsule`: median `83.05 µs` (p95 `176.0 µs`)
- `mcc_open_endpoint_capsule`: median `107.6 µs` (p95 `230.4 µs`)

---

## 2. Chapter 3 Combinatorics & Parallel `rayon` Monte Carlo (`800,000` Trials/Model)

Command:
```bash
cargo run --release -p cco-cli -- bench monte-carlo --trials 800000 --n 10 --m 2 --j 3
```

| Model (`n=10, m=2, j=3`) | Exact Analytical Probability | Simulated (`800,000` trials) | Abs Error (Bound `<= 0.004`) | Python Elapsed | Rust `rayon` Elapsed | Speedup |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `F1` (Tor-like baseline) | `0.642857` (`36/56`) | `0.642849` | `0.000008` | `1996.76 ms` | **`1.79 ms`** | **1,115×** |
| `F3` (Proposed, no repeats) | `0.558219` (`326/584`) | `0.557824` | `0.000395` | — | **`2.36 ms`** | — |
| `F4` (Proposed, with repeats) | `0.542683` (`356/656`) | `0.542829` | `0.000146` | — | **`2.33 ms`** | — |
| **Total (2,400,000 routes)** | — | — | **All `<= 0.0004`** | ~6,000 ms (est.) | **`6.48 ms`** | **~900–1,100×** |

Exact `n50` threshold verification (`m = 2, j = 5`):
- `F1`: `n50 = 20`
- `F3`: `n50 = 18`
- `F4`: `n50 = 17` (**15% smaller required node pool** than `F1`, matching dissertation conclusion #4)

---

## 3. WireGuard 27-Scenario Canonical Matrix

Command:
```bash
cargo run --release -p cco-cli -- wg-sim --format csv
```
- Scenarios: `27/27` passed (`bidir12`: 2, `disjoint5`: 5, `ring10`: 10, `reverse5`: 10)
- `direct_control_packets == 0` across all 27 scenarios; `type 4` transport bypasses overlay directly (`direct_data_packets > 0`).
- End-to-end Rust CLI execution (including process startup + JSON serialization): **`13.5 ms`**.

---

## 4. Live Multi-Node UDP (L2) & Live Linux `strongSwan` `ip netns` (L3)

### L2 Localhost UDP E2E (`cargo test -p cco-transport --test e2e_udp`)
- **4-node lazy session test (`preconnect=false`):** `IKE_SA_INIT` + `IKE_AUTH` roundtrip (`4/4` deliveries), initiator `A` never learns `X2`.
- **10-node concurrent mesh (`5` simultaneous routes × `9` MCC copies, `adaptive` mode):** `20/20` deliveries (`100%`), verified across `6/6` consecutive stress runs (~3.15 s/run in unoptimized debug build).
- **Live Rust ↔ Python UDP wire cross-compat:** 4-step `MGMT` handshake + `>2000 B` `LINK_FRAG` fragmentation + AES-256-GCM hop decryption verified against a live Python peer on both Windows and Linux.

### L3 Live Linux Kernel + `strongSwan 5.9.5` + `nftables` + `tcpdump` (`lab/scripts/netns_e2e.sh`)
- **Topology:** 5 isolated Linux network namespaces (`cco-isp` bridge + `cco-A`, `cco-X1`, `cco-X2`, `cco-B`) using RFC 5737 addresses (`192.0.2.10..13/24`, tunnel `198.51.100.10/32 <-> 198.51.100.13/32`).
- **Release Linux binary size (`cco`, unstripped):** `8.0 MB` (stripped/musl L4 drop-in `~4–5 MB`).
- **Observed strongSwan exchange:**
  - `IKE_SA_INIT`: `462 B` request, `470 B` response
  - `IKE_AUTH`: `288 B` request, `224 B` response
  - `CHILD_SA tunnel{1}` established (`ESP:AES_CBC_256/HMAC_SHA2_256_128`)
- **ICMP tunnel verification:** `5 packets transmitted, 5 received, 0% packet loss`, RTT `min/avg/max = 0.087 / 0.101 / 0.141 ms`.
- **Provider-bridge pcap audit (`verify_no_direct_ike.sh`):**
  - `direct_ike_udp500`: **`0`**
  - `direct_ike_udp4500_nonesp`: **`0`**
  - `overlay_udp_packets` (port 9000): **`324`**
  - `direct_esp_proto50`: **`10`** (5 Echo Request + 5 Echo Reply)
