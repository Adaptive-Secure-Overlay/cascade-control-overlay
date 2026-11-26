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

---

## 5. Live Userspace WireGuard (`boringtun 0.7.1`) vs Kernel `strongSwan` Comparison (`v0.2.0`)

Commands:
```bash
# In-memory 4-node split WireGuard E2E (Windows / Linux / macOS)
cargo test -p cco-wg-tunnel --test split_wg_e2e

# Live Linux kernel /dev/net/tun + ip netns + tcpdump verification
sudo CCO_BIN=./target/release/cco bash lab/scripts/wg_userspace_e2e.sh
```

| Metric (4-Node `ip netns` RFC 5737 Lab, Linux 6.6) | Kernel IPsec (`strongSwan 5.9.5` + `cco node`) | Userspace WireGuard (`boringtun 0.7.1` + `cco wg-tunnel`) |
| :--- | :---: | :---: |
| Control-plane protocol over MCC (`A -> X1 -> X2 -> B`) | IKEv2 (`IKE_SA_INIT`, `IKE_AUTH`) | WireGuard Handshake (`Type 1/2/3`) |
| Direct control packets on provider bridge (`provider.pcap`) | **`0`** (`direct_ike_total == 0`) | **`0`** (`type1=0, type2=0, type3=0`) |
| Unsolicited direct handshake drop guard | `nftables` TPROXY redirect | In-process drop (`direct_handshake_rx_dropped`) |
| Direct data-plane packets on provider bridge (`provider.pcap`) | `10` (`ESP proto 50`) | `14` (`WG Type 4`, `692 B` tx / `692 B` rx) |
| Overlay UDP packets on provider bridge (port `9000`) | `324` | `1,735` |
| Initial overlay handshake latency (`handshake_ms`) | `< 150 ms` | **`105 ms`** |
| Tunnel ICMP ping (`198.51.100.10 -> 198.51.100.13`, 5 packets) | `5/5` (`0%` loss) | `5/5` (`0%` loss) |
| Tunnel ICMP RTT (`min / avg / max`) | `0.087 / 0.101 / 0.141 ms` | `0.390 / 0.452 / 0.489 ms` |
| Desktop / Mobile portability (no root / no unsigned drivers) | Linux routers (`nftables` + `XFRM`) | **Android `VpnService`, Windows `Wintun`, macOS `utun`, Linux TUN** |

### Cross-Platform FFI & GUI Footprint (`v0.2.0` Release Artifacts)
- **Android (`apps/android`):** stripped `libcco_ffi.so` `arm64-v8a` = **`4.68 MB`**, `x86_64` = **`5.16 MB`**, universal APK = **`19.53 MB`**.
- **Windows (`apps/windows`):** `cco_ffi.dll` = **`5.26 MB`**, `CcoOverlayWindows.exe` = **`156 KB`**, official signed `wintun.dll` (`WireGuard LLC`, 0.14.1, SHA-256 verified at build time) = **`428 KB`**.
- **C-ABI & P/Invoke / XCTest roundtrip:** full 4-node split WireGuard handshake + L3 IPv4 packet delivery through `cco_tunnel_start_channel` completes in **`0.42–0.43 s`** (`cargo test -p cco-ffi`), and `.NET 9` xUnit P/Invoke suite (`Cco.Windows.Tests`) completes in **`0.39 s`**.
- **Security audit (`cargo audit`):** **`0` vulnerabilities** across all `204` Cargo dependencies (including `boringtun 0.7.1`, `ring 0.17.14`, `rusqlite 0.43.0`, `jni 0.21.1`).

---

## 6. Live 4-Node Geo-Distributed WAN Verification (Dual NAT, Docker Compose)

All three architectures — the **dissertation Python MCC reference prototype (`01-mcc-e2e-candidate`, CPython `3.14.10` + `cryptography 50.0.2`)**, **Rust `cco` + Kernel IPsec (`strongSwan`)**, and **100% Rust Userspace WireGuard (`cco wg-tunnel` / `boringtun 0.7.1`)** — were evaluated on the **same 4-node geographically distributed WAN testbed** in isolated Docker Compose containers (Python relays on `UDP/19001` running in parallel with Rust relays on `UDP/19000`, zero host routing or firewall interference):

- **Topology:** `Node A` (behind residential NAT) `->` `Node X1` (City-1 public relay) `->` `Node X2` (City-2 public relay) `->` `Node B` (City-3 behind NAT router with UDP port forwarding).
- **Underlay RTT baseline:** `A <-> X1` `8.7 ms`, `X1 <-> X2` `11.1–12.2 ms`, `X2 <-> B` `21.9 ms`, direct `A <-> B` `~23–25 ms`.
- **Shared security profile:** identical `Trust Registry v2`, Ed25519/X25519 MCC capsules (`mode=first`, `x1=2, x2=2, ike=1`), authenticated NAT endpoint roaming, `notrack` `ESP-in-UDP` firewall rules (`74f84a0`), and host-interface `tcpdump` capture at both endpoints `A` and `B`.

| Metric (Same 4-Node Geo-Distributed WAN, Dual NAT) | Python Reference + Kernel IPsec (`strongSwan 6.0.1` + `CPython 3.14.10`) | Rust `cco` + Kernel IPsec (`strongSwan 5.9.8` + `cco --ike-proxy`) | 100% Rust Userspace WireGuard (`cco wg-tunnel` / `boringtun 0.7.1`) |
| :--- | :---: | :---: | :---: |
| Control-plane protocol over MCC (`A -> X1 -> X2 -> B`) | IKEv2 (`UDP/500`, `UDP/4500` Non-ESP) + legacy `PRIV_BKEY`/`X1B_SEAL` | IKEv2 (`UDP/500`, `UDP/4500` Non-ESP) | WireGuard `Noise_IKpsk2` (`Type 1/2/3`) |
| Data-plane protocol direct (`A <-> B`) | Kernel XFRM NAT-T `ESP-in-UDP` (`UDP/4500`, AES-256-CBC / HMAC-SHA2-256) | Kernel XFRM NAT-T `ESP-in-UDP` (`UDP/4500`, AES-256-CBC / HMAC-SHA2-256) | Userspace `ChaCha20-Poly1305` (`Type 4` `UDP/4500`) |
| Required container stack / privileges | `CPython 3.14` + `cryptography 50.0.2` + `strongSwan` + `nftables` + `NET_ADMIN`/`NET_RAW` | Single Rust binary `cco` + `strongSwan` + `nftables` + `NET_ADMIN`/`NET_RAW` | **Single Rust binary `cco` + `/dev/net/tun` (`NET_ADMIN`, zero `nftables`)** |
| Container image size (relay / endpoint) | `217 MB` / `247 MB` | `150 MB` / `159 MB` | `150 MB` / **`151 MB`** |
| Overlay daemon peak RAM (`VmHWM`, relay / endpoint) | `41.9–42.3 MB` / `41.1–43.1 MB` (+`9.4–11.2 MB` `charon`) | **`8.46–8.74 MB`** / **`9.40–10.33 MB`** (+`10.6–10.8 MB` `charon`) | **`2.57–4.94 MiB`** total container RAM (**no `charon`**, `10–15×` less RAM) |
| **Cold start** (`PRECONNECT=0`, on-demand MGMT) | `36,109.8 ms` (`36.1 s`, 4 IKE retransmits — sync `recv` self-deadlock!) | **`529.0 ms`** (`68.3×` faster, async `tokio` lazy sessions) | **`128.0 ms`** (**`4.1×`** faster than Rust IPsec, 1-RTT `Noise_IKpsk2`) |
| **Warm start** (MGMT sessions established, 2–3 runs) | `234.6 / 247.5 / 354.0 ms` (median `247.5 ms`, 3-hop `F4` `A->X1->B` + `PRIV_BKEY`) | `316.2 / 336.5 ms` (4-hop `A->X1->X2->B`, 2-RTT IKEv2) | **`128.0 ms`** (4-hop `A->X1->X2->B`, 1-RTT `Noise_IKpsk2`) |
| Overlay UDP packets per handshake (host `A` `tcpdump`) | `~546 pkts/session` (`1,638` pkts for 3 warm runs; `PRIV_BKEY` + `LINK_FRAG`) | **`~112 pkts/session`** (`~4.9×` lower relay packet amplification) | `~188 pkts` (fanout `A->X1` + `A->X2`) |
| Direct control-plane leakage (`tcpdump` on hosts `A` & `B`) | **`0`** (`UDP/500 = 0`, `UDP/4500 Non-ESP = 0`, `OV_AB = 0`) | **`0`** (`UDP/500 = 0`, `UDP/4500 Non-ESP = 0`) | **`0`** (`Type 1 = 0`, `Type 2 = 0`, `Type 3 = 0`) |
| Steady-state tunnel ICMP RTT (10 probes, `0%` loss) | `23.10 / 23.94 / 24.43 ms` (`min / avg / max`) | `23.38 / 24.46 / 31.63 ms` (`min / avg / max`) | `23.58 / 25.45 / 29.82 ms` (`min / avg / max`, `< 1.5 ms` delta) |
| `iperf3` TCP 1-stream `A -> B` (`10 s`, uplink-limited) | `72.8` sender / `70.8 Mbps` receiver | `71.9` sender / `70.1 Mbps` receiver | `69.7` sender / `67.1 Mbps` receiver (`96%` of kernel XFRM) |
| `iperf3` TCP 4-streams `A -> B` (`10 s`) | `72.6` sender / `71.0 Mbps` receiver | `70.8` sender / `69.2 Mbps` receiver | **`72.9`** sender / **`70.3 Mbps`** receiver (`99–102%` of kernel XFRM) |
| `iperf3` TCP 4-streams reverse `B -> A` (`10 s`) | `90.8` sender / `87.3 Mbps` receiver | `89.3` sender / `86.6 Mbps` receiver | `88.6` sender / `86.0 Mbps` receiver (`98.5–99.3%` of kernel XFRM) |
| Total encrypted payload moved across WAN during test | `> 307.8 MB` (`314,050` ESP packets) | `> 301 MB` (`305,157` ESP packets) | `> 309 MB` (`307,975` WG Type 4 packets) |
| Live rekey over MCC overlay (under continuous ping) | `CHILD_SA = 132.4 ms`, `IKE_SA = 88.4 ms` (warm 3-hop `A->X1->B`) | `CHILD_SA = 203.7–275.2 ms`, `IKE_SA = 111.9–258.1 ms` (4-hop `A->X1->X2->B`) | Automatic `120 s` PFS rekey (`Type 1/2` routed 4-hop `A -> X1 -> X2 -> B`) |
| Packet loss during live rekey | **`0 / 40` (`0.0%` loss)**, RTT avg `24.10 ms` | **`0 / 40` (`0.0%` loss)**, RTT avg `23.66 ms` | **`0 / 62` (`0.0%` loss)**, RTT avg `24.60 ms` |
| Direct control leakage during live rekey (`tcpdump`) | **`0`** (`UDP/500 = 0`, `UDP/4500 Non-ESP = 0`, `240` ESP pkts) | **`0`** (`UDP/500 = 0`, `UDP/4500 Non-ESP = 0`, `80` ESP pkts) | **`0`** (`Type 1/2/3 = 0`, `132` direct Type 4 pkts) |
| Same-VPS (`City-2` Linux x86_64) crypto microbenchmark (`200` iters) | `Ed25519` `244.1 µs`, `MCC capsule seal+open` `589.1 µs`, `SQLite 3-tx` `9.64 ms` | **`Ed25519` `130.2 µs`** (`1.87×` faster), **`X25519+AES-256-GCM` `201.2 µs`** (`2.93×` faster) | Same pure-Rust core + `boringtun` ChaCha20-Poly1305 |

### Key Engineering Findings Confirmed on Live WAN
1. **Why Python stalls on cold on-demand starts (`36.1 s` vs `529 ms` in Rust):** The dissertation Python daemon (`node_daemon.py`) runs a single-threaded `serve_forever()` UDP receive loop that synchronously invokes `ensure_session()` (`init_ev.wait(2.0)`) inside `handle_MCC_START()`. With `PRECONNECT_ENABLED=0`, relays block their own receive loop waiting for `MGMT_INIT_RESP`, causing a self-deadlock until 2 s timeouts flush the socket queue (`68.3×` slower than Rust). Python therefore mandates `PRECONNECT_ENABLED=1` ($O(N^2)$ background full-mesh traffic), whereas Rust's non-blocking `tokio::spawn` + `pending_sends` queue establishes lazy sessions on demand in `529 ms` with zero background preconnect traffic.
2. **4.2–5.0× lower RAM & 4.9× lower relay packet amplification in Rust:** Under live WAN load on the exact same hosts, the Python overlay process consumes `41.1–43.1 MB` peak RSS (`VmHWM`) vs `8.46–10.33 MB` for Rust `cco` (and only `2.57–4.94 MiB` total for userspace Rust WireGuard with zero `charon`). Eliminating Python's legacy `PRIV_BKEY_REQ`/`PRIV_X1B_SEAL` locator round-trip inside MCC also cuts overlay packet volume per IKEv2 handshake from `~546` to `~112` UDP packets (`4.9×` reduction).
3. **Why WireGuard converges 2.5–4.1× faster than IPsec (`128 ms` vs `316–529 ms`):** Standard IKEv2 (RFC 7296) requires **2 full round-trips** (`IKE_SA_INIT` + `IKE_AUTH`) before kernel XFRM installs `CHILD_SA` (`~90 ms/RTT` across two transit cities plus DH/CLI overhead -> `316–336 ms` warm, `529 ms` cold; single-RTT `CREATE_CHILD_SA` rekey drops to `112–204 ms`). WireGuard `Noise_IKpsk2` uses the pre-distributed static responder key to establish transport keys in **1 RTT** (`128 ms` across 4 hops).
4. **Data-plane language independence & userspace parity:** All three stacks deliver identical ~`70–87 Mbps` TCP throughput and `23.9–25.5 ms` RTT across the same WAN link (`Python IPsec = 71.0 / 87.3 Mbps`, `Rust IPsec = 69.2 / 86.6 Mbps`, `Rust Userspace WG = 70.3 / 86.0 Mbps`), proving both that control-plane language never throttles direct data-plane throughput and that userspace `boringtun` matches kernel XFRM within `1–3%` while removing `strongSwan`, `nftables`, and `CAP_NET_RAW`.
5. **Zero-loss seamless PFS rotation & NAT-T `conntrack` fix (`74f84a0`):** All three stacks rotated keys under continuous ping with **`0.0%` packet loss** (`40/40`, `40/40`, `62/62`) and **`0` direct control-plane packets** on both host interfaces. Live dual-NAT testing also identified and permanently fixed (`74f84a0`) the Linux `conntrack` stickiness on `UDP/4500` by adding `notrack` rules in `output_raw` for non-zero SPI and 1-byte NAT-T keepalives.
