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

## 6. Live 4-Node Geo-Distributed WAN Verification (Full 2×2 Matrix, Dual NAT, Docker Compose)

All four combinations of the **2×2 factorial matrix (`{Python, Rust} × {IPsec, WireGuard}`)** were evaluated on the **same 4-node geographically distributed WAN testbed** in isolated Docker Compose containers (Python relays on `UDP/19001` running in parallel with Rust relays on `UDP/19000`, zero host routing or firewall interference):

- **Topology:** `Node A` (behind residential NAT) `->` `Node X1` (City-1 public relay) `->` `Node X2` (City-2 public relay) `->` `Node B` (City-3 behind NAT router with UDP port forwarding).
- **Underlay RTT baseline:** `A <-> X1` `8.7 ms`, `X1 <-> X2` `11.1–12.2 ms`, `X2 <-> B` `21.9 ms`, direct `A <-> B` `~21–25 ms`.
- **Shared security profile:** identical `Trust Registry v2`, Ed25519/X25519 MCC capsules (`mode=first`, `x1=2, x2=2, ike=1`), authenticated NAT endpoint roaming, `notrack` data-plane firewall rules (`74f84a0`), and host-interface `tcpdump` capture at both endpoints `A` and `B`.
- **Python + Kernel WireGuard (`wg0`):** combines the unmodified dissertation Python MCC daemon (`01-mcc-e2e-candidate`) and WireGuard framing parser (`wg_handshake_overlay/parser.py`) with Linux kernel `wg0` + `nftables` (`@th,64,32` `0x01/0x02/0x03` redirect, `0x04` `notrack` direct bypass) and RFC 768 raw IPv4/UDP injection (`SO_MARK 0x53`).

| Metric (Same 4-Node Geo-Distributed WAN, Dual NAT) | Python + Kernel IPsec (`CPython 3.14.10` + `strongSwan 6.0.1`) | Python + Kernel WG (`CPython 3.14.10` + Linux `wg0`) | Rust + Kernel IPsec (`cco` + `strongSwan 5.9.8`) | 100% Rust Userspace WG (`cco wg-tunnel` / `boringtun 0.7.1`) |
| :--- | :---: | :---: | :---: | :---: |
| Control plane via MCC (`A -> X1 -> X2 -> B`) | IKEv2 (`500`/`4500` Non-ESP) + `PRIV_BKEY` | WG `Type 1/2/3` + `PRIV_BKEY` | IKEv2 (`500`/`4500` Non-ESP) | WG `Noise_IKpsk2` (`Type 1/2/3`) |
| Data plane direct (`A <-> B`) | Kernel XFRM `ESP-in-UDP` (`4500`) | Kernel `wg0` `Type 4` (`4500`) | Kernel XFRM `ESP-in-UDP` (`4500`) | Userspace `boringtun` `Type 4` (`4500`) |
| Container stack / privileges | `CPython` + `strongSwan` + `nftables` + `NET_ADMIN`/`NET_RAW` | `CPython` + kernel `wg.ko` + `nftables` + `NET_ADMIN`/`NET_RAW` | `cco` + `strongSwan` + `nftables` + `NET_ADMIN`/`NET_RAW` | **Single `cco` binary + `/dev/net/tun` (`NET_ADMIN`, zero `nftables`)** |
| Container image size (relay / endpoint) | `217 MB` / `247 MB` | `217 MB` / `248 MB` | `150 MB` / `159 MB` | `150 MB` / **`151 MB`** |
| Peak overlay RAM (`VmHWM`, relay / endpoint) | `41.9–42.3 MB` / `41.1–43.1 MB` (+`~10 MB charon`) | `41.9–42.3 MB` / `41.7–42.4 MB` | **`8.46–8.74 MB`** / **`9.40–10.33 MB`** (+`~11 MB charon`) | **`2.57–4.94 MiB`** total (**no `charon`**, `8.5–16×` less RAM) |
| **Cold start** (`PRECONNECT=0`, on-demand `MGMT`) | `36,109.8 ms` (`36.1 s` — sync `recv` self-deadlock) | Requires `PRECONNECT=1` (same sync `recv` loop) | **`529.0 ms`** (`68.3×` faster than Python) | **`128.0 ms`** (**`4.1×` faster** than Rust IPsec, 1-RTT) |
| **Warm start** (`MGMT` ready) | `234.6 / 247.5 / 354.0 ms` (median `247.5 ms`, 3-hop) | `~146 ms` (`167.2 ms` incl. 1st `Type 4` ICMP reply) | `316.2 / 336.5 ms` (4-hop, 2-RTT IKEv2) | **`128.0 ms`** (4-hop, 1-RTT `Noise_IKpsk2`) |
| Overlay UDP packets / handshake (host `A` `tcpdump`) | `~546 pkts` (`1,638` / 3 runs; `PRIV_BKEY` + `LINK_FRAG`) | `354 pkts` (`168` `X1` + `186` `X2`; `PRIV_BKEY`) | **`~112 pkts`** (`4.9×` fewer than Python IPsec) | **`~188 pkts`** (`1.9×` fewer than Python WG) |
| Direct control leakage (`tcpdump` on `A` & `B`) | **`0`** (`500=0`, `4500 Non-ESP=0`, `OV_AB=0`) | **`0`** (`Type 1/2/3 = 0`, `OV_AB=0`) | **`0`** (`500=0`, `4500 Non-ESP=0`) | **`0`** (`Type 1/2/3 = 0`) |
| Steady-state tunnel ICMP RTT (10 probes, `0%` loss) | `23.10 / 23.94 / 24.43 ms` | **`20.65 / 21.03 / 21.76 ms`** | `23.38 / 24.46 / 31.63 ms` | `23.58 / 25.45 / 29.82 ms` |
| `iperf3` TCP 1-stream `A -> B` (`10 s`, receiver) | `70.8 Mbps` (`72.8` sender) | **`71.1 Mbps`** (`73.1` sender) | `70.1 Mbps` (`71.9` sender) | `67.1 Mbps` (`69.7` sender) |
| `iperf3` TCP 4-streams `A -> B` (`10 s`, receiver) | `71.0 Mbps` (`72.6` sender) | **`71.9 Mbps`** (`74.1` sender) | `69.2 Mbps` (`70.8` sender) | `70.3 Mbps` (`72.9` sender; `97.8%` of kernel `wg0`) |
| `iperf3` TCP 4-streams reverse `B -> A` (`10 s`, receiver) | `87.3 Mbps` (`90.8` sender) | **`88.0 Mbps`** (`91.2` sender) | `86.6 Mbps` (`89.3` sender) | `86.0 Mbps` (`88.6` sender; `97.7%` of kernel `wg0`) |
| Total encrypted payload transferred during test | `> 307.8 MB` (`314,050` ESP pkts) | `> 306.3 MiB` (`wg0` `Type 4`) | `> 301 MB` (`305,157` ESP pkts) | `> 309 MB` (`307,975` `Type 4` pkts) |
| Live rekey over MCC overlay (under continuous ping) | `CHILD 132.4 ms`, `IKE 88.4 ms` (3-hop) | Auto `121 s` PFS rekey (`16:51:20 -> 16:53:21`) | `CHILD 204–275 ms`, `IKE 112–258 ms` (4-hop) | Auto `120 s` PFS rekey (4-hop `A->X1->X2->B`) |
| Packet loss during live rekey | **`0 / 40` (`0.0%`)**, avg `24.10 ms` | **`0 / 75` (`0.0%`)**, avg `21.13 ms` | **`0 / 40` (`0.0%`)**, avg `23.66 ms` | **`0 / 62` (`0.0%`)**, avg `24.60 ms` |
| Direct control leakage during live rekey (`tcpdump`) | **`0`** (`240` ESP pkts) | **`0`** (`453` direct `Type 4` pkts) | **`0`** (`80` ESP pkts) | **`0`** (`132` direct `Type 4` pkts) |
| Same-VPS (`City-2` Linux x86_64) crypto microbenchmark (`200` iters) | `Ed25519` `244.1 µs`, capsule `589.1 µs`, `SQLite 3-tx` `9.64 ms` | Same `CPython 3.14.10` + `cryptography 50.0.2` | **`Ed25519` `130.2 µs`** (`1.87×`), **capsule `201.2 µs`** (`2.93×`) | Same pure-Rust core + `boringtun` |

### Key Engineering Findings Confirmed Across the 2×2 WAN Matrix
1. **Why Python stalls on cold on-demand starts (`36.1 s` vs `529 ms` in Rust):** The dissertation Python daemon (`node_daemon.py`) runs a single-threaded `serve_forever()` UDP receive loop that synchronously invokes `ensure_session()` (`init_ev.wait(2.0)`) inside `handle_MCC_START()`. With `PRECONNECT_ENABLED=0`, relays block their own receive loop waiting for `MGMT_INIT_RESP`, causing a self-deadlock until 2 s timeouts flush the socket queue (`68.3×` slower than Rust). Both Python IPsec and Python WireGuard therefore mandate `PRECONNECT_ENABLED=1` ($O(N^2)$ background full-mesh traffic), whereas Rust's non-blocking `tokio::spawn` + `pending_sends` queue establishes lazy sessions on demand in `529 ms` (IPsec) / `128 ms` (WireGuard) with zero background preconnect traffic.
2. **4.2–16× lower RAM & 1.9–4.9× lower relay packet amplification in Rust:** Under live WAN load on the exact same hosts, the Python overlay process consumes `41.1–43.1 MB` peak RSS (`VmHWM`) for both IPsec and WireGuard vs `8.46–10.33 MB` for Rust `cco` IPsec and only `2.57–4.94 MiB` total for userspace Rust WireGuard. Eliminating Python's legacy `PRIV_BKEY_REQ`/`PRIV_X1B_SEAL` locator round-trip inside MCC also cuts overlay packet volume per handshake from `~546` to `~112` (IPsec, `4.9×`) and from `354` to `~188` (WireGuard, `1.9×`).
3. **Why WireGuard converges 2–4× faster than IPsec across both languages:** Standard IKEv2 (RFC 7296) requires **2 full round-trips** (`IKE_SA_INIT` + `IKE_AUTH`) before kernel XFRM installs `CHILD_SA` (`247–336 ms` warm, `529 ms` cold; single-RTT `CREATE_CHILD_SA` rekey drops to `88–204 ms`). WireGuard `Noise_IKpsk2` establishes session keys in **1 RTT** (`~146 ms` warm on Python + `wg0`, **`128.0 ms`** on Rust `boringtun`).
4. **Userspace Rust `boringtun` matches Linux kernel `wg0` within `2.3%`:** On the exact same WAN link, 100% userspace `cco wg-tunnel` (`70.3 / 86.0 Mbps`) reaches **`97.7–97.8%`** of native Linux kernel `wg0` (`71.9 / 88.0 Mbps`) and matches kernel `strongSwan` XFRM (`69.2–71.0 / 86.6–87.3 Mbps`), while eliminating `wireguard.ko`, `strongSwan`, `nftables`, and `CAP_NET_RAW` — enabling rootless Android `VpnService`, signed Windows `Wintun`, and macOS `utun`.
5. **Zero-loss seamless PFS rotation across all 4 cells & NAT-T `conntrack` fix (`74f84a0`):** Every cell in the 2×2 matrix rotated session keys under continuous ping with **`0.0%` packet loss** (`40/40`, `75/75`, `40/40`, `62/62`) and **`0` direct control-plane packets** on both host interfaces. Live dual-NAT testing also identified and fixed the Linux `conntrack` stickiness on `UDP/4500` via `output_raw` `notrack` rules for non-zero SPI (`ESP-in-UDP`) and `0x04000000` (`WireGuard Type 4`).
