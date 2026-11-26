# Experimental Plan for Follow-Up Journal Study (Scopus / WoS)

This document defines a reproducible post-dissertation experimental agenda extending the baseline IPsec/IKEv2 + WireGuard control-plane separation architecture to a **single cross-platform Rust engine (`cco-wg-tunnel` + `cco-ffi`)** supporting Linux, Android (`VpnService`), Windows (`Wintun`), and macOS (`utun` / `NEPacketTunnelProvider`).

> **Scope note:** Every experiment below evaluates new `v0.2.0` artifacts (in-process userspace WireGuard `boringtun` split engine, JNI/C-ABI mobile & desktop clients, and kernel-vs-userspace data-plane trade-offs) beyond the original dissertation testbed.

---

## Research Questions

1. **RQ1 (Control-Plane Isolation vs Latency):** What is the exact handshake latency overhead of routing WireGuard `Type 1/2/3` handshakes through an `H`-hop Ed25519/X25519 MCC cascade (`A -> X1 -> X2 -> B`) across the four receiver selection modes (`first`, `window`, `adaptive`, `wait-all`) under realistic WAN RTT and packet loss?
2. **RQ2 (Userspace vs Kernel Data-Plane Trade-Off):** How do steady-state RTT, jitter, throughput, and CPU utilization compare between:
   - **Baseline A:** direct unmodified WireGuard / IPsec (no control-plane hiding),
   - **Kernel Split (`v0.1.0`):** unmodified kernel `strongSwan` + `nftables`/`TPROXY`/`SO_MARK` overlay (`cco node`), and
   - **Userspace Split (`v0.2.0`):** in-process `boringtun` + MCC overlay (`cco wg-tunnel` / `cco-ffi`) requiring zero root privileges on Android and zero unsigned kernel drivers on Windows/macOS?
3. **RQ3 (Cross-Platform Parity):** Does a single `#![forbid(unsafe_code)]` Rust cryptographic and state-machine core preserve byte-exact security invariants (`direct_handshake_tx == 0`, fail-closed Trust Registry v2, SQLite anti-replay) across Android ARM64, Windows x86_64 (`Wintun`), macOS Apple Silicon (`utun`), and Linux `ip netns`?

---

## Reproducible Experiment Matrix (E1–E5)

| ID | Objective | Harness / Command | Primary Metrics |
| :--- | :--- | :--- | :--- |
| **E1** | Split-plane invariant proof (userspace WG vs kernel strongSwan) | `sudo bash lab/scripts/wg_userspace_e2e.sh` and `sudo bash lab/scripts/netns_e2e.sh` | `direct_wg_control_total == 0`, `direct_ike_total == 0`, `direct_type4 > 0`, `direct_esp > 0`, pcap verification |
| **E2** | Handshake latency & MCC mode sensitivity under WAN impairment | Linux `ip netns` + `tc qdisc add dev ... netem delay 20..80ms loss 0..5%` across `first`, `window`, `adaptive`, `wait-all` and fanouts `(1..4) x (1..4)` | `handshake_ms` (median, p95, p99), success rate, overlay byte amplification |
| **E3** | Steady-state data-plane performance (userspace `boringtun` vs kernel `strongSwan XFRM`) | `ping -c 100 -i 0.05` + `iperf3 -t 30` across RFC 5737 tunnel `198.51.100.10 <-> 198.51.100.13` | RTT (min/avg/p95/max), throughput (Mbps), CPU% per Gbps, zero control leakage during rekey (`120 s` WG rekey interval) |
| **E4** | Cross-platform FFI & OS TUN overhead | Android `VpnService` (`arm64-v8a` / `x86_64`), Windows `Wintun 0.14.1` (`CcoOverlayWindows.exe`), macOS `utun` (`CcoMacApp.app`) | Initial handshake latency, FFI call overhead (`cco_tunnel_push_outbound_ip` / `pop_inbound_ip`), binary footprint |
| **E5** | Analytical vs empirical relay-compromise scaling | `cco analytics routes`, `cco analytics n50`, `cco bench monte-carlo --trials 800000`, and negative-security tamper injection (`cco-trust` + `cco-cascade`) | Exact vs empirical compromise probability (`abs_err <= 0.0004`), `n50` reduction, 100% rejection of forged/replayed/downgraded offers |

---

## Preliminary `v0.2.0` Baseline Measurements (WSL2 Linux 6.6 `ip netns`)

Already reproduced in automated CI (`netns-l3-live` and `wg-userspace-l3-live`):

| Architecture | Control Plane Path | Direct Control Leakage (`provider.pcap`) | Data Plane Path | Measured RTT (avg) | Initial Handshake | Privilege / Driver Requirement |
| :--- | :--- | :---: | :--- | :---: | :---: | :--- |
| Kernel IPsec (`strongSwan 5.9.5` + `cco node`) | IKEv2 UDP/500 & 4500 via MCC `A -> X1 -> X2 -> B` | **`0`** | Direct kernel XFRM ESP (`proto 50`) | `0.101 ms` (`0%` loss) | `< 150 ms` | Linux `CAP_NET_ADMIN` + `nftables` |
| Userspace WG (`boringtun 0.7.1` + `cco wg-tunnel`) | WG Type 1/2/3 via MCC `A -> X1 -> X2 -> B` | **`0`** | Direct userspace WG Type 4 UDP | `0.452 ms` (`0%` loss) | `105 ms` | Rootless Android `VpnService` / signed `Wintun` / macOS `utun` |

### Completed Geo-Distributed 4-Node WAN Measurements (Dual NAT, `BENCHMARKS.md §6`)

Executed across 4 real WAN hosts (`Node A [Home NAT] -> Node X1 [City-1] -> Node X2 [City-2] -> Node B [City-3 NAT]`):

| Architecture (Live 4-Node WAN) | Cold / Warm Handshake | Peak Daemon RAM (`VmHWM`) | Direct Control Leakage | Avg Tunnel RTT | `iperf3` 4-Stream TCP (`A->B` / `B->A`) | Seamless Rekey (`0%` Ping Loss) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Python Reference + Kernel IPsec (`CPython 3.14.10` + `strongSwan 6.0.1`) | `36,110 ms` (`PRECONNECT=0`) / `247.5 ms` warm (3-hop) | `41.1–43.1 MB` (+`charon`) | **`0`** (`500`/`4500` Non-ESP) | `23.94 ms` | `71.0` / `87.3 Mbps` (receiver) | `CHILD_SA 132 ms`, `IKE_SA 88 ms` (`40/40`, `0` direct IKE) |
| Rust `cco` + Kernel IPsec (`strongSwan 5.9.8` + `cco --ike-proxy`) | **`529.0 ms`** cold / `316–336 ms` warm (4-hop) | **`8.46–10.33 MB`** (+`charon`) | **`0`** (`500`/`4500` Non-ESP) | `24.46 ms` | `69.2` / `86.6 Mbps` (receiver) | `CHILD_SA 204–275 ms`, `IKE_SA 112–258 ms` (`40/40`, `0` direct IKE) |
| 100% Rust Userspace WG (`boringtun 0.7.1` + `cco wg-tunnel`) | **`128.0 ms`** (1-RTT, 4-hop) | **`2.57–4.94 MiB`** total (no `charon`) | **`0`** (`Type 1/2/3`) | `25.45 ms` | **`70.3`** / `86.0 Mbps` (receiver) | Auto `120 s` PFS rekey (`62/62`, `0` direct WG ctrl) |

## Artifact Archival Checklist for Paper Submission

- Pin exact Git tag (e.g., `v0.2.0`) and release `SHA256SUMS.txt`.
- Archive raw `provider.pcap` files, `TunnelStats` JSON dumps, and `tc netem` profiles in `Adaptive-Secure-Overlay/adaptive-overlay-experiments`.
- Include threat-model boundary table stating explicitly that the data plane remains direct (`A <-> B`) and global passive timing correlation is out of scope.
