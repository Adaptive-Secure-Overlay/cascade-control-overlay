# Architecture

## Hybrid Control-Plane / Data-Plane Split

Cascade Control Overlay decouples **VPN session establishment** (IKEv2 `IKE_SA_INIT`/`IKE_AUTH` or WireGuard `type 1/2/3`) from **encrypted bulk data transport** (IPsec ESP or WireGuard `type 4`), requiring **zero modifications** to `strongSwan` (`charon`) or WireGuard kernels.

```text
  Endpoint A (192.0.2.10)                         Endpoint B (192.0.2.13)
  +---------------------+                         +---------------------+
  | strongSwan / charon |                         | strongSwan / charon |
  +----------+----------+                         +----------+----------+
             | UDP/500 or UDP/4500 (Non-ESP)                 ^
             v  nftables output redirect                     | SOCK_RAW + SO_MARK 0x53
  +----------+----------+                         +----------+----------+
  | cco-linux-proxy     |                         | cco-linux-proxy     |
  +----------+----------+                         +----------+----------+
             | LocalDeliveryProof (move-only)                ^
             v                                               |
  +----------+----------+   MGMT + MCC (UDP/9000) +----------+----------+
  | cco-transport +     | ---> X1 ---> X2 ------> | cco-transport +     |
  | cco-cascade (MCC)   | <--- X1 <--- X2 <------ | cco-cascade (MCC)   |
  +---------------------+                         +---------------------+

  =========== Direct IPsec ESP (proto 50) / WireGuard type 4 ===========
  Endpoint A (192.0.2.10) <=====================> Endpoint B (192.0.2.13)
```

## Crate Dependency Graph

```text
cco-cli
 ├── cco-analytics ── cco-crypto
 ├── cco-linux-proxy ─┬─ cco-transport ─┬─ cco-cascade ─┬─ cco-trust ─┬─ cco-crypto
 │                    ├─ cco-cascade    ├─ cco-proto    ├─ cco-proto  └─ cco-proto
 │                    └─ cco-proto      ├─ cco-trust    └─ cco-crypto
 │                                      └─ cco-crypto
 └── cco-trust
```

## Key Architectural Principles

### 1. Sans-I/O Core (`cco-cascade`)
All protocol state machines (`MccNodeMachine`, `UniversalCascadeNode`, `WgHandshakeOverlayEngine`) perform zero socket I/O and read zero wall-clock globals. They accept `(peer, message_type, plaintext, now_ms)` and return explicit `Action` enumerations (`Send`, `DeliverIke`, `Reject`). This guarantees deterministic unit testing of every branch-selection mode, replay path, and fault-injection case without sockets.

### 2. Fail-Closed Trust Gate (`cco-trust` -> `cco-transport`)
`OverlayNode::start` accepts an `EndpointSecurity` token that can only be constructed from a `VerifiedRegistry`. As a result, the compiler enforces at the type level that a node **cannot** bind its UDP overlay socket until Trust Registry v2 verification against a pinned root succeeds.

### 3. Move-Only Delivery Proof & Durable At-Most-Once Ledger
When receiver `B` selects a verified MCC branch, `MccNodeMachine` reserves the delivery in SQLite (`claim_delivery`) and mints a non-`Clone`, non-`Copy` `LocalDeliveryProof`. The transport/proxy adapter must consume `LocalDeliveryProof` exactly once and return `(IkeInjectionOutcome, DeliveryReceipt)` to `complete_delivery`:
- `Sent`: marks the exchange permanently `delivered` in SQLite.
- `Rejected`: rolls back the reservation and fails over to the next verified queued MCC branch.
- `Unknown`: retains the durable `in_flight` claim and forbids automatic retry.

### 4. Non-Blocking Hop Session Worker (`cco-transport`)
Hop-to-hop links establish 4-step `MGMT` symmetric sessions lazily or via deterministic tie-broken `preconnect` (`self_name < peer`). Messages arriving before a hop session finishes are queued in bounded `pending_sends` without blocking the UDP receive loop; a two-slot `PeerSessionSlot` (`active` + `previous`) prevents packet drops during concurrent crossing handshakes or rekey overlap.

### 5. Isolated Linux Privilege Boundary (`cco-linux-proxy`)
All 7 protocol/analytics/CLI crates enforce `#![forbid(unsafe_code)]`. Only `cco-linux-proxy` (under `#[cfg(target_os = "linux")]`) contains minimal isolated `unsafe` socket calls (`IP_RECVORIGDSTADDR`, `IP_TRANSPARENT`, `IP_FREEBIND`, `SO_MARK`, `IP_HDRINCL`, `SOCK_RAW`). On non-Linux hosts, a safe fail-closed stub compiles cleanly so `cargo test --workspace` runs everywhere.
