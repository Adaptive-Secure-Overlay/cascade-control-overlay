# Threat Model & Boundaries of Applicability

This threat model mirrors the formal assumptions of the dissertation (Chapters 1, 2, 3, and Section 4.3.4) without overclaiming guarantees outside the studied model.

---

## 1. Protected Assets

1. **VPN Handshake Confidentiality & Linkability at the Local Provider Edge:** Preventing a local provider-plane observer between endpoint `A` and endpoint `B` from observing direct `A <-> B` IKEv2 (`UDP/500`, `UDP/4500` Non-ESP) or WireGuard (`type 1/2/3`) control exchanges.
2. **Control-Plane Integrity & Authenticity:** Preventing untrusted or compromised relays (`X1`, `X2`, or intermediate `UniversalCascade` hops) from forging, substituting, replaying, or tampering with IKEv2 / WireGuard handshake messages.
3. **Hop-Scope Role Isolation (Privacy):**
   - **2-hop MCC (`--route-mode mcc2`):** `X1` learns `A` and candidate `X2` nodes, `X2` learns `X1` and `B`, and `A` continues `IKE_AUTH` via `opaque_token` without learning which `X2` branch `B` selected.
   - **Arbitrary `m`-hop `UniversalCascade` (`--route-mode cascade --hops m`, `m >= 2`):**
     - Initiator `A` knows only its chosen entry `X1` and destination `B` (never `X2..Xm`).
     - Receiver `B` knows only its last hop `Xm` and verified source `A` (never `X1..X(m-1)`).
     - Entry relay `X1` knows only `A` and `X2`; exit relay `Xm` knows only `X(m-1)` and `B`.
     - Every interior relay `Xk` (`2 <= k <= m - 1`) knows **only** its immediate predecessor `X(k-1)` and successor `X(k+1)` — never `A`, `B`, or any non-adjacent relay. Once active, `RelayCell::build_ctx` is wiped so memory retains only `(inbound_handle, previous_peer, outbound_handle, next_peer, expires_at)`.
     - **Constant-size wire framing & no plaintext hop counter / visited list:** Every `CASCADE_*` message is padded to a fixed `3,584 B` on the wire (`2,048 B` payload block, `128 B` source guard); plaintext `remaining`, total length `m`, and `visited` lists are absent from both wire frames and relay state (enforced by automated negative leakage tests for `m = 3, 5, 10` in `cco-cascade/tests/universal_cascade_suite.rs` and live UDP E2E memory audits in `cco-transport/tests/cascade_udp_e2e.rs`).
4. **Trust Catalog Integrity:** Preventing unauthorized node injection, key substitution, key reuse, or downgrade to a revoked/stale node directory.

---

## 2. Adversary Capabilities Addressed

| Threat | Mitigation Implemented | Verification |
| :--- | :--- | :--- |
| **Provider-plane direct IKE/WG sniffing** | `nftables` captures only IKEv2 control (UDP/500 & UDP/4500 Non-ESP `00 00 00 00`), routing it via encrypted multi-hop MCC (`UDP/9000`). | Live L3 `netns_e2e.sh` pcap audit: `direct_ike_total == 0`. |
| **Active relay tampering / wrapper spoofing** | Receiver `B` opens `endpoint` capsule and verifies `Ed25519` (`verify_strict`) + signed fields (`src`, `dst`, `context`, `ike_payload`, `request_digest`, `selection`) **before** allocating pending state or ledger rows; contradictory outer wrapper fields are rejected. | `cco-cascade/tests/mcc_suite.rs` (forged first/last offers, all-bad burst allocates zero state). |
| **Replay / duplicate injection across restarts** | Durable SQLite at-most-once ledger reserves `(message_key)` before emitting move-only `LocalDeliveryProof`; `Unknown` injection outcome locks the claim permanently. | `mcc_suite.rs::twenty_seven_copies_and_restart_durable_anti_replay` & `rejected_injection_fails_over_while_unknown_forbids_retry`. |
| **Trust Registry downgrade / corruption** | Pinned external root (`trust-root/v1`), strict duplicate-free canonical JSON, strictly monotonic version store, SHA-256 verification on equal version, atomic `fsync + rename`, verified `last-valid` recovery. | `cco-trust/tests/security_matrix.rs` (12 negative & recovery tests). |
| **Data-plane hijacking into overlay** | `nftables` Non-ESP filter (`@th,64,32 0x00000000`), `cco-proto` `is_ike_payload` guard, `cco-proto` WireGuard `type 4` hard rejection, `ip xfrm policy` bypass for overlay UDP port. | `cco-proto` unit tests, `wireguard_suite.rs` (27 scenarios), `cco-linux-proxy` unit tests & L3 live lab. |
| **Compromised subset of `m` honest-but-curious relays** | Combinatorial route-space expansion (`F3` / `F4` models + MCC multi-branch fanout + arbitrary `m`-hop `UniversalCascade` with linear `K` parallel chains) quantifies exact interception probability and minimum network size `n50`. | `cco-analytics/tests/analytics_suite.rs` (exact match to Chapter 3 + 2.4M Monte Carlo trials) & `cco bench cascade`. |
| **Relay knowledge leakage across `m >= 3` hops** | Role-limited `RelayCell` isolation, Ed25519-signed `endpoint` capsules, SHA-256 `hop_token`/`stop_tag` progression without plaintext `remaining`/`visited`, and constant `3,584 B` wire padding. | `universal_cascade_suite.rs::negative_knowledge_leakage_and_constant_size_padding_for_m_3_5_10` & `cascade_udp_e2e.rs`. |

---

## 3. Explicit Non-Goals & Limitations

1. **Global Passive Adversary (GPA):** If an adversary monitors all network links simultaneously and correlates packet timings/sizes across `A -> X1`, `X1 -> X2`, `X2 -> B` (or across `m` hops), the overlay does not provide strong traffic-analysis anonymity. (In the dissertation's Section 4.3.5 evaluation across 4,500 local traces with 9 candidate recipients, packet-sequence metadata classifiers achieved 23.07% accuracy on random splits and 17.20% on held-out parameter cells — above random guessing `11.11%`, demonstrating that local timing/size side channels exist and must be stated transparently.)
2. **Direct Data Plane After Handshake:** Once IPsec `CHILD_SA` or WireGuard session keys are established, `ESP` (proto 50 / UDP 4500) or WireGuard `type 4` packets traverse the direct path between `A` and `B` to preserve native VPN latency and throughput. Anyone observing the `A <-> B` underlay after setup sees direct encrypted ESP/WireGuard traffic.
3. **Colluding Relays on the Same Chain & `hop_token` Residual Distance Boundary:** If colluding relays span the entry and exit (or full chain), they can correlate `A` and `B` (modeled analytically in `cco-analytics`). In addition, because `UniversalCascade` performs decentralized hop-by-hop routing where `A` does not pre-know `X2..Xm`, relays advance an opaque SHA-256 chain `(hop_token, stop_tag)` without any plaintext `remaining` field; while `Xk` cannot invert SHA-256 to learn its distance `k` from `A` or total length `m`, a curious relay that locally iterates `hop_step` forward up to `max_hops` can compute the remaining distance `m - k` to the exit. Full hiding of `m - k` would require source-routed onion encryption (which contradicts the model requirement that `A` must not know `X2..Xm`).
4. **End-Host Compromise:** Compromise of endpoint `A` or `B` private signing/encryption keys or the offline root signing key breaks trust assumptions until revoked via a newer signed Trust Registry v2 release.
5. **Audit Status:** Experimental research software; not externally audited for production deployment.
