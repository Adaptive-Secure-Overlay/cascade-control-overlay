# Security Policy

## Scope and Status

**Cascade Control Overlay (`cco`)** is an open-source research implementation of hybrid VPN control-plane algorithms (Multiple Start Connections / MCC, multi-hop IKEv2 and WireGuard handshake overlay, Universal H-hop Cascade, and Trust Registry v2).

It has **not** undergone an independent third-party cryptographic security audit and should be treated as an experimental research system rather than a hardened production VPN gateway.

## Security Invariants Enforced by Design

1. **Vetted Cryptography Only:** All cryptographic operations use audited RustCrypto / dalek crates (`x25519-dalek`, `ed25519-dalek` with `verify_strict`, `hkdf`, `sha2`, `aes-gcm`, `subtle`). Secret keys, DH shared secrets, and derived symmetric keys implement `Zeroize` / `ZeroizeOnDrop` with redacted `Debug` representations.
2. **Fail-Closed Trust Gate:** Nodes refuse to bind UDP sockets or process overlay traffic unless a valid `ipsec-ike-cascade-trust-registry/v2` document is cryptographically verified against a pinned external trust root (`ipsec-ike-cascade-trust-root/v1`). No password-based fallback mode exists.
3. **Separate Keys and Strict Anti-Rollback:** Every node uses distinct `X25519` (encryption) and `Ed25519` (verification) keys; root signers cannot overlap with node signers; registry versions are strictly monotonic and persisted atomically (`temp file -> sync_all -> rename`) with SHA-256 verification and `last-valid` recovery.
4. **At-Most-Once Delivery & Move-Only Proof:** `LocalDeliveryProof` is a move-only Rust type (no `Clone`, no `Copy`) backed by a durable SQLite anti-replay ledger. Ambiguous local injection (`IkeInjectionOutcome::Unknown`) retains the in-flight reservation and forbids automatic retries.
5. **Memory Safety:** `#![forbid(unsafe_code)]` is enforced across 7 of 8 workspace crates. Only `cco-linux-proxy` uses minimal isolated `unsafe` blocks for Linux socket options (`IP_TRANSPARENT`, `IP_RECVORIGDSTADDR`, `SO_MARK`, `IP_HDRINCL`).
6. **Log Hygiene:** Rejection paths emit stable, sanitized reason codes (`invalid_record`, `stale_version`, `replay_detected`, `legacy_proxy_disabled`) without logging raw keys, ciphertexts, or attacker-controlled strings.

## Explicit Limitations (Out of Scope)

- **Global Passive Adversary (GPA):** This architecture does not attempt to resist a global adversary observing all links simultaneously with end-to-end timing and volume correlation.
- **Direct Data-Plane Visibility:** By design, once IKEv2 or WireGuard negotiation succeeds, IPsec ESP or WireGuard `type 4` packets flow directly between endpoints `A` and `B`.
- **Anonymity Networks:** Not a replacement for Tor or I2P for anonymous web browsing.

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for the complete adversary model.

## Reporting a Vulnerability

If you discover a cryptographic, parsing, protocol, or memory-safety issue:

1. **Do not** open a public issue with exploit details.
2. Report privately via GitHub Security Advisories on `Adaptive-Secure-Overlay/cascade-control-overlay` or contact the maintainer directly.
3. Include a minimal reproduction test case, affected crate/version, and impact summary.
