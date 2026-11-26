# Wire Protocol & Cryptographic Specification

This document defines the exact wire framing, canonical JSON encoding, UDP fragmentation, and HKDF/AEAD domain separation implemented in `cco-crypto`, `cco-trust`, `cco-proto`, `cco-cascade`, and `cco-transport`. All contexts are verified byte-for-byte against Python golden vectors (`crates/cco-crypto/tests/golden_vectors.rs`, `crates/cco-trust/tests/security_matrix.rs`, and `crates/cco-transport/tests/e2e_udp.rs`).

---

## 1. Canonical JSON & Strict Parsing

- Wire JSON objects use **sorted keys** and compact separators `("," , ":")` with UTF-8 encoding (`cco_proto::canonical`).
- Security-critical inputs (Trust Registry v2, signed MCC records, hop payloads) reject:
  - duplicate JSON object keys at any nesting depth;
  - floating-point numbers where integers are required;
  - oversized frames (`MAX_REGISTRY_BYTES = 262_144`, `MAX_PLAINTEXT = 65_507`, `MAX_IKE = 8_192`).
- Hex fields require strictly lowercase canonical hex (`[0-9a-f]`) without whitespace.

---

## 2. `LinkFrag` UDP Fragmentation (`cco-proto`)

Any UDP frame whose serialized size exceeds `LINK_FRAG_MAX_WIRE = 1200` bytes is split into `LINK_FRAG` envelopes:

| Constant | Value |
| :--- | :--- |
| `LINK_FRAG_MAX_WIRE` | `1200` bytes |
| `LINK_FRAG_CHUNK_BYTES` | `700` bytes (base64-encoded inside JSON) |
| `LINK_FRAG_TTL_S` | `15` seconds |
| `LINK_FRAG_MAX_TOTAL` | `94` fragments |
| `LINK_FRAG_MAX_ASSEMBLED` | `65_507` bytes |
| `LINK_FRAG_MAX_BUFFERS` | `32` concurrent reassembly buffers |

Nested `LINK_FRAG` inside a reassembled payload is unconditionally rejected.

---

## 3. Hop Transport: 4-Step `MGMT` Handshake & Link AEAD

Every adjacent hop `(I, R)` negotiates an ephemeral X25519 symmetric link key `KD` using four JSON messages (`MGMT_INIT`, `MGMT_INIT_RESP`, `MGMT_AUTH`, `MGMT_AUTH_RESP`):

- **Label:** `"{I}-{R}"`
- **Key derivation:** `KD = HKDF-SHA256(ikm = X25519(sk, pk), salt = ni || nr, info = b"mgmt|ikev2-like|" || label, len = 32)`
- **Handshake confirmation AAD:** `AUTH:{label}:{from}->{to}:{sid}`
- **Hop message envelope (`SecureEnvelope`):** AES-256-GCM with 12-byte random nonce and AAD `{mtype}:{from}->{to}:{sid}`

---

## 4. Authenticated Trust Registry v2 (`cco-trust`)

- **Trust Root schema:** `ipsec-ike-cascade-trust-root/v1` (`signers: { "<issuer_id>": "<ed25519_pub_hex>" }`)
- **Registry schema:** `ipsec-ike-cascade-trust-registry/v2`
- **Per-node record:**
  - `encryption`: 32-byte lowercase hex `X25519` public key
  - `verification`: 32-byte lowercase hex `Ed25519` public key (`!= encryption`)
  - `key_id`: lowercase hex `SHA-256(raw_verification_bytes)`
  - `revoked`: boolean (`true` fails verification for required nodes)
- **Key uniqueness:** No two nodes may share an `encryption` or `verification` key; root signers cannot reuse any node verification key.
- **Anti-rollback state:** Persisted atomically (`NamedTempFile -> sync_all -> rename`) tracking `(version, sha256)`; strictly monotonic updates (`new_version > current_version`), fail-closed on equal-version hash mismatch, automatic recovery from verified `last-valid` backup if the primary file is truncated or corrupted.

---

## 5. MCC Authenticated & Opaque Privacy Protocol (`cco-cascade::mcc`)

### Cryptographic Contexts

| Purpose | KDF / Hash Construction | AAD |
| :--- | :--- | :--- |
| Recipient Capsule (`hop` / `endpoint`) | `HKDF-SHA256(ikm = X25519(epk, recipient_pub), salt = epk_raw \|\| recipient_pub_raw, info = b"mcc-recipient-capsule/v1\x00" \|\| aad, len = 32)` | `canonical_json({"context": ctx, "domain": "mcc-recipient-capsule", "purpose": "hop"\|"endpoint", "version": 1})` |
| Endpoint Signature (`Ed25519`) | `Ed25519::sign` / `verify_strict` over `canonical_json(signed_payload)` | Bound inside signed JSON: `domain="mcc-endpoint-message"`, `sender`, `recipient`, `context`, `copy_id`, `expected_copies`, `direction`, `phase`, `message_id`, `expires`, `body` |
| Reverse `B -> A` (`PRIV_BACK`) | `HKDF-SHA256(ikm = X25519(b_priv, a_pub), salt = context, info = b"priv-b-a-v1", len = 32)` | `priv-b-a:{context}` |
| Forward Continuation `A -> B` (`MCC_OPAQUE_FWD`) | `HKDF-SHA256(ikm = X25519(a_priv, b_pub), salt = context, info = b"mcc-a-b-forward-v1", len = 32)` | `mcc-a-b-fwd:{context}` |
| Forward Lookup Tag | `SHA-256(b"mcc-auth-forward-lookup-v1:" \|\| forward_key)` (32 bytes hex) | — |

### Wire Flow (`A -> X1 -> X2 -> B`)
1. `A -> X1` (`MCC_START`): batches (`<= 28 KiB` plaintext) containing `hop` capsules encrypted to candidate `X2` nodes, each wrapping an `endpoint` capsule encrypted to `B` containing the Ed25519-signed `IKE_SA_INIT`.
2. `X1 -> X2` (`MCC_X2`): `X1` selects `x2_fanout` next hops without opening `hop` or `endpoint` capsules and forwards selected branches.
3. `X2 -> B` (`MCC_OFFER`): `X2` opens its `hop` capsule, learns `dst = B`, and forwards `sealed_b` without being able to open the `endpoint` capsule.
4. `B`: verifies `endpoint` capsule + Ed25519 signature + SQLite ledger **before** admitting to selection (`first` / `window` / `adaptive` / `wait-all`). Reserves delivery, emits `LocalDeliveryProof`, injects into `charon`.
5. `B -> X2 -> X1 -> A` (`PRIV_BACK`): `B` encrypts signed `IKE_SA_INIT` response under `back_key` (`priv-b-a-v1`). `X1` issues an opaque `opaque_token` to `A` so `A` never learns `X2`.
6. `A -> X1 -> X2 -> B` (`MCC_OPAQUE_FWD`): `A` sends `IKE_AUTH` encrypted under `forward_key` (`mcc-a-b-forward-v1`) addressed by `opaque_token`; `X1` resolves `opaque_token -> (X2, conn_id)` and forwards.

Legacy sibling message types (`I1`, `I2`, `OKX2`, `PROXY_BLOB`, `PRIV_FWD`, `PRIV_DELIVER`, `PRIV_INLINE_*`, `MCC_ACCEPT`, `LOCAL_CONNECT`) are permanently closed and rejected.

---

## 6. Universal H-Hop Cascade (`cco-cascade::universal`)

Generalizes relay privacy to arbitrary hop depth `H >= 2`:
- **Messages:** `CASCADE_BUILD`, `CASCADE_REJECT`, `CASCADE_ABORT`, `CASCADE_PROBE`, `CASCADE_ACCEPT`, `CASCADE_DATA`, `CASCADE_BACK`, `CASCADE_CLOSE`.
- **Endpoint Capsule:** `HKDF-SHA256(salt = b"", info = b"universal-cascade-endpoint-v1")`, AAD `universal-cascade-endpoint-capsule-v1`.
- **Route Key:** `HKDF-SHA256(salt = route_tag_bytes, info = b"universal-cascade-route-v1")`, packet AAD `universal-cascade-data-v1:{route_tag}:{direction}:{sequence}`.
- Every intermediate `RelayCell` stores only `(previous_peer, incoming_handle, next_peer, outgoing_handle)`.

---

## 7. Control-Plane Protocol Parsers (`cco-proto`)

### IKEv2 (`ikev2.rs`)
- **UDP/500:** minimum 28 bytes, version byte `(b[17] >> 4) == 2`, declared length `u32::from_be_bytes(b[24..28]) == payload.len()`.
- **UDP/4500:** requires 4-byte Non-ESP Marker `00 00 00 00` followed by a valid 28+ byte IKEv2 header. Non-zero first 4 bytes represent ESP-in-UDP and are **strictly rejected** from entering the overlay.

### WireGuard (`wireguard.rs`)
- Accepts **only** control handshakes with zero reserved bytes `[0, 0, 0]`:
  - `type 1` (Handshake Initiation): exact `148` bytes
  - `type 2` (Handshake Response): exact `92` bytes
  - `type 3` (Cookie Reply): exact `64` bytes
- **Strictly rejects `type 4` (Transport Data):** user data must never enter the overlay.
