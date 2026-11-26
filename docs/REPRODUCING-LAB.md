# Reproducing the Verification Lab (L1–L4)

This project avoids multi-gigabyte VM images by using a four-level verification pyramid. Every level runs deterministically from this repository.

---

## Level 1 — Unit, Crypto Golden Vectors, Security Matrix & Analytics (Any OS)

Runs on Windows, Linux, and macOS without root privileges or network interfaces:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

What is verified:
- `cco-crypto/tests/golden_vectors.rs`: byte-exact match of X25519, MGMT HKDF, MCC forward/capsule AEAD, and UniversalCascade KDF against Python reference vectors.
- `cco-trust/tests/security_matrix.rs`: 12 negative/positive security tests + byte-exact Trust Registry v2 golden vector.
- `cco-cascade/tests/{mcc_suite,universal_cascade_suite,wireguard_suite}.rs`: 9/27/64-copy MCC, forged offers, SQLite restart replay protection, `Rejected` failover vs `Unknown` non-retry, H=2..5 UniversalCascade, and 27 WireGuard scenarios.
- `cco-analytics/tests/analytics_suite.rs`: exact match to all 18 Chapter 3 control values, `n50` thresholds, and 2.4M-route `rayon` Monte Carlo verification.

---

## Level 2 — Localhost Multi-Node UDP E2E & Live Rust↔Python Cross-Compat (Any OS)

```bash
# Ensure Python 3 with `cryptography` is available for the Rust<->Python wire test:
python3 -m pip install cryptography
cargo test -p cco-transport --test e2e_udp -- --nocapture
```

Runs:
1. 4-node localhost UDP MCC with `preconnect=false` (lazy session establishment).
2. 10-node localhost UDP mesh with 5 concurrent IKEv2 routes × 9 copies in `adaptive` mode (20/20 deliveries).
3. Live Rust `OverlayNode` talking 4-step `MGMT` + `>2000 B` `LINK_FRAG` over real UDP sockets to a live Python peer.

---

## Level 3 — Lightweight Linux `strongSwan` + `nftables` + `tcpdump` Live Lab (~200 MB)

### Option A: Native Linux or WSL2 (`ip netns`, Zero Docker Overhead)

Requirements on Ubuntu/Debian (or WSL2 `Ubuntu-22.04` with Linux kernel `6.x` supporting `XFRM`, `esp4`, `nftables`):

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  strongswan strongswan-swanctl strongswan-charon \
  nftables iproute2 tcpdump iputils-ping openssl

cargo build --release -p cco-cli
sudo CCO_BIN="$PWD/target/release/cco" bash lab/scripts/netns_e2e.sh
```

Expected final output:
```text
PASS: direct_ike == 0, overlay_udp == <N>, direct_esp == 10
```

Set `KEEP_WORKDIR=1` to inspect generated `provider.pcap`, `charon-A.log`, `charon-B.log`, and `cco-*.log` after the run.

### Option B: Multi-Stage Docker Compose (~200 MB Runtime Image)

```bash
docker compose -f lab/docker-compose.yml up --build
```

The `provisioner` container generates ephemeral Trust Registry v2 keys and an RFC 5737 `peers.json` (`192.0.2.10..13`) on startup; `node-a`, `node-x1`, `node-x2`, and `node-b` then boot with `CAP_NET_ADMIN` / `CAP_NET_RAW`.

---

## Level 4 — Optional Drop-In Static Linux Binary for Existing EVE-NG Topologies

If you already operate a routed lab topology (e.g., EVE-NG / GNS3 / Linux VMs) and want to drop in `cco` without Python dependencies:

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools
cargo build --release --target x86_64-unknown-linux-musl -p cco-cli
strip target/x86_64-unknown-linux-musl/release/cco
```

On each node:
1. Provision Trust Registry v2 offline with `cco trust-admin init-root`, `keygen`, and `sign-registry`.
2. Render and apply per-node firewall/XFRM bypass rules from your topology's `peers.json`:
   ```bash
   sudo ./lab/scripts/nft_apply.sh <NODE_NAME> /etc/cco/peers.json 9000 /usr/local/bin/cco
   ```
3. Launch `cco node --name <NODE_NAME> --peers /etc/cco/peers.json --trust-registry ... --trust-root ... --signing-key ... --encryption-key ... --replay-db ... --ike-proxy` (omit `--ike-proxy` on relay-only nodes).
4. Audit the provider-plane pcap with `./lab/scripts/verify_no_direct_ike.sh <capture.pcap> <IP_A> <IP_B> 9000`.
