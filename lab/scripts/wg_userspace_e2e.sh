#!/usr/bin/env bash
# Level 3 (L3) Live Verification for Userspace WireGuard (boringtun) + MCC Overlay:
# Spins up 5 isolated Linux network namespaces:
#   cco-wg-isp (provider bridge cco-wg-br0 with tcpdump capture)
#   cco-wg-A   (192.0.2.10, TUN cco0 198.51.100.10/24) -- cco wg-tunnel (initiator)
#   cco-wg-X1  (192.0.2.11)                            -- cco relay node
#   cco-wg-X2  (192.0.2.12)                            -- cco relay node
#   cco-wg-B   (192.0.2.13, TUN cco0 198.51.100.13/24) -- cco wg-tunnel (responder)
#
# Proves on a real Linux kernel with real /dev/net/tun + tcpdump:
#   1. WireGuard Type 1/2/3 handshakes traverse ONLY MCC overlay (UDP/9000)
#   2. Direct WireGuard control packets between A and B on provider bridge == 0
#   3. Direct WireGuard Type 4 transport data between A and B >= 10 (5 ICMP echo pairs)
#   4. ICMP ping across userspace WireGuard tunnel succeeds 100% (5/5)
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: wg_userspace_e2e.sh requires root privileges (CAP_NET_ADMIN)" >&2
  exit 1
fi

CCO_BIN="${CCO_BIN:-$(command -v cco || true)}"
OVERLAY_PORT="${OVERLAY_PORT:-9000}"
WG_DIRECT_PORT="${WG_DIRECT_PORT:-51820}"

if [[ -z "$CCO_BIN" || ! -x "$CCO_BIN" ]]; then
  echo "ERROR: cco binary not found; build with 'cargo build --release -p cco-cli' and set CCO_BIN" >&2
  exit 1
fi

for tool in ip tcpdump ping; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: required Linux tool not installed: $tool" >&2
    exit 1
  fi
done

if [[ ! -c /dev/net/tun ]]; then
  echo "ERROR: /dev/net/tun device is not available" >&2
  exit 1
fi

WORKDIR="$(mktemp -d /tmp/cco-wg-netns-lab.XXXXXX)"
PIDS=()

cleanup() {
  set +e
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  sleep 0.4
  for pid in "${PIDS[@]}"; do
    kill -9 "$pid" 2>/dev/null || true
  done
  for ns in cco-wg-A cco-wg-X1 cco-wg-X2 cco-wg-B cco-wg-isp; do
    ip netns del "$ns" 2>/dev/null || true
  done
  if [[ "${KEEP_WORKDIR:-0}" != "1" ]]; then
    rm -rf "$WORKDIR"
  else
    echo "Preserved lab artifacts in $WORKDIR"
  fi
}
trap cleanup EXIT

echo "[1/7] Provisioning Trust Registry v2, RFC 5737 peers, and WireGuard X25519 keys..."
mkdir -p "$WORKDIR/keys" "$WORKDIR/db" "$WORKDIR/logs"
"$CCO_BIN" trust-admin init-root \
  --issuer-id wg-netns-root \
  --key-out "$WORKDIR/root.key" \
  --root-out "$WORKDIR/trust-root.json" >/dev/null

for node in A X1 X2 B; do
  "$CCO_BIN" trust-admin keygen --node "$node" --directory "$WORKDIR/keys/$node" >/dev/null
done

"$CCO_BIN" trust-admin sign-registry \
  --entries "$WORKDIR/keys/A/public-entry.json" \
            "$WORKDIR/keys/X1/public-entry.json" \
            "$WORKDIR/keys/X2/public-entry.json" \
            "$WORKDIR/keys/B/public-entry.json" \
  --trust-root "$WORKDIR/trust-root.json" \
  --issuer-key "$WORKDIR/root.key" \
  --issuer-id wg-netns-root \
  --version 1 \
  --output "$WORKDIR/trust-registry-v2.json" >/dev/null
rm -f "$WORKDIR/root.key"

WG_PUB_A="$("$CCO_BIN" wg-keygen --key-out "$WORKDIR/keys/wg-A.key" | sed -n 's/.*"public_key_hex":"\([0-9a-f]*\)".*/\1/p')"
WG_PUB_B="$("$CCO_BIN" wg-keygen --key-out "$WORKDIR/keys/wg-B.key" | sed -n 's/.*"public_key_hex":"\([0-9a-f]*\)".*/\1/p')"

cat >"$WORKDIR/peers.json" <<JSON
[
  {"name": "A",  "overlay_addr": "192.0.2.10:${OVERLAY_PORT}", "underlay_ip": "192.0.2.10"},
  {"name": "X1", "overlay_addr": "192.0.2.11:${OVERLAY_PORT}", "underlay_ip": "192.0.2.11"},
  {"name": "X2", "overlay_addr": "192.0.2.12:${OVERLAY_PORT}", "underlay_ip": "192.0.2.12"},
  {"name": "B",  "overlay_addr": "192.0.2.13:${OVERLAY_PORT}", "underlay_ip": "192.0.2.13"}
]
JSON

echo "[2/7] Creating isolated Linux network namespaces (cco-wg-isp, A, X1, X2, B)..."
for ns in cco-wg-isp cco-wg-A cco-wg-X1 cco-wg-X2 cco-wg-B; do
  ip netns del "$ns" 2>/dev/null || true
  ip netns add "$ns"
  ip netns exec "$ns" ip link set lo up
done

ip netns exec cco-wg-isp ip link add cco-wg-br0 type bridge
ip netns exec cco-wg-isp ip link set cco-wg-br0 up

attach_node() {
  local node="$1"
  local ip_addr="$2"
  local v_host="vw-${node}"
  local v_br="bw-${node}"
  ip link add "$v_host" type veth peer name "$v_br"
  ip link set "$v_host" netns "cco-wg-${node}"
  ip link set "$v_br" netns cco-wg-isp
  ip netns exec cco-wg-isp ip link set "$v_br" master cco-wg-br0
  ip netns exec cco-wg-isp ip link set "$v_br" up
  ip netns exec "cco-wg-${node}" ip addr add "${ip_addr}/24" dev "$v_host"
  ip netns exec "cco-wg-${node}" ip link set "$v_host" up
}

attach_node A  192.0.2.10
attach_node X1 192.0.2.11
attach_node X2 192.0.2.12
attach_node B  192.0.2.13

echo "[3/7] Starting provider-plane tcpdump on cco-wg-isp/cco-wg-br0..."
PCAP_FILE="$WORKDIR/wg_provider.pcap"
ip netns exec cco-wg-isp tcpdump -i cco-wg-br0 -U -w "$PCAP_FILE" >/dev/null 2>"$WORKDIR/logs/tcpdump.log" &
TCPDUMP_PID=$!
PIDS+=("$TCPDUMP_PID")
sleep 0.5

echo "[4/7] Starting MCC relay nodes X1 and X2..."
for relay in X1 X2; do
  ip netns exec "cco-wg-${relay}" env RUST_LOG=info "$CCO_BIN" node \
    --name "$relay" \
    --peers "$WORKDIR/peers.json" \
    --trust-registry "$WORKDIR/trust-registry-v2.json" \
    --trust-root "$WORKDIR/trust-root.json" \
    --trust-state "$WORKDIR/db/${relay}.state.json" \
    --trust-backup "$WORKDIR/db/${relay}.backup.json" \
    --signing-key "$WORKDIR/keys/${relay}/signing.key" \
    --encryption-key "$WORKDIR/keys/${relay}/encryption.key" \
    --replay-db "$WORKDIR/db/${relay}.sqlite" \
    --mode first --x1-fanout 2 --x2-fanout 2 --ike-fanout 1 \
    >"$WORKDIR/logs/cco-${relay}.log" 2>&1 &
  PIDS+=("$!")
done

echo "[5/7] Starting userspace WireGuard split tunnels on B and A (TUN cco0)..."
ip netns exec cco-wg-B env RUST_LOG=info "$CCO_BIN" wg-tunnel \
  --name B --peer A \
  --peers "$WORKDIR/peers.json" \
  --trust-registry "$WORKDIR/trust-registry-v2.json" \
  --trust-root "$WORKDIR/trust-root.json" \
  --trust-state "$WORKDIR/db/B.state.json" \
  --trust-backup "$WORKDIR/db/B.backup.json" \
  --signing-key "$WORKDIR/keys/B/signing.key" \
  --encryption-key "$WORKDIR/keys/B/encryption.key" \
  --replay-db "$WORKDIR/db/B.sqlite" \
  --wg-private-key "$WORKDIR/keys/wg-B.key" \
  --peer-wg-public-key "$WG_PUB_A" \
  --direct-bind "192.0.2.13:${WG_DIRECT_PORT}" \
  --peer-direct-addr "192.0.2.10:${WG_DIRECT_PORT}" \
  --tun-name cco0 \
  --mode first --x1-fanout 2 --x2-fanout 2 --ike-fanout 1 \
  --stats-out "$WORKDIR/stats-B.json" \
  >"$WORKDIR/logs/cco-B.log" 2>&1 &
PIDS+=("$!")

ip netns exec cco-wg-A env RUST_LOG=info "$CCO_BIN" wg-tunnel \
  --name A --peer B \
  --peers "$WORKDIR/peers.json" \
  --trust-registry "$WORKDIR/trust-registry-v2.json" \
  --trust-root "$WORKDIR/trust-root.json" \
  --trust-state "$WORKDIR/db/A.state.json" \
  --trust-backup "$WORKDIR/db/A.backup.json" \
  --signing-key "$WORKDIR/keys/A/signing.key" \
  --encryption-key "$WORKDIR/keys/A/encryption.key" \
  --replay-db "$WORKDIR/db/A.sqlite" \
  --wg-private-key "$WORKDIR/keys/wg-A.key" \
  --peer-wg-public-key "$WG_PUB_B" \
  --direct-bind "192.0.2.10:${WG_DIRECT_PORT}" \
  --peer-direct-addr "192.0.2.13:${WG_DIRECT_PORT}" \
  --tun-name cco0 \
  --mode first --x1-fanout 2 --x2-fanout 2 --ike-fanout 1 \
  --initiate \
  --stats-out "$WORKDIR/stats-A.json" \
  >"$WORKDIR/logs/cco-A.log" 2>&1 &
PIDS+=("$!")

for pair in "A:198.51.100.10/24" "B:198.51.100.13/24"; do
  node="${pair%%:*}"
  cidr="${pair#*:}"
  for _ in $(seq 1 40); do
    if ip netns exec "cco-wg-${node}" ip link show cco0 >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  ip netns exec "cco-wg-${node}" ip addr add "$cidr" dev cco0
  ip netns exec "cco-wg-${node}" ip link set cco0 mtu 1420 up
done

echo "[6/7] Waiting for MCC WireGuard handshake and running 5 ICMP probes through direct Type 4..."
sleep 1.5
ip netns exec cco-wg-A ping -c 5 -i 0.2 -W 2 198.51.100.13

sleep 0.6
kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "[7/7] Auditing provider bridge pcap for zero direct WG type 1/2/3 and live direct WG type 4..."
count_filter() {
  tcpdump -nn -r "$PCAP_FILE" "$1" 2>/dev/null | wc -l | tr -d '[:space:]'
}

PAIR="((src host 192.0.2.10 and dst host 192.0.2.13) or (src host 192.0.2.13 and dst host 192.0.2.10))"
DIRECT_WG_T1="$(count_filter "$PAIR and udp port $WG_DIRECT_PORT and udp[8:4] == 0x01000000")"
DIRECT_WG_T2="$(count_filter "$PAIR and udp port $WG_DIRECT_PORT and udp[8:4] == 0x02000000")"
DIRECT_WG_T3="$(count_filter "$PAIR and udp port $WG_DIRECT_PORT and udp[8:4] == 0x03000000")"
DIRECT_WG_CTRL=$((DIRECT_WG_T1 + DIRECT_WG_T2 + DIRECT_WG_T3))
DIRECT_WG_T4="$(count_filter "$PAIR and udp port $WG_DIRECT_PORT and udp[8:4] == 0x04000000")"
OVERLAY_UDP="$(count_filter "udp port $OVERLAY_PORT")"

cat <<JSON
{
  "pcap": "$PCAP_FILE",
  "direct_wg_type1": $DIRECT_WG_T1,
  "direct_wg_type2": $DIRECT_WG_T2,
  "direct_wg_type3": $DIRECT_WG_T3,
  "direct_wg_control_total": $DIRECT_WG_CTRL,
  "direct_wg_type4_data": $DIRECT_WG_T4,
  "overlay_udp_packets": $OVERLAY_UDP
}
JSON

if [[ -f "$WORKDIR/stats-A.json" ]]; then
  echo "--- Endpoint A TunnelStats ---"
  cat "$WORKDIR/stats-A.json"
  echo ""
fi

if [[ "$DIRECT_WG_CTRL" -ne 0 ]]; then
  echo "FAIL: direct WireGuard control packets leaked between A and B ($DIRECT_WG_CTRL)" >&2
  exit 1
fi
if [[ "$OVERLAY_UDP" -le 0 ]]; then
  echo "FAIL: no overlay UDP control traffic observed on port $OVERLAY_PORT" >&2
  exit 1
fi
if [[ "$DIRECT_WG_T4" -lt 10 ]]; then
  echo "FAIL: expected >= 10 direct WireGuard Type 4 data packets, got $DIRECT_WG_T4" >&2
  exit 1
fi

echo "PASS: direct_wg_control == 0, overlay_udp == $OVERLAY_UDP, direct_wg_type4 == $DIRECT_WG_T4"
