#!/usr/bin/env bash
# Level 3 (L3) Live Verification without EVE-NG or Docker:
# Spins up 5 isolated Linux network namespaces:
#   cco-isp (provider bridge cco-br0 with tcpdump capture)
#   cco-A   (192.0.2.10, tunnel 198.51.100.10/32) -- strongSwan charon + nftables + cco --ike-proxy
#   cco-X1  (192.0.2.11)                          -- cco relay node
#   cco-X2  (192.0.2.12)                          -- cco relay node
#   cco-B   (192.0.2.13, tunnel 198.51.100.13/32) -- strongSwan charon + nftables + cco --ike-proxy
#
# Proves on a real Linux kernel with real strongSwan + XFRM/ESP:
#   1. IKEv2 SA_INIT + IKE_AUTH traverse A -> X1 -> X2 -> B via encrypted MCC overlay (UDP/9000)
#   2. Direct IKEv2 packets between A and B on provider bridge == 0
#   3. IPsec CHILD_SA establishes and ICMP ping across tunnel succeeds 100% (5/5) via direct ESP
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: netns_e2e.sh requires root privileges (CAP_NET_ADMIN / CAP_NET_RAW)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CCO_BIN="${CCO_BIN:-$(command -v cco || true)}"
CHARON_BIN="${CHARON_BIN:-/usr/lib/ipsec/charon}"
OVERLAY_PORT="${OVERLAY_PORT:-9000}"
CCO_ROUTE_MODE="${CCO_ROUTE_MODE:-mcc2}"
CCO_HOPS="${CCO_HOPS:-3}"
CCO_MAX_HOPS="${CCO_MAX_HOPS:-16}"
CCO_HOP_MODEL="${CCO_HOP_MODEL:-f4}"
CCO_PARALLEL_CHAINS="${CCO_PARALLEL_CHAINS:-2}"

if [[ -z "$CCO_BIN" || ! -x "$CCO_BIN" ]]; then
  echo "ERROR: cco binary not found; build with 'cargo build --release -p cco-cli' and set CCO_BIN" >&2
  exit 1
fi
if [[ ! -x "$CHARON_BIN" ]]; then
  echo "ERROR: strongSwan charon not found at $CHARON_BIN" >&2
  exit 1
fi

for tool in ip nft tcpdump swanctl ping openssl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: required Linux tool not installed: $tool" >&2
    exit 1
  fi
done

WORKDIR="$(mktemp -d /tmp/cco-netns-lab.XXXXXX)"
PIDS=()

cleanup() {
  local rc=$?
  set +e
  if [[ "$rc" -ne 0 && -d "$WORKDIR/logs" ]]; then
    echo "=== netns_e2e.sh failed (exit=$rc); diagnostic logs ===" >&2
    for f in "$WORKDIR"/logs/*.stdout "$WORKDIR"/logs/*.log; do
      if [[ -s "$f" ]]; then
        echo "--- $(basename "$f") ---" >&2
        tail -n 30 "$f" >&2
      fi
    done
  fi
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  sleep 0.3
  for pid in "${PIDS[@]}"; do
    kill -9 "$pid" 2>/dev/null || true
  done
  for ns in cco-A cco-X1 cco-X2 cco-B cco-isp; do
    ip netns del "$ns" 2>/dev/null || true
  done
  if [[ "${KEEP_WORKDIR:-0}" != "1" ]]; then
    rm -rf "$WORKDIR"
  else
    echo "Preserved lab artifacts in $WORKDIR"
  fi
}
trap cleanup EXIT

echo "[1/7] Provisioning ephemeral Trust Registry v2 and RFC 5737 peer directory..."
mkdir -p "$WORKDIR/keys" "$WORKDIR/db" "$WORKDIR/logs"
"$CCO_BIN" trust-admin init-root \
  --issuer-id netns-lab-root \
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
  --issuer-id netns-lab-root \
  --version 1 \
  --output "$WORKDIR/trust-registry-v2.json" >/dev/null
rm -f "$WORKDIR/root.key"

cat >"$WORKDIR/peers.json" <<JSON
[
  {"name": "A",  "overlay_addr": "192.0.2.10:${OVERLAY_PORT}", "underlay_ip": "192.0.2.10"},
  {"name": "X1", "overlay_addr": "192.0.2.11:${OVERLAY_PORT}", "underlay_ip": "192.0.2.11"},
  {"name": "X2", "overlay_addr": "192.0.2.12:${OVERLAY_PORT}", "underlay_ip": "192.0.2.12"},
  {"name": "B",  "overlay_addr": "192.0.2.13:${OVERLAY_PORT}", "underlay_ip": "192.0.2.13"}
]
JSON

echo "[2/7] Creating isolated Linux network namespaces (cco-isp, cco-A, cco-X1, cco-X2, cco-B)..."
for ns in cco-isp cco-A cco-X1 cco-X2 cco-B; do
  ip netns del "$ns" 2>/dev/null || true
  ip netns add "$ns"
  ip netns exec "$ns" ip link set lo up
done

ip netns exec cco-isp ip link add cco-br0 type bridge
ip netns exec cco-isp ip link set cco-br0 up

attach_node() {
  local node="$1"
  local ip_addr="$2"
  local v_host="v-${node}"
  local v_br="b-${node}"
  ip link add "$v_host" type veth peer name "$v_br"
  ip link set "$v_host" netns "cco-${node}"
  ip link set "$v_br" netns cco-isp
  ip netns exec cco-isp ip link set "$v_br" master cco-br0
  ip netns exec cco-isp ip link set "$v_br" up
  ip netns exec "cco-${node}" ip addr add "${ip_addr}/24" dev "$v_host"
  ip netns exec "cco-${node}" ip link set "$v_host" up
}

attach_node A  192.0.2.10
attach_node X1 192.0.2.11
attach_node X2 192.0.2.12
attach_node B  192.0.2.13

# Dedicated RFC 5737 TEST-NET-2 loopback endpoints for tunnel-mode IPsec traffic
ip netns exec cco-A ip addr add 198.51.100.10/32 dev lo
ip netns exec cco-B ip addr add 198.51.100.13/32 dev lo
ip netns exec cco-A ip route add 198.51.100.13/32 via 192.0.2.13
ip netns exec cco-B ip route add 198.51.100.10/32 via 192.0.2.10

# Load esp4 kernel module if modula
modprobe esp4 2>/dev/null || true
modprobe xfrm_user 2>/dev/null || true

echo "[3/7] Starting provider-plane tcpdump on cco-isp/cco-br0..."
PCAP_FILE="$WORKDIR/provider.pcap"
ip netns exec cco-isp tcpdump -i cco-br0 -U -w "$PCAP_FILE" >/dev/null 2>"$WORKDIR/logs/tcpdump.log" &
TCPDUMP_PID=$!
PIDS+=("$TCPDUMP_PID")
sleep 0.5

echo "[4/7] Applying nftables IKE-only capture rules & XFRM bypass on endpoints A and B..."
ip netns exec cco-A "$SCRIPT_DIR/nft_apply.sh" A "$WORKDIR/peers.json" "$OVERLAY_PORT" "$CCO_BIN"
ip netns exec cco-B "$SCRIPT_DIR/nft_apply.sh" B "$WORKDIR/peers.json" "$OVERLAY_PORT" "$CCO_BIN"

echo "[5/7] Starting 4 authenticated cco overlay nodes (X1, X2 relays; A, B with --ike-proxy)..."
start_cco() {
  local node="$1"
  shift
  ip netns exec "cco-${node}" env RUST_LOG=info "$CCO_BIN" node \
    --name "$node" \
    --peers "$WORKDIR/peers.json" \
    --trust-registry "$WORKDIR/trust-registry-v2.json" \
    --trust-root "$WORKDIR/trust-root.json" \
    --trust-state "$WORKDIR/db/${node}.state.json" \
    --trust-backup "$WORKDIR/db/${node}.backup.json" \
    --signing-key "$WORKDIR/keys/${node}/signing.key" \
    --encryption-key "$WORKDIR/keys/${node}/encryption.key" \
    --replay-db "$WORKDIR/db/${node}.sqlite" \
    --route-mode "$CCO_ROUTE_MODE" \
    --hops "$CCO_HOPS" \
    --max-hops "$CCO_MAX_HOPS" \
    --hop-model "$CCO_HOP_MODEL" \
    --parallel-chains "$CCO_PARALLEL_CHAINS" \
    --mode first \
    --x1-fanout 2 \
    --x2-fanout 2 \
    --ike-fanout 1 \
    "$@" >"$WORKDIR/logs/cco-${node}.log" 2>&1 &
  PIDS+=("$!")
}

start_cco X1
start_cco X2
start_cco B --ike-proxy
start_cco A --ike-proxy
sleep 1.5

echo "[6/7] Starting isolated strongSwan charon daemons on A and B and initiating IKEv2..."
EPHEMERAL_PSK="$(openssl rand -hex 24)"

write_strongswan_cfg() {
  local node="$1"
  local local_ip="$2"
  local remote_ip="$3"
  local local_ts="$4"
  local remote_ts="$5"
  local local_id="$6"
  local remote_id="$7"

  cat >"$WORKDIR/strongswan-${node}.conf" <<CONF
charon {
  port = 500
  port_nat_t = 4500
  install_routes = no
  retransmit_tries = 6
  retransmit_timeout = 2.0
  filelog {
    lablog {
      path = ${WORKDIR}/logs/charon-${node}.log
      default = 1
      ike = 2
      net = 2
      flush_line = yes
    }
  }
  plugins {
    stroke {
      load = no
    }
    vici {
      load = yes
      socket = unix://${WORKDIR}/charon-${node}.vici
    }
  }
}
CONF

  (
    umask 077
    cat >"$WORKDIR/swanctl-${node}.conf" <<SWAN
connections {
  overlay-ike {
    version = 2
    local_addrs = ${local_ip}
    remote_addrs = ${remote_ip}
    encap = no
    mobike = no
    proposals = aes256-sha256-modp2048
    local {
      auth = psk
      id = ${local_id}
    }
    remote {
      auth = psk
      id = ${remote_id}
    }
    children {
      tunnel {
        local_ts = ${local_ts}
        remote_ts = ${remote_ts}
        esp_proposals = aes256-sha256
        mode = tunnel
      }
    }
  }
}
secrets {
  ike-lab {
    id-1 = ${local_id}
    id-2 = ${remote_id}
    secret = "${EPHEMERAL_PSK}"
  }
}
SWAN
  )
}

write_strongswan_cfg A 192.0.2.10 192.0.2.13 198.51.100.10/32 198.51.100.13/32 node-a.example node-b.example
write_strongswan_cfg B 192.0.2.13 192.0.2.10 198.51.100.13/32 198.51.100.10/32 node-b.example node-a.example

mkdir -p "$WORKDIR/run-A" "$WORKDIR/run-B"
ip netns exec cco-B unshare --mount --propagation private bash -c \
  "mount --bind '$WORKDIR/run-B' /run && exec env STRONGSWAN_CONF='$WORKDIR/strongswan-B.conf' '$CHARON_BIN'" \
  >"$WORKDIR/logs/charon-B.stdout" 2>&1 &
PIDS+=("$!")
ip netns exec cco-A unshare --mount --propagation private bash -c \
  "mount --bind '$WORKDIR/run-A' /run && exec env STRONGSWAN_CONF='$WORKDIR/strongswan-A.conf' '$CHARON_BIN'" \
  >"$WORKDIR/logs/charon-A.stdout" 2>&1 &
PIDS+=("$!")

for node in B A; do
  for _ in $(seq 1 30); do
    if [[ -S "$WORKDIR/charon-${node}.vici" ]]; then
      break
    fi
    sleep 0.2
  done
  ip netns exec "cco-${node}" env STRONGSWAN_CONF="$WORKDIR/strongswan-${node}.conf" \
    swanctl --load-all --uri "unix://${WORKDIR}/charon-${node}.vici" --file "$WORKDIR/swanctl-${node}.conf"
done

echo "Initiating IKEv2 SA_INIT + IKE_AUTH from A to B (must traverse overlay, never direct)..."
ip netns exec cco-A env STRONGSWAN_CONF="$WORKDIR/strongswan-A.conf" \
  swanctl --initiate --uri "unix://${WORKDIR}/charon-A.vici" --child tunnel --timeout 15

echo "Verifying IPsec XFRM states and running 5 ICMP probes through the direct ESP tunnel..."
ip netns exec cco-A ip xfrm state | grep -E "proto esp|src 192.0.2." || true
ip netns exec cco-A ping -c 5 -i 0.2 -W 2 -I 198.51.100.10 198.51.100.13

sleep 0.5
kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "[7/7] Auditing provider bridge pcap for zero direct IKEv2 leakage and live ESP traffic..."
"$SCRIPT_DIR/verify_no_direct_ike.sh" "$PCAP_FILE" 192.0.2.10 192.0.2.13 "$OVERLAY_PORT"
