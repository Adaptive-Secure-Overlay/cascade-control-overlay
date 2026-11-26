#!/usr/bin/env bash
# Provision ephemeral Trust Registry v2 + peers.json + ephemeral strongSwan PSK for Docker lab.
set -euo pipefail

STATE_DIR="${STATE_DIR:-/state}"
OVERLAY_PORT="${OVERLAY_PORT:-9000}"

rm -rf "${STATE_DIR:?}"/*
mkdir -p "$STATE_DIR/keys" "$STATE_DIR/db"

cco trust-admin init-root \
  --issuer-id lab-root \
  --key-out "$STATE_DIR/root.key" \
  --root-out "$STATE_DIR/trust-root.json" >/dev/null

for node in A X1 X2 B; do
  cco trust-admin keygen --node "$node" --directory "$STATE_DIR/keys/$node" >/dev/null
done

cco trust-admin sign-registry \
  --entries "$STATE_DIR/keys/A/public-entry.json" \
            "$STATE_DIR/keys/X1/public-entry.json" \
            "$STATE_DIR/keys/X2/public-entry.json" \
            "$STATE_DIR/keys/B/public-entry.json" \
  --trust-root "$STATE_DIR/trust-root.json" \
  --issuer-key "$STATE_DIR/root.key" \
  --issuer-id lab-root \
  --version 1 \
  --output "$STATE_DIR/trust-registry-v2.json" >/dev/null

rm -f "$STATE_DIR/root.key"

cat >"$STATE_DIR/peers.json" <<JSON
[
  {"name": "A",  "overlay_addr": "192.0.2.10:${OVERLAY_PORT}", "underlay_ip": "192.0.2.10"},
  {"name": "X1", "overlay_addr": "192.0.2.11:${OVERLAY_PORT}", "underlay_ip": "192.0.2.11"},
  {"name": "X2", "overlay_addr": "192.0.2.12:${OVERLAY_PORT}", "underlay_ip": "192.0.2.12"},
  {"name": "B",  "overlay_addr": "192.0.2.13:${OVERLAY_PORT}", "underlay_ip": "192.0.2.13"}
]
JSON

umask 077
openssl rand -hex 24 >"$STATE_DIR/ephemeral.psk"
echo "Provisioned Trust Registry v2 and RFC 5737 peers in $STATE_DIR"
