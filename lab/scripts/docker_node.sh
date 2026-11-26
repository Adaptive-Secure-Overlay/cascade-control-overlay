#!/usr/bin/env bash
# Entrypoint for a single Docker container node (relay or strongSwan endpoint).
set -euo pipefail

NODE_NAME="${1:?node name required}"
ROLE="${2:-relay}"
STATE_DIR="${STATE_DIR:-/state}"
OVERLAY_PORT="${OVERLAY_PORT:-9000}"

EXTRA_ARGS=()
if [[ "$ROLE" == "endpoint" ]]; then
  /opt/cco-lab/scripts/nft_apply.sh "$NODE_NAME" "$STATE_DIR/peers.json" "$OVERLAY_PORT" cco
  EXTRA_ARGS+=(--ike-proxy)
fi

exec cco node \
  --name "$NODE_NAME" \
  --peers "$STATE_DIR/peers.json" \
  --trust-registry "$STATE_DIR/trust-registry-v2.json" \
  --trust-root "$STATE_DIR/trust-root.json" \
  --trust-state "$STATE_DIR/db/${NODE_NAME}.state.json" \
  --trust-backup "$STATE_DIR/db/${NODE_NAME}.backup.json" \
  --signing-key "$STATE_DIR/keys/${NODE_NAME}/signing.key" \
  --encryption-key "$STATE_DIR/keys/${NODE_NAME}/encryption.key" \
  --replay-db "$STATE_DIR/db/${NODE_NAME}.sqlite" \
  --mode first \
  --x1-fanout 2 \
  --x2-fanout 2 \
  --ike-fanout 1 \
  "${EXTRA_ARGS[@]}"
