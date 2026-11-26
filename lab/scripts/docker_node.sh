#!/usr/bin/env bash
# Entrypoint for a single Docker container node (relay or strongSwan endpoint).
set -euo pipefail

NODE_NAME="${1:?node name required}"
ROLE="${2:-relay}"
STATE_DIR="${STATE_DIR:-/state}"
OVERLAY_PORT="${OVERLAY_PORT:-9000}"
CCO_ROUTE_MODE="${CCO_ROUTE_MODE:-mcc2}"
CCO_HOPS="${CCO_HOPS:-3}"
CCO_MAX_HOPS="${CCO_MAX_HOPS:-16}"
CCO_HOP_MODEL="${CCO_HOP_MODEL:-f4}"
CCO_PARALLEL_CHAINS="${CCO_PARALLEL_CHAINS:-2}"

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
  --route-mode "$CCO_ROUTE_MODE" \
  --hops "$CCO_HOPS" \
  --max-hops "$CCO_MAX_HOPS" \
  --hop-model "$CCO_HOP_MODEL" \
  --parallel-chains "$CCO_PARALLEL_CHAINS" \
  --mode first \
  --x1-fanout 2 \
  --x2-fanout 2 \
  --ike-fanout 1 \
  "${EXTRA_ARGS[@]}"
