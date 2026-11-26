#!/usr/bin/env bash
# Parameterized wrapper applying nftables IKE-only capture rules and XFRM overlay bypass.
# Zero hard-coded lab IP addresses: every rule is rendered from the peers JSON directory.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <node-name> <peers.json> [overlay-port=9000] [cco-bin=cco]" >&2
  exit 2
fi

NODE_NAME="$1"
PEERS_JSON="$2"
OVERLAY_PORT="${3:-9000}"
CCO_BIN="${4:-cco}"

"$CCO_BIN" render-firewall --name "$NODE_NAME" --peers "$PEERS_JSON" --kind nft | bash
"$CCO_BIN" render-firewall --name "$NODE_NAME" --peers "$PEERS_JSON" --kind xfrm --overlay-port "$OVERLAY_PORT" | bash
