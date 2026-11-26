#!/usr/bin/env bash
# Fail-closed pcap audit for provider-plane observability:
#   1. Direct IKEv2 between endpoint A and endpoint B (UDP/500 or UDP/4500 Non-ESP) == 0
#   2. Multi-hop overlay UDP control traffic on overlay_port > 0
#   3. Direct IPsec ESP data traffic (proto 50 or ESP-in-UDP 4500 non-zero SPI) > 0
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <capture.pcap> <ip-a> <ip-b> [overlay-port=9000]" >&2
  exit 2
fi

PCAP="$1"
IP_A="$2"
IP_B="$3"
OVERLAY_PORT="${4:-9000}"

if [[ ! -r "$PCAP" ]]; then
  echo "ERROR: pcap not readable: $PCAP" >&2
  exit 1
fi

count_filter() {
  local expr="$1"
  tcpdump -nn -r "$PCAP" "$expr" 2>/dev/null | wc -l | tr -d '[:space:]'
}

PAIR="((src host $IP_A and dst host $IP_B) or (src host $IP_B and dst host $IP_A))"

DIRECT_IKE_500="$(count_filter "$PAIR and udp port 500")"
DIRECT_IKE_4500_NONESP="$(count_filter "$PAIR and udp port 4500 and udp[8:4] == 0")"
DIRECT_IKE_TOTAL=$((DIRECT_IKE_500 + DIRECT_IKE_4500_NONESP))

OVERLAY_UDP="$(count_filter "udp port $OVERLAY_PORT")"
DIRECT_ESP_NATIVE="$(count_filter "$PAIR and proto 50")"
DIRECT_ESP_UDP="$(count_filter "$PAIR and udp port 4500 and udp[8:4] != 0")"
DIRECT_ESP_TOTAL=$((DIRECT_ESP_NATIVE + DIRECT_ESP_UDP))

cat <<JSON
{
  "pcap": "$PCAP",
  "endpoint_a": "$IP_A",
  "endpoint_b": "$IP_B",
  "overlay_port": $OVERLAY_PORT,
  "direct_ike_udp500": $DIRECT_IKE_500,
  "direct_ike_udp4500_nonesp": $DIRECT_IKE_4500_NONESP,
  "direct_ike_total": $DIRECT_IKE_TOTAL,
  "overlay_udp_packets": $OVERLAY_UDP,
  "direct_esp_proto50": $DIRECT_ESP_NATIVE,
  "direct_esp_udp4500": $DIRECT_ESP_UDP,
  "direct_esp_total": $DIRECT_ESP_TOTAL
}
JSON

if [[ "$DIRECT_IKE_TOTAL" -ne 0 ]]; then
  echo "FAIL: direct IKEv2 leakage detected between $IP_A and $IP_B ($DIRECT_IKE_TOTAL packets)" >&2
  exit 1
fi
if [[ "$OVERLAY_UDP" -le 0 ]]; then
  echo "FAIL: no overlay UDP control traffic observed on port $OVERLAY_PORT" >&2
  exit 1
fi
if [[ "$DIRECT_ESP_TOTAL" -le 0 ]]; then
  echo "FAIL: no direct IPsec ESP traffic observed between $IP_A and $IP_B" >&2
  exit 1
fi

echo "PASS: direct_ike == 0, overlay_udp == $OVERLAY_UDP, direct_esp == $DIRECT_ESP_TOTAL"
