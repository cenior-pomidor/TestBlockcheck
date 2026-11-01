#!/bin/sh
# Эталон портов перехвата: фрагмент _firewall_start (lib/common.sh:1453–1474) на функциях
# оригинала. Пишет ports.jsonl рядом с собой.
set -eu
. "$(dirname "$0")/common.sh"
OUT="$HERE/ports.jsonl"; : > "$OUT"
for f in "$PRESETS"/*.conf; do
  name=$(basename "$f" .conf)
  for auto in 0 1; do for bq in 0 1; do for calls in 0 1; do
    (
      set +eu  # код оригинала не рассчитан на nounset/errexit
      export MODDIR="$UP" CONFDIR="$(mktemp -d)"
      . "$UP/lib/common.sh"
      set_defaults >/dev/null 2>&1 || true
      . "$f" >/dev/null 2>&1
      AUTO_PORTS=$auto BLOCK_QUIC=$bq CALLS_BYPASS=$calls
      TCP_PORTS=80,443,1984,2053,2083,2087,2096,5222,8443
      UDP_PORTS=443,590:600,1400,3478:3481,5349,19294:19344,49152:65535
      if [ "$AUTO_PORTS" = 1 ]; then t=$(collect_capture_ports tcp); IPT_TCP_PORTS="${t:-80,443}"
      else IPT_TCP_PORTS=$(printf '%s' "$TCP_PORTS" | tr '-' ':'); fi
      if [ "$AUTO_PORTS" = 1 ]; then IPT_UDP_EFF=$(collect_capture_ports udp)
      else IPT_UDP_EFF=$(printf '%s' "$UDP_PORTS" | tr '-' ':'); fi
      [ "$BLOCK_QUIC" = 1 ] && IPT_UDP_EFF=$(port_list_without "$IPT_UDP_EFF" 443)
      if [ "$CALLS_BYPASS" = 1 ]; then
        IPT_UDP_EFF=$(port_list_add "$IPT_UDP_EFF" 590:1400 3478:3482)
        IPT_TCP_PORTS=$(port_list_add "$IPT_TCP_PORTS" 5222)
      fi
      printf '{"preset":"%s","auto_ports":%s,"block_quic":%s,"calls":%s,"tcp":%s,"udp":%s}\n' \
        "$name" "$auto" "$bq" "$calls" "$(json_str "$IPT_TCP_PORTS")" "$(json_str "$IPT_UDP_EFF")"
      rm -rf "$CONFDIR"
    ) >> "$OUT"
  done; done; done
done
wc -l < "$OUT"
