#!/bin/sh
# Эталон командной строки nfqws2: _startup_args (lib/common.sh:537) оригинала для каждого
# пресета × режим списков × BLOCK_QUIC × CALLS_BYPASS × ipset. Пишет args.jsonl.
set -eu
. "$(dirname "$0")/common.sh"
OUT="$HERE/args.jsonl"; : > "$OUT"
for f in "$PRESETS"/*.conf; do
  name=$(basename "$f" .conf)
  for mode in list all auto; do for bq in 0 1; do for calls in 0 1; do for ips in 0 1; do
    (
      set +eu  # код оригинала не рассчитан на nounset/errexit
      DATA=$(mktemp -d)
      export MODDIR="$UP" CONFDIR="$DATA"
      . "$UP/lib/common.sh"
      mkdir -p "$LISTS_DIR" "$LOG_DIR"
      if [ "$ips" = 1 ]; then echo 1.1.1.1 > "$LISTS_DIR/ipset.list"; else : > "$LISTS_DIR/ipset.list"; fi
      set_defaults >/dev/null 2>&1 || true
      . "$f" >/dev/null 2>&1
      case "$mode" in
        list) NFQWS_EXTRA_ARGS="$MODE_LIST" ;;
        all)  NFQWS_EXTRA_ARGS="$MODE_ALL" ;;
        auto) NFQWS_EXTRA_ARGS="$MODE_AUTO" ;;
      esac
      BLOCK_QUIC=$bq CALLS_BYPASS=$calls LOG_LEVEL=0 NFQUEUE_NUM=300 NFQWS_USER=root ISP_INTERFACE=""
      args=$(_startup_args | sed "s#$UP#<MOD>#g; s#$DATA#<DATA>#g")
      arr=""
      for a in $args; do arr="$arr${arr:+,}$(json_str "$a")"; done
      printf '{"preset":"%s","mode":"%s","block_quic":%s,"calls":%s,"ipset":%s,"args":[%s]}\n' \
        "$name" "$mode" "$bq" "$calls" "$ips" "$arr"
      rm -rf "$DATA"
    ) >> "$OUT"
  done; done; done; done
done
wc -l < "$OUT"
