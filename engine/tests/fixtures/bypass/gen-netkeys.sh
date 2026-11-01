#!/bin/sh
# Эталон ключей сети: current_network_key (lib/common.sh:2263) оригинала. Пишет netkeys.jsonl.
set -eu
. "$(dirname "$0")/common.sh"
OUT="$HERE/netkeys.jsonl"; : > "$OUT"
one() { # <raw как у _raw_network_id>
  (
    set +eu
    export MODDIR="$UP" CONFDIR="$(mktemp -d)"
    . "$UP/lib/common.sh"
    RAW="$1"
    _raw_network_id() { printf '%s' "$RAW"; }
    printf '{"raw":%s,"key":%s}\n' "$(json_str "$RAW")" "$(json_str "$(current_network_key)")"
  ) >> "$OUT"
}
for r in 'wifi:Home' 'wifi:Мой дом' 'wifi:a"b c' 'wifi:Café ☕' 'wifi:net-5G_x.y' 'cell:MegaFon' 'cell:MTS RUS' 'cellular'; do
  one "$r"
done
cat "$OUT"
