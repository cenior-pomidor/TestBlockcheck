#!/bin/sh
# Ссылки пресетов разрешаются в файлы модуля; состав пресетов — 28 без smart.
set -u
M=$(cd "$(dirname "$0")/.." && pwd)
fail=0
err() { echo "FAIL: $*" >&2; fail=1; }

n=$(ls "$M"/strategies/*.conf 2>/dev/null | wc -l)
[ "$n" -eq 28 ] || err "пресетов $n, ожидалось 28"
[ ! -e "$M/strategies/smart.conf" ] || err "smart.conf не должен быть в модуле"

for f in "$M"/strategies/*.conf; do
  [ -f "$f" ] || continue
  name=$(basename "$f" .conf)
  grep -q "^$name	" "$M/strategies/meta.tsv" 2>/dev/null || err "нет строки meta.tsv для $name"
  for b in $(grep -o '\$BLOBS_DIR/[A-Za-z0-9_.-]*' "$f" | sed 's#.*/##' | sort -u); do
    [ -f "$M/blobs/$b" ] || err "$name: нет blobs/$b"
  done
  for l in $(grep -o '\$LISTS_DIR/[A-Za-z0-9_.-]*' "$f" | sed 's#.*/##' | sort -u); do
    [ -f "$M/lists/$l" ] || [ -f "$M/defaults/lists/$l" ] || err "$name: нет lists/$l"
  done
done
for b in stun.bin tls_clienthello.bin; do [ -f "$M/blobs/$b" ] || err "нет blobs/$b для обхода звонков"; done
[ -f "$M/defaults/calls-bypass.conf" ] || err "нет defaults/calls-bypass.conf"
for l in user auto exclude ipset ipset_exclude; do
  [ -f "$M/defaults/lists/$l.list" ] || err "нет defaults/lists/$l.list"
done
[ -f "$M/NOTICE.md" ] || err "нет NOTICE.md"
[ "$fail" -eq 0 ] && echo "test_refs: ok"
exit $fail
