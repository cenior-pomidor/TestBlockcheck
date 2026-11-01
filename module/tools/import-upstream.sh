#!/bin/sh
# Перенос пресетов, списков и блобов из nfqws2-android v2.0.4 (MIT) в module/.
# Использование: import-upstream.sh <клон dea1hwatcher/nfqws2-android>
set -eu
SRC=${1:?нужен путь к клону nfqws2-android}
COMMIT=8e916c8
M=$(cd "$(dirname "$0")/.." && pwd)
head=$(git -C "$SRC" rev-parse HEAD)
case "$head" in "$COMMIT"*) ;; *) echo "клон на $head, нужен $COMMIT" >&2; exit 1 ;; esac

mkdir -p "$M/strategies" "$M/defaults/lists" "$M/lists" "$M/blobs"
for f in "$SRC"/strategies/*.conf; do
  [ "$(basename "$f")" = smart.conf ] && continue
  cp "$f" "$M/strategies/"
done
# Пресет «default» в оригинале — его defaults/nfqws2.conf.
cp "$SRC/defaults/nfqws2.conf" "$M/strategies/default.conf"
grep -v '^smart	' "$SRC/strategies/meta.tsv" > "$M/strategies/meta.tsv"
for l in user auto exclude ipset ipset_exclude; do cp "$SRC/defaults/lists/$l.list" "$M/defaults/lists/"; done
cp "$SRC/defaults/calls-bypass.conf" "$M/defaults/"
cp "$SRC/LICENSE" "$M/LICENSE.upstream"

refs() { grep -ho "\\\$$1/[A-Za-z0-9_.-]*" "$M"/strategies/*.conf | sed 's#.*/##' | sort -u; }
for l in $(refs LISTS_DIR); do
  [ -f "$M/defaults/lists/$l" ] && continue
  cp "$SRC/lists/$l" "$M/lists/"
done
for b in $(refs BLOBS_DIR) stun.bin tls_clienthello.bin; do cp "$SRC/blobs/$b" "$M/blobs/"; done

{
  echo "# Откуда взяты файлы модуля"
  echo
  echo "Источник: [nfqws2-android](https://github.com/dea1hwatcher/nfqws2-android) v2.0.4, коммит \`$COMMIT\`,"
  echo "лицензия MIT (\`LICENSE.upstream\`, автор deathwatcher). Перенесено скриптом \`tools/import-upstream.sh\` без изменений."
  echo
  echo "| Файлы | Источник | Автор | Лицензия |"
  echo "|---|---|---|---|"
  echo "| \`defaults/lists/*\`, \`defaults/calls-bypass.conf\`, \`lists/*\`, \`blobs/*\` | nfqws2-android | deathwatcher и авторы, указанные там | MIT (nfqws2-android) |"
  tail -n +1 "$M/strategies/meta.tsv" | grep -v '^#' | while IFS='	' read -r name author repo date; do
    [ "$name" = default ] && name_file="defaults/nfqws2.conf → strategies/default.conf" || name_file="strategies/$name.conf"
    if [ "$repo" = "rndnaame/nfqws-menu" ]; then lic="в источнике не указана"; else lic="MIT (nfqws2-android)"; fi
    echo "| \`$name_file\` | [$repo](https://github.com/$repo) ($date) | $author | $lic |"
  done
} > "$M/NOTICE.md"
echo "import: ok"
