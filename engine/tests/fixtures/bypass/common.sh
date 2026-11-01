# Общая часть генераторов эталонов: клон nfqws2-android на коммите 8e916c8.
# Использование: . common.sh <клон или пусто>
UPSTREAM_COMMIT=8e916c8
UP=${1:-/tmp/src_nfq/nfqws2-android}
if [ ! -d "$UP/.git" ]; then
  git clone -q https://github.com/dea1hwatcher/nfqws2-android "$UP"
fi
git -C "$UP" checkout -q "$UPSTREAM_COMMIT"
case "$(git -C "$UP" rev-parse HEAD)" in "$UPSTREAM_COMMIT"*) ;; *) echo "не тот коммит" >&2; exit 1 ;; esac
HERE=$(cd "$(dirname "$0")" && pwd)
PRESETS=$(cd "$HERE/../../../../module/strategies" && pwd)
json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
