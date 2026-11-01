#!/bin/sh
# Скрипты модуля: установка, запуск службы, удаление. Android-команды — заглушки на PATH.
set -u
M=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
trap 'kill $SVC 2>/dev/null; rm -rf "$T"' EXIT
fail=0
err() { echo "FAIL: $*" >&2; fail=1; }

for f in customize.sh service.sh uninstall.sh; do
  sh -n "$M/$f" || err "синтаксис $f"
done

# --- customize.sh: только KernelSU и arm64
install() { # <ARCH> <KSU>
  ( set +u
    MODPATH="$T/inst"; rm -rf "$MODPATH"; mkdir -p "$MODPATH/bin" "$MODPATH/tests" "$MODPATH/tools"
    : > "$MODPATH/bin/bcw"; : > "$MODPATH/bin/nfqws2"
    cp "$M/module.prop" "$MODPATH/"
    ARCH=$1 KSU=$2
    ui_print() { :; }
    abort() { echo "ABORT: $*"; exit 3; }
    set_perm() { echo "perm $*" >> "$T/perms"; }
    set_perm_recursive() { echo "permr $*" >> "$T/perms"; }
    . "$M/customize.sh"
    [ -d "$MODPATH/tests" ] && echo "tests left"
    exit 0
  )
}
out=$(install arm 1 true); [ $? -eq 3 ] || err "arm не отвергнут: $out"
out=$(install arm64 ""); [ $? -eq 3 ] || err "без KernelSU не отвергнуто: $out"
: > "$T/perms"
out=$(install arm64 true); rc=$?
[ $rc -eq 0 ] || err "arm64+KernelSU отвергнут: $out"
case "$out" in *"tests left"*) err "tests/ остался в модуле" ;; esac
grep -q "perm $T/inst/bin/bcw 0 0 0755" "$T/perms" || err "права bcw: $(cat "$T/perms")"
grep -q "perm $T/inst/bin/nfqws2 0 0 0755" "$T/perms" || err "права nfqws2"
grep -q "webroot" "$T/perms" && err "права webroot трогать нельзя"

# --- service.sh: ждёт загрузки, первый запуск с --boot, перезапуск после выхода
mkdir -p "$T/path" "$T/mod/bin" "$T/data"
cat > "$T/path/getprop" <<'S'
#!/bin/sh
[ "$1" = sys.boot_completed ] && cat "$BOOTFLAG" 2>/dev/null
S
cat > "$T/mod/bin/bcw" <<'S'
#!/bin/sh
echo "$*" >> "$CALLS"
S
chmod +x "$T/path/getprop" "$T/mod/bin/bcw"
cp "$M/service.sh" "$T/mod/"
export BOOTFLAG="$T/boot" CALLS="$T/calls" BCW_DATA_DIR="$T/data"
echo 0 > "$BOOTFLAG"
PATH="$T/path:$PATH" sh "$T/mod/service.sh" & SVC=$!
sleep 3
[ -s "$CALLS" ] && err "служба стартовала до конца загрузки"
echo 1 > "$BOOTFLAG"
sleep 10
kill $SVC 2>/dev/null
n=$(wc -l < "$CALLS" 2>/dev/null || echo 0)
[ "$n" -ge 2 ] || err "служба не перезапущена: $(cat "$CALLS" 2>/dev/null)"
[ "$(sed -n 1p "$CALLS")" = "svc run --boot" ] || err "первый запуск: $(sed -n 1p "$CALLS")"
[ "$(sed -n 2p "$CALLS")" = "svc run" ] || err "второй запуск: $(sed -n 2p "$CALLS")"

# --- uninstall.sh: снять правила и стереть данные
: > "$CALLS"; mkdir -p "$T/data/lists"; echo x > "$T/data/settings.conf"
cp "$M/uninstall.sh" "$T/mod/"
cat > "$T/path/pkill" <<'S'
#!/bin/sh
exit 0
S
chmod +x "$T/path/pkill"
PATH="$T/path:$PATH" sh "$T/mod/uninstall.sh"
grep -qx "svc cleanup" "$CALLS" || err "uninstall не снял правила: $(cat "$CALLS")"
[ -e "$T/data" ] && err "данные не удалены"

[ "$fail" -eq 0 ] && echo "test_scripts: ok"
exit $fail
