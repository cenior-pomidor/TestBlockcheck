# Установщик модуля bcw (подключается установщиком KernelSU: MODPATH, ARCH, KSU,
# ui_print, abort, set_perm). Только KernelSU и arm64 — так решено для этапа 2.
version=$(sed -n 's/^version=//p' "$MODPATH/module.prop" | tr -d '\r')
ui_print "- bcw $version"
[ "$KSU" = true ] || abort "! Нужен KernelSU"
[ "$ARCH" = arm64 ] || abort "! Нужен arm64, а здесь ${ARCH:-неизвестно}"
for f in bin/bcw bin/nfqws2; do
  [ -f "$MODPATH/$f" ] || abort "! Нет $f в архиве"
done
rm -rf "$MODPATH/tests" "$MODPATH/tools"
set_perm "$MODPATH/bin/bcw" 0 0 0755
set_perm "$MODPATH/bin/nfqws2" 0 0 0755
if [ -d /data/adb/modules/nfqws2-android ] && [ ! -f /data/adb/modules/nfqws2-android/disable ]; then
  ui_print "! Включён nfqws2-android: обход bcw не запустится, пока его не отключить"
fi
ui_print "- Готово. Настройка — в WebUI модуля."
