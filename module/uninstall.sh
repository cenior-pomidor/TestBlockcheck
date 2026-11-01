#!/system/bin/sh
# Удаление модуля bcw: остановить службу, снять правила dpi_*, стереть данные (решение владельца).
MODDIR=${0%/*}
DATA=${BCW_DATA_DIR:-/data/adb/bcw}
pkill -f "$MODDIR/bin/bcw svc" 2>/dev/null
"$MODDIR/bin/bcw" svc cleanup >/dev/null 2>&1
rm -rf "$DATA"
exit 0
