#!/system/bin/sh
# Служба обхода bcw: после загрузки — `bcw svc run --boot`, при выходе — перезапуск через 5 с.
MODDIR=${0%/*}
DATA=${BCW_DATA_DIR:-/data/adb/bcw}
until [ "$(getprop sys.boot_completed)" = 1 ]; do sleep 2; done
mkdir -p "$DATA/logs"
flag=--boot
while :; do
  "$MODDIR/bin/bcw" svc run $flag >> "$DATA/logs/svc.out" 2>&1
  flag=
  sleep 5
done
