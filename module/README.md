# bcw — модуль обхода DPI для KernelSU

Обход на nfqws2 со стратегиями по сетям, паузой в домашнем Wi-Fi, сторожем и откатом;
28 пресетов nfqws2-android с редактором; поиск стратегий `bcw` (этап 3 — вкладка «Поиск»).
Только KernelSU и arm64. Спецификация: `docs/superpowers/specs/2026-11-01-bcw-module-design.md`.

Откуда взяты пресеты, списки, блобы и скрипт сборки nfqws2 — `NOTICE.md`.

## Где что лежит на телефоне

| Путь | Что там |
|---|---|
| `/data/adb/modules/bcw/` | код модуля: `bin/bcw`, `bin/nfqws2`, `lua/`, пресеты, списки и блобы |
| `/data/adb/bcw/` | данные: `settings.conf`, `lists/`, `strategies/`, `networks.tsv`, `home_wifi.list`, `logs/`, `runs/` |

Удаление модуля стирает и `/data/adb/bcw/`.

## Проверка на телефоне, веха 2а (из Termux)

Все команды — в Termux на телефоне. Для краткости:

```
B=/data/adb/modules/bcw/bin/bcw
```

1. **Подготовка.** В менеджере KernelSU **отключите** nfqws2-android (переключатель), затем
   «Установить из хранилища» → `bcw-module-v0.1.0.zip` → перезагрузка.
2. **SSID (риск R1).** `su -c 'cmd wifi status'` на Wi-Fi — в выводе должна быть строка
   `Wifi is connected to "<имя сети>"`. Пришлите вывод.
3. **Служба.** `su -c "$B ctl status"` → `"state":"running"`, `"strategy":"default"`.
4. **Обход.** rutracker.org открывается в браузере — на Wi-Fi и на мобильной сети.
5. **Стратегии по сетям.** На Wi-Fi:
   ```
   su -c "$B ctl settings set NET_STRATEGY 1"
   su -c "$B ctl strategy apply alt --network"
   su -c "$B ctl status"
   ```
   → `"strategy":"alt"`. Переключитесь на мобильную сеть, через ~10 с `ctl status` →
   `"strategy":"default"`; обратно на Wi-Fi → снова `alt`.
6. **Пауза дома.** На домашнем Wi-Fi (подставьте имя сети):
   ```
   su -c "$B ctl settings set HOME_WIFI 1"
   su -c "$B ctl home add 'Имя сети'"
   su -c "$B ctl status"
   ```
   → `"state":"paused_home"`. Затем `su -c "$B ctl home resume"` → `"state":"running"`.
7. **Сторож.** `su -c 'kill -9 $(pidof nfqws2)'`, через 10 с `ctl status` → `running`;
   `su -c "$B ctl logs service --tail 5"` → строка `restart сторож: …`.
8. **Перезагрузка.** После перезагрузки `ctl status` → `running` без ваших действий.
9. **Без дублей.** Трижды `su -c "$B ctl restart"`, затем
   `su -c "iptables-save -t mangle | grep -c 'A POSTROUTING -j dpi_post'"` → `1`.
   `su -c "$B ctl stop"` → `su -c "iptables-save | grep -c dpi_"` → `0`; `su -c "$B ctl start"`.
10. **Поиск рядом с обходом.**
    ```
    su -c "$B -w 254 scan -d rutracker.org -p tls12 | $B check -d rutracker.org --take 3"
    ```
    Во время прогона сайты через обход продолжают открываться; поиск находит стратегии.
11. **Сосед.** (Необязательно.) Включите nfqws2-android и перезагрузитесь → `ctl status` →
    `"state":"blocked_neighbour"`; отключите его и перезагрузитесь снова.

Что прислать: вывод шагов 2, 3, 5, 6, 7, 9 и `su -c "$B ctl logs service"`; где не так —
что видели.
