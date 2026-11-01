# Этап 2. Модуль обхода `bcw` для KernelSU — дизайн

Дата: 2026-11-01
Статус: на согласовании
Репозиторий: `cenior-pomidor/TestBlockcheck`, ветка `stage2-module`
Предыдущий этап: `docs/superpowers/specs/2026-10-31-bcw-android-engine-design.md` (слит в `main`, PR #1)

## 1. Цель

Модуль KernelSU с WebUI, который обходит DPI на телефоне владельца и заменяет установленный
nfqws2-android. Модуль пишется **с нуля**, поведение повторяет оставленные функции
[nfqws2-android](https://github.com/dea1hwatcher/nfqws2-android) v2.0.4 (коммит `8e916c8`, MIT).
Куски оригинала (скрипт сборки nfqws2, пресеты, списки, блобы, способ узнать SSID) берутся
с указанием авторства.

Этап 2 готов, когда модуль стоит на телефоне вместо nfqws2-android и обходит блокировки так же,
а поиск `bcw` с этапа 1 работает рядом, не прерывая обход. Вкладка «Поиск» и превращение
найденного в стратегию сети — этап 3.

### 1.1. Решения владельца

| Вопрос | Решение |
|---|---|
| Отношение к nfqws2-android | свой модуль: id `bcw`, обновления из этого репозитория |
| Перенос данных из nfqws2-android | нет, чистая установка с умолчаниями |
| Платформа | только KernelSU и arm64 |
| Способ | новый модуль с нуля в `module/` (не урезание оригинала) |
| Логика | в Rust-бинаре `bcw`: подкоманды `svc` и `ctl`; шелл только запускает |
| Пресеты | все 28 пресетов оригинала, кроме `smart`, с авторами и источником |
| IPv6 | не делаем (решение этапа 1); последствия — §9, R5 |
| Удаление модуля | стирает и данные `/data/adb/bcw/` |

Функции:

| Оставить | Убрать |
|---|---|
| применение стратегий; стратегии по сетям; пауза в домашнем Wi-Fi; автозапуск; сторож; откат | умный режим; фильтр приложений; VPN-пауза; пауза при «белых списках»; раздача |
| пресеты и редактор | импорт конфигов nfqws2-keenetic; замер стратегий `zapret2-bench` |
| `BLOCK_QUIC`; `META_QUIC_REJECT`; обход звонков `CALLS_BYPASS` | wakelock |
| `TCP_MSS_CLAMP`; `AUTO_PORTS`; `NAT_FIX` | IPv6; `ISP_INTERFACE`; `NFQWS_USER` |
| списки: свой, авто, исключения, ipset, исключения ipset | каталоги; резервная копия; проверки DPI/DNS/Telegram |
| журналы со статистикой; обновления из менеджера | темы и выбор языка; Magisk, APatch; arm, x86, x86_64 |

### 1.2. Факты, на которых держится дизайн

Из исходников nfqws2-android v2.0.4:

- Командная строка nfqws2 собирается в `_startup_args` (`lib/common.sh:537`) в порядке:
  `--qnum`, `--debug`, база, обход звонков, `NFQWS_ARGS_CUSTOM`, UDP, QUIC (если не
  `BLOCK_QUIC`; с ipset и без), TCP (с ipset и без), режим списков; блоки разделяются `--new`.
- Правила — `_firewall_start` и `_fw_iface_rules` (`lib/common.sh:1398–1575`): исключения
  интерфейсов, `connbytes 1:15` в обе стороны, SYN-ACK/FIN/RST в очередь, `--queue-bypass`,
  `BLOCK_QUIC` как DROP UDP 443, `TCP_MSS_CLAMP`, `NAT_FIX` (connmark бит 31 + MASQUERADE UDP),
  отказ QUIC к сетям Meta в таблице filter (`_meta_quic_chain`, `lib/common.sh:1636`).
- Метки: `0x40000000` — пакеты nfqws2; `0x80000000` в connmark — `NAT_FIX`.
- У владельца в `iptables-save` правило `-A POSTROUTING -m mark --mark 0x40000000/0x40000000
  -j MARK --set-xmark 0x0/0x40000000` стоит трижды (факт). Вероятная причина, не проверенная:
  `_firewall_start` вставляет его `-I POSTROUTING 2|3 … || true` без проверки наличия
  (`lib/common.sh:1544–1553`). Новый модуль ставит правила транзакцией и снимает своё целиком.
- SSID: `cmd wifi status`, запасной путь — `dumpsys wifi` (`current_ssid`, `lib/common.sh:2108`);
  мобильная сеть — `getprop gsm.operator.alpha` (`_raw_network_id`, `lib/common.sh:2247`).
- Сторож — цикл раз в 20 с, после 5 падений подряд пауза 60 с (`watchdog`, `service.sh:557`).
- Во всех 28 пресетах общие ключи (`TCP_PORTS`, `UDP_PORTS`, `PKT_LIMIT_*`, `BLOCK_QUIC`,
  `AUTOSTART`, `NFQWS_EXTRA_ARGS="$MODE_AUTO"`, …) одинаковы; различаются только 6 ключей
  стратегии. Переменные в пресетах: `$LUA_DIR`, `$BLOBS_DIR`, `$LISTS_DIR`, `$LOG_DIR`,
  `$MODE_LIST`, `$MODE_ALL`, `$MODE_AUTO`. Lua: только `zapret-lib`, `zapret-antidpi`,
  `zapret-auto`.
- Пресеты взяты из [rndnaame/nfqws-menu](https://github.com/rndnaame/nfqws-menu) (27 шт.,
  `strategies/meta.tsv`) и самого nfqws2-android (`default`). В nfqws-menu файла лицензии нет
  (проверено клоном 2026-11-01). Владелец принял это (R4).
- nfqws2 собирается скриптом `.github/scripts/build-android-binaries.sh` через Android NDK из
  zapret2 `v1.0.6` (коммит `f924d796b49da9e455c6bb09268298ef1471cd74`) с патчами
  `001-tls-reasm-fastpath.patch` и `libnetfilter_queue-android.patch`. В nfqws2 есть
  `--dry-run` (проверка параметров).
- WebUI оригинала вызывает мост KernelSU напрямую: `window.ksu.exec(cmd, '{}', callbackName)`,
  при наличии — `window.ksu.spawn` (`webroot/js/core.js:264–325`); документация KernelSU
  описывает тот же мост через npm-библиотеку `kernelsu`
  ([kernelsu.org/guide/module-webui.html](https://kernelsu.org/guide/module-webui.html)).
  Длинный аргумент ограничен ~128 КБ — большие данные отправляются частями.

С телефона владельца (этап 1): `CONFIG_NETFILTER_XT_MATCH_CONNBYTES=y`, nftables нет;
поиск `bcw` держит метки в битах 21–29, свои цепочки `bcw_*`, очередь 777.

## 2. Устройство

```
TestBlockcheck/
├── engine/        # bcw (Rust): поиск (этап 1) + svc/ctl (этап 2)
├── module/        # файлы модуля KernelSU
│   ├── module.prop, update.json, customize.sh, service.sh, uninstall.sh
│   ├── webroot/   # WebUI
│   ├── strategies/  # 28 пресетов оригинала без изменений + meta.tsv
│   ├── defaults/  # умолчания настроек и списков, calls-bypass.conf
│   ├── lists/     # тематические списки, на которые ссылаются пресеты
│   ├── blobs/     # блобы, на которые ссылаются пресеты и обход звонков
│   └── NOTICE.md  # откуда что взято, авторы, лицензии
├── docs/superpowers/specs/
└── .github/workflows/
```

На телефоне:

| Путь | Что там | Обновление модуля |
|---|---|---|
| `/data/adb/modules/bcw/` | код модуля, `bin/bcw`, `bin/nfqws2`, `lua/`, пресеты, списки и блобы модуля | заменяется целиком |
| `/data/adb/bcw/` | `settings.conf`, `lists/`, `strategies/` (правки и свои пресеты), `networks.tsv`, `home_wifi.list`, `logs/`, `state/`, `runs/` (поиск) | сохраняется |

Пути по умолчанию в `bcw` (`engine/src/config.rs`) переезжают на `/data/adb/modules/bcw/bin/nfqws2`
и `/data/adb/modules/bcw/lua`.

**Соседство с nfqws2-android.** Установка не блокируется. Служба не запускает обход, пока
каталог `/data/adb/modules/nfqws2-android` существует без файлов `disable` и `remove`;
состояние «Не запущено: включён nfqws2-android» видно в `ctl status`, WebUI и журнале.

## 3. Служба `bcw svc`

### 3.1. Процессы

- `service.sh` (после загрузки): цикл «`bcw svc run`; если вышел — пауза 5 с и снова».
- `bcw svc run` — один долгоживущий процесс: nfqws2 (очередь 300) как дочерний, правила,
  сторож (раз в 20 с), слежение за сетью (раз в 5 с).
- `bcw ctl` связывается со службой через абстрактный unix-сокет `bcw.svc`
  (запрос и ответ — JSON). Замок поиска `bcw.instance` служба не берёт.
- При старте `svc run` снимает свои прошлые правила и чужие процессы nfqws2 на очереди 300 не
  трогает: это признак включённого nfqws2-android (см. §2).

### 3.2. Состояния

| Состояние | Когда | Обход |
|---|---|---|
| `running` | желаемое «вкл», не дома, nfqws2 жив | да |
| `stopped` | выключено владельцем | нет |
| `paused_home` | `HOME_WIFI=1`, текущий SSID в `home_wifi.list`, нет `home resume` для этой сети | нет |
| `blocked_neighbour` | включён nfqws2-android | нет |
| `failed` | 5 падений подряд; через 60 с новая попытка | нет |

Желаемое «вкл/выкл» хранится в `state/desired`. `AUTOSTART=1` — после загрузки желаемое «вкл».
`home resume` действует, пока телефон в этой сети (как `HOME_OVERRIDE_FILE` оригинала).
`WATCHDOG=0` — упавший nfqws2 не перезапускается, состояние `failed` сразу.

### 3.3. Сеть

- Ключ и подпись сети: Wi-Fi — SSID из `cmd wifi status` (запас — `dumpsys wifi`), мобильная —
  `getprop gsm.operator.alpha` (запас — `gsm.sim.operator.alpha`, иначе «Мобильная»).
  Ключ кодируется так же, как `current_network_key` оригинала.
- Решение «сеть сменилась → что делать» — чистая функция
  `(состояние, настройки, сеть, сохранённые сети) → действие`; действия: пауза, снятие паузы,
  перезапуск с другой стратегией, ничего.
- Стратегия сети: запись в `networks.tsv`, если `NET_STRATEGY=1`; иначе `DEFAULT_STRATEGY`.

### 3.4. Применение стратегии и откат

1. Стратегия = пресет (§4.1) + настройки (§4.2) → командная строка nfqws2 в порядке
   `_startup_args` (§1.2). Отличия: только пути (`/data/adb/modules/bcw/…`, `/data/adb/bcw/…`).
2. `nfqws2 --dry-run` с этой строкой; ошибка — стратегия не применяется, текст ошибки уходит
   в ответ `ctl` и журнал.
3. Запуск. Если nfqws2 упал в первые 10 с — возврат к последней рабочей конфигурации
   (`state/last_good`), перезапуск, запись в журнал. Рабочей считается конфигурация, проработавшая
   10 с.

### 3.5. Правила iptables (только IPv4)

Ставятся транзакцией `iptables-restore --noflush -w` на таблицу тем же исполнителем, что поиск
(`engine/src/firewall/ipt.rs`); снимаются целиком. Цепочки: `dpi_post`, `dpi_pre` (mangle),
`dpi_nat` (nat), `dpi_mquic` (filter).

`dpi_post` / `dpi_pre`, по порядку:

1. **изоляция от поиска** (нового в сравнении с оригиналом): `-m mark ! --mark 0x0/0x3FE00000 -j RETURN`
   и `-m connmark ! --mark 0x0/0x00200000 -j RETURN` — пакеты и соединения поиска (биты 21–29)
   обход не трогает;
2. `-m mark --mark 0x40000000/0x40000000 -j RETURN` — уже обработанное nfqws2;
3. исключения интерфейсов `lo tun+ tap+ wg+ ppp+ ipsec+ ifb+ dummy+`;
4. `BLOCK_QUIC=1`: `dpi_post -p udp --dport 443 -j DROP`;
5. по `_fw_iface_rules`: UDP и TCP в очередь по `connbytes 1:N` (N — `PKT_LIMIT_*` или
   `NFQWS2_*_PKT_*` пресета), FIN/RST исходящие, SYN-ACK/FIN/RST входящие, `TCP_MSS_CLAMP`
   (1 → 536); всё — `-j NFQUEUE --queue-num 300 --queue-bypass`.

Переходы: `-I POSTROUTING <k>` / `-I PREROUTING <k>`, где `k` — позиция сразу после переходов
`bcw_*`, если поиск сейчас идёт, иначе 1. `NAT_FIX=1`: в POSTROUTING после перехода —
`CONNMARK --set-xmark 0x80000000/0x80000000` и `MARK --set-xmark 0x0/0x40000000` для меченых
пакетов, `dpi_nat`: `-p udp -m connmark --mark 0x80000000/0x80000000 -j MASQUERADE`.
`NAT_FIX=0`: только сброс бита 30. `META_QUIC_REJECT=1`: `dpi_mquic` с
`-p udp --dport 443 -d <сети Meta> -j REJECT --reject-with icmp-port-unreachable`, переход из
filter `OUTPUT`.

Порты: `TCP_PORTS`/`UDP_PORTS` или, при `AUTO_PORTS=1`, из фильтров стратегии
(`collect_capture_ports` оригинала); `BLOCK_QUIC=1` убирает 443 из UDP; `CALLS_BYPASS=1`
добавляет UDP `590:1400`, `3478:3482` и TCP `5222` (`port_list_add` оригинала, не более
15 портов на `multiport`).

## 4. Данные

### 4.1. Пресеты

- `module/strategies/*.conf` — файлы оригинала без изменений, `meta.tsv` — автор, источник,
  дата. `smart.conf` не берётся.
- Разбор в Rust, без шелла: строки `КЛЮЧ="…"` (значение может занимать несколько строк),
  комментарии `#`, подстановка только переменных из §1.2; неизвестная переменная — ошибка с
  номером строки. Берутся 6 ключей стратегии (`NFQWS_BASE_ARGS`, `NFQWS_ARGS`,
  `NFQWS_ARGS_QUIC`, `NFQWS_ARGS_UDP`, `NFQWS_ARGS_IPSET`, `NFQWS_ARGS_CUSTOM`) и необязательные
  `NFQWS2_{TCP,UDP}_PKT_{OUT,IN}`; остальные ключи игнорируются.
- `$MODE_*` раскрываются по настройке `MODE` (§4.2), а не по тексту пресета.
- Правка или новый пресет — `/data/adb/bcw/strategies/<имя>.conf` (только ключи стратегии),
  перекрывает модульный; «вернуть к исходнику» — удалить перекрытие. Имя — `[A-Za-z0-9_-]{1,64}`.

### 4.2. Настройки

`/data/adb/bcw/settings.conf`, строки `КЛЮЧ=значение`. Умолчания — из `defaults/nfqws2.conf`
оригинала:

| Ключ | Умолчание | Значения |
|---|---|---|
| `DEFAULT_STRATEGY` | `default` | имя пресета |
| `MODE` | `auto` | `list` / `all` / `auto` |
| `TCP_PORTS` | `80,443,1984,2053,2083,2087,2096,5222,8443` | список портов и диапазонов |
| `UDP_PORTS` | `443,590:600,1400,3478:3481,5349,19294:19344,49152:65535` | то же |
| `AUTO_PORTS` | `0` | 0/1 |
| `PKT_LIMIT_OUT`, `PKT_LIMIT_IN` | `15` | 1–100 |
| `BLOCK_QUIC` | `0` | 0/1 |
| `META_QUIC_REJECT` | `1` | 0/1 |
| `CALLS_BYPASS` | `0` | 0/1 |
| `TCP_MSS_CLAMP` | `0` | 0, 1 (=536), 88–1460 |
| `NAT_FIX` | `1` | 0/1 |
| `AUTOSTART` | `1` | 0/1 |
| `WATCHDOG` | `1` | 0/1 |
| `HOME_WIFI` | `0` | 0/1 |
| `NET_STRATEGY` | `0` | 0/1 |
| `LOG_LEVEL` | `0` | 0/1 |
| `LOG_MAX_KB` | `512` | 64–4096 |

Очередь всегда 300. Неверное значение отвергается `ctl` с объяснением; неверная строка в файле —
умолчание и запись в журнал.

### 4.3. Списки

- Свои: `user`, `auto`, `exclude`, `ipset`, `ipset_exclude` в `/data/adb/bcw/lists/`;
  при первом запуске создаются из `defaults/lists/` оригинала.
- Тематические (`youtube`, `google`, `geoblock`, `ipset_cloudflare`, `ipset_ovh`, … — все, на
  которые ссылаются пресеты): в `module/lists/`.
- `$LISTS_DIR/<имя>`: файл из `/data/adb/bcw/lists/`, если есть, иначе из модуля.
- ipset-аргументы стратегии подключаются только при непустом `ipset.list` (как в оригинале).

### 4.4. Сети, журналы

- `networks.tsv`: `ключ<TAB>подпись<TAB>пресет`. `home_wifi.list`: SSID по строке.
- `logs/service.log` — события службы (запуск, остановка, автоперезапуск, ошибка, смена сети,
  пауза, откат); `logs/nfqws2.log` — `--debug=@…`; `logs/auto.log` — `--hostlist-auto-debug`.
  Предел — `LOG_MAX_KB` на файл, при превышении остаётся новая половина.
- Статистика (`ctl stats`): число запусков, автоперезапусков, ошибок, доменов, добавленных
  в `auto.list`, — по журналам.

## 5. `bcw ctl`

Ответ всегда JSON: `{"schema":1,"ok":true,…}` или `{"schema":1,"ok":false,"error":"…"}`
(по-русски).

| Группа | Команды |
|---|---|
| служба | `status`, `start`, `stop`, `restart` |
| стратегии | `strategies`, `strategy get <имя>`, `strategy save <имя> --from <файл>`, `strategy reset <имя>`, `strategy delete <имя>`, `strategy apply <имя> [--default \| --network]` |
| настройки | `settings get`, `settings set <ключ> <значение>` |
| списки | `lists`, `list get <имя>`, `list set <имя> --from <файл>` |
| сети | `networks`, `network set <ключ> <пресет>`, `network delete <ключ>`, `home add <SSID>`, `home remove <SSID>`, `home resume` |
| журналы | `logs <service\|nfqws2\|auto> [--errors] [--tail N]`, `logs clear`, `stats` |
| прочее | `version`, `upload begin`, `upload chunk <base64>`, `upload end` → путь файла для `--from` |

- `upload` пишет в `/data/adb/bcw/tmp/`: так большие списки проходят предел длины аргумента.
- Без работающей службы команды чтения работают с файлами; `start`/`stop`/`restart` отвечают
  «служба не запущена».

## 6. WebUI

HTML/CSS/JS без сборки и без внешних загрузок; вызовы `window.ksu.exec(…)` с запасным
`window.ksu.spawn`, как в оригинале (§1.2). Русский язык; светлая/тёмная тема — из системы.

| Вкладка | Что на ней |
|---|---|
| Состояние | состояние и причина; сеть и её стратегия; «Запустить» / «Остановить» / «Перезапустить»; в паузе — «Включить здесь сейчас» |
| Стратегии | пресеты с автором и отметкой «изменён»; «Для этой сети» / «По умолчанию»; редактор 6 полей с проверкой `--dry-run`; «Вернуть к исходнику»; «Новый» |
| Сети | сохранённые сети и стратегии, удаление; домашние Wi-Fi: «Добавить текущую», удалить; тумблеры «Стратегии по сетям», «Пауза дома» |
| Списки | 5 своих списков: просмотр, правка, число строк; режим списков |
| Журналы | служба / nfqws2 / авто-список; фильтр «Ошибки»; статистика; очистка |
| Настройки | ключи §4.2 кроме `DEFAULT_STRATEGY` и `MODE`; версия |

Этап 3 добавит вкладку «Поиск».

## 7. Сборка и обновления

- `bcw` — `cross`, `aarch64-unknown-linux-musl`, статический (как этап 1).
- nfqws2 — скрипт сборки оригинала (MIT, с авторством), урезанный до arm64; проверки скрипта
  (архитектура, выравнивание 16 КБ, зависимости, наличие патча) сохраняются.
- Lua — `zapret-lib.lua`, `zapret-antidpi.lua`, `zapret-auto.lua` из того же коммита zapret2.
- Блобы и тематические списки — те, на которые ссылаются пресеты и `calls-bypass.conf`;
  набор считает скрипт сборки, CI проверяет, что все ссылки пресетов разрешаются.
- Архив `bcw-module-vX.Y.Z.zip` из `module/` и бинарников; CI проверяет `id=bcw`, состав,
  совпадение версии `module.prop` с тегом.
- Релиз: коммит поднимает `version`/`versionCode` в `module.prop` и `update.json`; тег `vX.Y.Z`
  запускает сборку и GitHub Release. `updateJson` —
  `https://raw.githubusercontent.com/cenior-pomidor/TestBlockcheck/main/module/update.json`.
  Первая версия — `v0.1.0`.
- `uninstall.sh`: остановить службу, снять правила, удалить `/data/adb/bcw/`.

## 8. Тесты и приёмка

### 8.1. Автоматические

1. Пресеты: все 28 файлов разбираются; ошибки разбора — с номером строки.
2. **Эталон командной строки**: скриптом оригинала (`_startup_args` в его песочнице
   `tests/lib/harness.sh`) один раз генерируются строки nfqws2 для каждого пресета ×
   `MODE` (3) × `BLOCK_QUIC` (2) × `CALLS_BYPASS` (2) × ipset (пуст/непуст). Эталоны
   и скрипт генерации — в репозитории; `bcw` обязан дать те же строки с поправкой на пути.
3. Правила: модульные на подставном исполнителе (как этап 1); на реальном ядре в CI
   (iptables-legacy в контейнере) — постановка и снятие, **нет дублей после 10 перезапусков**,
   переходы обхода после `bcw_*`, контрольная проба поиска проходит мимо работающего обхода.
4. Решение по сети (§3.3) — таблица случаев.
5. Откат (§3.4) — подставной nfqws2, падающий через 1 с.
6. `ctl` — форма JSON каждой команды; WebUI — синтаксис скриптов и сверка ожидаемых полей с
   выводом `ctl` (сохранённые образцы).

### 8.2. На телефоне

Веха **2а** (служба и `ctl`, из Termux; nfqws2-android отключён):

1. Первым — `cmd wifi status` от root отдаёт SSID (R1).
2. Модуль ставится; `bcw ctl status` — `running`.
3. rutracker открывается в браузере на Wi-Fi и мобильной сети.
4. Смена сети переключает стратегию сети; дома — `paused_home`; `home resume` снимает паузу.
5. `kill` nfqws2 — сторож перезапускает; стратегия с ошибкой — откат.
6. Перезагрузка — обход стартует сам.
7. После нескольких перезапусков `iptables-save` без дублей; после `stop` — без `dpi_`.
8. `bcw scan | bcw check` параллельно с обходом; обход не прерывается, поиск находит стратегии.
9. Включённый nfqws2-android — состояние `blocked_neighbour`.

Веха **2б** (WebUI): те же сценарии через интерфейс; удаление модуля стирает `/data/adb/bcw/`.

## 9. Риски

| # | Риск | Меры |
|---|---|---|
| R1 | `cmd wifi status` от root может не отдать SSID на Android 17 | первый шаг вехи 2а; запас — `dumpsys wifi` |
| R2 | Мост `window.ksu` изменится в новых версиях менеджера | вызов в одном месте WebUI; `exec` и `spawn`, как в оригинале |
| R3 | Переписанное поведение разойдётся с оригиналом | эталонные строки (§8.1 п.2); правила сверяются с `_fw_iface_rules` в ревью |
| R4 | У пресетов nfqws-menu не указана лицензия | принято владельцем; источник и авторы — в `meta.tsv` и `NOTICE.md` |
| R5 | Без IPv6 соединения по IPv6 идут без обхода, отказ QUIC Meta по IPv6 не действует | принятый риск |
| R6 | Скрипт NDK-сборки потребует правок в этом CI | отдельная задача плана; проверка артефакта |
| R7 | Служба упала, правила остались | `--queue-bypass`; `service.sh` перезапускает за 5 с; при старте свои правила снимаются |
| R8 | Удаление стирает и отчёты поиска `runs/` | решение владельца |
