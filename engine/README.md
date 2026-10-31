# bcw — поиск стратегий обхода DPI на Android

`bcw` — форк [blockcheckw](https://github.com/rcd27/blockcheckw) 0.12.1 для телефона под root.
Он перебирает корпус стратегий nfqws2 (13 943 штуки) параллельно, проверяет кандидатов
настоящей загрузкой страницы и отдаёт рабочие. Отличия от оригинала — в
[`UPSTREAM.md`](UPSTREAM.md), README оригинала — в [`README.upstream.md`](README.upstream.md).

Главное отличие: на Android в ядре нет nftables, поэтому правила ставятся через
**iptables**, а метка пакетов разложена так, чтобы не мешать маршрутизации Android
и работающему модулю обхода (nfqws2-android, magisk-zapret2). Обход на телефоне во время
поиска продолжает работать: пробы `bcw` идут мимо его цепочек.

## Требования

- root (KernelSU, Magisk, APatch); запуск — через `su -c`;
- ядро с NFQUEUE, connbytes, CONNMARK, CT, таблицами mangle и raw (проверяет `bcw doctor`);
- nfqws2 не старше v1.0.5 (нужен `--filter-mark`) и его Lua-файлы `zapret-lib.lua`,
  `zapret-antidpi.lua`. По умолчанию берутся из установленного модуля nfqws2-android:
  `/data/adb/modules/nfqws2-android/bin/nfqws2` и `/data/adb/modules/nfqws2-android/lua`.

## Установка

Бинарь собирает CI (артефакт `bcw-aarch64` в GitHub Actions): статический
`aarch64-unknown-linux-musl`, без UPX.

```sh
adb push bcw /data/local/tmp/
adb shell su -c chmod 755 /data/local/tmp/bcw
```

## Использование

```sh
su -c '/data/local/tmp/bcw doctor'
su -c '/data/local/tmp/bcw benchmark -t 15'
su -c '/data/local/tmp/bcw -w 64 scan -d rutracker.org -p tls12 | /data/local/tmp/bcw check -d rutracker.org --take 3'
```

Отчёты и замок экземпляра лежат в рабочем каталоге: `/data/adb/bcw/runs/<дата-время>/`.
Память прошлых запусков не ведётся — число воркеров задаётся ключом `-w` каждый раз.

### Ключи Android

| Ключ | Умолчание | Что задаёт |
|---|---|---|
| `--nfqws2 <PATH>` | `/data/adb/modules/nfqws2-android/bin/nfqws2` | бинарь движка |
| `--lua-dir <PATH>` | `/data/adb/modules/nfqws2-android/lua` | каталог Lua-библиотек движка |
| `--work-dir <PATH>` | `/data/adb/bcw` | замок и отчёты прогонов |
| `--chain-prefix <NAME>` | `bcw` | префикс наших цепочек iptables (`<p>_raw`, `<p>_out`, `<p>_post`, `<p>_pre`, `<p>_q`, `<p>_qin`, `<p>_ctl`) |
| `--qnum <N>` | `777` | очередь NFQUEUE (не 200 и не 300 — их занимают magisk-zapret2 и nfqws2-android) |
| `--doh <IP[:ИМЯ]>` | — | свой DoH-резолвер, можно несколько; опрашиваются раньше 1.1.1.1, 8.8.8.8, 9.9.9.9 |
| `--mark-desync <MARK>` | `0x00200000` | бит пакетов, отправленных nfqws2 поиска |
| `--mark-profile-shift <N>` | `22` | сдвиг поля номера стратегии (ширина 8 бит) |
| `-w`, `--profiles-per-instance` | `8`, `254` | воркеры и стратегий в одном nfqws2; потолок обоих — 254 |

Убраны за ненадобностью на Android: `--via`, `--alive-via`, `--upgrade`, `completions`,
`--embedded` (встроенный режим включён всегда), остановка службы zapret2.

### Карта битов метки

| Биты | Владелец | Значение |
|---|---|---|
| 0–20 | Android netd | в наших пробах всегда `0` — иначе маршрут «сеть по умолчанию» (`fwmark 0x0/0xffff`) не сработает |
| 21 | bcw | `0x00200000` — пакеты, отправленные nfqws2 поиска |
| 22–29 | bcw | `0x3FC00000` — номер стратегии `1…254`; `255` — контроль и DoH |
| 30 | модули обхода | пакеты nfqws2 обхода — не трогаем |
| 31 | Android netd | не трогаем |

«Наше соединение» в метке соединения опознаётся только по биту 21: модули обхода держат в
метке соединения свои биты 24–29.

## Проверка на телефоне

1. `su -c '/data/local/tmp/bcw doctor'` — все проверки зелёные.
2. `su -c '/data/local/tmp/bcw benchmark -t 15'` — скорость.
3. На домашнем Wi-Fi, затем на мобильной сети, с включённым nfqws2-android:
   `bcw -w <N> scan -d rutracker.org -p tls12 | bcw check -d rutracker.org --take 3`;
   во время прогона обход на телефоне продолжает работать.
4. После прогона `iptables-save -t mangle` и `-t raw` не содержат `bcw_`.
5. `kill -9` посреди прогона, повторный запуск — остатки сняты при старте.
6. С включённым nfqws2-android: `su -c "iptables-save -t mangle | grep -E 'MARK|CONNMARK|NFQUEUE'"` —
   проверить, что модуль обхода не пишет в метку ПАКЕТА биты 21–29 (на этом держится изоляция).

## Скорость

README оригинала: ~2 мин на TLS 1.2 и ~150 стратегий/с при 1024 воркерах (железо замера не
указано). На Android воркеров не больше 254. Замер на телефоне ещё не проведён — его
результат будет записан здесь.

На стенде (x86_64, ядро 6.18, 128 стратегий HTTP): 8 воркеров — 91 стратегия/с,
16 и 64 — около 54 стратегий/с. Это проверка конвейера, а не оценка скорости телефона.
