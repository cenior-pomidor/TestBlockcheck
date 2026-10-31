# Происхождение кода `engine/`

`engine/` — форк [rcd27/blockcheckw](https://github.com/rcd27/blockcheckw), версия 0.12.1,
коммит `9ac14855e32a406afffd6c45f5d888b53cf8ebac`. Лицензия MIT, автор — rcd27
(см. `LICENSE`). Исходный код импортирован без изменений отдельным коммитом
`import: blockcheckw 0.12.1 (9ac1485) без изменений`; все правки — следующими коммитами.

Подмодуль `reference/zapret2` — [bol-van/zapret2](https://github.com/bol-van/zapret2)
на коммите `a1bca5a85e25ab138e9617a560c262fcf53e969a` (тот же, что в upstream),
используется интеграционными тестами.

Исправления из upstream переносятся вручную.

## Отличия от upstream

Удалено из импорта как инфраструктура upstream: `.github/`, `.claude/`, `.githooks/`,
`config.json` (ссылка на личный конфиг автора), `.gitmodules` (подмодуль объявлен в корне
репозитория), `release-please-config.json`, `.release-please-manifest.json`.
