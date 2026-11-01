// Аргументы `bcw ctl` для всех действий интерфейса — в одном месте.
// Значения от пользователя (имена, SSID, ключи, значения) идут после `--`, чтобы clap
// не принял «-x» за ключ. Соответствие CLI проверяет engine (тест webui_argv_parses).

export const cmd = {
  status: () => ['status'],
  start: () => ['start'],
  stop: () => ['stop'],
  restart: () => ['restart'],
  homeResume: () => ['home', 'resume'],
  homeAdd: (ssid) => ['home', 'add', '--', ssid],
  homeRemove: (ssid) => ['home', 'remove', '--', ssid],
  networks: () => ['networks'],
  networkDelete: (key) => ['network', 'delete', '--', key],
  strategies: () => ['strategies'],
  strategyGet: (name) => ['strategy', 'get', '--', name],
  strategySave: (name, path) => ['strategy', 'save', '--from', path, '--', name],
  strategyReset: (name) => ['strategy', 'reset', '--', name],
  strategyDelete: (name) => ['strategy', 'delete', '--', name],
  strategyApplyNetwork: (name) => ['strategy', 'apply', '--network', '--', name],
  strategyApplyDefault: (name) => ['strategy', 'apply', '--default', '--', name],
  settingsGet: () => ['settings', 'get'],
  settingsSet: (key, value) => ['settings', 'set', '--', key, value],
  lists: () => ['lists'],
  listGet: (name) => ['list', 'get', '--', name],
  listSet: (name, path) => ['list', 'set', '--from', path, '--', name],
  logs: (file, tail, errorsOnly) => ['logs', '--tail', String(tail), ...(errorsOnly ? ['--errors'] : []), '--', file],
  logsClear: () => ['logs', '--', 'clear'],
  stats: () => ['stats'],
  version: () => ['version'],
  uploadBegin: () => ['upload', 'begin'],
  uploadChunk: (path, data) => ['upload', 'chunk', path, data],
  uploadEnd: (path) => ['upload', 'end', path],
};
