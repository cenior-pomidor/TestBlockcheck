// Аргументы всех действий WebUI → engine/src/cmd/ctl.rs (тест webui_argv_parses) разбирает их clap.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { root, check, done } from './helpers.mjs';
const { cmd } = await import('../../webroot/js/commands.js');

// Значения, начинающиеся с «-», и с пробелами — clap не должен принять их за ключи.
const N = '-x', P = '/data/adb/bcw/tmp/upload-1-2', V = '-1';
const calls = {
  status: [], start: [], stop: [], restart: [], homeResume: [],
  homeAdd: ['-кафе wifi'], homeRemove: [' дом '], networks: [], networkDelete: ['wifi_-x'],
  strategies: [], strategyGet: [N], strategySave: [N, P], strategyReset: [N], strategyDelete: [N],
  strategyApplyNetwork: [N], strategyApplyDefault: [N], settingsGet: [], settingsSet: ['TCP_MSS_CLAMP', V],
  lists: [], listGet: ['user'], listSet: ['user', P], logs: ['service', 500, true], logsClear: [],
  stats: [], version: [], uploadBegin: [], uploadChunk: [P, '+/AA'], uploadEnd: [P],
};
check(Object.keys(calls).sort().join() === Object.keys(cmd).sort().join(), 'не все команды перечислены');
const argv = Object.fromEntries(Object.entries(calls).map(([k, a]) => [k, cmd[k](...a)]));
const text = JSON.stringify(argv, null, 1) + '\n';
const fixture = join(root, 'tests', 'webui', 'argv.json');
if (process.env.UPDATE_SAMPLES === '1') writeFileSync(fixture, text);
check(readFileSync(fixture, 'utf8') === text, 'argv.json устарел: UPDATE_SAMPLES=1 node test_commands.mjs');
done('test_commands');
