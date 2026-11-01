// Вкладка «Настройки».
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { root, sample, check, done } from './helpers.mjs';
const { renderSettings, settingControls } = await import('../../webroot/js/settings.js');

const s = sample('settings-get');
const keys = Object.keys(s.settings).filter((k) => k !== 'DEFAULT_STRATEGY' && k !== 'MODE');
check(keys.length === 16 && settingControls.length === 16, `16 ключей: ${keys.length}/${settingControls.length}`);
const h = renderSettings(s, sample('version'));
for (const k of keys) check(h.includes(`data-key="${k}"`), `нет элемента ${k}`);
check(/data-key="AUTOSTART" checked/.test(h) && !/data-key="BLOCK_QUIC" checked/.test(h), 'флаги по значениям');
check(h.includes('value="15"') && h.includes('bcw 0.12.1') && h.includes('модуль v0.1.0'), 'числа и версии');
const msg = 'PKT_LIMIT_OUT: число от 1 до 100, получено «500»';
check(renderSettings(s, null, { PKT_LIMIT_OUT: msg }).includes(msg), 'текст ошибки из ctl');
const src = readFileSync(join(root, 'webroot', 'js', 'settings.js'), 'utf8');
check(!/parseInt|Number\(|isNaN|\b(min|max)=/.test(src), 'своих проверок значений на JS нет');
done('test_settings');
