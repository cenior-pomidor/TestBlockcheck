// Вкладка «Списки».
import { sample, check, done } from './helpers.mjs';
const { renderLists, renderListEditor } = await import('../../webroot/js/lists.js');

const l = sample('lists'), s = sample('settings-get');
const h = renderLists(l, s);
check((h.match(/data-list=/g) || []).length === 5, 'пять списков');
check(h.includes('>28418<') && h.includes('>375<'), 'число строк');
check(/value="auto" checked/.test(h) && !/value="list" checked/.test(h), 'режим auto выбран');
const h2 = renderLists(l, { ...s, settings: { ...s.settings, MODE: 'list' } });
check(/value="list" checked/.test(h2), 'режим из настроек');
const e = renderListEditor({ ...sample('list-get'), text: 'a.com\n</textarea><script>' });
check(!e.includes('<script>') && e.includes('a.com'), 'экранирование текста списка');
done('test_lists');
