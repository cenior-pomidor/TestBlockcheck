// Вкладка «Стратегии»: список, кнопки редактора, текст пресета.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { root, sample, check, done } from './helpers.mjs';
const { renderStrategies, renderEditor, editorToText } = await import('../../webroot/js/strategies.js');

const list = sample('strategies');
const status = sample('status');
const html = renderStrategies(list, status);
check(html.includes('MartinBacker') && html.includes('Flowseal'), 'автор в списке');
check(/data-open="default"[^]*?сейчас/.test(html), 'текущая стратегия отмечена');
check(html.includes('data-act="new"'), 'кнопка «Новый»');
const mod = { ...list, strategies: [{ name: 'alt', author: 'Flowseal', builtin: true, modified: true }, { name: 'mine', builtin: false, modified: false }] };
const h2 = renderStrategies(mod, status);
check(h2.includes('изменён') && h2.includes('свой'), 'отметки «изменён» и «свой»');
check(!renderStrategies({ ...list, strategies: [{ name: '<x>', builtin: true }] }, status).includes('<x>'), 'экранирование имени');

const get = sample('strategy-get');
const e = renderEditor(get);
check(e.includes('Для этой сети') && e.includes('По умолчанию'), 'применение');
check(!e.includes('Вернуть к исходнику') && !e.includes('data-act="delete"'), 'неизменённый встроенный: без сброса и удаления');
check(renderEditor({ ...get, modified: true }).includes('Вернуть к исходнику'), 'сброс у изменённого встроенного');
const own = renderEditor({ ...get, builtin: false });
check(own.includes('data-act="delete"') && !own.includes('Вернуть к исходнику'), 'удаление только у своих');
const fresh = renderEditor(null);
check(fresh.includes('name="name"') && !fresh.includes('Для этой сети'), 'новый: поле имени');
check(fresh.includes('name="NFQWS_ARGS"'), 'новый: поля ключей');

// Текст из редактора сверяется с разбором bcw в engine/src/bypass/preset.rs (тест editor_roundtrip).
const text = editorToText(get.fields);
const fixture = join(root, 'tests', 'webui', 'editor-roundtrip.conf');
if (process.env.UPDATE_SAMPLES === '1') writeFileSync(fixture, text);
check(readFileSync(fixture, 'utf8') === text, 'editor-roundtrip.conf устарел: UPDATE_SAMPLES=1 node test_strategies.mjs');
check(text.split('\n').filter((l) => /^[A-Z_]+="/.test(l)).length === 6, 'шесть ключей');
let threw = false;
try { editorToText({ ...get.fields, NFQWS_ARGS: 'a"b' }); } catch (_) { threw = true; }
check(threw, 'кавычка в значении отвергается');
check(editorToText({ NFQWS_ARGS: 'x\r\ny' }).includes('NFQWS_ARGS="x\ny"'), 'CRLF → LF');
const { dedent } = await import('../../webroot/js/strategies.js');
check(!/\n +--/.test(renderEditor(get)), 'отступы строк в редакторе убраны');
check(dedent('a\n    b  ') === 'a\nb', 'dedent');
const withPkt = editorToText(get.fields, 'X=1\nNFQWS2_TCP_PKT_OUT=20\n# NFQWS2_UDP_PKT_IN=5\n');
check(withPkt.includes('\nNFQWS2_TCP_PKT_OUT=20\n# NFQWS2_UDP_PKT_IN=5\n') && !withPkt.includes('X=1'), 'лимиты пакетов переносятся');
// FOUND_*: показываются только при непустом значении; значение сохраняется при сборке.
check(!/FOUND_/.test(e) && !/FOUND_/.test(text), 'found_hidden: без FOUND_* поля и ключи не выводятся');
const foundFields = { ...get.fields, FOUND_TLS: '--lua-desync=T' };
const fe = renderEditor({ ...get, fields: foundFields });
check(fe.includes('name="FOUND_TLS"') && fe.includes('name="FOUND_YOUTUBE"') && fe.includes('name="FOUND_HTTP"'), 'found: три поля при непустом FOUND_*');
check(fe.includes('Найдено: YouTube') && fe.includes('Найдено: TLS') && fe.includes('Найдено: HTTP'), 'found: подписи');
check(fe.includes('--lua-desync=T</textarea>'), 'found: значение в поле');
const ft = editorToText(foundFields);
check(ft.includes('FOUND_TLS="--lua-desync=T"\n') && ft.includes('FOUND_YOUTUBE=""\n') && ft.includes('FOUND_HTTP=""\n'), 'roundtrip_found: все три ключа');
let thr = false;
try { editorToText({ ...foundFields, FOUND_TLS: 'a"b' }); } catch (_) { thr = true; }
check(thr, 'found: кавычка отвергается');
done('test_strategies');
