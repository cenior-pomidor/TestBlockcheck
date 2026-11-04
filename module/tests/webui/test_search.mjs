// Вкладка «Поиск»: итоги, ход, согласие на NET_STRATEGY, основа, списки.
import { sample, check, done } from './helpers.mjs';
const S = await import('../../webroot/js/search.js');
const { cmd } = await import('../../webroot/js/commands.js');

const T = {
  applied: ['applied', 'Применено и проверено'],
  pY: [{ partial: { failed: 'youtube' } }, 'Применено частично: не подошло — YouTube'],
  pG: [{ partial: { failed: 'general' } }, 'Применено частично: не подошло — Общие'],
  rb: [{ rolled_back: { reason: 'проверка не прошла' } }, 'Откат: проверка не прошла'],
  nf: ['not_found', 'Не найдено'],
  st: ['stopped', 'Остановлено'],
  nc: ['network_changed', 'Сеть сменилась — найденное не применено'],
  sna: [{ saved_not_applied: { state: 'paused_home' } }, 'Сохранено, не применено: обход paused_home'],
};
for (const [k, [o, t]] of Object.entries(T)) check(S.outcomeText(o) === t, `outcomeText ${k}: ${S.outcomeText(o)}`);
check(S.outcomeText({ rolled_back: { reason: '<b>' } }).includes('&lt;b&gt;') === false, 'outcomeText возвращает текст, не HTML');

// Ход
const st = sample('searchStatus').state;
const h = S.renderState(st);
check(h.includes('120') && h.includes('480'), 'сделано/всего');
check(h.includes('1:03 / 5:00'), 'время m:ss / 5:00');
check(h.includes('rutracker.org') && h.includes('37'), 'строка домена и остаток');
check(h.includes('Общие') || h.includes('общ'), 'группа');
check(h.includes('Wi-Fi «Home»'), 'сеть');
check(h.includes('<progress'), 'полоса');
const xs = S.renderState({ ...st, domains: [{ group: 'general', domain: '<img src=x>', block: '<b>', left: 1 }], network_title: '<i>' });
check(!xs.includes('<img') && !xs.includes('<i>') && !xs.includes('<b>'), 'экранирование ctl-значений');

// Итог
const rep = sample('searchReport').state;
const r = S.renderState(rep);
check(r.includes('Применено частично: не подошло — YouTube'), 'итог в отчёте');
check(/<pre[^>]*>[^<]*fake_default_tls/.test(r) && r.includes('fake_default_http'), 'найденное в pre');
const ok = S.renderState({ ...rep, outcome: 'applied' });
check(ok.includes('Откройте видео в YouTube'), 'просьба открыть видео');
check(!S.renderState({ ...rep, outcome: 'not_found' }).includes('Откройте видео'), 'просьбы нет при not_found');

// Цифры check (спека §7.2)
check(rep.check.length === 4 && rep.verify.length === 5, 'образец: check и verify');
check(r.includes('Проверка check'), 'таблица check');
check(r.includes('3/3') && r.includes('91 %') && r.includes('2/3') && r.includes('64 %'), 'full/total и медиана');
check(r.includes('multidisorder:pos=1') && r.includes('1/3'), 'невыбранная строка check');
check((r.match(/выбрана/g) || []).length === 3, 'отметка «выбрана» у трёх выбранных');
const chk = S.renderState({ ...rep, check: [{ group: 'general', chain: 'tls', args: '<img src=x>', full: 1, total: '<b>', median_pct: null, picked: false }] });
check(!chk.includes('<img') && !chk.includes('<b>') && chk.includes('&lt;img'), 'экранирование check');
check(chk.includes('—') && !chk.includes('выбрана'), 'медиана без значения, не выбрана');
// Проверка через обход
check(r.includes('Проверка через обход'), 'таблица проверки через обход');
check(r.includes('www.youtube.com') && r.includes('TLS 1.3') && r.includes('HTTP'), 'домен и протокол');
check(r.includes('ok') && r.includes('сбой'), 'ok/сбой');
check(/<td>2<\/td>/.test(r) && /<td>1<\/td>/.test(r), 'номер круга');
const ver = S.renderState({ ...rep, verify: [{ group: 'general', domain: '<script>', proto: '<i>', ok: true, round: '<u>' }] });
check(!ver.includes('<script>') && !ver.includes('<i>') && !ver.includes('<u>'), 'экранирование проверки через обход');
check(!S.renderState({ ...rep, check: [], verify: [] }).includes('Проверка check'), 'без check — без таблицы');
check(!S.renderState({ ...rep, check: undefined, verify: undefined }).includes('Проверка через обход'), 'старый state без полей');

// Типы блокировки и шаги
for (const [b, t] of [['ip_blocked', 'блок по IP'], ['dns_failed', 'нет DNS'], ['deadline', 'срок истёк'], ['stopped', 'остановлено']]) {
  check(S.renderState({ ...st, domains: [{ group: 'general', domain: 'a.org', block: b, left: null }] }).includes(t), `тип блокировки ${b}`);
}
check(S.renderState({ ...st, phase: { check: { group: 'youtube' } } }).includes('YouTube'), 'шаг check');
check(S.renderState({ ...st, phase: 'verify' }).includes('Проверка через обход'), 'шаг verify');

// Partial: строки провалившейся группы помечены
const pre = (h) => (h.match(/<pre[^>]*>([^<]*)<\/pre>/) || [])[1] || '';
const pY = pre(r).split('\n');
check(pY.some((l) => l.startsWith('youtube:') && l.includes('убрано после проверки')), 'youtube помечен при partial youtube');
check(pY.filter((l) => l.includes('убрано после проверки')).length === 1, 'tls/http не помечены при partial youtube');
const pG = pre(S.renderState({ ...rep, outcome: { partial: { failed: 'general' } } })).split('\n');
check(pG.filter((l) => l.includes('убрано после проверки')).length === 2
  && pG.some((l) => l.startsWith('tls:') && l.includes('убрано')) && pG.some((l) => l.startsWith('http:') && l.includes('убрано')), 'tls и http помечены при partial general');
check(!S.renderState({ ...rep, outcome: 'applied' }).includes('убрано после проверки'), 'applied без пометок');

const er = S.renderState({ ...st, outcome: null, error: 'нет сети <x>' });
check(er.includes('нет сети &lt;x&gt;'), 'ошибка до шага 1');

// Основа
const nets = sample('networks'), set = sample('settings-get');
check(S.pickBase(nets, set) === 'default', 'NET_STRATEGY=0 → DEFAULT_STRATEGY');
const set1 = { ...set, settings: { ...set.settings, NET_STRATEGY: '1' } };
check(S.pickBase(nets, set1) === 'alt', 'NET_STRATEGY=1 → стратегия сети');
check(S.pickBase({ ...nets, current_key: 'zzz' }, set1) === 'default', 'нет записи → DEFAULT_STRATEGY');

// Запуск и согласие
async function run(netStrategy, answer) {
  const calls = []; const asked = [];
  const ctlFn = async (a) => { calls.push(a); return sample('searchStart'); };
  const r = await S.startSearch({ base: 'alt', netStrategy, confirmFn: (t) => { asked.push(t); return answer; }, ctlFn });
  return { calls, asked, r };
}
let x = await run('0', false);
check(x.calls.length === 0 && x.asked.length === 1, 'без согласия searchStart не вызван');
check(x.asked[0] === 'Чтобы назначить найденное этой сети, нужно включить стратегии по сетям. Сети с сохранённой стратегией начнут её использовать. Включить?', 'текст согласия');
x = await run('0', true);
check(JSON.stringify(x.calls) === JSON.stringify([cmd.searchStartNet('alt')]) && x.calls[0].includes('--enable-net-strategy'), 'с согласием --enable-net-strategy');
x = await run('1', false);
check(x.asked.length === 0 && JSON.stringify(x.calls) === JSON.stringify([cmd.searchStart('alt')]), 'NET_STRATEGY=1 без вопроса');

// Списки
check(S.DEFAULT_LISTS.general === 'rutracker.org\ndiscord.com\nx.com\ninstagram.com\n', 'умолчание Общие');
check(S.DEFAULT_LISTS.youtube === 'www.youtube.com\ni.ytimg.com\nredirector.googlevideo.com\n', 'умолчание YouTube');
const page = S.renderSearch({ nets, settings: set, base: 'default', lists: { general: 'a.com\n</textarea><script>', youtube: 'b.com\n' }, state: null, runs: sample('searchRuns').runs, strategies: ['default', 'alt'] });
check(!page.includes('<script>'), 'экранирование списка');
check(page.includes('data-act="find"') && !page.includes('data-act="stop"'), 'Найти без Стоп в простое');
check((page.match(/data-run=/g) || []).length === 3, 'история');
check(page.includes('Wi-Fi «Home»') && page.includes('<option'), 'сеть и основа');
check(/NET_STRATEGY|по сетям/.test(page), 'предупреждение про стратегии по сетям');
const busy = S.renderSearch({ nets, settings: set, base: 'default', lists: {}, state: st, runs: [], strategies: [] });
check(busy.includes('data-act="stop"') && !busy.includes('data-act="find"'), 'Стоп во время поиска');
done('test_search');
