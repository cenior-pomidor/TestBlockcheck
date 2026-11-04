// showSearch с поддельными DOM, мостом KernelSU и таймерами: утечка опроса, сохранение правок списков.
import { sample, check, done } from './helpers.mjs';

const intervals = new Set(); let nid = 1; const fns = new Map();
globalThis.setInterval = (f) => { const i = nid++; intervals.add(i); fns.set(i, f); return i; };
globalThis.clearInterval = (i) => { intervals.delete(i); };

let statusState = sample('searchStatus').state;
let holdReport = null; // функция-освобождение отложенного ответа report
globalThis.window = {
  ksu: {
    exec(line, _o, name) {
      const reply = (v) => window[name](0, JSON.stringify(v), '');
      if (line.includes("'report'")) { holdReport = () => reply(sample('searchReport')); return; }
      if (line.includes("'status'") && line.includes("'search'")) return reply({ ok: true, state: statusState, schema: 1 });
      if (line.includes("'search'") && line.includes("'runs'")) return reply(sample('searchRuns'));
      if (line.includes("'list'") && line.includes("'get'")) return reply({ ok: true, text: 'orig.com\n' });
      if (line.includes("'networks'")) return reply(sample('networks'));
      if (line.includes("'settings'")) return reply(sample('settings-get'));
      if (line.includes("'strategies'")) return reply(sample('strategies'));
      if (line.includes("'status'")) return reply(sample('status'));
      reply({ ok: false, error: 'неожиданно' });
    },
  },
};
const { showSearch } = await import('../../webroot/js/search.js');

function makeRoot() {
  const r = { html: '', stubs: {} };
  Object.defineProperty(r, 'innerHTML', { get: () => r.html, set: (v) => { r.html = v; r.stubs = {}; } });
  const stub = (k, init = {}) => (r.stubs[k] ||= { dataset: {}, ...init });
  r.querySelector = (sel) => {
    let m;
    if ((m = sel.match(/^textarea\[name="(\w+)"\]$/))) {
      const t = r.html.match(new RegExp(`name="${m[1]}"[^>]*>([^<]*)</textarea>`));
      return t ? stub(sel, { value: t[1] }) : null;
    }
    if (sel === 'select[name="base"]') return r.html.includes('<select') ? stub(sel, { value: 'default' }) : null;
    if (sel === '#search-state') return r.html.includes('id="search-state"') ? stub(sel) : null;
    if ((m = sel.match(/^\[data-act="([\w-]+)"\]$/))) return r.html.includes(`data-act="${m[1]}"`) ? stub(sel) : null;
    return null;
  };
  r.querySelectorAll = (sel) => {
    if (sel !== '[data-run]') return [];
    return [...r.html.matchAll(/data-run="([^"]+)"/g)].map((x) => stub('run' + x[1], { dataset: { run: x[1] } }));
  };
  return r;
}

// F1: уход с вкладки во время запроса отчёта не оставляет интервалов
{
  const root = makeRoot();
  const cleanup = await showSearch(root, () => {});
  check(typeof cleanup === 'function', 'showSearch возвращает cleanup');
  check(intervals.size === 1, 'опрос запущен при идущем поиске');
  const run = root.querySelectorAll('[data-run]')[0];
  const p = run.onclick();
  await new Promise((r) => setTimeout(r, 5));
  check(holdReport, 'отчёт запрошен');
  cleanup();
  holdReport();
  await p;
  check(intervals.size === 0, `интервалов после ухода: ${intervals.size}`);
}

// F2: правки списка переживают перерисовку по окончании поиска
{
  intervals.clear();
  statusState = sample('searchStatus').state;
  const root = makeRoot();
  const cleanup = await showSearch(root, () => {});
  const ta = root.querySelector('textarea[name="general"]');
  ta.value = 'edited.com';
  statusState = { ...statusState, outcome: 'not_found', phase: 'done' };
  await fns.get([...intervals][0])();
  check(root.html.includes('edited.com'), 'правка списка сохранена после перерисовки');
  check(!root.html.includes('orig.com') || root.html.indexOf('edited.com') >= 0, 'значение не затёрто');
  cleanup();
}
const S = await import('../../webroot/js/search.js');
check(S.outcomeText({ weird: 1 }) === '{"weird":1}', 'неизвестный итог — JSON');
done('test_search_tab');
