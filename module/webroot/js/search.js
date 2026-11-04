// Вкладка «Поиск»: фоновый поиск стратегии (`bcw ctl search …`), ход, итог, история, списки доменов.
import { LONG, ctl, uploadText } from './bridge.js';
import { esc, button } from './util.js';
import { cmd } from './commands.js';

const GROUPS = { general: 'Общие', youtube: 'YouTube' };
const LISTS = { general: 'search-general', youtube: 'search-youtube' };
const BLOCKS = { sni_blocked: 'блок по SNI', not_blocked: 'не заблокирован', throttled: 'замедление' };
const STEPS = {
  prepare: 'Подготовка', baseline: 'Проверка доменов', apply: 'Применение', verify: 'Проверка через обход',
  rollback: 'Откат', done: 'Готово',
};
export const NET_CONSENT = 'Чтобы назначить найденное этой сети, нужно включить стратегии по сетям. '
  + 'Сети с сохранённой стратегией начнут её использовать. Включить?';
export const DEFAULT_LISTS = {
  general: 'rutracker.org\ndiscord.com\nx.com\ninstagram.com\n',
  youtube: 'www.youtube.com\ni.ytimg.com\nredirector.googlevideo.com\n',
};

const group = (g) => GROUPS[g] || String(g ?? '');

/** Текст итога (без HTML-экранирования: оно при выводе). */
export function outcomeText(o) {
  if (o === 'applied') return 'Применено и проверено';
  if (o === 'not_found') return 'Не найдено';
  if (o === 'stopped') return 'Остановлено';
  if (o === 'network_changed') return 'Сеть сменилась — найденное не применено';
  if (o && typeof o === 'object') {
    if (o.partial) return `Применено частично: не подошло — ${group(o.partial.failed)}`;
    if (o.rolled_back) return `Откат: ${o.rolled_back.reason ?? ''}`;
    if (o.saved_not_applied) return `Сохранено, не применено: обход ${o.saved_not_applied.state ?? ''}`;
  }
  if (o && typeof o === 'object') return JSON.stringify(o);
  return String(o ?? '');
}

function phaseText(p) {
  if (typeof p === 'string') return STEPS[p] || p;
  if (p && p.narrow) return `Перебор: ${group(p.narrow.group)}`;
  if (p && p.check) return `Уточнение: ${group(p.check.group)}`;
  return '';
}

const mmss = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;

/** HTML хода или итога поиска по `state` из `search status`/`search report`. */
export function renderState(s) {
  if (!s) return '';
  const out = [];
  if (s.network_title) out.push(`<p class="hint">Сеть: ${esc(s.network_title)} · основа: ${esc(s.base)}</p>`);
  if (s.error) out.push(`<p class="state bad">Ошибка: ${esc(s.error)}</p>`);
  if (s.outcome == null && !s.error) {
    out.push(`<p class="state warn">${esc(phaseText(s.phase))}</p>`
      + `<progress max="${Number(s.total) || 0}" value="${Number(s.done) || 0}"></progress>`
      + `<p>${Number(s.done) || 0} / ${Number(s.total) || 0} · ${mmss(Number(s.elapsed_s) || 0)} / 5:00</p>`);
  } else if (s.outcome != null) {
    const good = s.outcome === 'applied' || !!(s.outcome && s.outcome.partial);
    out.push(`<p class="state ${good ? 'good' : 'warn'}">${esc(outcomeText(s.outcome))}</p>`);
    if (s.outcome === 'applied' || (s.outcome && s.outcome.partial)) {
      out.push('<p>Откройте видео в YouTube и убедитесь, что оно идёт: серверы видео автоматически не проверяются.</p>');
    }
  }
  const rows = (s.domains || []).map((d) => `<div class="item"><span>${esc(group(d.group))} · ${esc(d.domain)}</span>`
    + `<span class="hint">${esc(BLOCKS[d.block] || d.block || '—')}${d.left == null ? '' : ` · осталось ${esc(d.left)}`}</span></div>`).join('');
  if (rows) out.push(`<div class="card">${rows}</div>`);
  const f = s.found || {};
  const lines = ['tls', 'http', 'youtube'].filter((k) => f[k]).map((k) => `${k}: ${f[k]}`);
  if (lines.length) out.push(`<h2>Найдено</h2><pre>${esc(lines.join('\n'))}</pre>`);
  return out.join('');
}

/** Основа по умолчанию: стратегия текущей сети (при NET_STRATEGY=1 и записи) или DEFAULT_STRATEGY. */
export function pickBase(nets, settings) {
  const v = settings?.settings || {};
  const def = v.DEFAULT_STRATEGY || 'default';
  if (v.NET_STRATEGY !== '1') return def;
  const n = (nets?.networks || []).find((x) => x.key === nets.current_key);
  return n && n.strategy ? n.strategy : def;
}

/**
 * Запуск поиска. При NET_STRATEGY=0 нужно согласие (confirmFn); без него `search start` не вызывается.
 * Возвращает ответ ctl или null, если пользователь отказался.
 */
export async function startSearch({ base, netStrategy, confirmFn, ctlFn = ctl }) {
  if (netStrategy !== '1') {
    if (!confirmFn(NET_CONSENT)) return null;
    return ctlFn(cmd.searchStartNet(base), { timeoutMs: LONG });
  }
  return ctlFn(cmd.searchStart(base), { timeoutMs: LONG });
}

const running = (s) => !!s && s.outcome == null && !s.error;

/** Страница вкладки. m: {nets, settings, base, lists, state, runs, strategies, status}. */
export function renderSearch(m) {
  const net = m.nets?.current_title;
  const names = [...new Set([...(m.strategies || []), m.base].filter(Boolean))];
  const opts = names.map((n) => `<option value="${esc(n)}"${n === m.base ? ' selected' : ''}>${esc(n)}</option>`).join('');
  const busy = running(m.state);
  const netOn = m.settings?.settings?.NET_STRATEGY === '1';
  const head = `<div class="card"><h2>Поиск стратегии</h2>`
    + `<p>Сеть: ${esc(net || 'нет сети')}${m.status?.state ? ` · обход: ${esc(m.status.state)}` : ''}</p>`
    + `<label>Основа <select name="base"${busy ? ' disabled' : ''}>${opts}</select></label>`
    + (netOn ? '' : '<p class="hint">Стратегии по сетям (NET_STRATEGY) выключены: перед запуском будет вопрос о включении.</p>')
    + `<div class="actions">${busy ? button('stop', 'Стоп') : button('find', 'Найти')}</div></div>`;
  const lists = Object.keys(GROUPS).map((g) => `<label>${esc(GROUPS[g])}`
    + `<textarea name="${g}" spellcheck="false" autocapitalize="off"${busy ? ' disabled' : ''}>${esc(m.lists?.[g] ?? '')}</textarea></label>`
    + `<div class="actions">${button('save-' + g, 'Сохранить')}${button('default-' + g, 'По умолчанию')}</div>`).join('');
  const hist = (m.runs || []).map((r) => `<button type="button" class="row" data-run="${esc(r.id)}"><b>${esc(r.time || r.id)}</b>`
    + ` <small class="hint">${esc(r.network_title || '')}</small><br>`
    + `${esc(r.error ? `Ошибка: ${r.error}` : r.outcome == null ? 'Идёт или прервано' : outcomeText(r.outcome))}</button>`).join('');
  return `${head}<div id="search-state">${renderState(m.state)}</div>`
    + `<form class="editor card" onsubmit="return false"><h2>Домены для проверки</h2>`
    + `<p class="hint">По одному домену на строку.</p>${lists}</form>`
    + `<h2>История</h2><div class="list">${hist || '<p class="hint">Поисков ещё не было</p>'}</div>`;
}

async function readLists() {
  const out = {};
  for (const g of Object.keys(LISTS)) {
    const r = await ctl(cmd.listGet(LISTS[g]), { timeoutMs: 30000 });
    out[g] = r.ok ? r.text : '';
  }
  return out;
}

/** Вкладка; возвращает функцию остановки опроса. */
export async function showSearch(root, toast) {
  let timer = null;
  let alive = true;
  const stopPoll = () => { if (timer) { clearInterval(timer); timer = null; } };
  const cleanup = () => { alive = false; stopPoll(); };

  async function load() {
    const [nets, settings, strategies, status, st, runs, lists] = await Promise.all([
      ctl(cmd.networks()), ctl(cmd.settingsGet()), ctl(cmd.strategies()), ctl(cmd.status()),
      ctl(cmd.searchStatus()), ctl(cmd.searchRuns()), readLists(),
    ]);
    if (!alive) return;
    // Несохранённые правки списков переживают перерисовку (например, по окончании поиска).
    for (const g of Object.keys(LISTS)) {
      const ta = root.querySelector(`textarea[name="${g}"]`);
      if (ta) lists[g] = ta.value;
    }
    const state = st.ok && st.state ? st.state : null;
    const keepBase = root.querySelector('select[name="base"]')?.value;
    root.innerHTML = renderSearch({
      nets, settings, status, lists, state, runs: runs.ok ? runs.runs : [],
      strategies: strategies.ok ? strategies.strategies.map((x) => x.name) : [],
      base: keepBase || pickBase(nets, settings),
    });
    bind(settings?.settings?.NET_STRATEGY, state);
    if (running(state)) poll();
  }

  function poll() {
    stopPoll();
    if (!alive) return;
    timer = setInterval(async () => {
      const st = await ctl(cmd.searchStatus());
      if (!alive) return;
      const box = root.querySelector('#search-state');
      if (!st.ok || !st.state) return;
      if (box) box.innerHTML = renderState(st.state);
      if (!running(st.state)) { stopPoll(); await load(); }
    }, 1000);
  }

  function bind(netStrategy, state) {
    const base = () => root.querySelector('select[name="base"]').value;
    const act = (a) => root.querySelector(`[data-act="${a}"]`);
    if (act('find')) {
      act('find').onclick = async () => {
        const r = await startSearch({ base: base(), netStrategy, confirmFn: (t) => globalThis.confirm(t) });
        if (!alive) return;
        if (r === null) return;
        if (!r.ok) { toast(r.error || 'не удалось запустить поиск'); return; }
        await load();
      };
    }
    if (act('stop')) {
      act('stop').onclick = async () => {
        act('stop').disabled = true;
        const r = await ctl(cmd.searchStop(), { timeoutMs: LONG });
        if (!alive) return;
        if (!r.ok) toast(r.error || 'не удалось остановить');
        await load();
      };
    }
    for (const g of Object.keys(LISTS)) {
      const ta = root.querySelector(`textarea[name="${g}"]`);
      act('default-' + g).onclick = () => { ta.value = DEFAULT_LISTS[g]; };
      act('save-' + g).onclick = async () => {
        let r;
        try {
          const path = await uploadText(ta.value.replace(/\r\n?/g, '\n'));
          r = await ctl(cmd.listSet(LISTS[g], path), { timeoutMs: LONG });
        } catch (e) { r = { ok: false, error: e.message }; }
        if (!alive) return;
        toast(r.ok ? 'Сохранено' : r.error);
      };
    }
    root.querySelectorAll('[data-run]').forEach((b) => {
      b.onclick = async () => {
        const r = await ctl(cmd.searchReport(b.dataset.run));
        if (!alive) return;
        if (!r.ok) { toast(r.error); return; }
        stopPoll();
        root.querySelector('#search-state').innerHTML = renderState(r.state);
        if (running(state) && r.state.id === state.id) poll();
      };
    });
  }

  await load();
  return cleanup;
}
