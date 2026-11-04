// Вкладка «Стратегии»: список пресетов и редактор шести ключей.
import { LONG, ctl, uploadText } from './bridge.js';
import { esc, button } from './util.js';
import { cmd } from './commands.js';

export const KEYS = ['NFQWS_BASE_ARGS', 'NFQWS_ARGS', 'NFQWS_ARGS_QUIC', 'NFQWS_ARGS_UDP', 'NFQWS_ARGS_IPSET', 'NFQWS_ARGS_CUSTOM', 'FOUND_YOUTUBE', 'FOUND_TLS', 'FOUND_HTTP'];
const FOUND = KEYS.slice(6);
const BASE = KEYS.slice(0, 6);
/** Поля `FOUND_*` нужны, только если в пресете хотя бы одно непустое. */
const hasFound = (fields) => FOUND.some((k) => String(fields?.[k] ?? '').trim() !== '');
const LABELS = {
  NFQWS_BASE_ARGS: 'Общие аргументы (lua, blob)',
  NFQWS_ARGS: 'TCP',
  NFQWS_ARGS_QUIC: 'QUIC',
  NFQWS_ARGS_UDP: 'UDP',
  NFQWS_ARGS_IPSET: 'Списки IP',
  NFQWS_ARGS_CUSTOM: 'Дополнительно',
  FOUND_YOUTUBE: 'Найдено: YouTube',
  FOUND_TLS: 'Найдено: TLS',
  FOUND_HTTP: 'Найдено: HTTP',
};

/** Список стратегий; текущая берётся из `ctl status`. */
export function renderStrategies(list, status) {
  if (!list || list.ok === false) return `<p class="state bad">Ошибка: ${esc(list?.error || 'нет ответа')}</p>`;
  const current = status && status.ok !== false ? status.strategy : null;
  const items = list.strategies.map((s) => {
    const marks = [];
    if (s.name === current) marks.push('<span class="tag good">сейчас</span>');
    if (s.name === list.default_strategy) marks.push('<span class="tag">по умолчанию</span>');
    if (s.modified) marks.push('<span class="tag warn">изменён</span>');
    if (!s.builtin) marks.push('<span class="tag">свой</span>');
    const who = [s.author, s.source].filter(Boolean).map(esc).join(' · ');
    return `<button type="button" class="row" data-open="${esc(s.name)}"><b>${esc(s.name)}</b> ${marks.join(' ')}`
      + (who ? `<br><small class="hint">${who}</small>` : '') + '</button>';
  });
  return `<div class="actions">${button('new', 'Новый')}</div><div class="list">${items.join('')}</div>`;
}

/** Отступы строк убираются: аргументы разделяются любыми пробелами, смысл не меняется. */
export function dedent(v) {
  return String(v || '').split('\n').map((l) => l.trim()).join('\n');
}

/** Редактор по ответу `ctl strategy get` или пустой (`null`) для новой стратегии. */
export function renderEditor(s) {
  const isNew = !s;
  const fields = s?.fields || {};
  const head = isNew
    ? '<label>Имя новой стратегии<input name="name" autocomplete="off" spellcheck="false" placeholder="my-strategy"></label>'
    : `<h2>${esc(s.name)}${s.modified ? ' <span class="tag warn">изменён</span>' : ''}</h2>`;
  const areas = (hasFound(fields) ? KEYS : BASE).map((k) => `<label>${esc(LABELS[k])} <small class="hint">${k}</small>`
    + `<textarea name="${k}" spellcheck="false" autocapitalize="off" rows="4">${esc(dedent(fields[k]))}</textarea></label>`).join('');
  const acts = [button('save', 'Сохранить')];
  if (!isNew) {
    acts.push(button('apply-network', 'Для этой сети'), button('apply-default', 'По умолчанию'));
    if (s.builtin && s.modified) acts.push(button('reset', 'Вернуть к исходнику'));
    if (!s.builtin) acts.push(button('delete', 'Удалить'));
  }
  acts.push(button('back', 'Назад'));
  return `<form class="editor" onsubmit="return false">${head}${areas}<p class="error" id="editor-error" hidden></p>`
    + `<div class="actions">${acts.join('')}</div></form>`;
}

/** Строки лимитов пакетов пресета (`NFQWS2_{TCP,UDP}_PKT_{OUT,IN}`, в т. ч. закомментированные). */
export function pktLines(text) {
  return String(text || '').split('\n').filter((l) => /^[\s#]*NFQWS2_(TCP|UDP)_PKT_(OUT|IN)=/.test(l));
}

/** Поля редактора → текст пресета: по ключу на строку, значение в двойных кавычках.
 *  Лимиты пакетов из исходного текста (`original`) переносятся без изменений. */
export function editorToText(fields, original = '') {
  const keys = (hasFound(fields) ? KEYS : BASE).map((k) => {
    const v = String(fields[k] ?? '').replace(/\r\n?/g, '\n').trim();
    if (v.includes('"')) throw new Error(`${k}: двойная кавычка в значении не поддерживается`);
    return `${k}="${v}"\n`;
  }).join('');
  const pkt = pktLines(original);
  return pkt.length ? `${keys}\n${pkt.join('\n')}\n` : keys;
}

function readFields(form) {
  const f = {};
  for (const k of KEYS) if (form.elements[k]) f[k] = form.elements[k].value;
  return f;
}

async function showList(root, toast) {
  const [list, status] = await Promise.all([ctl(cmd.strategies()), ctl(cmd.status())]);
  root.innerHTML = renderStrategies(list, status);
  root.querySelectorAll('[data-open]').forEach((b) => { b.onclick = () => showEditor(root, toast, b.dataset.open); });
  const n = root.querySelector('[data-act="new"]');
  if (n) n.onclick = () => showEditor(root, toast, null);
}

async function showEditor(root, toast, name) {
  let s = null;
  if (name) {
    s = await ctl(cmd.strategyGet(name));
    if (!s.ok) { toast(s.error); return; }
  }
  root.innerHTML = renderEditor(s);
  const form = root.querySelector('form');
  const errBox = root.querySelector('#editor-error');
  const fail = (msg) => { errBox.textContent = msg; errBox.hidden = false; };
  let dirty = false;
  const isApply = (b) => b.dataset.act === 'apply-network' || b.dataset.act === 'apply-default';
  const busy = (on) => form.querySelectorAll('button').forEach((b) => { b.disabled = on || (dirty && isApply(b)); });
  const run = async (args, okMsg, after) => {
    busy(true);
    errBox.hidden = true;
    const r = await ctl(args, { timeoutMs: LONG });
    busy(false);
    if (!r.ok) { fail(r.error); return; }
    toast(r.warning ? `${okMsg}. ${r.warning}` : okMsg);
    await after();
  };
  const target = () => (name || form.elements.name.value.trim());
  // Применяется сохранённая версия: пока есть несохранённые правки, применять нельзя.
  form.querySelectorAll('textarea').forEach((t) => {
    t.oninput = () => {
      dirty = true;
      form.querySelectorAll('button').forEach((b) => { if (isApply(b)) { b.disabled = true; b.title = 'Сначала сохраните'; } });
    };
  });
  form.querySelectorAll('button[data-act]').forEach((b) => {
    b.onclick = async () => {
      switch (b.dataset.act) {
        case 'save': {
          let path;
          try {
            if (!target()) throw new Error('укажите имя');
            if (!name) {
              const list = await ctl(cmd.strategies());
              const taken = list.ok && list.strategies.some((x) => x.name === target());
              if (taken && globalThis.confirm && !confirm(`Стратегия «${target()}» уже есть. Заменить её?`)) return;
            }
            busy(true);
            path = await uploadText(editorToText(readFields(form), s?.text));
          } catch (e) { busy(false); fail(e.message); return; }
          await run(cmd.strategySave(target(), path), 'Сохранено', () => showEditor(root, toast, target()));
          break;
        }
        case 'apply-network': await run(cmd.strategyApplyNetwork(name), 'Применено для этой сети', () => showList(root, toast)); break;
        case 'apply-default': await run(cmd.strategyApplyDefault(name), 'Стратегия по умолчанию', () => showList(root, toast)); break;
        case 'reset': await run(cmd.strategyReset(name), 'Возвращён исходник', () => showEditor(root, toast, name)); break;
        case 'delete':
          if (globalThis.confirm && !confirm(`Удалить «${name}»?`)) return;
          await run(cmd.strategyDelete(name), 'Удалено', () => showList(root, toast));
          break;
        default: await showList(root, toast);
      }
    };
  });
}

export const showStrategies = showList;
