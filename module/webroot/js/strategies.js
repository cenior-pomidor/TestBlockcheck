// Вкладка «Стратегии»: список пресетов и редактор шести ключей.
import { ctl, uploadText } from './bridge.js';
import { esc, button } from './util.js';

export const KEYS = ['NFQWS_BASE_ARGS', 'NFQWS_ARGS', 'NFQWS_ARGS_QUIC', 'NFQWS_ARGS_UDP', 'NFQWS_ARGS_IPSET', 'NFQWS_ARGS_CUSTOM'];
const LABELS = {
  NFQWS_BASE_ARGS: 'Общие аргументы (lua, blob)',
  NFQWS_ARGS: 'TCP',
  NFQWS_ARGS_QUIC: 'QUIC',
  NFQWS_ARGS_UDP: 'UDP',
  NFQWS_ARGS_IPSET: 'Списки IP',
  NFQWS_ARGS_CUSTOM: 'Дополнительно',
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
  const areas = KEYS.map((k) => `<label>${esc(LABELS[k])} <small class="hint">${k}</small>`
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

/** Поля редактора → текст пресета: по ключу на строку, значение в двойных кавычках. */
export function editorToText(fields) {
  return KEYS.map((k) => {
    const v = String(fields[k] ?? '').replace(/\r\n?/g, '\n').trim();
    if (v.includes('"')) throw new Error(`${k}: двойная кавычка в значении не поддерживается`);
    return `${k}="${v}"\n`;
  }).join('');
}

function readFields(form) {
  const f = {};
  for (const k of KEYS) f[k] = form.elements[k].value;
  return f;
}

async function showList(root, toast) {
  const [list, status] = await Promise.all([ctl(['strategies']), ctl(['status'])]);
  root.innerHTML = renderStrategies(list, status);
  root.querySelectorAll('[data-open]').forEach((b) => { b.onclick = () => showEditor(root, toast, b.dataset.open); });
  const n = root.querySelector('[data-act="new"]');
  if (n) n.onclick = () => showEditor(root, toast, null);
}

async function showEditor(root, toast, name) {
  let s = null;
  if (name) {
    s = await ctl(['strategy', 'get', name]);
    if (!s.ok) { toast(s.error); return; }
  }
  root.innerHTML = renderEditor(s);
  const form = root.querySelector('form');
  const errBox = root.querySelector('#editor-error');
  const fail = (msg) => { errBox.textContent = msg; errBox.hidden = false; };
  const busy = (on) => form.querySelectorAll('button').forEach((b) => { b.disabled = on; });
  const run = async (args, okMsg, after) => {
    busy(true);
    errBox.hidden = true;
    const r = await ctl(args, { timeoutMs: 40000 });
    busy(false);
    if (!r.ok) { fail(r.error); return; }
    toast(r.warning ? `${okMsg}. ${r.warning}` : okMsg);
    await after();
  };
  const target = () => (name || form.elements.name.value.trim());
  form.querySelectorAll('button[data-act]').forEach((b) => {
    b.onclick = async () => {
      switch (b.dataset.act) {
        case 'save': {
          let path;
          try {
            if (!target()) throw new Error('укажите имя');
            busy(true);
            path = await uploadText(editorToText(readFields(form)));
          } catch (e) { busy(false); fail(e.message); return; }
          await run(['strategy', 'save', target(), '--from', path], 'Сохранено', () => showEditor(root, toast, target()));
          break;
        }
        case 'apply-network': await run(['strategy', 'apply', name, '--network'], 'Применено для этой сети', () => showList(root, toast)); break;
        case 'apply-default': await run(['strategy', 'apply', name, '--default'], 'Стратегия по умолчанию', () => showList(root, toast)); break;
        case 'reset': await run(['strategy', 'reset', name], 'Возвращён исходник', () => showEditor(root, toast, name)); break;
        case 'delete':
          if (globalThis.confirm && !confirm(`Удалить «${name}»?`)) return;
          await run(['strategy', 'delete', name], 'Удалено', () => showList(root, toast));
          break;
        default: await showList(root, toast);
      }
    };
  });
}

export const showStrategies = showList;
