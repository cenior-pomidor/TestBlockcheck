// Вкладка «Списки»: режим фильтрации и редактирование списков.
import { ctl, uploadText } from './bridge.js';
import { esc, button } from './util.js';

const TITLES = {
  user: 'Сайты для обхода',
  auto: 'Найденные автоматически',
  exclude: 'Исключения',
  ipset: 'IP-адреса для обхода',
  ipset_exclude: 'Исключённые IP-адреса',
};
const MODES = [
  ['list', 'Только сайты из списка'],
  ['all', 'Все сайты, кроме исключений'],
  ['auto', 'Список + автоматически найденные'],
];

export function renderLists(lists, settings) {
  if (!lists || lists.ok === false) return `<p class="state bad">Ошибка: ${esc(lists?.error || 'нет ответа')}</p>`;
  const mode = settings?.settings?.MODE || lists.mode;
  const opts = MODES.map(([v, t]) => `<label class="toggle"><input type="radio" name="mode" value="${v}"${v === mode ? ' checked' : ''}> ${esc(t)}</label>`).join('');
  const rows = lists.lists.map((l) => `<button type="button" class="row" data-list="${esc(l.name)}"><b>${esc(TITLES[l.name] || l.name)}</b>`
    + ` <span class="tag">${l.count}</span><br><small class="hint">${esc(l.name)}.list</small></button>`).join('');
  return `<div class="card"><h2>Режим</h2>${opts}</div><div class="list">${rows}</div>`;
}

export function renderListEditor(l) {
  return `<form class="editor" onsubmit="return false"><h2>${esc(TITLES[l.name] || l.name)}</h2>`
    + '<p class="hint">По одному домену или адресу на строку; строки с # — комментарии.</p>'
    + `<textarea name="text" spellcheck="false" autocapitalize="off">${esc(l.text)}</textarea>`
    + '<p class="error" id="editor-error" hidden></p>'
    + `<div class="actions">${button('save', 'Сохранить')}${button('back', 'Назад')}</div></form>`;
}

async function showEditor(root, toast, name) {
  const l = await ctl(['list', 'get', name], { timeoutMs: 30000 });
  if (!l.ok) { toast(l.error); return; }
  root.innerHTML = renderListEditor(l);
  const form = root.querySelector('form');
  const errBox = root.querySelector('#editor-error');
  form.querySelector('[data-act="back"]').onclick = () => showLists(root, toast);
  form.querySelector('[data-act="save"]').onclick = async () => {
    form.querySelectorAll('button').forEach((b) => { b.disabled = true; });
    errBox.hidden = true;
    let r;
    try {
      const path = await uploadText(form.elements.text.value.replace(/\r\n?/g, '\n'));
      r = await ctl(['list', 'set', name, '--from', path], { timeoutMs: 60000 });
    } catch (e) { r = { ok: false, error: e.message }; }
    form.querySelectorAll('button').forEach((b) => { b.disabled = false; });
    if (!r.ok) { errBox.textContent = r.error; errBox.hidden = false; return; }
    toast(r.warning ? `Сохранено. ${r.warning}` : 'Сохранено');
    await showLists(root, toast);
  };
}

export async function showLists(root, toast) {
  const [lists, settings] = await Promise.all([ctl(['lists']), ctl(['settings', 'get'])]);
  root.innerHTML = renderLists(lists, settings);
  root.querySelectorAll('input[name="mode"]').forEach((i) => {
    i.onchange = async () => {
      const r = await ctl(['settings', 'set', 'MODE', i.value], { timeoutMs: 40000 });
      toast(r.ok ? (r.warning ? `Режим изменён. ${r.warning}` : 'Режим изменён') : r.error);
      await showLists(root, toast);
    };
  });
  root.querySelectorAll('[data-list]').forEach((b) => { b.onclick = () => showEditor(root, toast, b.dataset.list); });
}
