// Вкладка «Журналы».
import { ctl } from './bridge.js';
import { esc, button } from './util.js';
import { cmd } from './commands.js';

export const LOG_FILES = [['service', 'Служба'], ['nfqws2', 'nfqws2'], ['auto', 'Автосписок']];
const TAIL = 500;

export function renderLogs(logs, stats, { file = 'service', errorsOnly = false } = {}) {
  const pick = LOG_FILES.map(([id, t]) => `<label class="toggle"><input type="radio" name="file" value="${id}"${id === file ? ' checked' : ''}> ${esc(t)}</label>`).join('');
  const st = stats?.ok !== false && stats?.stats
    ? `<p class="hint">Запусков: ${stats.stats.starts} · перезапусков: ${stats.stats.restarts} · ошибок: ${stats.stats.errors} · добавлено в автосписок: ${stats.stats.auto_added}</p>`
    : '';
  let body;
  if (!logs || logs.ok === false) body = `<p class="error">${esc(logs?.error || 'нет ответа')}</p>`;
  else body = logs.text ? `<pre>${esc(logs.text)}</pre>` : '<p class="hint">Пусто.</p>';
  return `<div class="card">${pick}<label class="toggle"><input type="checkbox" name="errors"${errorsOnly ? ' checked' : ''}> Только ошибки</label></div>`
    + st + `<div class="actions">${button('refresh', 'Обновить')}${button('clear', 'Очистить все')}</div>`
    + `<p class="hint">Последние ${TAIL} строк.</p>${body}`;
}

export async function showLogs(root, toast, view = { file: 'service', errorsOnly: false }) {
  const [logs, stats] = await Promise.all([ctl(cmd.logs(view.file, TAIL, view.errorsOnly)), ctl(cmd.stats())]);
  root.innerHTML = renderLogs(logs, stats, view);
  const again = () => showLogs(root, toast, {
    file: root.querySelector('input[name="file"]:checked').value,
    errorsOnly: root.querySelector('input[name="errors"]').checked,
  });
  root.querySelectorAll('input').forEach((i) => { i.onchange = again; });
  root.querySelector('[data-act="refresh"]').onclick = again;
  root.querySelector('[data-act="clear"]').onclick = async () => {
    if (globalThis.confirm && !confirm('Очистить все журналы?')) return;
    const r = await ctl(cmd.logsClear());
    if (!r.ok) toast(r.error);
    await again();
  };
  const pre = root.querySelector('pre');
  if (pre) pre.scrollIntoView({ block: 'end' });
}
