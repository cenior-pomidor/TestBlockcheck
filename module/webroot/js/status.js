// Вкладка «Состояние».
import { LONG, ctl } from './bridge.js';
import { esc, button } from './util.js';
import { cmd } from './commands.js';

const capital = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);

/** HTML вкладки по ответу `ctl status`. */
export function renderStatus(s) {
  if (!s || s.ok === false) {
    return `<p class="state bad">Ошибка: ${esc(s?.error || 'нет ответа')}</p>${button('refresh', 'Обновить')}`;
  }
  let line;
  let cls = 'warn';
  let acts = [];
  switch (s.state) {
    case 'running':
      line = 'Работает'; cls = 'good';
      acts = [button('restart', 'Перезапустить'), button('stop', 'Остановить')];
      break;
    case 'paused_home':
      line = `Пауза: ${s.reason || 'домашняя сеть'}`;
      acts = [button('resume', 'Включить здесь сейчас'), button('stop', 'Остановить')];
      break;
    case 'blocked_neighbour':
      line = `Не запущено: ${s.reason || 'работает другой модуль обхода'}`; cls = 'bad';
      acts = [button('start', 'Запустить')];
      break;
    case 'failed':
      line = `Ошибка: ${s.reason || 'nfqws2 не запускается'}`; cls = 'bad';
      acts = [button('start', 'Запустить'), button('stop', 'Остановить')];
      break;
    case 'not_running':
      line = 'Служба не запущена'; cls = 'bad';
      break;
    default:
      line = s.reason ? `Остановлено: ${s.reason}` : 'Остановлено';
      acts = [button('start', 'Запустить')];
  }
  const rows = [];
  if (s.network_title) rows.push(['Сеть', s.network_title]);
  if (s.strategy) rows.push(['Стратегия', s.strategy]);
  const dl = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
  return `<p class="state ${cls}">${esc(capital(line))}</p>`
    + (dl ? `<dl>${dl}</dl>` : '')
    + `<div class="actions">${acts.join('')}${button('refresh', 'Обновить')}</div>`
    + (s.state === 'not_running' ? '<p class="hint">Служба стартует после загрузки телефона. Если её нет дольше минуты — смотрите журнал svc.out в /data/adb/bcw/logs.</p>' : '');
}

const ACTS = { start: cmd.start(), stop: cmd.stop(), restart: cmd.restart(), resume: cmd.homeResume() };

/** Нарисовать вкладку и навесить кнопки. */
export async function showStatus(root, toast) {
  const s = await ctl(cmd.status());
  root.innerHTML = renderStatus(s);
  root.querySelectorAll('button[data-act]').forEach((b) => {
    b.onclick = async () => {
      const act = b.dataset.act;
      if (ACTS[act]) {
        root.querySelectorAll('button').forEach((x) => { x.disabled = true; });
        const r = await ctl(ACTS[act], { timeoutMs: LONG });
        if (!r.ok) toast(r.error || 'не удалось');
      }
      await showStatus(root, toast);
    };
  });
}
