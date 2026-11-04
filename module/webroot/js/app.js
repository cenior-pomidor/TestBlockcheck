// Вкладки и общий каркас WebUI.
import { showStatus } from './status.js';
import { showSearch } from './search.js';
import { showStrategies } from './strategies.js';
import { showNetworks } from './networks.js';
import { showLists } from './lists.js';
import { showLogs } from './logs.js';
import { showSettings } from './settings.js';

const tabs = [];

/** Зарегистрировать вкладку: show(root, toast) рисует её содержимое. */
export function registerTab(id, title, show) {
  tabs.push({ id, title, show });
}

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 6000);
}

let cleanup = null; // освобождение ресурсов открытой вкладки (например, опроса)
let opening = 0;

async function open(id) {
  const my = ++opening;
  if (cleanup) { try { cleanup(); } catch (_) { /* ничего */ } cleanup = null; }
  const tab = tabs.find((t) => t.id === id) || tabs[0];
  document.querySelectorAll('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab.id));
  const root = document.getElementById('content');
  root.innerHTML = '<p class="hint">Загрузка…</p>';
  try {
    const c = await tab.show(root, toast);
    if (typeof c === 'function') {
      if (my === opening) cleanup = c; else c();
    }
  } catch (e) {
    root.innerHTML = '';
    toast(String(e.message || e));
  }
}

registerTab('status', 'Состояние', showStatus);
registerTab('search', 'Поиск', showSearch);
registerTab('strategies', 'Стратегии', showStrategies);
registerTab('networks', 'Сети', showNetworks);
registerTab('lists', 'Списки', showLists);
registerTab('logs', 'Журналы', showLogs);
registerTab('settings', 'Настройки', showSettings);

function start() {
  const nav = document.getElementById('tabs');
  nav.innerHTML = '';
  for (const t of tabs) {
    const b = document.createElement('button');
    b.type = 'button';
    b.dataset.tab = t.id;
    b.textContent = t.title;
    b.onclick = () => open(t.id);
    nav.appendChild(b);
  }
  open('status');
}

if (globalThis.document) {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
}
