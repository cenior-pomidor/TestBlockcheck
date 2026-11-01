// Вкладка «Сети»: стратегии по сетям и домашние Wi-Fi.
import { LONG, ctl } from './bridge.js';
import { esc, button } from './util.js';
import { cmd } from './commands.js';

const WIFI_PREFIX = 'Wi-Fi «';

/** SSID текущей сети из подписи `Wi-Fi «…»` (формат Network::title), иначе null. */
export function currentSsid(n) {
  const t = n?.current_title;
  if (!n?.current_key?.startsWith('wifi_') || !t?.startsWith(WIFI_PREFIX) || !t.endsWith('»')) return null;
  return t.slice(WIFI_PREFIX.length, -1);
}

function toggle(key, title, on, hint) {
  return `<label class="toggle"><input type="checkbox" data-setting="${key}"${on ? ' checked' : ''}> ${esc(title)}</label>`
    + `<p class="hint">${esc(hint)}</p>`;
}

export function renderNetworks(n, settings, status) {
  if (!n || n.ok === false) return `<p class="state bad">Ошибка: ${esc(n?.error || 'нет ответа')}</p>`;
  const s = settings?.settings || {};
  const parts = [];
  parts.push('<div class="card">'
    + toggle('NET_STRATEGY', 'Своя стратегия для каждой сети', s.NET_STRATEGY === '1',
      'Стратегия, применённая «Для этой сети», запоминается за сетью и включается при подключении к ней.')
    + toggle('HOME_WIFI', 'Пауза в домашних Wi-Fi', s.HOME_WIFI === '1',
      'В сетях из списка ниже обход выключается.')
    + '</div>');

  const ssid = currentSsid(n);
  const strategy = status && status.ok !== false ? status.strategy : null;
  let cur = `<h2>Сейчас</h2><p>${esc(n.current_title || 'нет сети')}${strategy ? ` — <b>${esc(strategy)}</b>` : ''}</p>`;
  if (ssid !== null && !n.home.includes(ssid)) cur += `<div class="actions">${button('home-add', 'Добавить текущую в домашние')}</div>`;
  parts.push(`<div class="card">${cur}</div>`);

  const saved = n.networks.map((x) => `<div class="item"><span>${esc(x.title)} — <b>${esc(x.strategy)}</b></span>`
    + `<button type="button" data-net-del="${esc(x.key)}">Забыть</button></div>`).join('');
  parts.push(`<div class="card"><h2>Сети со своей стратегией</h2>${saved || '<p class="hint">Пока нет.</p>'}</div>`);

  const home = n.home.map((h) => `<div class="item"><span>${esc(h)}</span>`
    + `<button type="button" data-home-del="${esc(h)}">Убрать</button></div>`).join('');
  parts.push(`<div class="card"><h2>Домашние Wi-Fi</h2>${home || '<p class="hint">Пока нет.</p>'}</div>`);

  const w = [...(n.warnings || []), ...(settings?.warnings || [])];
  if (w.length) parts.push(`<div class="card warn">${w.map((x) => `<p>${esc(x)}</p>`).join('')}</div>`);
  return parts.join('');
}

export async function showNetworks(root, toast) {
  const [n, settings, status] = await Promise.all([ctl(cmd.networks()), ctl(cmd.settingsGet()), ctl(cmd.status())]);
  root.innerHTML = renderNetworks(n, settings, status);
  const after = async (r, msg) => {
    if (!r.ok) toast(r.error || 'не удалось');
    else if (r.warning) toast(`${msg}. ${r.warning}`);
    else toast(msg);
    await showNetworks(root, toast);
  };
  root.querySelectorAll('input[data-setting]').forEach((i) => {
    i.onchange = async () => after(await ctl(cmd.settingsSet(i.dataset.setting, i.checked ? '1' : '0'), { timeoutMs: LONG }), 'Сохранено');
  });
  const add = root.querySelector('[data-act="home-add"]');
  if (add) add.onclick = async () => after(await ctl(cmd.homeAdd(currentSsid(n)), { timeoutMs: LONG }), 'Добавлено');
  root.querySelectorAll('[data-net-del]').forEach((b) => {
    b.onclick = async () => after(await ctl(cmd.networkDelete(b.dataset.netDel), { timeoutMs: LONG }), 'Забыто');
  });
  root.querySelectorAll('[data-home-del]').forEach((b) => {
    b.onclick = async () => after(await ctl(cmd.homeRemove(b.dataset.homeDel), { timeoutMs: LONG }), 'Убрано');
  });
}
