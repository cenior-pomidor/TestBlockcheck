// Вкладка «Настройки». Значения проверяет `bcw ctl settings set`; здесь своих проверок нет.
import { ctl } from './bridge.js';
import { esc, button } from './util.js';

export const settingControls = [
  { key: 'AUTOSTART', label: 'Запускать обход после загрузки', kind: 'bool' },
  { key: 'WATCHDOG', label: 'Перезапускать nfqws2, если он упал', kind: 'bool' },
  { key: 'NET_STRATEGY', label: 'Своя стратегия для каждой сети', kind: 'bool' },
  { key: 'HOME_WIFI', label: 'Пауза в домашних Wi-Fi', kind: 'bool' },
  { key: 'TCP_PORTS', label: 'TCP-порты', kind: 'text', hint: 'через запятую, диапазон — a:b' },
  { key: 'UDP_PORTS', label: 'UDP-порты', kind: 'text', hint: 'через запятую, диапазон — a:b' },
  { key: 'AUTO_PORTS', label: 'Порты из стратегии вместо списка выше', kind: 'bool' },
  { key: 'PKT_LIMIT_OUT', label: 'Исходящих пакетов соединения в nfqws2', kind: 'number', hint: '1–100' },
  { key: 'PKT_LIMIT_IN', label: 'Входящих пакетов соединения в nfqws2', kind: 'number', hint: '1–100' },
  { key: 'BLOCK_QUIC', label: 'Блокировать QUIC (UDP 443)', kind: 'bool' },
  { key: 'META_QUIC_REJECT', label: 'Отклонять QUIC к серверам Meta', kind: 'bool' },
  { key: 'CALLS_BYPASS', label: 'Обход блокировки звонков WhatsApp и Telegram', kind: 'bool' },
  { key: 'TCP_MSS_CLAMP', label: 'Ограничение MSS', kind: 'number', hint: '0 — выкл., 1 — 536, иначе 88–1460' },
  { key: 'NAT_FIX', label: 'Исправление для раздачи интернета (NAT)', kind: 'bool' },
  { key: 'LOG_LEVEL', label: 'Подробный журнал nfqws2', kind: 'bool' },
  { key: 'LOG_MAX_KB', label: 'Размер журнала, КБ', kind: 'number', hint: '64–4096' },
];

/** errors: {KEY: текст ошибки из ответа ctl}. */
export function renderSettings(settings, version, errors = {}) {
  if (!settings || settings.ok === false) return `<p class="state bad">Ошибка: ${esc(settings?.error || 'нет ответа')}</p>`;
  const v = settings.settings;
  const rows = settingControls.map((c) => {
    const err = errors[c.key] ? `<p class="error">${esc(errors[c.key])}</p>` : '';
    if (c.kind === 'bool') {
      return `<div class="setting"><label class="toggle"><input type="checkbox" data-key="${c.key}"${v[c.key] === '1' ? ' checked' : ''}> ${esc(c.label)}</label>${err}</div>`;
    }
    const type = c.kind === 'number' ? ' inputmode="numeric"' : '';
    return `<div class="setting"><label>${esc(c.label)}${c.hint ? ` <small class="hint">${esc(c.hint)}</small>` : ''}`
      + `<span class="field"><input data-key="${c.key}" value="${esc(v[c.key] ?? '')}"${type} spellcheck="false" autocapitalize="off">`
      + `<button type="button" data-save="${c.key}">Сохранить</button></span></label>${err}</div>`;
  }).join('');
  const w = (settings.warnings || []).map((x) => `<p>${esc(x)}</p>`).join('');
  const ver = version && version.ok !== false ? `<p class="hint">bcw ${esc(version.bcw)} · модуль ${esc(version.module)}</p>` : '';
  return `<div class="card">${rows}</div>${w ? `<div class="card warn">${w}</div>` : ''}${ver}`;
}

export async function showSettings(root, toast, errors = {}) {
  const [settings, version] = await Promise.all([ctl(['settings', 'get']), ctl(['version'])]);
  root.innerHTML = renderSettings(settings, version, errors);
  const save = async (key, value) => {
    root.querySelectorAll('input,button').forEach((x) => { x.disabled = true; });
    const r = await ctl(['settings', 'set', key, value], { timeoutMs: 40000 });
    if (r.ok) toast(r.warning ? `Сохранено. ${r.warning}` : 'Сохранено');
    await showSettings(root, toast, r.ok ? {} : { [key]: r.error || 'не удалось' });
  };
  root.querySelectorAll('input[type="checkbox"][data-key]').forEach((i) => {
    i.onchange = () => save(i.dataset.key, i.checked ? '1' : '0');
  });
  root.querySelectorAll('[data-save]').forEach((b) => {
    b.onclick = () => save(b.dataset.save, root.querySelector(`input[data-key="${b.dataset.save}"]`).value);
  });
}
