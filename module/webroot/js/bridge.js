// Мост к KernelSU WebUI: запуск `bcw ctl` от root и передача больших данных.
// API KernelSU: ksu.exec(cmd, options, callbackName) → callback(errno, stdout, stderr).

export const BCW = '/data/adb/modules/bcw/bin/bcw';
const CHUNK = 48 * 1024; // кратно 3: каждая часть — самостоятельный base64 без «=» внутри

let seq = 0;

/** Аргумент в одинарных кавычках для sh. */
export function quote(a) {
  return "'" + String(a).replace(/'/g, "'\\''") + "'";
}

/** Выполнить команду sh от root. Ответ: {errno, stdout, stderr}. */
export function exec(cmd, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const ksu = globalThis.window && window.ksu;
    if (!ksu || typeof ksu.exec !== 'function') {
      resolve({ errno: -1, stdout: '', stderr: 'нет моста KernelSU (откройте страницу из менеджера KernelSU)' });
      return;
    }
    const name = `__bcw_cb_${Date.now()}_${seq++}`;
    const timer = setTimeout(() => {
      delete window[name];
      resolve({ errno: -1, stdout: '', stderr: `команда не ответила за ${Math.round(timeoutMs / 1000)} с` });
    }, timeoutMs);
    window[name] = (errno, stdout, stderr) => {
      clearTimeout(timer);
      delete window[name];
      resolve({ errno, stdout: stdout || '', stderr: stderr || '' });
    };
    try {
      ksu.exec(cmd, '{}', name);
    } catch (e) {
      clearTimeout(timer);
      delete window[name];
      resolve({ errno: -1, stdout: '', stderr: String(e) });
    }
  });
}

/** `bcw ctl <args…>` → разобранный JSON; при сбое {ok:false, error}. */
export async function ctl(args, { timeoutMs = 15000 } = {}) {
  const r = await exec(`${BCW} ctl ${args.map(quote).join(' ')}`, timeoutMs);
  const out = r.stdout.trim();
  try {
    const v = JSON.parse(out);
    if (v && typeof v === 'object') return v;
  } catch (_) { /* ниже */ }
  const why = r.stderr.trim() || out || `код ${r.errno}`;
  return { ok: false, error: `не JSON-ответ от bcw ctl: ${why}` };
}

function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

/** Передать текст частями через `ctl upload`; вернуть путь к файлу или бросить ошибку. */
export async function uploadText(text) {
  const begin = await ctl(['upload', 'begin']);
  if (!begin.ok) throw new Error(begin.error);
  const bytes = new TextEncoder().encode(text);
  for (let i = 0; i < bytes.length; i += CHUNK) {
    const r = await ctl(['upload', 'chunk', begin.path, b64(bytes.subarray(i, i + CHUNK))]);
    if (!r.ok) throw new Error(r.error);
  }
  const end = await ctl(['upload', 'end', begin.path]);
  if (!end.ok) throw new Error(end.error);
  return end.path;
}
