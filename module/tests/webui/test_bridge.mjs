// Мост к KernelSU: кавычки аргументов, разбор ответа, передача частями.
import { check, done } from './helpers.mjs';

const calls = [];
const files = new Map();
globalThis.window = globalThis;
window.ksu = {
  exec(cmd, opts, cb) {
    calls.push(cmd);
    let out = '';
    const m = cmd.match(/ ctl (.*)$/);
    const args = m ? [...m[1].matchAll(/'((?:[^']|'\\'')*)'/g)].map((x) => x[1].replace(/'\\''/g, "'")) : [];
    if (args[0] === 'upload' && args[1] === 'begin') { files.set('/t/upload-1', ''); out = JSON.stringify({ schema: 1, ok: true, path: '/t/upload-1' }); }
    else if (args[0] === 'upload' && args[1] === 'chunk') { files.set(args[2], files.get(args[2]) + args[3]); out = JSON.stringify({ schema: 1, ok: true }); }
    else if (args[0] === 'upload' && args[1] === 'end') { out = JSON.stringify({ schema: 1, ok: true, path: args[2] }); }
    else if (args[0] === 'garbage') { out = 'not json'; }
    else { out = JSON.stringify({ schema: 1, ok: true, args }); }
    setTimeout(() => window[cb](0, out, ''), 0);
  },
};

const { ctl, quote, uploadText } = await import('../../webroot/js/bridge.js');

check(quote("a'b") === "'a'\\''b'", `quote: ${quote("a'b")}`);
const r = await ctl(['home', 'add', "Дом 'мой'; rm -rf /"]);
check(r.ok && r.args[2] === "Дом 'мой'; rm -rf /", `аргумент дошёл не целиком: ${JSON.stringify(r)}`);
check(calls[0].startsWith('/data/adb/modules/bcw/bin/bcw ctl '), calls[0]);
const bad = await ctl(['garbage']);
check(bad.ok === false && /JSON/.test(bad.error), `плохой ответ: ${JSON.stringify(bad)}`);

const text = 'строка\n'.repeat(20000);
const path = await uploadText(text);
check(path === '/t/upload-1', path);
const b64 = files.get(path);
const chunks = calls.filter((c) => c.includes("'chunk'"));
check(chunks.length > 1, 'передано одним куском');
check(chunks.every((c) => c.length < 100 * 1024), 'команда длиннее 100 КБ (MAX_ARG_STRLEN 128 КБ)');
check(Buffer.from(b64, 'base64').toString('utf8') === text, 'текст исказился при передаче');
done('test_bridge');
