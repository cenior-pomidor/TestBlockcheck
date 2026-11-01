// Синтаксис скриптов и отсутствие внешних загрузок.
import { readdirSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { root, check, done } from './helpers.mjs';

const web = join(root, 'webroot');
const js = readdirSync(join(web, 'js')).filter((f) => f.endsWith('.js'));
check(js.length > 0, 'нет скриптов в webroot/js');
for (const f of js) {
  try { execFileSync(process.execPath, ['--check', join(web, 'js', f)]); }
  catch (e) { check(false, `синтаксис ${f}: ${e.message}`); }
}
const html = readFileSync(join(web, 'index.html'), 'utf8');
check(/<script type="module" src="js\/app\.js"><\/script>/.test(html), 'index.html не подключает js/app.js модулем');
for (const m of html.matchAll(/\b(?:src|href)="([^"]+)"/g)) {
  check(!/^(https?:)?\/\//.test(m[1]), `внешняя загрузка: ${m[1]}`);
}
check(/lang="ru"/.test(html), 'index.html без lang="ru"');
for (const f of js) {
  const t = readFileSync(join(web, 'js', f), 'utf8');
  check(!/https?:\/\//.test(t.replace(/\/\/.*$/gm, '')), `${f}: внешний адрес в коде`);
}
done('test_static');
