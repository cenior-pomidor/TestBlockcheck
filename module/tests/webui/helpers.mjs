// Общее для тестов WebUI: образцы ответов `bcw ctl` и простые проверки.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
export const root = join(here, '..', '..');
export const sample = (name) => JSON.parse(readFileSync(join(root, 'tests', 'ctl-samples', `${name}.json`), 'utf8'));

let failed = 0;
export function check(cond, msg) {
  if (!cond) { failed++; console.error('FAIL:', msg); }
}
export function done(name) {
  if (failed) { console.error(`${name}: ${failed} провал(ов)`); process.exit(1); }
  console.log(`${name}: ok`);
}
