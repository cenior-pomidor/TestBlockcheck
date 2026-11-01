// Вкладка «Состояние» на образцах ответов `ctl status`.
import { sample, check, done } from './helpers.mjs';
const { renderStatus } = await import('../../webroot/js/status.js');

const run = renderStatus(sample('status'));
check(run.includes('Работает'), 'running → «Работает»');
check(run.includes('default') && run.includes('Wi-Fi «Home»'), 'стратегия и сеть');
check(run.includes('data-act="stop"') && run.includes('data-act="restart"'), 'кнопки остановки и перезапуска');
check(!run.includes('data-act="resume"'), '«Включить здесь» только в паузе');

const p = renderStatus(sample('status-paused'));
check(p.includes('Пауза: домашний Wi-Fi «Home»'), `пауза: ${p}`);
check(p.includes('data-act="resume"') && p.includes('Включить здесь сейчас'), 'кнопка «Включить здесь сейчас»');

check(renderStatus(sample('status-blocked')).includes('Не запущено: включён nfqws2-android'), 'сосед');
const f = renderStatus(sample('status-failed'));
check(f.includes('Ошибка') && f.includes('5 раз подряд') && f.includes('data-act="start"'), 'ошибка и «Запустить»');
const n = renderStatus(sample('status-not-running'));
check(n.includes('Служба не запущена') && !n.includes('data-act="stop"'), 'служба не запущена');

const xss = renderStatus({ ok: true, state: 'running', strategy: '<b>x</b>', network_title: 'Wi-Fi «<img src=x>»' });
check(!xss.includes('<img') && !xss.includes('<b>x'), 'экранирование HTML');
done('test_status');
