// Вкладка «Журналы».
import { sample, check, done } from './helpers.mjs';
const { renderLogs, LOG_FILES } = await import('../../webroot/js/logs.js');

const h = renderLogs(sample('logs'), sample('stats'), { file: 'service' });
check(LOG_FILES.length === 3 && ['service', 'nfqws2', 'auto'].every((f) => h.includes(`value="${f}"`)), 'три журнала');
check(/value="service" checked/.test(h), 'выбран service');
check(h.includes('перезапуск №1'), 'текст журнала');
check(h.includes('Запусков: 1') && h.includes('ошибок: 1'), 'статистика');
check(!/name="errors" checked/.test(h) && /name="errors" checked/.test(renderLogs(sample('logs'), sample('stats'), { errorsOnly: true })), 'фильтр «Только ошибки»');
check(!renderLogs({ ok: true, text: '<img src=x>' }, null).includes('<img'), 'экранирование');
check(renderLogs({ ok: false, error: 'служба не запущена' }, null).includes('служба не запущена'), 'ошибка ctl');
done('test_logs');
