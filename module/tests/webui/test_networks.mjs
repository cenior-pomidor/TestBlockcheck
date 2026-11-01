// Вкладка «Сети».
import { sample, check, done } from './helpers.mjs';
const { renderNetworks, currentSsid } = await import('../../webroot/js/networks.js');

const n = sample('networks'), s = sample('settings-get'), st = sample('status');
const h = renderNetworks(n, s, st);
check(h.includes('Wi-Fi «Home»') && h.includes('<b>alt</b>'), 'сохранённая сеть со стратегией');
check(!h.includes('data-act="home-add"'), 'Home уже домашняя — кнопки нет');
check(!/data-setting="NET_STRATEGY" checked/.test(h) && !/data-setting="HOME_WIFI" checked/.test(h), 'тумблеры выключены');
const on = { ...s, settings: { ...s.settings, NET_STRATEGY: '1', HOME_WIFI: '1' } };
const h2 = renderNetworks(n, on, st);
check(/data-setting="NET_STRATEGY" checked/.test(h2) && /data-setting="HOME_WIFI" checked/.test(h2), 'тумблеры включены');

const odd = 'a<b>"&\'»';
const wifi = { ...n, current_key: 'wifi_x', current_title: `Wi-Fi «${odd}»`, home: [odd], networks: [{ key: 'wifi_x', title: `Wi-Fi «${odd}»`, strategy: '<s>' }] };
check(currentSsid({ ...wifi, home: [] }) === odd, `SSID из подписи: ${currentSsid(wifi)}`);
const h3 = renderNetworks(wifi, s, st);
check(!h3.includes('<b>"') && !h3.includes('a<b>') && !h3.includes('<s>'), 'экранирование SSID');
check(renderNetworks({ ...wifi, home: [] }, s, st).includes('data-act="home-add"'), '«Добавить текущую» на новом Wi-Fi');
const cell = { ...n, current_key: 'cell_MegaFon', current_title: 'Мобильная (MegaFon)', home: [] };
check(currentSsid(cell) === null && !renderNetworks(cell, s, st).includes('data-act="home-add"'), 'на мобильной кнопки нет');
done('test_networks');
