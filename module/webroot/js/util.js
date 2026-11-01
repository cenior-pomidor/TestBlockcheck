// Общие мелочи интерфейса.

/** Экранирование текста для вставки в HTML. */
export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

/** Кнопка с действием data-act. */
export function button(act, title, extra = '') {
  return `<button type="button" data-act="${esc(act)}" ${extra}>${esc(title)}</button>`;
}
