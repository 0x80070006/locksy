// Champs de formulaire (règle A9) : étiquette visible reliée, aide et erreur
// reliées par aria-describedby, aria-invalid ; l'erreur est affichée à côté du
// champ et annoncée une fois.

import { t, fmtNumber } from "../i18n.js";
import { h, icon, uid } from "./core.js";
import { announce } from "./status.js";

const fields = new WeakMap();

/** Ajoute ou retire des identifiants dans aria-describedby. */
export function describe(el, add = [], remove = []) {
  const ids = new Set((el.getAttribute("aria-describedby") || "").split(" ").filter(Boolean));
  for (const id of remove) ids.delete(id);
  for (const id of add) if (id) ids.add(id);
  if (ids.size) el.setAttribute("aria-describedby", [...ids].join(" "));
  else el.removeAttribute("aria-describedby");
}

/**
 * field({ label, help, error, optional, input, control, suffix, count }) -> HTMLElement
 *   input   : le champ (ou la liste) qui reçoit l'étiquette, l'aide et l'erreur ;
 *   control : bloc affiché à la place de input s'il contient d'autres éléments ;
 *   suffix  : unité affichée après le champ (« minutes ») ;
 *   count   : compteur « 12 / 200 » (input doit avoir maxlength).
 */
export function field({ label, help, error, optional, input, control, suffix, count }) {
  const id = input.id || uid("fld");
  input.id = id;
  const helpId = help ? `${id}-aide` : null;
  const errorId = `${id}-erreur`;
  const labelEl = h("label", { class: "c-field__label", for: id }, label,
    optional ? h("span", { class: "u-muted" }, ` ${t("ui.field.optional")}`) : null);
  let block = control || input;
  if (suffix) block = h("div", { class: "c-field__control" }, block, h("span", { class: "c-field__suffix" }, suffix));
  const counter = count && input.maxLength > 0 ? h("span", { class: "c-field__count", "aria-hidden": "true" }) : null;
  const errorText = h("span", {});
  const errorEl = h("p", { class: "c-field__error", id: errorId, hidden: true }, icon("error", { size: "sm" }), errorText);
  const el = h("div", { class: "c-field" }, labelEl, block, counter,
    help ? h("p", { class: "c-field__help", id: helpId }, help) : null, errorEl);
  describe(input, [helpId]);
  fields.set(el, { input, errorEl, errorText, last: null });
  if (counter) {
    const refresh = () => {
      counter.textContent = t("ui.field.count", { n: fmtNumber(input.value.length), max: fmtNumber(input.maxLength) });
    };
    input.addEventListener("input", refresh);
    refresh();
  }
  if (error) fieldError(el, error, { announce: false });
  return el;
}

/** Champ (input, select, textarea…) d'un bloc construit par field(). */
export function fieldInput(fieldEl) {
  return fields.get(fieldEl)?.input || null;
}

/**
 * Affiche (ou retire avec null) l'erreur d'un champ. Une nouvelle erreur est
 * annoncée une fois (#alert) ; la même erreur répétée ne l'est pas.
 */
export function fieldError(fieldEl, message, { announce: say = true } = {}) {
  const state = fields.get(fieldEl);
  if (!state) return;
  const text = message ? String(message) : "";
  state.errorText.textContent = text;
  state.errorEl.hidden = !text;
  if (text) {
    state.input.setAttribute("aria-invalid", "true");
    describe(state.input, [state.errorEl.id]);
  } else {
    state.input.removeAttribute("aria-invalid");
    describe(state.input, [], [state.errorEl.id]);
  }
  if (text && say && text !== state.last) announce(text, { assertive: true });
  state.last = text || null;
}

/** Champ texte : { name, value, type = "text", autocomplete, inputmode, maxlength, required, placeholder, id, readonly, disabled }. */
export function textInput({ name, value, type = "text", autocomplete, inputmode, maxlength, required, placeholder, id, readonly, disabled, min, max, step, spellcheck }) {
  return h("input", {
    class: "c-input", type, name, id, value: value ?? "", autocomplete, inputmode, maxlength, placeholder, min, max, step,
    required: !!required, "aria-required": required ? "true" : undefined, readonly: !!readonly, disabled: !!disabled,
    spellcheck: spellcheck === undefined ? undefined : String(!!spellcheck),
  });
}

/** Zone de texte : { name, value, rows = 4, maxlength, required, id, disabled }. */
export function textArea({ name, value, rows = 4, maxlength, required, id, disabled, placeholder }) {
  return h("textarea", {
    class: "c-textarea", name, id, rows, maxlength, placeholder, value: value ?? "",
    required: !!required, "aria-required": required ? "true" : undefined, disabled: !!disabled,
  });
}

/** Liste de choix : { name, options: [{ value, label, disabled, title }], value, id, disabled }. */
export function selectInput({ name, options = [], value, id, disabled, required }) {
  const select = h("select", { class: "c-select", name, id, disabled: !!disabled, required: !!required },
    options.map((o) => h("option", { value: String(o.value), disabled: !!o.disabled, title: o.title }, o.label)));
  if (value !== undefined && value !== null) select.value = String(value);
  return select;
}
