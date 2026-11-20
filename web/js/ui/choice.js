// Choix : interrupteur (role=switch, état écrit « Activé » / « Désactivé »),
// choix segmenté et cartes de choix (boutons radio natifs dans un fieldset
// avec légende), cases à cocher groupées.

import { t } from "../i18n.js";
import { h, icon, uid } from "./core.js";
import { isInactive, setDisabled } from "./button.js";

/**
 * toggle({ label, checked, onChange, help, disabled, reason, id }) -> HTMLElement
 * onChange(checked) à chaque bascule.
 */
export function toggle({ label, checked = false, onChange, help, disabled, reason, id }) {
  const btnId = id || uid("tgl");
  const labelId = `${btnId}-lbl`;
  const helpId = help ? `${btnId}-aide` : undefined;
  const state = h("span", { "aria-hidden": "true" });
  const btn = h("button", {
    type: "button", role: "switch", class: "c-toggle", id: btnId, "aria-labelledby": labelId, "aria-describedby": helpId,
  }, state);
  const set = (on) => {
    btn.setAttribute("aria-checked", String(!!on));
    state.textContent = on ? t("common.state.enabled") : t("common.state.disabled");
  };
  set(checked);
  if (disabled) setDisabled(btn, true, reason);
  btn.addEventListener("click", () => {
    if (isInactive(btn)) return;
    const next = btn.getAttribute("aria-checked") !== "true";
    set(next);
    onChange?.(next);
  });
  return h("div", { class: "c-field" },
    h("label", { class: "c-field__label", id: labelId, for: btnId }, label),
    btn,
    help ? h("p", { class: "c-field__help", id: helpId }, help) : null);
}

/** Change l'état d'un interrupteur construit par toggle(), sans appeler onChange. */
export function setToggle(el, checked) {
  const btn = el.querySelector("[role=switch]");
  btn.setAttribute("aria-checked", String(!!checked));
  btn.firstElementChild.textContent = checked ? t("common.state.enabled") : t("common.state.disabled");
}

function radios({ cls, legend, options, value, onChange, name, disabled, help, card }) {
  const groupName = name || uid("choix");
  const helpId = help ? uid("aide") : undefined;
  const set = h("fieldset", { class: cls, disabled: !!disabled, "aria-describedby": helpId },
    h("legend", {}, legend),
    options.map((o) => {
      const input = h("input", { type: "radio", name: groupName, value: String(o.value), checked: String(o.value) === String(value), disabled: !!o.disabled });
      if (!card) return h("label", { title: o.reason }, input, o.label);
      return h("label", { title: o.reason }, input,
        h("span", { class: "l-cluster" }, o.icon ? icon(o.icon) : null, h("strong", {}, o.label)),
        o.description ? h("span", { class: "u-muted" }, o.description) : null);
    }),
    help ? h("p", { class: "c-field__help", id: helpId }, help) : null);
  set.addEventListener("change", (e) => {
    if (e.target instanceof HTMLInputElement && e.target.checked) onChange?.(e.target.value);
  });
  return set;
}

/** Choix segmenté (2 à 4 options courtes) : { label, options: [{ value, label, disabled }], value, onChange, name, help }. */
export function segmented({ label, options, value, onChange, name, disabled, help }) {
  return radios({ cls: "c-segmented", legend: label, options, value, onChange, name, disabled, help, card: false });
}

/** Cartes de choix : { legend, options: [{ value, label, description, icon }], value, onChange, name, help }. */
export function radioCards({ legend, options, value, onChange, name, disabled, help }) {
  return radios({ cls: "c-radio-cards", legend, options, value, onChange, name, disabled, help, card: true });
}

/**
 * Cases à cocher groupées : { legend, options: [{ value, label, description }], values, onChange, name }.
 * onChange(valeursCochées).
 */
export function checkboxGroup({ legend, options, values = [], onChange, name, disabled, help }) {
  const groupName = name || uid("cases");
  const selected = new Set(values.map(String));
  const helpId = help ? uid("aide") : undefined;
  const set = h("fieldset", { class: "c-radio-cards", disabled: !!disabled, "aria-describedby": helpId },
    h("legend", {}, legend),
    options.map((o) => h("label", {},
      h("input", { type: "checkbox", name: groupName, value: String(o.value), checked: selected.has(String(o.value)) }),
      h("strong", {}, o.label),
      o.description ? h("span", { class: "u-muted" }, o.description) : null)),
    help ? h("p", { class: "c-field__help", id: helpId }, help) : null);
  set.addEventListener("change", () => {
    onChange?.([...set.querySelectorAll("input:checked")].map((i) => i.value));
  });
  return set;
}
