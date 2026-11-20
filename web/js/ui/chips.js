// Saisie de listes (domaines, plages IP, adresses, mots) : chaque valeur
// devient une pastille avec un bouton « Retirer » ; Entrée, virgule,
// point-virgule ou la sortie du champ valident ; un collage de plusieurs
// valeurs les ajoute toutes. Une valeur refusée reste dans le champ, avec
// l'erreur à côté.

import { t } from "../i18n.js";
import { h, icon } from "./core.js";
import { field, fieldError } from "./field.js";
import { announce } from "./status.js";

const SEPARATORS = /[\s,;]+/u;

/**
 * chipsInput({ label, values, validate, placeholderKey, onChange, help, error, max }) -> HTMLElement
 * validate(valeur) -> null si elle est acceptée, sinon le message d'erreur.
 * onChange(valeurs) après chaque ajout ou retrait.
 */
export function chipsInput({ label, values = [], validate, placeholderKey, onChange, help, error, max }) {
  const current = [...values].map(String);
  const input = h("input", {
    type: "text", class: "c-chips__input", autocomplete: "off", spellcheck: "false",
    placeholder: placeholderKey ? t(placeholderKey) : undefined,
  });
  const entry = h("li", { class: "c-chips__entry" }, input);
  const list = h("ul", { class: "c-chips", role: "list" });
  const el = field({ label, help, error, input, control: list });

  const render = () => {
    list.replaceChildren(...current.map((v, i) => h("li", { "aria-invalid": validate?.(v) ? "true" : undefined },
      h("span", {}, v),
      h("button", {
        type: "button", class: "c-button c-button--quiet c-button--icon", "data-remove": String(i),
        "aria-label": t("ui.chips.remove", { value: v }), title: t("ui.chips.remove", { value: v }),
      }, icon("close", { size: "sm" })))), entry);
  };

  const add = (raw) => {
    const tokens = String(raw).split(SEPARATORS).map((s) => s.trim()).filter(Boolean);
    if (!tokens.length) return true;
    const refused = [];
    let message = null;
    const added = [];
    for (const tok of tokens) {
      if (current.includes(tok)) continue;
      const problem = validate?.(tok) || (max && current.length >= max ? t("ui.chips.too_many", { max }) : null);
      if (problem) {
        refused.push(tok);
        message ??= problem;
        continue;
      }
      current.push(tok);
      added.push(tok);
    }
    input.value = refused.join(" ");
    fieldError(el, message);
    if (added.length) {
      render();
      input.focus();
      announce(t("ui.chips.added", { value: added.join(", ") }));
      onChange?.([...current]);
    }
    return !refused.length;
  };

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === "," || e.key === ";") {
      e.preventDefault();
      add(input.value);
    }
  });
  input.addEventListener("blur", () => {
    if (input.value.trim()) add(input.value);
  });
  input.addEventListener("paste", (e) => {
    const text = e.clipboardData?.getData("text");
    if (!text || !SEPARATORS.test(text.trim())) return;
    e.preventDefault();
    add(`${input.value} ${text}`);
  });
  list.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-remove]");
    if (!btn) {
      if (e.target === list) input.focus();
      return;
    }
    const [removed] = current.splice(Number(btn.dataset.remove), 1);
    render();
    input.focus();
    announce(t("ui.chips.removed", { value: removed }));
    onChange?.([...current]);
  });
  render();
  return el;
}
