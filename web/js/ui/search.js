// Champ de recherche : formulaire role=search, étiquette (masquée
// visuellement), recherche sans accents ni casse, délai de 80 ms ; Échap
// efface puis rend le focus ; ↓ va au premier résultat ; raccourci affiché.

import { t } from "../i18n.js";
import { h, icon, uid } from "./core.js";
import { focusSafely } from "./focus.js";

/** Texte comparable : sans accents (NFD), en minuscules, espaces réduits. */
export function normalize(text) {
  return String(text ?? "").normalize("NFD").replace(/\p{M}+/gu, "").toLocaleLowerCase("fr-FR").replace(/\s+/g, " ").trim();
}

/**
 * searchBox({ label, placeholderKey, value, onInput, onSubmit, onArrowDown, shortcut = "Ctrl+K", delay = 80 })
 *   -> HTMLElement (<form role="search">)
 * onInput(normalisé, brut) après le délai ; onSubmit(brut) sur Entrée ;
 * onArrowDown() sur ↓ (le premier résultat prend le focus).
 */
export function searchBox({ label, placeholderKey, value = "", onInput, onSubmit, onArrowDown, shortcut = "Ctrl+K", delay = 80 }) {
  const id = uid("recherche");
  const input = h("input", {
    type: "search", id, class: "c-input", value, autocomplete: "off", spellcheck: "false",
    placeholder: placeholderKey ? t(placeholderKey) : undefined,
    "aria-keyshortcuts": shortcut ? shortcut.replace("Ctrl", "Control") : undefined,
  });
  const kbd = shortcut ? h("kbd", { class: "c-kbd", "aria-hidden": "true" }, shortcut.replace("Ctrl", t("ui.key.ctrl")).replace("+", " ")) : null;
  const form = h("form", { role: "search", class: "c-search" },
    h("label", { for: id, class: "u-sr-only" }, label), icon("search"), input, kbd);
  let previous = null;
  let timer = 0;
  const emit = () => onInput?.(normalize(input.value), input.value);

  input.addEventListener("focus", (e) => {
    if (e.relatedTarget && !form.contains(e.relatedTarget)) previous = e.relatedTarget;
  });
  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(emit, delay);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      if (input.value) {
        input.value = "";
        clearTimeout(timer);
        emit();
      } else if (previous?.isConnected) {
        focusSafely(previous);
      }
    } else if (e.key === "ArrowDown" && typeof onArrowDown === "function") {
      e.preventDefault();
      onArrowDown();
    }
  });
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    clearTimeout(timer);
    emit();
    onSubmit?.(input.value);
  });
  return form;
}
