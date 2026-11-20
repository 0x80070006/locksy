// Code de vérification à 6 chiffres : un seul champ (pas de cases séparées),
// clavier numérique, saisie automatique du code reçu par le système ; les
// espaces et tirets collés sont retirés ; onComplete est appelée au 6e chiffre.

import { t } from "../i18n.js";
import { field, textInput } from "./field.js";

/** Garde les chiffres seulement : « 273 647 » -> « 273647 ». */
export function normalizeCode(text, digits = 6) {
  return String(text ?? "").replace(/\D+/g, "").slice(0, digits);
}

/**
 * otpInput({ label, onComplete, digits = 6, name = "code", help, error }) -> HTMLElement
 * onComplete(code) est appelée une fois par code complet saisi ou collé.
 */
export function otpInput({ label = t("common.glossary.verification_code"), onComplete, digits = 6, name = "code", help, error }) {
  const input = textInput({ name, inputmode: "numeric", autocomplete: "one-time-code", spellcheck: false });
  input.classList.add("c-otp");
  input.setAttribute("pattern", `[0-9 ]{${digits},${digits * 2}}`);
  input.setAttribute("enterkeyhint", "done");
  let completed = "";

  const settle = (raw) => {
    const code = normalizeCode(raw, digits);
    if (input.value !== code) input.value = code;
    if (code.length === digits && code !== completed) {
      completed = code;
      onComplete?.(code);
    } else if (code.length < digits) {
      completed = "";
    }
  };
  input.addEventListener("paste", (e) => {
    const text = e.clipboardData?.getData("text");
    if (text === undefined) return;
    e.preventDefault();
    const start = input.selectionStart ?? input.value.length;
    const end = input.selectionEnd ?? input.value.length;
    settle(input.value.slice(0, start) + text + input.value.slice(end));
  });
  input.addEventListener("input", () => settle(input.value));
  return field({ label, help, error, input });
}
