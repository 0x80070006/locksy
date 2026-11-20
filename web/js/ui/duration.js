// Choix d'une durée : préréglages lisibles (« 15 minutes », « 4 heures »),
// « Jamais » si permis, « Autre… » qui ouvre un champ numérique borné.
// Les valeurs hors bornes restent visibles mais désactivées, avec la raison
// (bornes ou politique de l'organisation) reliée par aria-describedby.

import { plural, t } from "../i18n.js";
import { h, icon, uid } from "./core.js";
import { describe, field, fieldError, textInput } from "./field.js";

const SECONDS = Object.freeze({ seconds: 1, minutes: 60, hours: 3600, days: 86400 });
const OTHER = "autre";

/** Durée lisible : 240 minutes -> « 4 heures », 1440 -> « 1 jour », 0 -> « Jamais » si never. */
export function formatDuration(value, unit = "minutes", { never = false } = {}) {
  const n = Number(value);
  if (never && n === 0) return t("common.unit.never");
  const s = n * (SECONDS[unit] || 60);
  if (s >= 86400 && s % 86400 === 0) return plural("common.unit.days", s / 86400);
  if (s >= 3600 && s % 3600 === 0) return plural("common.unit.hours", s / 3600);
  if (s >= 60 && s % 60 === 0) return plural("common.unit.minutes", s / 60);
  return plural("common.unit.seconds", s);
}

/**
 * durationSelect({ label, value, presets, min, max, allowNever, unit = "minutes",
 *   disabledReason, onChange, help, name, id }) -> HTMLElement
 * value 0 = « Jamais » (avec allowNever). onChange(nombre) à chaque choix valide.
 * disabledReason : raison des options hors bornes (ex. « Limité à 30 min par
 * votre organisation ») ; à défaut, les bornes (« Entre 1 minute et 1 jour »).
 */
export function durationSelect({ label, value, presets = [], min, max, allowNever = false, unit = "minutes", disabledReason, onChange, help, name, id }) {
  const fmt = (v) => formatDuration(v, unit, { never: allowNever });
  const inRange = (v) => (v === 0 ? allowNever : (min == null || v >= min) && (max == null || v <= max));
  const values = [...new Set([...presets, value].filter((v) => v !== null && v !== undefined && v !== "").map(Number))]
    .filter((v) => Number.isFinite(v) && (v !== 0 || allowNever))
    .sort((a, b) => (a === 0) - (b === 0) || a - b);
  if (allowNever && !values.includes(0)) values.push(0);

  const rangeText = min != null && max != null ? t("ui.duration.range", { min: fmt(min), max: fmt(max) })
    : max != null ? t("ui.duration.at_most", { max: fmt(max) })
      : min != null ? t("ui.duration.at_least", { min: fmt(min) }) : "";
  const reason = disabledReason || rangeText;
  const someOut = values.some((v) => !inRange(v));
  const reasonId = uid("duree-raison");

  const select = h("select", { class: "c-select", name, id },
    values.map((v) => h("option", {
      value: String(v), disabled: !inRange(v), title: inRange(v) ? undefined : reason,
    }, inRange(v) ? fmt(v) : t("ui.duration.unavailable", { label: fmt(v) }))),
    h("option", { value: OTHER }, t("ui.duration.other")));
  if (value !== undefined && value !== null) select.value = String(Number(value));

  const customInput = textInput({ type: "number", inputmode: "numeric", min: min ?? (allowNever ? 0 : 1), max, step: 1 });
  const custom = field({
    label: t("ui.duration.custom_label", { unit: t(`ui.duration.unit.${unit}`) }),
    input: customInput, suffix: t(`ui.duration.unit.${unit}`),
  });
  custom.hidden = true;

  const hint = reason
    ? h("p", { class: disabledReason ? "c-policy-hint" : "c-field__help", id: reasonId },
      disabledReason ? icon("lock", { size: "sm" }) : null, h("span", {}, reason))
    : null;
  if (hint && (someOut || disabledReason || min != null || max != null)) describe(select, [reasonId]);

  select.addEventListener("change", () => {
    if (select.value === OTHER) {
      custom.hidden = false;
      customInput.value = value ?? "";
      customInput.focus();
      return;
    }
    custom.hidden = true;
    value = Number(select.value);
    onChange?.(value);
  });
  customInput.addEventListener("change", () => {
    const n = Number(customInput.value);
    if (!Number.isInteger(n) || !inRange(n)) {
      fieldError(custom, reason || t("ui.duration.invalid"));
      return;
    }
    fieldError(custom, null);
    value = n;
    onChange?.(n);
  });

  const el = field({ label, help, input: select });
  if (hint) el.querySelector(".c-field__error").before(hint);
  el.append(custom);
  return el;
}
