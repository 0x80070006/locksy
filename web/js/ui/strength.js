// Force d'un mot de passe et problèmes relevés. La couleur n'est jamais le
// seul repère : jauge, mot (« Solide ») et icône. Jamais « Très solide »
// quand un problème est relevé (réutilisation, suite, ancienneté…).

import { has, plural, t } from "../i18n.js";
import { clear, h, icon } from "./core.js";

const LEVELS = ["very_weak", "weak", "medium", "strong", "very_strong"];
const LEVEL_ICONS = ["error", "error", "warn", "check", "check"];

/** Niveau 0 à 4 ; plafonné à 3 si des problèmes sont relevés. */
export function strengthLevel(score, issues = []) {
  const n = Math.min(4, Math.max(0, Math.round(Number(score) || 0)));
  return issues && issues.length && n === 4 ? 3 : n;
}

/** Libellé d'un niveau : « Très faible » … « Très solide ». */
export function strengthLabel(level) {
  return t(`ui.strength.${LEVELS[level] || LEVELS[0]}`);
}

/** Jauge { score, issues } -> HTMLElement ; score null : jauge masquée. */
export function strengthMeter({ score, issues = [] } = {}) {
  const el = h("div", { class: "c-strength" },
    h("span", { class: "c-strength__bar", "aria-hidden": "true" }),
    h("span", { class: "c-strength__label" }));
  updateStrength(el, { score, issues });
  return el;
}

/** Met à jour une jauge construite par strengthMeter(). */
export function updateStrength(el, { score, issues = [] } = {}) {
  if (score === null || score === undefined) {
    el.hidden = true;
    el.removeAttribute("data-level");
    return;
  }
  const level = strengthLevel(score, issues);
  el.hidden = false;
  el.dataset.level = String(level);
  clear(el.querySelector(".c-strength__label"),
    icon(LEVEL_ICONS[level], { size: "sm" }),
    h("span", { class: "u-sr-only" }, t("ui.strength.prefix")),
    strengthLabel(level));
}

/** Texte d'un problème { code, n, params } (ou texte déjà rédigé). */
export function issueText(issue) {
  if (typeof issue === "string") return issue;
  const key = `ui.issue.${issue?.code}`;
  if (!has(key)) return t("ui.issue.other");
  return typeof issue.n === "number" ? plural(key, issue.n, issue.params) : t(key, issue.params);
}

/**
 * Pastille de problème cliquable : « Réutilisé sur 1 autre élément › ».
 * { issue, onClick, href } : un lien si href est donné, sinon un bouton.
 */
export function issueChip({ issue, onClick, href }) {
  const content = [h("span", {}, issueText(issue)), icon("chevron-right", { size: "sm" })];
  if (href) return h("a", { class: "c-issue", href }, content);
  return h("button", { type: "button", class: "c-issue", onclick: onClick }, content);
}
