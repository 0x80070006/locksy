// Cartes : chiffre clé, alerte avec action, carte d'état (mise en service,
// connexion d'entreprise). La tonalité est doublée d'une icône et d'un texte.

import { fmtNumber } from "../i18n.js";
import { h, icon } from "./core.js";
import { button } from "./button.js";
import { TONE_ICONS } from "./toast.js";

/** Action d'une carte : { label, onClick | href } -> lien ou bouton. */
function actionEl(action, variant = "secondary") {
  if (!action) return null;
  if (action.href) return h("a", { class: "c-button", href: action.href }, action.label);
  return button({ label: action.label, variant, onClick: action.onClick, busyLabel: action.busyLabel });
}

/** Chiffre clé : { value, label, href, tone } (un lien si href). */
export function statCard({ value, label, href, tone, onClick }) {
  const content = [
    h("span", { class: "c-stat__value" }, typeof value === "number" ? fmtNumber(value) : value),
    h("span", { class: "c-stat__label" }, label),
  ];
  if (onClick) return h("button", { type: "button", class: "c-stat", "data-tone": tone, "aria-pressed": "false", onclick: onClick }, content);
  return href
    ? h("a", { class: "c-stat", href, "data-tone": tone }, content)
    : h("div", { class: "c-stat", "data-tone": tone }, content);
}

/** Alerte : { tone = "info", title, text, action: { label, onClick | href } }. */
export function alertCard({ tone = "info", title, text, action }) {
  return h("div", { class: "c-alert", "data-tone": tone },
    icon(TONE_ICONS[tone] || "info"),
    h("div", { class: "l-stack", "data-gap": "2" },
      title ? h("p", { class: "c-status__title" }, title) : null,
      text ? h("p", {}, text) : null,
      actionEl(action)));
}

/** Carte d'état : { tone, title, detail, action }. */
export function statusCard({ tone = "info", title, detail, action }) {
  return h("div", { class: "c-status", "data-tone": tone },
    icon(TONE_ICONS[tone] || "info"),
    h("div", { class: "l-stack", "data-gap": "1" },
      h("p", { class: "c-status__title" }, title),
      detail ? h("p", { class: "c-status__detail" }, detail) : null,
      actionEl(action)));
}
