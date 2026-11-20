// États obligatoires d'une vue (cahier §2.12) : vide (avec l'action qui le
// remplit), chargement (squelette au-delà de 300 ms, jamais d'écran blanc),
// erreur (ce qui s'est passé + « Réessayer »), hors ligne.

import { errorText, t } from "../i18n.js";
import { clear, h, icon } from "./core.js";
import { button } from "./button.js";
import { alertCard } from "./cards.js";

/**
 * État vide : { icon, title, text, actions, level = 2 } -> HTMLElement.
 * actions : éléments, ou { label, onClick | href, variant }.
 */
export function emptyState({ icon: name = "search", title, text, actions = [], level = 2 }) {
  return h("div", { class: "c-empty" },
    icon(name),
    h(`h${Math.min(6, Math.max(2, level))}`, { class: "c-empty__title" }, title),
    text ? h("p", { class: "c-empty__text" }, text) : null,
    actions.length ? h("div", { class: "l-cluster" }, actions.map((a) => {
      if (a instanceof Node) return a;
      if (a.href) return h("a", { class: `c-button${a.variant === "primary" ? " c-button--primary" : ""}`, href: a.href }, a.label);
      return button({ label: a.label, icon: a.icon, variant: a.variant || "primary", onClick: a.onClick });
    })) : null);
}

/** Squelette de chargement : { lines = 3 } ; le texte « Chargement… » est lu par les lecteurs d'écran. */
export function skeleton({ lines = 3 } = {}) {
  return h("div", { class: "c-skeleton" },
    h("p", { class: "u-sr-only" }, t("common.state.loading")),
    Array.from({ length: Math.max(1, lines) }, () => h("span", { "aria-hidden": "true" })));
}

/** Erreur de chargement : { error, title, onRetry } -> HTMLElement. */
export function errorState({ error, title = t("ui.state.error_title"), onRetry, level = 2 }) {
  return emptyState({
    icon: "error", title, text: errorText(error), level,
    actions: onRetry ? [{ label: t("common.action.retry"), icon: "refresh", onClick: onRetry }] : [],
  });
}

/** Bandeau hors ligne (écritures désactivées par l'appelant, avec la raison). */
export function offlineBanner() {
  return alertCard({ tone: "warn", text: t("common.state.offline") });
}

/**
 * Charge une vue sans écran blanc : `container` reçoit aria-busy, puis un
 * squelette si la promesse dure plus de 300 ms ; renvoie le résultat de la
 * promesse (le rendu final est fait par l'appelant).
 */
export async function withLoading(container, promise, { lines = 3, delay = 300 } = {}) {
  container.setAttribute("aria-busy", "true");
  const timer = setTimeout(() => clear(container, skeleton({ lines })), delay);
  try {
    return await promise;
  } finally {
    clearTimeout(timer);
    container.removeAttribute("aria-busy");
  }
}
