// Badges d'état (le texte porte l'information, la couleur la double) et ligne
// d'audience d'un élément (« Visible par vous seul »).

import { plural, t } from "../i18n.js";
import { h, icon } from "./core.js";

const TONES = new Set(["ok", "warn", "danger", "info", "neutral"]);

/** Badge : { tone = "neutral", label, icon, title } -> HTMLElement. */
export function badge({ tone = "neutral", label, icon: name, title }) {
  return h("span", { class: "c-badge", "data-tone": TONES.has(tone) ? tone : "neutral", title },
    name ? icon(name, { size: "sm" }) : null, label);
}

/**
 * Audience : { collection: { name, personal }, members } -> HTMLElement.
 * « Visible par vous seul » (coffre personnel) ; « Visible par Équipe IT · 3 personnes ».
 * members : nombre de personnes ou liste.
 */
export function audienceLine({ collection, members }) {
  const count = Array.isArray(members) ? members.length : Number(members) || 0;
  const personal = !collection || collection.personal;
  const text = personal
    ? t("ui.audience.personal")
    : plural("ui.audience.shared", count, { name: collection.name });
  return h("p", { class: "c-audience" }, icon(personal ? "user" : "users", { size: "sm" }), text);
}
