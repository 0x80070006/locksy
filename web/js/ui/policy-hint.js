// Mention de la politique sur un contrôle (jamais cachée) :
// « Limité à 30 min par votre organisation » (mode par défaut avec plafond),
// « Imposé par votre organisation » (mode imposé),
// « Imposé par votre poste de travail » (réglage du poste plus strict).

import { fmtNumber, t } from "../i18n.js";
import { h, icon, uid } from "./core.js";

/**
 * Texte de la mention, ou null si rien ne limite le choix.
 * entry : { value, mode, min, max, source } (forme de GET /settings/policy,
 * source "machine" pour une règle du poste) ; format(valeur) met en forme le plafond.
 */
export function policyText(entry, format = fmtNumber) {
  if (!entry) return null;
  if (entry.source === "machine") return t("ui.policy.machine");
  if (entry.mode === "enforced") return t("ui.policy.enforced");
  if (entry.max !== null && entry.max !== undefined && entry.mode === "default") return t("ui.policy.limited", { max: format(entry.max) });
  return null;
}

/**
 * policyHint({ key, policy, format }) -> HTMLElement | null
 * policy : l'entrée de la clé, ou toute la politique ({ clé: entrée }).
 * L'élément a un id : le relier au contrôle par aria-describedby.
 */
export function policyHint({ key, policy, format }) {
  const entry = policy && key && Object.hasOwn(policy, key) ? policy[key] : policy;
  const text = policyText(entry, format);
  if (!text) return null;
  return h("p", { class: "c-policy-hint", id: uid("politique") }, icon("lock", { size: "sm" }), h("span", {}, text));
}
