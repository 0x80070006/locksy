// Page d'inscription : Locksy la reconnaît, propose un mot de passe solide,
// l'écrit dans les champs « mot de passe » (et « confirmation ») de la page,
// puis ouvre l'enregistrement du compte avec ce mot de passe.
//
// Reconnaissance (sans jamais lire ni envoyer le contenu de la page) :
//  - un champ autocomplete="new-password" visible ;
//  - sinon deux champs « mot de passe » visibles dans un même formulaire
//    (mot de passe + confirmation) ;
//  - sinon un seul champ, si l'adresse de la page, le formulaire ou le bouton
//    d'envoi parlent d'inscription (sign up, register, inscription, créer un compte…).
// Un formulaire de connexion (autocomplete="current-password" seul) n'est jamais pris
// pour une inscription. Dans un formulaire de changement de mot de passe, l'ancien
// mot de passe est laissé tel quel.

import { h, t, alertCard } from "../lib/ui/index.js";
import { webPage } from "../match.js";
import { S, ext, go, showError, action } from "./context.js";
import { touch } from "./session.js";
import { pageState } from "./fill.js";
import { generateFresh } from "./generate.js";
import { writableCollections } from "./save.js";

/**
 * Exécutée dans la page (cadre principal). Fonction autonome (sérialisée par
 * executeScript) : aucune référence externe.
 * Sans `password` : { signup } ; avec : remplit et renvoie { signup, filled }.
 * Renvoie { error: "origin" } si la page n'est plus celle attendue.
 */
export function signupPage(expectedOrigin, password) {
  if (location.origin !== expectedOrigin) return { error: "origin" };
  const visible = (el) => el.getClientRects().length > 0 && !el.disabled && !el.readOnly && getComputedStyle(el).visibility !== "hidden";
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const word = /sign.?up|regist|inscri|cr[ée]er.{0,12}compte|create.{0,12}account|new.?account|nouveau.{0,6}compte|enroll|join/i;
  const pws = [...document.querySelectorAll('input[type="password"]')].filter((el) => visible(el) && el.autocomplete !== "one-time-code");
  const groups = new Map();
  for (const el of pws) {
    const key = el.form || document.body;
    groups.set(key, [...(groups.get(key) || []), el]);
  }
  for (const [form, list] of groups) {
    const fresh = list.filter((el) => el.autocomplete === "new-password");
    let targets = [];
    if (fresh.length) {
      targets = fresh;
    } else if (list.every((el) => el.autocomplete === "current-password")) {
      continue;
    } else {
      const buttons = [...form.querySelectorAll('button, input[type="submit"]')].slice(0, 10).map((b) => b.innerText || b.value || "");
      const hint = [location.pathname, form.id || "", form.getAttribute?.("action") || "", ...buttons].join(" ");
      if (list.length >= 2 || word.test(hint)) targets = list.length >= 3 ? list.slice(1) : list;
    }
    if (!targets.length) continue;
    if (!password) return { signup: true };
    for (const el of targets) set(el, password);
    return { signup: true, filled: targets.length };
  }
  return { signup: false };
}

/** Exécute signupPage dans l'onglet actif ; null si la page est protégée ou a changé. */
async function run(password) {
  if (!ext.scripting) return signupPage(location.origin, password); // mode --dev
  try {
    const current = await ext.tabs.get(S.tab.id).catch(() => null);
    if (webPage(current?.url)?.origin !== S.page.origin) return null;
    const [{ result } = {}] = await ext.scripting.executeScript({
      target: { tabId: S.tab.id, frameIds: [0] }, func: signupPage, args: [S.page.origin, password || null],
    });
    return result?.error ? null : result;
  } catch {
    return null;
  }
}

/** Mot de passe créé, écrit dans la page, puis enregistrement du compte. */
async function propose() {
  const r = await run(await generateFresh());
  if (!r?.filled) return showError(t("extension.signup.no_field"));
  await touch();
  go("save");
}

/**
 * Carte « page d'inscription » si la page en est une et si le compte peut être
 * enregistré (politique extension.offer_save, site non exclu, page non bloquée,
 * coffre accessible en écriture) ; null sinon.
 */
export async function signupCard() {
  const p = pageState();
  if (!S.page || !S.rules.offerSave || p.excluded || p.blocked || !writableCollections().length) return null;
  const r = await run(null);
  if (!r?.signup) return null;
  return h("div", { class: "l-stack", "data-gap": "2" },
    alertCard({ tone: "info", title: t("extension.signup.title"), text: t("extension.signup.text") }),
    action({ label: t("extension.signup.propose"), icon: "generate", variant: "primary", onClick: propose }));
}
