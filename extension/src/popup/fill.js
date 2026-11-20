// Remplissage de la page active : identifiant, mot de passe et, si l'élément le
// permet (totp_fill), code de vérification. Sinon, le code est copié selon
// extension.copy_totp_after_fill pour l'étape suivante (connexion en deux temps).
//
// Règles (cahier §3.5.1, politique extension.*) :
//  - jamais sur un site exclu (extension.excluded_sites) ;
//  - page http hors boucle locale : bloqué si extension.http_fill = block,
//    avertissement sinon ; un compte enregistré en https n'est jamais rempli
//    sur une page http (descente) ;
//  - compte d'un autre site : seulement si extension.allow_mismatch_fill, après
//    confirmation ;
//  - l'origine de la page est revérifiée dans la page, juste avant d'écrire.

import { t, notify, announce } from "../lib/ui/index.js";
import { call } from "../lib/wasm.js";
import { matchStatus, isInsecurePage, webPage } from "../match.js";
import { siteExcluded } from "../settings.js";
import { S, ext, copyValue, showError } from "./context.js";
import { touch } from "./session.js";

/**
 * Exécutée dans la page (cadre principal) : remplit le formulaire visible.
 * Fonction autonome (sérialisée par executeScript) : aucune référence externe.
 * Renvoie { user, password, totp } (champs remplis) ou { error: "origin" }.
 */
export function fillPage(username, password, code, expectedOrigin) {
  if (location.origin !== expectedOrigin) return { error: "origin" };
  const visible = (el) => el.getClientRects().length > 0 && !el.disabled && !el.readOnly && getComputedStyle(el).visibility !== "hidden";
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const text = ["email", "text", "tel", "number"].map((k) => `input[type="${k}"]`).concat("input:not([type])").join(", ");
  const describe = (el) => `${el.name} ${el.id} ${el.autocomplete} ${el.placeholder} ${el.getAttribute("aria-label") || ""}`;
  const pw = [...document.querySelectorAll('input[type="password"]')].find((el) => visible(el) && el.autocomplete !== "one-time-code") || null;

  // Champ du code : désigné comme tel (autocomplete, nom usuel, clavier numérique court).
  let otp = null;
  if (code) {
    const fields = [...document.querySelectorAll(`${text}, input[type="password"]`)].filter(visible);
    const named = (el) => /(^|[^a-z])(otp|totp|2fa|mfa|one.?time|code|verif|authenticat|token)/i.test(describe(el))
      && !/user|login|mail|search|promo|coupon|postal|zip|captcha/i.test(describe(el));
    const numeric = (el) => el.inputMode === "numeric" && el.maxLength >= 6 && el.maxLength <= 8;
    otp = fields.find((el) => el.autocomplete === "one-time-code") || fields.find((el) => el !== pw && (named(el) || numeric(el))) || null;
  }

  const scope = pw?.form || document;
  const candidates = [...scope.querySelectorAll(text)].filter((el) => visible(el) && el !== otp);
  const isUser = (el) => /user|login|mail|ident/i.test(`${el.name} ${el.id} ${el.autocomplete}`) || el.type === "email";
  let user = null;
  if (pw) {
    const before = candidates.filter((el) => el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING);
    user = before[before.length - 1] || null;
  } else {
    // Connexion en deux étapes (identifiant d'abord) : seulement un champ
    // clairement désigné, jamais un champ texte quelconque.
    user = candidates.find(isUser) || null;
  }
  if (user && username) set(user, username);
  if (pw && password) set(pw, password);
  if (otp) set(otp, code);
  return { user: !!(user && username), password: !!(pw && password), totp: !!otp };
}

/** Code de vérification courant d'un élément, ou null. */
export function currentCode(data) {
  if (!data?.totp) return null;
  try {
    return call("totp", { secret: data.totp, time: Math.floor(Date.now() / 1000) }).code || null;
  } catch {
    return null;
  }
}

/** Meilleure correspondance d'un élément avec la page : { status, url }. */
export function siteMatch(item) {
  const d = item.data;
  if (!S.page || !d || (d.kind && d.kind !== "login")) return { status: "nomatch", url: null };
  let best = { status: "nomatch", url: null };
  for (const u of d.urls || []) {
    const s = matchStatus(u, S.page.href);
    if (s === "match") return { status: s, url: u };
    if (s === "downgrade") best = { status: s, url: u };
  }
  return best;
}

/**
 * État de la page pour le remplissage : { excluded, insecure, blocked }.
 * blocked : page http et extension.http_fill = block.
 */
export function pageState() {
  if (!S.page) return { excluded: false, insecure: false, blocked: false };
  const excluded = siteExcluded(S.page.hostname, S.rules.excludedSites);
  const insecure = isInsecurePage(S.page.href);
  return { excluded, insecure, blocked: insecure && S.rules.httpFill === "block" };
}

/**
 * Raison pour laquelle un élément ne peut pas être rempli ici (clé de texte),
 * ou null. `m` : siteMatch(item).
 */
export function fillRefusal(item, m) {
  const d = item.data;
  if (!S.page) return "extension.fill.no_page";
  if (!d?.username && !d?.password) return "extension.fill.nothing";
  const p = pageState();
  if (p.excluded) return "extension.fill.excluded";
  if (p.blocked) return "extension.fill.http_blocked";
  if (m.status === "downgrade") return "extension.fill.downgrade";
  if (m.status !== "match" && !S.rules.allowMismatchFill) return "extension.fill.other_site";
  return null;
}

/**
 * Remplit la page avec l'élément. Renvoie le résultat de la page, ou null si
 * le remplissage a été refusé (le message est affiché).
 */
export async function fill(item) {
  const m = siteMatch(item);
  const refusal = fillRefusal(item, m);
  if (refusal) {
    showError(t(refusal));
    return null;
  }
  const d = item.data;
  const expectedOrigin = S.page.origin;
  const code = currentCode(d);
  const inject = d.totp_fill === true ? code : null;

  let r;
  if (!ext.scripting) {
    // Mode --dev : la « page » est le popup lui-même.
    r = fillPage(d.username || "", d.password || "", inject || "", location.origin);
  } else {
    // L'onglet a pu naviguer depuis l'ouverture du popup. La page revérifie
    // son origine AVANT d'écrire (fillPage) : la relecture de l'onglet, faite
    // en même temps, sert seulement à choisir le message d'un échec.
    const [current, injected] = await Promise.all([
      ext.tabs.get(S.tab.id).catch(() => null),
      ext.scripting.executeScript({
        target: { tabId: S.tab.id, frameIds: [0] },
        func: fillPage,
        args: [d.username || "", d.password || "", inject || "", expectedOrigin],
      }).then(([{ result } = {}]) => ({ result }), () => null),
    ]);
    if (webPage(current?.url)?.origin !== expectedOrigin) {
      showError(t("extension.fill.page_changed"));
      return null;
    }
    if (!injected) {
      showError(t("extension.fill.protected"));
      return null;
    }
    r = injected.result;
  }
  if (r?.error === "origin") {
    showError(t("extension.fill.page_changed"));
    return null;
  }
  if (!r?.password && !r?.user && !r?.totp) {
    showError(t("extension.fill.no_field"));
    return null;
  }
  await touch();
  if (code && r.totp) {
    announce(t("extension.fill.code_typed"));
  } else if (code && S.rules.copyTotpAfterFill) {
    // Le popup reste ouvert pour lire le message ; il se ferme quand la page reprend le focus.
    await copyValue(code, "totp", "extension.fill.code_copied");
    return r;
  }
  if (ext.scripting) window.close();
  else notify({ text: t("extension.fill.done"), tone: "ok" });
  return r;
}
