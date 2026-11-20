// État partagé du popup : accès au navigateur, stockage, navigation entre
// écrans, en-tête commun, erreurs (#alert) et copie avec effacement.
//
// Hors extension, la simulation des API (dev-fake.js) n'existe que dans un
// build --dev ; en production, ce contexte est refusé (ext = null).

import { h, clear, t, plural, announce, button, iconButton, copySecret, errorText, busyWhile } from "../lib/ui/index.js";
import { DEV } from "../lib/build-flags.js";

export const ext = globalThis.chrome?.storage?.session
  ? globalThis.chrome
  : (DEV ? (await import("../dev-fake.js")).fake : null);

export const LOCK_ALARM = "locksy-autolock";

// Repères de performance (popup.html?perf=1, comme l'interface web) : étapes
// de l'ouverture, relevées par les tests de bout en bout (cahier §6.5).
const PERF = /[?&]perf=1(?:&|$)/.test(globalThis.location?.search || "");

/** Pose le repère « locksy:popup:<nom> » quand les repères sont actifs. */
export function perfMark(name) {
  if (PERF) performance.mark(`locksy:popup:${name}`);
}

/** Pose le repère juste après le prochain affichage (image peinte). */
export function perfMarkAfterPaint(name) {
  if (PERF) requestAnimationFrame(() => setTimeout(() => perfMark(name), 0));
}

export const store = {
  get: async (area, k) => (await ext.storage[area].get(k))[k],
  set: (area, k, v) => ext.storage[area].set({ [k]: v }),
  del: (area, k) => ext.storage[area].remove(k),
};

export const alarms = {
  create: async (name, info) => { try { await ext.alarms?.create(name, info); } catch { /* API absente */ } },
  clear: async (name) => { try { await ext.alarms?.clear(name); } catch { /* API absente */ } },
};

/**
 * État du popup :
 *   tab, page        onglet actif et son adresse web (URL) ou null ;
 *   server           origine du serveur Locksy ;
 *   managed          politique du poste { server, machine } (settings.js) ;
 *   rules            règles effectives (extensionRules) ;
 *   expiresAt        échéance de verrouillage (ms), null = jamais, 0 = verrouillé.
 */
export const S = {
  tab: null,
  page: null,
  server: null,
  managed: { server: null, machine: {} },
  rules: null,
  expiresAt: 0,
};

// ------------------------------------------------------------------ Navigation

const screens = {};

/** Déclare les écrans (popup.js) : { nom: (…args) => rendu }. */
export function registerScreens(map) {
  Object.assign(screens, map);
}

/** Affiche un écran (chaque écran passe par screen(), qui retire les erreurs du précédent). */
export function go(name, ...args) {
  return screens[name](...args);
}

const root = () => document.getElementById("app");

/** Minutes restantes avant le verrouillage, ou null (jamais, ou verrouillé). */
export function minutesLeft(now = Date.now()) {
  return S.expiresAt ? Math.max(1, Math.ceil((S.expiresAt - now) / 60_000)) : null;
}

let lockTicker = 0;

/** Indicateur « Verrouillage dans N min » tenu à jour tant que le popup reste ouvert. */
function tickLock() {
  const el = root()?.querySelector(".x-head__lock");
  const left = minutesLeft();
  if (el && left) el.textContent = plural("extension.session.lock_in", left);
}

/**
 * Écran : en-tête (titre de niveau 1 « Locksy », indicateur de verrouillage,
 * actions), titre de l'écran facultatif (niveau 2), contenu.
 * { title, back, actions, session } ; back : retour (bouton « Retour »).
 * L'erreur de l'écran précédent est retirée ; l'appelant affiche la sienne après.
 */
export function screen({ title, back, actions = [], session = false }, ...content) {
  clearError();
  const left = session ? minutesLeft() : null;
  const head = h("header", { class: "x-head" },
    back ? iconButton({ icon: "arrow-left", label: t("common.action.back"), onClick: back }) : null,
    h("h1", { class: "x-head__title" }, t("extension.title")),
    left ? h("p", { class: "x-head__lock u-muted" }, plural("extension.session.lock_in", left)) : null,
    h("div", { class: "x-head__actions" }, actions));
  clear(root(), head, title ? h("h2", { class: "x-title" }, title) : null, ...content);
  if (left && !lockTicker) lockTicker = setInterval(tickLock, 15_000);
}

// ------------------------------------------------------------------ Erreurs

const alertBox = () => document.getElementById("alert");

/** Erreur visible et annoncée (#alert). Accepte un texte ou une erreur de l'API. */
export function showError(err) {
  const text = typeof err === "string" ? err : errorText(err);
  const box = alertBox();
  if (box) box.hidden = false;
  announce(text, { assertive: true });
}

export function clearError() {
  const box = alertBox();
  if (box) box.hidden = true;
  announce("", { assertive: true });
}

/** Message bloquant (contexte non pris en charge, échec du démarrage). */
export function fatal(err) {
  clear(root(), h("header", { class: "x-head" }, h("h1", { class: "x-head__title" }, t("extension.title"))));
  showError(err);
}

// ------------------------------------------------------------------ Presse-papiers

/**
 * Copie avec effacement après client.clipboard_clear_seconds : le composant
 * partagé efface tant que le popup est ouvert ; le service worker prend le
 * relais une fois le popup fermé (« text » n'est jamais effacé).
 */
export async function copyValue(value, kind, labelKey) {
  const ok = await copySecret(value, { kind, labelKey });
  if (ok) await armClipboard(kind);
  return ok;
}

/** Confie l'effacement d'une copie au service worker (après une copie réussie). */
export async function armClipboard(kind) {
  const seconds = kind === "text" ? 0 : S.rules?.clipboardSeconds ?? 30;
  try {
    await ext.runtime?.sendMessage?.({ type: "locksy:clipboard", seconds });
  } catch { /* service worker indisponible : l'effacement du popup reste */ }
}

/** Bouton dont l'échec (promesse rejetée) s'affiche dans #alert. */
export function action(opts) {
  return button({ onError: showError, ...opts });
}

/** Formulaire : soumission avec bouton « en cours » ; l'erreur va dans #alert. */
export function form(onSubmit, ...children) {
  const el = h("form", { class: "l-stack x-form", novalidate: true }, ...children);
  el.addEventListener("submit", (e) => {
    e.preventDefault();
    const btn = el.querySelector("button[type=submit]");
    if (btn?.getAttribute("aria-busy") === "true") return;
    const run = Promise.resolve().then(onSubmit);
    if (btn) busyWhile(btn, run).catch(() => {});
    run.catch((err) => showError(err));
  });
  return el;
}

/** Bouton d'envoi d'un formulaire construit par form(). */
export const submitButton = (label) => button({ label, variant: "primary", type: "submit" });
