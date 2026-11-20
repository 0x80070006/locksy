// Point d'entrée de l'interface web : démarrage, session (connexion,
// verrouillage, déconnexion), coquille et routeur (cahier §3.1-3.3.1, contrats
// C4.1-C4.3 de la vague 2).
//
// Ordre de démarrage : affichage (thème, contraste, taille du texte posés sur
// <html> avant le premier rendu), module de chiffrement, branchements
// (réglages, réauthentification, presse-papiers), puis le routeur.
//
// Aucune vue n'est importée de façon statique : chaque route charge son module
// (routes.js) ; un module absent ou en échec affiche « Cette page arrive
// bientôt ».
//
// Les cales historiques (`ui`, `go`, `refresh`, `showRecoveryKey`) sont
// retirées : plus aucune vue ne les importe depuis la suppression des vues
// d'avant la vague 2 (C0.13). Ce module n'exporte rien.

import { configure as configureI18n } from "./i18n.js";
import {
  t, errorText, h, clear, icon, button, notify, announce, hotkeys, closeAll, setClipboardPolicy, clearClipboardNow,
} from "./ui/index.js";
import { loadCrypto, call } from "./wasm.js";
import { api, hasToken, onSessionExpired, setReauthUi } from "./api.js";
import * as V from "./vault.js";
import * as S from "./settings-client.js";
import { applyAccent } from "./accent.js";
import { createRouter } from "./router.js";
import { ROUTES, ALIASES, HOME } from "./routes.js";
import { createShell } from "./views/shell.js";
import { reauthUi, loginErrorText } from "./views/auth.js";
import { charterGate } from "./views/static.js";

const appEl = document.getElementById("app");
const main = document.getElementById("contenu");
const DEV = ["localhost", "127.0.0.1"].includes(location.hostname);
const ACTIVITY_EVENTS = ["mousemove", "keydown", "pointerdown", "scroll", "touchstart"];
const LOCK_WARNING_S = 60;

let health = null;
let pendingTarget = null;
let lockReason = "reload";
let twofaNoticed = false;
const viewRefreshers = new Set();

// ------------------------------------------------------------ Affichage

/** Thème, contraste, taille du texte et densité sur <html> (préférences de l'appareil puis synchronisées). */
function applyDisplay() {
  const root = document.documentElement;
  const set = (name, value) => {
    if (value === null || value === undefined) delete root.dataset[name];
    else root.dataset[name] = String(value);
  };
  const theme = S.effective("ui.theme").value;
  set("theme", theme === "light" || theme === "dark" ? theme : null);
  const contrast = S.effective("ui.contrast").value;
  set("contrast", contrast === "more" ? "more" : null);
  const scale = Number(S.effective("ui.text_scale").value);
  set("textScale", scale === 112.5 || scale === 125 ? scale : null);
  set("density", S.effective("ui.density").value === "compact" ? "compact" : null);
}
applyDisplay();
for (const key of ["ui.theme", "ui.contrast", "ui.text_scale", "ui.density"]) S.subscribe(key, applyDisplay);

// ------------------------------------------------------------ Coquille et routeur

const shell = createShell({
  navigate: (path) => router.navigate(path),
  lock: (reason) => lockNow(reason),
  logout: () => logoutNow(),
  newVault,
  openGenerator,
});

/** Nom d'élément ou de coffre déchiffré (interdit dans le titre de l'onglet). */
function isSensitive(text) {
  const s = String(text).trim();
  if (!s) return false;
  for (const c of V.state.collections.values()) if (c.name === s) return true;
  for (const i of V.state.items.values()) if (i.data?.name === s) return true;
  return false;
}

/** Écran de message avec titre h1 (page absente, réservée, introuvable). */
function messagePage(ctx, { iconName = "info", titleKey, textKey, back = true }) {
  clear(ctx.root, h("div", { class: "c-empty" },
    icon(iconName),
    h("h1", { class: "c-empty__title" }, t(titleKey)),
    textKey ? h("p", { class: "c-empty__text" }, t(textKey)) : null,
    back ? h("p", {}, h("a", { class: "c-button c-button--primary", href: `#${V.isUnlocked() ? HOME : "/connexion"}` },
      t(V.isUnlocked() ? "shell.page.back_to_vault" : "auth.action.back_to_login"))) : null));
  return { dispose() {}, isDirty: () => false };
}

const router = createRouter({
  root: main,
  routes: ROUTES,
  aliases: ALIASES,
  dev: DEV,
  isSensitive,
  decide,
  makeContext,
  // Le titre de l'onglet reste celui de la route (la barre latérale la désigne aussi).
  comingSoon: (ctx) => messagePage(ctx, { titleKey: "shell.page.coming_soon_title", textKey: "shell.page.coming_soon_text" }),
  notFound: (ctx) => {
    ctx.setTitle("shell.page.not_found_title");
    return messagePage(ctx, { iconName: "search", titleKey: "shell.page.not_found_title", textKey: "shell.page.not_found_text" });
  },
  failed: (ctx, err) => {
    console.error(err);
    clear(ctx.root, h("div", { class: "c-empty" }, icon("error"),
      h("h1", { class: "c-empty__title" }, t("ui.state.error_title")),
      h("p", { class: "c-empty__text" }, errorText(err)),
      button({ label: t("common.action.retry"), icon: "refresh", variant: "primary", onClick: () => router.reload() })));
    return { dispose() {}, isDirty: () => false };
  },
  onNavigated: (cur) => {
    if (shell.isMounted()) shell.setCurrent(cur.route, cur.params);
  },
});

const target = (path, query) => `${path}${query && [...query.keys()].length ? `?${query}` : ""}`;

/** Choix de l'écran selon la session : accès, verrouillage, page réservée, vue. */
async function decide(match, query, _extras, routePath) {
  const r = match.route;
  const path = target(routePath, query);
  if (r.access === "public") {
    if (V.isUnlocked()) shell.mount(appEl, main);
    else shell.unmount();
    return { kind: "view" };
  }
  if (r.access === "auth") return decideAuth(r);
  if (!hasToken()) {
    pendingTarget = path;
    return { kind: "redirect", path: (await needsSetup()) ? "/installation" : "/connexion" };
  }
  if (!V.isUnlocked()) {
    pendingTarget = path;
    return { kind: "redirect", path: "/verrouille" };
  }
  if (V.state.profile?.must_setup_2fa && !r.pattern.startsWith("/parametres")) {
    if (!twofaNoticed) {
      twofaNoticed = true;
      notify({ text: t("errors.2fa_required"), tone: "warn" });
    }
    return { kind: "redirect", path: "/parametres/compte" };
  }
  shell.mount(appEl, main);
  if (r.admin && V.state.profile?.role === "user") {
    return {
      kind: "screen",
      titleKey: "shell.page.admin_only_title",
      render: (ctx) => messagePage(ctx, { iconName: "lock", titleKey: "shell.page.admin_only_title", textKey: "shell.page.admin_only_text" }),
    };
  }
  return { kind: "view" };
}

async function decideAuth(r) {
  const unlocked = V.isUnlocked();
  if (r.screen === "locked") {
    if (!hasToken()) return { kind: "redirect", path: "/connexion" };
    if (unlocked) return { kind: "redirect", path: takeTarget() };
    shell.unmount();
    return { kind: "screen", render: (ctx) => authView(ctx, { ...ctx.extras, lockReason }) };
  }
  if (unlocked) return { kind: "redirect", path: HOME };
  if (hasToken() && r.screen !== "sso") return { kind: "redirect", path: "/verrouille" };
  if (r.screen === "login" && (await needsSetup())) return { kind: "redirect", path: "/installation" };
  if (r.screen === "install" && !(await needsSetup())) return { kind: "redirect", path: "/connexion" };
  shell.unmount();
  return { kind: "screen", render: (ctx) => authView(ctx, ctx.extras) };
}

async function authView(ctx, extras) {
  const mod = await import("./views/auth.js");
  return mod.render({ ...ctx, extras: extras || {} });
}

function takeTarget() {
  const to = pendingTarget || HOME;
  pendingTarget = null;
  return to;
}

async function needsSetup() {
  if (health && !health.needs_setup) return false;
  health = await api("GET", "/health").catch(() => health);
  return !!health?.needs_setup;
}

function makeContext({ path, query, route, params, extras, setTitle, root }) {
  viewRefreshers.clear();
  const profile = V.state.profile;
  return {
    root: root ?? main,
    route,
    path,
    params,
    query,
    extras,
    health,
    navigate: (to, opts) => router.navigate(to, opts),
    setQuery: (obj) => router.setQuery(obj),
    setTitle,
    refresh: () => refreshApp(),
    onRefresh: (fn) => {
      viewRefreshers.add(fn);
      return () => viewRefreshers.delete(fn);
    },
    user: profile,
    role: profile?.role ?? null,
    unlocked: V.isUnlocked(),
    settings: S,
    announce,
    shell: shell.api,
    done: () => afterUnlock(),
    logout: () => logoutNow(),
  };
}

// ------------------------------------------------------------ Démarrage

async function boot() {
  clear(main, h("div", { class: "l-auth" }, h("p", { class: "l-cluster" }, h("span", { class: "c-spinner", "aria-hidden": "true" }), t("auth.busy.loading_crypto"))));
  const skip = document.querySelector(".c-skip-link");
  if (skip) {
    skip.textContent = t("shell.skip_link");
    // Pas de changement d'adresse (le fragment porte la route) : focus direct sur le contenu.
    skip.addEventListener("click", (e) => {
      e.preventDefault();
      main.focus();
    });
  }
  try {
    await loadCrypto();
  } catch {
    clear(main, h("div", { class: "l-auth" }, h("div", { class: "l-auth__card l-stack" },
      h("h1", {}, t("auth.error.crypto_unsupported_title")),
      h("p", {}, t("auth.error.crypto_unsupported_text")))));
    return;
  }
  S.configure({
    vault: V,
    estimator: (password) => call("strength", { password }).score,
  });
  setReauthUi(reauthUi);
  setClipboardPolicy({ clearSeconds: () => S.effective("client.clipboard_clear_seconds").value });
  onSessionExpired((err) => endSession(err));
  window.addEventListener("online", () => {
    shell.setOffline(false);
    // Retour du réseau : synchronisation (la coquille garde ses nœuds).
    if (V.isUnlocked()) refreshApp().catch(() => {});
  });
  window.addEventListener("offline", () => shell.setOffline(true));
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && V.isUnlocked() && S.effective("client.lock_on_hide").value === true) lockNow("hidden");
  });
  const [status, pub] = await Promise.all([api("GET", "/health").catch(() => null), S.loadPublic()]);
  health = status;
  if (pub?.i18n?.timezone) configureI18n({ timeZone: pub.i18n.timezone });
  // Couleur de l'organisation, dès l'écran de connexion.
  applyAccent(document.documentElement, pub?.branding?.accent_color);
  await router.start();
}

// ------------------------------------------------------------ Session

/** Après connexion ou déverrouillage : coffre, politique, préférences, charte, puis la route visée. */
async function afterUnlock() {
  clear(main, h("div", { class: "l-auth" }, h("p", { class: "l-cluster" }, h("span", { class: "c-spinner", "aria-hidden": "true" }), t("auth.busy.decrypt"))));
  try {
    await V.sync();
  } catch (e) {
    notify({ text: errorText(e), tone: "danger" });
  }
  await Promise.allSettled([S.loadPolicy(V.state.revisions?.policy ?? undefined), S.loadPrefs(V.state.revisions?.prefs ?? undefined)]);
  applyDisplay();
  hotkeys.setEnabled(S.effective("client.single_key_shortcuts").value !== false);
  if (!(await charterAccepted())) return undefined;
  startAutoLock();
  if (S.consumeClampNotice("client.autolock_minutes")) {
    const max = S.effective("client.autolock_minutes").max;
    notify({ text: t("shell.lock.clamped", { max: t("shell.lock.minutes", { n: max }) }), tone: "info" });
  }
  twofaNoticed = false;
  return router.navigate(takeTarget(), { replace: true });
}

/** Charte de l'organisation : à accepter si sa version a changé (serveur sans la route : rien). */
async function charterAccepted() {
  let status = null;
  try {
    status = await api("GET", "/me/charter");
  } catch {
    return true;
  }
  if (!status || !(status.required_version > status.accepted_version)) return true;
  document.title = t("common.title_suffix", { title: t("legal.charter.title") });
  return charterGate({ root: main }, status.required_version, { onLogout: () => logoutNow() });
}

/** Synchronise, met à jour la coquille (mêmes nœuds) et prévient la vue. */
async function refreshApp() {
  await V.sync();
  // Politique et préférences relues seulement si /sync annonce une autre révision.
  S.loadPolicy(V.state.revisions?.policy ?? undefined).catch(() => {});
  if (Number.isFinite(V.state.revisions?.prefs)) S.loadPrefs(V.state.revisions.prefs).catch(() => {});
  shell.update();
  for (const fn of [...viewRefreshers]) {
    try {
      await fn();
    } catch (e) {
      console.error(e);
    }
  }
}

/** Efface tout de suite le dernier secret copié (copySecret de ui/). */
function clearCopiedSecrets() {
  clearClipboardNow();
}

function stopSession() {
  stopAutoLock();
  unbindHotkeys();
  clearCopiedSecrets();
  closeAll();
}

/** Verrouillage : la session reste ouverte, les clés sont effacées de la mémoire. */
function lockNow(reason = "manual") {
  if (!V.isUnlocked()) return;
  const cur = router.current();
  if (cur?.route && cur.route.access !== "auth") pendingTarget = target(cur.path, cur.query);
  stopSession();
  V.lock();
  S.reset();
  shell.unmount();
  lockReason = reason;
  router.navigate("/verrouille", { replace: true, force: true });
}

/** Déconnexion complète : session close, clés et presse-papiers effacés. */
async function logoutNow() {
  stopSession();
  await V.logout();
  S.reset();
  shell.unmount();
  pendingTarget = null;
  return router.navigate("/connexion", { replace: true, force: true });
}

/**
 * Session refusée par le serveur (api.js : 401 unauthorized, 403
 * account_disabled ou account_expired) : clés effacées, retour à la
 * connexion avec la raison (compte désactivé : contact d'assistance).
 */
function endSession(err) {
  stopSession();
  V.lock();
  V.state.profile = null;
  S.reset();
  shell.unmount();
  // Après la reconnexion, retour sur la page quittée (comme au verrouillage).
  const cur = router.current();
  if (cur?.route && cur.route.access !== "auth") pendingTarget = target(cur.path, cur.query);
  notify({ text: loginErrorText(err), tone: "warn" });
  router.navigate("/connexion", { replace: true, force: true });
}

// ------------------------------------------------------------ Verrouillage automatique

let idleTimer = 0;
let warnTimer = 0;
let lastActivity = 0;
let activityWatched = false;
let unbind = [];

/** Relance le compte à rebours d'inactivité ; préavis 60 s avant (règle A12). */
function resetIdle() {
  clearTimeout(idleTimer);
  clearTimeout(warnTimer);
  shell.hideLockWarning();
  if (!V.isUnlocked()) return;
  const minutes = Number(S.effective("client.autolock_minutes").value);
  if (!(minutes > 0)) return;
  const ms = minutes * 60_000;
  if (ms > LOCK_WARNING_S * 1000) {
    warnTimer = setTimeout(() => shell.showLockWarning(LOCK_WARNING_S, resetIdle), ms - LOCK_WARNING_S * 1000);
  }
  idleTimer = setTimeout(() => lockNow("idle"), ms);
}

function onActivity() {
  const now = Date.now();
  if (now - lastActivity < 1000) return;
  lastActivity = now;
  resetIdle();
}

function startAutoLock() {
  if (!activityWatched) {
    activityWatched = true;
    for (const ev of ACTIVITY_EVENTS) window.addEventListener(ev, onActivity, { passive: true, capture: true });
    S.subscribe("client.autolock_minutes", () => resetIdle());
    S.subscribe("client.single_key_shortcuts", (e) => hotkeys.setEnabled(e.value !== false));
  }
  bindHotkeys();
  lastActivity = Date.now();
  resetIdle();
}

function stopAutoLock() {
  clearTimeout(idleTimer);
  clearTimeout(warnTimer);
  shell.hideLockWarning();
}

function bindHotkeys() {
  unbindHotkeys();
  unbind = [
    hotkeys.register({ id: "search.focus", run: () => shell.focusSearch() }),
    hotkeys.register({ id: "lock", run: () => lockNow("manual") }),
    hotkeys.register({ id: "help", run: () => hotkeys.helpDialog() }),
  ];
}

function unbindHotkeys() {
  for (const off of unbind) off();
  unbind = [];
}

// ------------------------------------------------------------ Branchements de la coquille

/** « Nouveau coffre » de la barre latérale : fenêtre du module du coffre (L10). */
async function newVault() {
  try {
    const { newCollectionDialog } = await import("./views/vault/actions.js");
    return newCollectionDialog({ navigate: (p) => router.navigate(p), refresh: () => refreshApp() });
  } catch (e) {
    console.error(e);
    notify({ text: errorText(e), tone: "danger" });
    return undefined;
  }
}

async function openGenerator(opts) {
  try {
    const m = await import("./views/tools/generator.js");
    if (typeof m.openGeneratorPanel === "function") return m.openGeneratorPanel(opts);
  } catch { /* générateur en panneau absent : page du générateur */ }
  return router.navigate("/generateur");
}

boot();
