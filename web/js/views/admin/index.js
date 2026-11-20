// Administration (lot L12) : point d'entrée des routes #/admin* (contrat C4.3).
//
//   #/admin                                  Accueil (home.js)
//   #/admin/personnes[?filtres]              Personnes (people.js)
//   #/admin/personnes/:id                    Personnes + fiche en panneau (person.js)
//   #/admin/personnes/:id/depart             Assistant « Départ de l'entreprise » (offboarding.js)
//   #/admin/reglages                         -> #/admin/reglages/login
//   #/admin/reglages/:section                Réglages générés (settings.js)
//   #/admin/reglages/historique|transfert|systeme
//   #/admin/journal[?filtres]                Journal (journal.js)
//   #/admin/connexion*                       délégué à ./identity/index.js (lot L13, C4.6)
//
// Chaque écran exporte renderPage(ctx, content, route) -> { dispose, isDirty, save? } ;
// route.subnav reçoit la navigation propre à l'écran (sections des réglages).
// Un module absent (serveur ou client partiel) affiche « Cette page arrive bientôt ».

import { adminShell, comingSoon, ensureAdminCss } from "./shell.js";

/** Pages des réglages qui ne sont pas des sections du registre. */
const SETTINGS_PAGES = Object.freeze({ historique: "history", transfert: "transfer", systeme: "system" });

/** Découpe le reste du chemin (#/admin/<reste>) en écran et paramètres. */
function parseAdminPath(rest = "") {
  const parts = String(rest || "").split("/").filter(Boolean);
  const [head, a, b] = parts;
  if (!head) return { page: "home", nav: "home" };
  if (head === "personnes") {
    if (!a) return { page: "people", nav: "people" };
    if (b === "depart") return { page: "offboarding", nav: "people", id: a };
    return { page: "people", nav: "people", id: a };
  }
  if (head === "reglages") {
    if (!a) return { page: "settings", nav: "settings", section: "login", redirect: "/admin/reglages/login" };
    if (SETTINGS_PAGES[a]) return { page: SETTINGS_PAGES[a], nav: "settings", section: a };
    return { page: "settings", nav: "settings", section: a };
  }
  if (head === "journal") return { page: "journal", nav: "journal" };
  if (head === "connexion") return { page: "identity", nav: "identity" };
  return { page: "not_found", nav: null };
}

const LOADERS = Object.freeze({
  home: () => import("./home.js"),
  people: () => import("./people.js"),
  offboarding: () => import("./offboarding.js"),
  settings: () => import("./settings.js"),
  history: () => import("./settings-history.js"),
  transfer: () => import("./settings-transfer.js"),
  system: () => import("./system.js"),
  journal: () => import("./journal.js"),
});

const TITLES = Object.freeze({
  home: "admin.title.home",
  people: "admin.title.people",
  offboarding: "admin.title.offboarding",
  settings: "admin.title.settings",
  history: "admin.title.history",
  transfer: "admin.title.transfer",
  system: "admin.title.system",
  journal: "admin.title.journal",
  identity: "admin.title.identity",
  not_found: "admin.title.home",
});

const idle = () => ({ dispose() {}, isDirty: () => false });

export async function render(ctx) {
  const route = parseAdminPath(ctx.params?.rest);
  if (route.redirect && typeof ctx.navigate === "function") {
    ctx.navigate(route.redirect, { replace: true });
    return idle();
  }
  ctx.setTitle?.(TITLES[route.page] || "admin.title.home");
  ensureAdminCss();
  const shell = adminShell(ctx, route.nav);

  if (route.page === "identity") {
    // Connexion d'entreprise : écrans du lot L13, dans la coquille admin.
    try {
      const mod = await import("./identity/index.js");
      return (await mod.render({ ...ctx, root: shell.content })) || idle();
    } catch {
      comingSoon(shell.content);
      return idle();
    }
  }

  const load = LOADERS[route.page];
  let mod = null;
  try {
    mod = load ? await load() : null;
  } catch {
    mod = null;
  }
  if (!mod) {
    comingSoon(shell.content);
    return idle();
  }
  return (await mod.renderPage(ctx, shell.content, { ...route, subnav: shell.subnav })) || idle();
}
