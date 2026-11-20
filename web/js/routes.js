// Table des routes de l'application (cahier §3.1, contrat C4.3 de la vague 2).
//
// Chaque entrée : { pattern, load: () => import("…"), titleKey, admin?, access?, screen?, page?, nav? }
//   pattern  : chemin du fragment, segments « :nom » (paramètre), « :nom? »
//              (facultatif) et « * » final (reste du chemin, dans params.rest) ;
//   load     : import dynamique du module de vue ; il exporte
//              `async function render(ctx)` -> { dispose(), isDirty(), save?() } ;
//   titleKey : titre par défaut (« <titre> · Locksy ») ; JAMAIS un nom d'élément
//              ni de coffre (règle R5) ;
//   admin    : réservé aux administrateurs et propriétaires ;
//   access   : "app" (coffre déverrouillé, défaut) | "public" (accessible sans
//              session : pages statiques) | "auth" (écran d'accès) ;
//   screen   : écran de views/auth.js (login, install, register, recover, sso, locked) ;
//   page     : page de views/static.js (help, accessibility, notice, charter) ;
//   nav      : entrée de la barre latérale à marquer (all, favorites,
//              collection, health, trash).
//
// Les écrans d'accès (connexion, inscription, récupération, verrouillage)
// sont choisis par app.js selon l'état de la session : ils figurent ici pour
// leur titre et leur adresse.
//
// Alias historiques (ALIASES) : anciennes adresses encore utilisées par des
// liens envoyés, les fixtures de test et le serveur (redirection SSO).

export const ROUTES = Object.freeze([
  // ---- Accès (choisis par app.js selon la session)
  { pattern: "/connexion", load: () => import("./views/auth.js"), titleKey: "auth.title.login", access: "auth", screen: "login" },
  { pattern: "/installation", load: () => import("./views/auth.js"), titleKey: "auth.title.install", access: "auth", screen: "install" },
  { pattern: "/inscription/:jeton", load: () => import("./views/auth.js"), titleKey: "auth.title.register", access: "auth", screen: "register" },
  { pattern: "/recuperation", load: () => import("./views/auth.js"), titleKey: "auth.title.recover", access: "auth", screen: "recover" },
  { pattern: "/sso", load: () => import("./views/auth.js"), titleKey: "auth.title.sso", access: "auth", screen: "sso" },
  { pattern: "/verrouille", load: () => import("./views/auth.js"), titleKey: "auth.title.locked", access: "auth", screen: "locked" },

  // ---- Accueil : tableau de bord de la personne connectée
  { pattern: "/accueil", load: () => import("./views/tools/index.js"), titleKey: "shell.title.home", nav: "home" },

  // ---- Coffre (L10)
  { pattern: "/coffre", load: () => import("./views/vault/index.js"), titleKey: "shell.title.vault", nav: "all" },
  { pattern: "/coffre/favoris", load: () => import("./views/vault/index.js"), titleKey: "shell.title.favorites", nav: "favorites" },
  { pattern: "/coffre/c/:collectionId", load: () => import("./views/vault/index.js"), titleKey: "shell.title.collection", nav: "collection" },
  { pattern: "/element/:id", load: () => import("./views/vault/index.js"), titleKey: "shell.title.item" },
  { pattern: "/element/:id/modifier", load: () => import("./views/vault/index.js"), titleKey: "shell.title.edit" },
  { pattern: "/nouveau/:type?", load: () => import("./views/vault/index.js"), titleKey: "shell.title.new" },
  { pattern: "/corbeille", load: () => import("./views/vault/index.js"), titleKey: "shell.title.trash", nav: "trash" },

  // ---- Outils (L11)
  { pattern: "/bilan", load: () => import("./views/tools/index.js"), titleKey: "shell.title.health", nav: "health" },
  { pattern: "/liens", load: () => import("./views/tools/index.js"), titleKey: "shell.title.links" },
  { pattern: "/generateur", load: () => import("./views/tools/index.js"), titleKey: "shell.title.generator" },
  { pattern: "/parametres/:section?", load: () => import("./views/settings/index.js"), titleKey: "shell.title.settings" },

  // ---- Administration (L12, qui délègue #/admin/connexion* à L13)
  { pattern: "/admin", load: () => import("./views/admin/index.js"), titleKey: "shell.title.admin", admin: true },
  { pattern: "/admin/*", load: () => import("./views/admin/index.js"), titleKey: "shell.title.admin", admin: true },

  // ---- Pages statiques (L9), accessibles aussi sans session
  { pattern: "/aide", load: () => import("./views/static.js"), titleKey: "shell.title.help", access: "public", page: "help" },
  { pattern: "/accessibilite", load: () => import("./views/static.js"), titleKey: "legal.a11y.title", access: "public", page: "accessibility" },
  { pattern: "/mentions", load: () => import("./views/static.js"), titleKey: "legal.notice.title", access: "public", page: "notice" },
  { pattern: "/charte", load: () => import("./views/static.js"), titleKey: "legal.charter.title", page: "charter" },
]);

/** Adresse d'accueil après connexion. */
export const HOME = "/accueil";

/**
 * Anciennes adresses -> nouvelles. Chaque règle reçoit (chemin, requête) et
 * renvoie { path, query } ou null. Le jeton d'installation est retiré de
 * l'adresse et transmis à part (setupToken), jamais gardé dans l'historique.
 */
export const ALIASES = Object.freeze([
  (path, q) => {
    if (path !== "/register") return null;
    if (q.get("setup")) return { path: "/installation", query: new URLSearchParams(), setupToken: q.get("setup") };
    if (q.get("token")) return { path: `/inscription/${encodeURIComponent(q.get("token"))}`, query: new URLSearchParams() };
    return { path: "/connexion", query: new URLSearchParams() };
  },
  simple("/recover", "/recuperation"),
  simple("/vault", "/coffre"),
  simple("/generator", "/generateur"),
  simple("/health", "/bilan"),
  simple("/shares", "/liens"),
  simple("/settings", "/parametres/compte"),
  simple("/login", "/connexion"),
  simple("/", HOME),
  simple("", HOME),
]);

function simple(from, to) {
  return (path, query) => (path === from ? { path: to, query } : null);
}
