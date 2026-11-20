// Routeur par fragment (#/…) : cahier §3.1, contrat C4.3 de la vague 2.
//
// Exports :
//   parseHash(hash)                       -> { path: "/coffre", query: URLSearchParams }
//   matchPattern(pattern, path)           -> params | null (« :nom », « :nom? », « * » final)
//   findRoute(routes, path)               -> { route, params } | null
//   resolveAlias(aliases, path, query)    -> { path, query, … } | null
//   createRouter({ root, routes, aliases, decide, makeContext, comingSoon,
//                  notFound, failed, isSensitive, onNavigated, dev }) -> {
//     start(), stop(), navigate(path, { replace, force }), setQuery(obj), reload(),
//     current() -> { path, query, route, params, handle }, confirmLeave(), setTitle(key, params)
//   }
//
// À chaque changement de route :
//   1. alias historique résolu (remplacement dans l'historique, sans entrée de plus) ;
//   2. garde de saisie : si une fenêtre ouverte (ui/dialog.js) ou la vue courante
//      (isDirty) est modifiée, « Quitter sans enregistrer ? » (Enregistrer si la
//      fenêtre ou la vue sait enregistrer, Abandonner, Rester) ;
//      « Rester » remet l'adresse précédente ;
//   3. dispose() de la vue courante ;
//   4. decide(match, query, extras, path) : { kind: "view" } | { kind: "redirect", path } |
//      { kind: "screen", render(ctx) } (écran d'accès, page réservée…) ;
//   5. titre par défaut de la route, import du module (échec : « Cette page
//      arrive bientôt »), render(ctx) ;
//   6. focus sur le h1 de la vue (règle A3), sauf si la vue a déjà placé le
//      focus (handle.focused = true, ex. premier champ vide d'un formulaire).
// La coquille n'est jamais touchée : seul `root` (<main id="contenu">) change.
// Chaque navigation rend dans son propre conteneur (`.l-view`, transparent
// pour la mise en page) passé en `ctx.root` : une vue périmée qui finit son
// rendu, ou le squelette de chargement d'une navigation dépassée, écrit dans
// un conteneur détaché et n'efface jamais la page affichée.

import { t } from "./i18n.js";
import { clear, dirtyGuard, focusHeading, modifiedDialog, withLoading } from "./ui/index.js";

export function parseHash(hash = location.hash) {
  const raw = String(hash || "").replace(/^#/, "");
  const cut = raw.indexOf("?");
  const pathPart = cut < 0 ? raw : raw.slice(0, cut);
  const trimmed = pathPart.replace(/^\/+|\/+$/g, "");
  const path = trimmed ? `/${trimmed}` : pathPart ? "/" : "";
  return { path, query: new URLSearchParams(cut < 0 ? "" : raw.slice(cut + 1)) };
}

export function matchPattern(pattern, path) {
  const want = pattern.split("/").filter(Boolean);
  const got = String(path).split("/").filter(Boolean);
  const params = {};
  for (let i = 0; i < want.length; i++) {
    const w = want[i];
    if (w === "*") {
      if (i !== want.length - 1 || got.length <= i) return null;
      params.rest = got.slice(i).map(decodeSafe).join("/");
      return params;
    }
    const g = got[i];
    if (w.startsWith(":")) {
      const optional = w.endsWith("?");
      const name = w.slice(1, optional ? -1 : undefined);
      if (g === undefined) {
        if (!optional) return null;
        continue;
      }
      params[name] = decodeSafe(g);
    } else if (g !== w) {
      return null;
    }
  }
  return got.length > want.length ? null : params;
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export function findRoute(routes, path) {
  for (const route of routes) {
    const params = matchPattern(route.pattern, path);
    if (params) return { route, params };
  }
  return null;
}

export function resolveAlias(aliases, path, query) {
  for (const rule of aliases) {
    const out = rule(path, query);
    if (out) return out;
  }
  return null;
}

const hashOf = (path, query) => {
  const q = query && [...query.keys()].length ? `?${query.toString()}` : "";
  return `#${path}${q}`;
};

export function createRouter({
  root, routes, aliases = [], decide = () => ({ kind: "view" }), makeContext, comingSoon, notFound, failed,
  isSensitive = () => false, onNavigated, dev = false,
}) {
  let cur = null; // { path, query, route, params, handle, hash, extras }
  let seq = 0;
  let started = false;
  let leaving = null;
  let force = false;

  function setTitle(key, params, { suffix = true } = {}) {
    let safe = params;
    if (params && Object.values(params).some((v) => typeof v === "string" && isSensitive(v))) {
      // Règle R5 : jamais de nom d'élément ni de coffre dans le titre de l'onglet.
      if (dev) console.error(`router : setTitle(« ${key} ») avec un nom d'élément ou de coffre refusé.`);
      safe = undefined;
      key = cur?.route?.titleKey || key;
    }
    const title = t(key, safe);
    document.title = suffix ? t("common.title_suffix", { title }) : title;
  }

  async function confirmLeave() {
    // Fenêtre ouverte et modifiée : sa garde d'abord (« Enregistrer » passe
    // par son action principale) ; quitter la ferme avant de changer d'écran.
    const dlg = modifiedDialog();
    if (dlg) {
      leaving ??= dlg.confirmLeave().finally(() => { leaving = null; });
      if ((await leaving) === "stay") return false;
      dlg.close();
    }
    const handle = cur?.handle;
    if (!handle || typeof handle.isDirty !== "function" || !handle.isDirty()) return true;
    leaving ??= dirtyGuard(() => true, {
      unload: false,
      onSave: typeof handle.save === "function" ? () => handle.save() : undefined,
    }).confirmLeave().finally(() => { leaving = null; });
    return (await leaving) !== "stay";
  }

  function disposeCurrent() {
    const handle = cur?.handle;
    if (!handle) return;
    cur.handle = null;
    try {
      handle.dispose?.();
    } catch (e) {
      console.error(e);
    }
  }

  async function handleHash() {
    // Ancre interne (« #contenu » du lien d'évitement) : pas une route.
    if (location.hash && !location.hash.startsWith("#/")) return;
    let { path, query } = parseHash();
    let extras = {};
    const alias = resolveAlias(aliases, path, query);
    if (alias) {
      ({ path, query } = alias);
      extras = alias;
      history.replaceState(history.state, "", hashOf(path, query));
    }
    const hash = hashOf(path, query);
    if (cur && cur.hash === hash && cur.handle) return;
    const skipGuard = force;
    force = false;
    if (cur?.handle && !skipGuard && !(await confirmLeave())) {
      history.replaceState(history.state, "", cur.hash);
      return;
    }
    await show(path, query, extras);
  }

  async function show(path, query, extras = {}) {
    const my = ++seq;
    disposeCurrent();
    const match = findRoute(routes, path);
    cur = { path, query, hash: hashOf(path, query), route: match?.route ?? null, params: match?.params ?? {}, handle: null, extras };
    let decision = match ? await decide(match, query, extras, path) : { kind: "not_found" };
    if (my !== seq) return;
    if (decision.kind === "redirect") {
      history.replaceState(history.state, "", hashOf(decision.path, decision.query ?? new URLSearchParams()));
      return show(decision.path, decision.query ?? new URLSearchParams(), { ...extras, ...decision.extras });
    }
    if (match) setTitle(decision.titleKey || match.route.titleKey);
    const host = document.createElement("div");
    host.className = "l-view";
    const ctx = makeContext({ path, query, route: match?.route ?? null, params: match?.params ?? {}, extras, setTitle, router: api, root: host });
    clear(root, host);
    let handle = null;
    try {
      if (decision.kind === "not_found") handle = await notFound(ctx);
      else if (decision.kind === "screen") handle = await decision.render(ctx);
      else handle = await renderRoute(match.route, ctx, host, () => my !== seq);
    } catch (e) {
      if (my !== seq) return;
      handle = await failed(ctx, e);
    }
    if (my !== seq) {
      try { handle?.dispose?.(); } catch { /* vue déjà remplacée */ }
      return;
    }
    cur.handle = handle || { dispose() {}, isDirty: () => false };
    if (!cur.handle.focused) focusHeading(root);
    onNavigated?.(cur);
  }

  async function renderRoute(route, ctx, host, stale) {
    let mod = null;
    try {
      mod = await withLoading(host, route.load());
    } catch (e) {
      if (stale()) return null;
      // Module absent (lot pas encore livré), en erreur ou réseau coupé.
      console.error(e);
      return comingSoon(ctx);
    }
    if (stale()) return null;
    clear(host);
    if (typeof mod?.render !== "function") return comingSoon(ctx);
    return mod.render(ctx);
  }

  const onHash = () => { handleHash().catch((e) => console.error(e)); };

  const api = {
    start() {
      if (started) return handleHash();
      started = true;
      window.addEventListener("hashchange", onHash);
      return handleHash();
    },
    stop() {
      started = false;
      window.removeEventListener("hashchange", onHash);
      disposeCurrent();
      cur = null;
    },
    /** force : sans garde de saisie (verrouillage, déconnexion, fin de session). */
    navigate(path, { replace = false, force: noGuard = false } = {}) {
      force = noGuard;
      const target = path.startsWith("#") ? path : `#${path.startsWith("/") ? path : `/${path}`}`;
      if (location.hash === target && !replace) return handleHash();
      if (replace) {
        history.replaceState(history.state, "", target);
        return handleHash();
      }
      location.hash = target;
      return Promise.resolve();
    },
    /** Met à jour la requête sans recharger la vue ni ajouter d'entrée d'historique. */
    setQuery(obj) {
      if (!cur) return;
      const q = new URLSearchParams(cur.query);
      for (const [k, v] of Object.entries(obj || {})) {
        if (v === null || v === undefined || v === "") q.delete(k);
        else q.set(k, String(v));
      }
      cur.query = q;
      cur.hash = hashOf(cur.path, q);
      history.replaceState(history.state, "", cur.hash);
    },
    /** Rend de nouveau la route courante (après un verrouillage, par exemple). */
    reload() {
      if (cur) cur.hash = null;
      return handleHash();
    },
    current: () => cur,
    confirmLeave,
    setTitle,
  };
  return api;
}
