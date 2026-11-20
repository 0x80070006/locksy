// Connexion d'entreprise (cahier §3.4.7), chargée par l'administration
// (views/admin/index.js) pour #/admin/connexion, #/admin/connexion/sso,
// #/admin/connexion/ad et #/admin/connexion/scim.
//
// export async function render(ctx) -> { dispose(), isDirty() } (contrat B.4).
// La page est lue dans ctx.params.rest (« connexion/sso »), ou à défaut dans le
// fragment ; ctx.query (URLSearchParams) porte le résultat d'un test SSO
// (?test=ok), effacé ensuite par ctx.setQuery.

import { clear, dirtyGuard, errorState, h, statusCard, t, withLoading } from "../../../ui/index.js";
import { adPage } from "./ad.js";
import { chooser } from "./choose.js";
import { pageHeader } from "./common.js";
import { scimPage } from "./scim.js";
import { ssoPage } from "./sso.js";
import { anyConfigured, identityStatusCards, loadIdentityStatus } from "./status-cards.js";

/** Aperçu : aide au choix (si rien n'est configuré) et cartes d'état. */
async function overviewPage(container) {
  const status = await loadIdentityStatus();
  const configured = anyConfigured(status);
  const help = h("div", {});
  const showHelp = ({ focus = false } = {}) => {
    const el = chooser();
    clear(help, el);
    if (focus) el.querySelector("input")?.focus();
  };
  if (!configured) showHelp();
  clear(container,
    ...pageHeader("identity.title", "identity.intro"),
    help,
    h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "identite-methodes" },
      h("h2", { id: "identite-methodes" }, t("identity.methods.title")),
      h("div", { class: "l-grid" }, ...identityStatusCards(status))),
    configured
      ? statusCard({ tone: "info", title: t("identity.choose.title"), detail: t("identity.choose.again"), action: { label: t("identity.choose.show"), onClick: () => showHelp({ focus: true }) } })
      : null);
  return {};
}

const PAGES = Object.freeze({ "": overviewPage, sso: ssoPage, ad: adPage, scim: scimPage });
const TITLES = Object.freeze({ "": "identity.title", sso: "identity.sso.title", ad: "identity.ad.title", scim: "identity.scim.title" });

/**
 * Page demandée : ctx.params.rest de l'administration (« connexion/sso »),
 * sinon le fragment (#/admin/connexion/<page>). Page inconnue : l'aperçu.
 */
function sectionOf(ctx) {
  const rest = typeof ctx?.params?.rest === "string" ? ctx.params.rest : location.hash.replace(/^#\/admin\/?/, "");
  const m = /^connexion\/([a-z]+)/.exec(rest.split("?")[0].toLowerCase());
  return m && Object.hasOwn(PAGES, m[1]) ? m[1] : "";
}

/** Paramètres de la requête du fragment (?test=ok&code=…). */
function queryOf(ctx) {
  if (ctx?.query instanceof URLSearchParams) return ctx.query;
  const i = location.hash.indexOf("?");
  return new URLSearchParams(i >= 0 ? location.hash.slice(i + 1) : "");
}

export async function render(ctx) {
  const section = sectionOf(ctx);
  if (typeof ctx.setTitle === "function") ctx.setTitle(TITLES[section]);
  else document.title = t("common.title_suffix", { title: t(TITLES[section]) });

  let page = null;
  let disposed = false;
  const isDirty = () => !disposed && !!page?.isDirty?.();
  // Fermeture de l'onglet avec une saisie en cours : le navigateur demande confirmation.
  const guard = dirtyGuard(isDirty);
  const container = h("div", {});
  clear(ctx.root, container);

  // La page est construite hors du document puis affichée d'un coup : le
  // squelette de chargement (posé au bout de 300 ms) ne peut donc pas effacer
  // une page déjà remplie qui attend encore une donnée secondaire
  // (historique des synchronisations…).
  const show = async () => {
    const view = h("div", { class: "l-stack", "data-gap": "5" });
    try {
      page = await withLoading(container, PAGES[section](view, { query: queryOf(ctx), setQuery: ctx.setQuery }));
    } catch (error) {
      page = null;
      clear(view, ...pageHeader(TITLES[section]), errorState({ error, onRetry: show }));
    }
    if (!disposed) clear(container, view);
  };
  await show();

  return {
    isDirty,
    dispose() {
      disposed = true;
      guard.destroy();
      page?.dispose?.();
    },
  };
}
