// Module d'entrée des pages outils (contrat B.4 / C4.3) : #/bilan,
// #/liens, #/generateur. Chaque page est chargée à la demande.

const PAGES = Object.freeze({
  accueil: () => import("./dashboard.js"),
  bilan: () => import("./health.js"),
  liens: () => import("./links.js"),
  generateur: () => import("./generator.js"),
});

/** Page demandée : paramètre du routeur, sinon premier segment de l'adresse. */
export function pageOf(ctx) {
  const fromParams = ctx?.params?.page;
  if (fromParams && Object.hasOwn(PAGES, fromParams)) return fromParams;
  const path = String(ctx?.path ?? globalThis.location?.hash ?? "").replace(/^#/, "").split("?")[0];
  const first = path.split("/").filter(Boolean)[0] || "";
  return Object.hasOwn(PAGES, first) ? first : "accueil";
}

export async function render(ctx) {
  const mod = await PAGES[pageOf(ctx)]();
  return mod.render(ctx);
}
