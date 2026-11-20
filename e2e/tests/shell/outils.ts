// Outils communs aux tests de la coquille et de l'authentification (lot L9).

import type { Page } from "@playwright/test";

/**
 * Modules d'entrée des vues de contenu des autres lots (routes.js) : ces
 * tests vérifient la coquille et l'authentification, pas le contenu des
 * vues, qui a ses propres suites. Chaque module est remplacé par un module
 * sans render() : la route affiche « Cette page arrive bientôt » (repli de
 * routes.js), avec le titre et l'entrée de navigation de la route.
 */
const VUES_DE_CONTENU = ["vault", "tools", "settings", "admin"];

export async function isolerVues(page: Page) {
  for (const vue of VUES_DE_CONTENU) {
    await page.route(`**/js/views/${vue}/index.js`, (route) => route.fulfill({ contentType: "text/javascript", body: "export {};\n" }));
  }
}

/**
 * Document de préférences absent : /sync l'annonce (prefs_revision 0) quand
 * le serveur ne le fait pas encore (route L7b), ce qui évite un GET
 * /me/prefs en 404 à chaque connexion. Une révision publiée par le serveur
 * est gardée telle quelle.
 */
export async function annoncerPreferences(page: Page) {
  await page.route("**/api/sync*", async (route) => {
    const res = await route.fetch();
    if (!res.ok()) return route.fulfill({ response: res });
    const body = await res.json();
    await route.fulfill({ response: res, json: { ...body, prefs_revision: body.prefs_revision ?? 0 } });
  });
}

/** Préparation commune des tests du lot : vues de contenu isolées, préférences annoncées. */
export async function preparer({ page }: { page: Page }) {
  await isolerVues(page);
  await annoncerPreferences(page);
}

/** Navigation principale de la coquille (annexe C). */
export const navPrincipale = (page: Page) => page.getByRole("navigation", { name: "Navigation principale" });

/**
 * Crée un élément « Mot de passe » dans le coffre personnel, par le module
 * de chiffrement de la page (même instance que l'application), sans passer
 * par l'éditeur (lot L10). Mot de passe solide par défaut. Renvoie
 * l'identifiant de l'élément et celui de son coffre.
 */
export async function creerElement(page: Page, name: string, password = "Mot-de-passe-de-test-42"): Promise<{ id: string; collectionId: string }> {
  return page.evaluate(async ([n, pw]) => {
    const V = await import("/js/vault.js");
    const personal = [...V.state.collections.values()].find((c) => c.personal);
    if (!personal) throw new Error("Coffre personnel introuvable.");
    const data = { ...V.emptyItem("login"), name: n, username: "camille", password: pw };
    const id = await V.createItem(personal.id, data);
    return { id, collectionId: personal.id };
  }, [name, password] as const);
}

/** Élément actif de la page : balise et texte (jamais <body> après une action). */
export async function elementActif(page: Page): Promise<{ tag: string; text: string }> {
  return page.evaluate(() => ({ tag: document.activeElement?.tagName ?? "", text: document.activeElement?.textContent?.trim() ?? "" }));
}

/**
 * Connexion par l'interface, valable à toutes les largeurs : sur téléphone,
 * la navigation est dans le tiroir fermé (hidden + inert, règle A7) ; la
 * coquille est reconnue au bouton « Menu du compte » de la barre du haut.
 */
export async function connecter(page: Page, a: { email: string; password: string }) {
  await page.goto("/");
  await page.getByLabel("Adresse e-mail").fill(a.email);
  await page.getByLabel(/^Mot de passe maître$/).fill(a.password);
  await page.getByRole("button", { name: /^Se connecter$/ }).click();
  await page.getByRole("button", { name: "Menu du compte" }).waitFor({ timeout: 60_000 });
}

/**
 * Coupure (true) ou retour (false) du réseau. Sous Firefox, Playwright coupe
 * le réseau sans changer navigator.onLine ni émettre « offline »/« online » :
 * l'événement est alors émis à la main, pour suivre le même chemin de code
 * que dans un vrai navigateur (bandeau hors ligne, synchronisation au retour).
 */
export async function reseau(page: Page, enLigne: boolean) {
  await page.context().setOffline(!enLigne);
  if (page.context().browser()?.browserType().name() !== "firefox") return;
  await page.evaluate((ev) => window.dispatchEvent(new Event(ev)), enLigne ? "online" : "offline");
}
