// Bilan de sécurité (cahier §3.3.7, parcours 6 du §3.6) : score, lignes à
// corriger avec le même mot que la jauge de force, « Corriger » qui ouvre le
// site et l'éditeur avec un nouveau mot de passe déjà généré : 3 clics
// (« Bilan de sécurité », « Corriger <nom> », « Enregistrer »).

import { test, expect } from "../../fixtures/index.ts";
import { aller, creerElements, nouveauCompte, tolerer } from "./outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(({ consoleGuard }) => tolerer(consoleGuard));

const FAIBLE = "azerty";
const PARTAGE = "Lune-Verte-Piano-Rivage-2024!";
/** Site de l'élément faible, servi par le test (le lanceur n'a pas accès à Internet). */
const SITE = "https://banque.exemple/connexion";

test("score, catégories alignées sur la jauge, « Corriger » en 3 clics", async ({ page, apiAs, clicks, context }) => {
  test.setTimeout(150_000);
  await nouveauCompte(page, await apiAs("owner"), "bilan");
  const [banqueId] = await creerElements(page, [
    { name: "Banque en ligne", username: "camille", password: FAIBLE, urls: [SITE] },
    { name: "Serveur NAS", username: "exploitation", password: PARTAGE },
    { name: "Wi-Fi bureau", username: "wifi", password: PARTAGE },
    { name: "Agenda", username: "camille", password: "Xq7!vT9#mPz2$Lw4&Rk8" },
  ]);
  await context.route("https://banque.exemple/**", (route) => route.fulfill({ contentType: "text/html", body: "<!doctype html><title>Banque</title>" }));
  await aller(page, "/coffre");

  const corriger = page.getByRole("button", { name: "Corriger Banque en ligne" });
  const site = context.waitForEvent("page");
  const n = await clicks.measure(async () => {
    await clicks.click(page.getByRole("navigation", { name: "Navigation principale" }).getByRole("link", { name: "Bilan de sécurité" }));
    await expect(page.getByRole("heading", { level: 1, name: "Bilan de sécurité" })).toBeVisible();

    // 3 mots de passe sur 4 sont à corriger (1 faible, 2 réutilisés) : 25 sur 100.
    await expect(page.getByText("Score 25 / 100")).toBeVisible();
    const tableau = page.getByRole("table", { name: "À corriger (3)" });
    await expect(tableau).toBeVisible();
    // Même mot que la jauge de force pour ce mot de passe.
    const libelle = await page.evaluate(async (pw) => {
      const W = await import("/js/wasm.js");
      const UI = await import("/js/ui/index.js");
      const s = W.call("strength", { password: pw });
      return UI.strengthLabel(UI.strengthLevel(s.score, s.warnings || []));
    }, FAIBLE);
    await expect(tableau.getByRole("row").filter({ hasText: "Banque en ligne" })).toContainText(libelle);
    await expect(tableau.getByRole("row").filter({ hasText: "Serveur NAS" })).toContainText("Réutilisé");
    await expect(tableau.getByRole("row").filter({ hasText: "Agenda" })).toHaveCount(0);

    await clicks.click(corriger);
    await expect(page).toHaveURL(new RegExp(`#/element/${banqueId}/modifier\\?regenerer=1$`));
    const champ = page.getByLabel(/^Mot de passe$/).first();
    await expect(champ).not.toHaveValue(FAIBLE);
    await expect(champ).not.toHaveValue("");
    await clicks.click(page.getByRole("button", { name: "Enregistrer", exact: true }));
  });
  expect(n).toBe(3);

  // Le site s'ouvre dans un nouvel onglet, sans référent ni accès à la page d'origine.
  const onglet = await site;
  await onglet.waitForLoadState();
  expect(onglet.url()).toBe(SITE);
  expect(await onglet.evaluate(() => window.opener)).toBeNull();
  await onglet.close();

  await expect.poll(() => page.evaluate(async (id) => {
    const V = await import("/js/vault.js");
    return V.state.items.get(id)?.data?.password;
  }, banqueId)).not.toBe(FAIBLE);
});

test("coffre sans mot de passe : état vide avec l'action qui le remplit", async ({ page, apiAs }) => {
  test.setTimeout(120_000);
  await nouveauCompte(page, await apiAs("owner"), "bilan-vide");
  await aller(page, "/bilan");
  await expect(page.getByRole("heading", { name: "Rien à analyser pour l'instant" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Ajouter un identifiant" })).toHaveAttribute("href", "#/nouveau/login");
});
