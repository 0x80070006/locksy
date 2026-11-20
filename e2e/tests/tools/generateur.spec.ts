// Générateur de mots de passe (cahier §3.3.6, fiche L11) : minimum imposé
// par l'organisation (curseur borné et mention), annonce différée qui ne
// contient jamais le secret, panneau ouvert depuis la coquille, réglage
// mémorisé dans les préférences synchronisées.

import { test, expect } from "../../fixtures/index.ts";
import { loginUi } from "../../fixtures/ui.ts";
import { aller, connecter, deverrouiller, glisser, nouveauCompte, politique, tolerer } from "./outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(({ consoleGuard }) => tolerer(consoleGuard));

/** Valeur affichée par le générateur (groupes de 4, sans espace réel). */
const valeur = (scope: import("@playwright/test").Locator) => scope.locator(".c-secret").first().textContent();

test("minimum imposé : curseur borné, mention visible, annonce sans le secret", async ({ page, org }) => {
  await politique(page, { "generator.min_length": { value: 16 } });
  await loginUi(page, org.accounts.user);
  await aller(page, "/generateur");

  await expect(page.getByRole("heading", { level: 1, name: "Générateur de mots de passe" })).toBeVisible();
  const longueur = page.getByRole("slider", { name: "Longueur" });
  await expect(longueur).toHaveAttribute("min", "16");
  await expect(page.getByText("Minimum imposé par votre organisation : 16 caractères.")).toBeVisible();
  // Une valeur sous le minimum est ramenée par le curseur lui-même.
  await glisser(longueur, 10);
  await expect(longueur).toHaveValue("16");

  // La valeur n'est dans aucune région annoncée.
  const secret = page.locator("#contenu .c-secret").first();
  expect(await secret.evaluate((el) => el.closest("[aria-live], [role=status], [role=alert]") === null)).toBe(true);

  await page.getByRole("button", { name: "Un autre" }).click();
  const v = (await valeur(page.locator("#contenu"))) ?? "";
  expect(v.length).toBeGreaterThanOrEqual(16);
  await expect(page.locator("#status")).toContainText("Nouveau mot de passe : 16 caractères");
  await expect(page.locator("#status")).not.toContainText(v);
});

test("panneau depuis la coquille : Copier, Un autre, sans Utiliser ; fermeture au clavier", async ({ page, org }) => {
  await loginUi(page, org.accounts.user);
  const ouvrir = page.getByRole("button", { name: "Générer", exact: true }).first();
  await ouvrir.click();
  const panneau = page.getByRole("dialog", { name: "Générer un mot de passe" });
  await expect(panneau).toBeVisible();
  await expect(panneau.getByRole("button", { name: "Copier" })).toBeVisible();
  await expect(panneau.getByRole("button", { name: "Utiliser" })).toHaveCount(0);
  const avant = await valeur(panneau);
  await panneau.getByRole("button", { name: "Un autre" }).click();
  await expect.poll(() => valeur(panneau)).not.toBe(avant);
  await page.keyboard.press("Escape");
  await expect(panneau).toHaveCount(0);
});

test("réglage du générateur mémorisé : relu après rechargement", async ({ page, apiAs }) => {
  test.setTimeout(150_000);
  const compte = await nouveauCompte(page, await apiAs("owner"), "generateur");
  await aller(page, "/generateur");
  const longueur = page.getByRole("slider", { name: "Longueur" });
  await expect(longueur).toBeVisible();
  const enregistre = page.waitForResponse((r) => r.url().includes("/api/me/prefs") && r.request().method() === "PUT");
  await glisser(longueur, 24);
  expect((await enregistre).ok()).toBe(true);

  await page.reload();
  await deverrouiller(page, compte.password);
  await aller(page, "/generateur");
  await expect(page.getByRole("slider", { name: "Longueur" })).toHaveValue("24");
  await expect(page.locator("#status")).not.toContainText((await valeur(page.locator("#contenu"))) ?? "§");
});

test("téléphone : pages des outils et des paramètres sans défilement horizontal", { tag: "@mobile" }, async ({ page, org }) => {
  await connecter(page, org.accounts.user);
  const largeurOk = () => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
  for (const [route, titre] of [
    ["/generateur", "Générateur de mots de passe"],
    ["/bilan", "Bilan de sécurité"],
    ["/liens", "Liens envoyés"],
    ["/parametres/compte", "Paramètres"],
    ["/parametres/preferences", "Paramètres"],
    ["/parametres/donnees", "Paramètres"],
  ] as const) {
    await aller(page, route);
    await expect(page.getByRole("heading", { level: 1, name: titre })).toBeVisible();
    expect(await largeurOk(), `défilement horizontal sur #${route}`).toBe(true);
  }
  await aller(page, "/generateur");
  await expect(page.getByRole("button", { name: "Copier" })).toBeInViewport();
});
