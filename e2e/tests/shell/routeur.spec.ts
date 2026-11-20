// Routeur (cahier §3.1, contrat C4.3) : garde de saisie « Quitter sans
// enregistrer ? » (Rester, Abandonner, Enregistrer), dispose() de la vue
// quittée, titre refusé quand il contiendrait le nom d'un élément.
//
// La vue du coffre est remplacée par une vue simulée (module servi par
// page.route) qui respecte le contrat render(ctx) -> { dispose, isDirty, save }.

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { loginUi } from "../../fixtures/ui.ts";
import { creerElement, navPrincipale, preparer } from "./outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(preparer);
test.skip(({ isMobile }) => isMobile, "parcours à la souris sur grand écran");

/** Vue simulée : un h1, une saisie « modifiée », un titre avec le nom de l'élément s'il est fourni. */
const VUE_SIMULEE = `
export async function render(ctx) {
  const w = window;
  w.__vue = { disposed: 0, saved: 0 };
  const h1 = document.createElement("h1");
  h1.textContent = "Fiche simulée";
  ctx.root.append(h1);
  const name = ctx.query.get("nom");
  if (name) ctx.setTitle("shell.title.item", { name });
  return {
    dispose() { w.__vue.disposed += 1; },
    isDirty: () => ctx.query.get("modifie") === "1" && w.__vue.saved === 0,
    async save() { w.__vue.saved += 1; },
  };
}
`;

async function vueSimulee(page: Page) {
  await page.route("**/js/views/vault/index.js", (route) => route.fulfill({ contentType: "text/javascript", body: VUE_SIMULEE }));
}

const etat = (page: Page) => page.evaluate(() => (window as unknown as { __vue: { disposed: number; saved: number } }).__vue);

test("saisie en cours : « Rester » garde la vue et l'adresse, « Abandonner » la quitte", async ({ page, org }) => {
  await vueSimulee(page);
  await loginUi(page, org.accounts.user);
  await page.goto("/#/coffre?modifie=1");
  await expect(page.getByRole("heading", { level: 1, name: "Fiche simulée" })).toBeVisible();

  await navPrincipale(page).getByRole("link", { name: /^Corbeille/ }).click();
  const guard = page.getByRole("dialog", { name: "Quitter sans enregistrer ?" });
  await expect(guard).toBeVisible();
  await guard.getByRole("button", { name: "Rester" }).click();
  await expect(guard).toHaveCount(0);
  await expect(page).toHaveURL(/#\/coffre\?modifie=1$/);
  expect((await etat(page)).disposed).toBe(0);

  await navPrincipale(page).getByRole("link", { name: /^Corbeille/ }).click();
  await guard.getByRole("button", { name: "Abandonner" }).click();
  await expect(page).toHaveTitle("Corbeille · Locksy");
});

test("saisie en cours : « Enregistrer » appelle save() puis quitte la vue (dispose)", async ({ page, org }) => {
  await vueSimulee(page);
  await loginUi(page, org.accounts.user);
  await page.goto("/#/coffre?modifie=1");
  await expect(page.getByRole("heading", { level: 1, name: "Fiche simulée" })).toBeVisible();
  await page.evaluate(() => { (window as unknown as { __garde: unknown }).__garde = (window as unknown as { __vue: unknown }).__vue; });
  await navPrincipale(page).getByRole("link", { name: /^Favoris/ }).click();
  await page.getByRole("dialog", { name: "Quitter sans enregistrer ?" }).getByRole("button", { name: "Enregistrer" }).click();
  await expect(page).toHaveTitle("Favoris · Locksy");
  const avant = await page.evaluate(() => (window as unknown as { __garde: { disposed: number; saved: number } }).__garde);
  expect(avant).toEqual({ disposed: 1, saved: 1 });
});

test("setTitle avec le nom d'un élément : refusé, titre de la route", async ({ page, org }) => {
  await vueSimulee(page);
  await loginUi(page, org.accounts.user);
  const name = `Compte bancaire secret ${Date.now()}`;
  await creerElement(page, name);
  await page.evaluate(async () => { await (await import("/js/vault.js")).sync(); });
  await page.goto(`/#/coffre?nom=${encodeURIComponent(name)}`);
  await expect(page.getByRole("heading", { level: 1, name: "Fiche simulée" })).toBeVisible();
  await expect(page).toHaveTitle("Mon coffre · Locksy");
});

/** Vue lente : écrit dans ctx.root bien après la navigation suivante. */
const VUE_LENTE = `
export async function render(ctx) {
  await new Promise((r) => setTimeout(r, 1500));
  const h1 = document.createElement("h1");
  h1.textContent = "Vue périmée";
  ctx.root.append(h1);
  return { dispose() {}, isDirty: () => false };
}
`;

test("navigation pendant le chargement d'une vue lente : la page affichée n'est jamais écrasée", async ({ page, org }) => {
  // Vraie page du générateur (preparer() remplace les modules de contenu).
  await page.unroute("**/js/views/tools/index.js");
  // Module du coffre long à charger (squelette après 300 ms) puis long à rendre.
  await page.route("**/js/views/vault/index.js", async (route) => {
    await new Promise((r) => setTimeout(r, 800));
    await route.fulfill({ contentType: "text/javascript", body: VUE_LENTE });
  });
  await loginUi(page, org.accounts.user);
  // Le coffre se charge encore (squelette affiché après 300 ms) : autre page.
  await expect(page).toHaveURL(/#\/coffre$/);
  await expect(page.locator("main .c-skeleton")).toBeVisible();
  await page.evaluate(() => { location.hash = "#/generateur"; });
  const titre = page.getByRole("heading", { level: 1, name: "Générateur de mots de passe" });
  await expect(titre).toBeVisible();
  // Le squelette et le rendu tardifs du coffre visent un conteneur détaché.
  await page.waitForTimeout(2500);
  await expect(titre).toBeVisible();
  await expect(page.getByRole("heading", { name: "Vue périmée" })).toHaveCount(0);
  await expect(page.locator("main .c-skeleton")).toHaveCount(0);
});
