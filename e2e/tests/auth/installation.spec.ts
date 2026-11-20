// Écran de première installation (cahier §3.1, fiche L9) sur le serveur
// neuf : redirection depuis la racine, ancienne adresse #/register?setup=
// dont le jeton est retiré de l'adresse, contrôle avant tout envoi.
// Le serveur neuf n'est PAS installé ici (aucun effet de bord).

import { test, expect } from "../../fixtures/index.ts";
import { seriousViolations } from "../../fixtures/axe.ts";
import { preparer } from "../shell/outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(preparer);

test("serveur neuf : la racine mène à l'installation, jeton demandé", async ({ page, org }) => {
  await page.goto(`${org.freshURL}/`);
  await expect(page).toHaveURL(/#\/installation$/);
  await expect(page.getByRole("heading", { level: 1, name: "Installation de Locksy" })).toBeVisible();
  await expect(page).toHaveTitle("Installation de Locksy · Locksy");
  await expect(page.getByLabel("Jeton d'installation")).toBeFocused();
  // Sans jeton : erreur sous le champ, rien n'est envoyé.
  let sent = 0;
  page.on("request", (r) => { if (r.url().includes("/api/auth/register")) sent += 1; });
  await page.getByRole("button", { name: "Créer mon coffre" }).click();
  await expect(page.getByLabel("Jeton d'installation")).toHaveAttribute("aria-invalid", "true");
  expect(sent).toBe(0);
  expect(await seriousViolations(page)).toEqual([]);
});

test("ancienne adresse #/register?setup= : jeton repris dans le champ et retiré de l'adresse", async ({ page, org }) => {
  await page.goto(`${org.freshURL}/#/register?setup=jeton-de-demonstration-42`);
  await expect(page).toHaveURL(/#\/installation$/);
  await expect(page.getByLabel("Jeton d'installation")).toHaveValue("jeton-de-demonstration-42");
  expect(page.url()).not.toContain("jeton-de-demonstration-42");
  await expect(page.getByLabel("Adresse e-mail")).toBeFocused();
});

test("serveur déjà installé : l'adresse d'installation mène à la connexion", async ({ page, org }) => {
  await page.goto(`${org.baseURL}/#/installation`);
  await expect(page).toHaveURL(/#\/connexion$/);
  await expect(page.getByRole("button", { name: /^Se connecter$/ })).toBeVisible();
});
