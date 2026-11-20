// Charte d'utilisation à accepter avant d'ouvrir le coffre (cahier §3.1,
// fiche L9) : affichée quand legal.charter_version dépasse la version
// acceptée, échec d'enregistrement lisible, puis le coffre.
//
// GET/POST /me/charter et la politique (legal.charter_text) sont simulés :
// accepter la charte pour de bon changerait l'état du compte partagé.

import { test, expect } from "../../fixtures/index.ts";
import { expectShell, KDF_TIMEOUT } from "../../fixtures/ui.ts";
import { preparer } from "../shell/outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(preparer);

const TEXTE = "Article 1. Les mots de passe de l'entreprise restent dans Locksy.\n\nArticle 2. Ne communiquez jamais votre mot de passe maître.";

test("nouvelle version de la charte : lecture, échec d'enregistrement, puis acceptation", async ({ page, org, consoleGuard }) => {
  consoleGuard.allow(/status of 500/);
  await page.route("**/api/settings/policy", async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    await route.fulfill({ json: { ...body, policy: { ...body.policy, "legal.charter_text": { value: TEXTE } } } });
  });
  const posted: unknown[] = [];
  let fail = true;
  await page.route("**/api/me/charter", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({ json: { required_version: 3, accepted_version: posted.length && !fail ? 3 : 1 } });
      return;
    }
    posted.push(route.request().postDataJSON());
    if (fail) {
      fail = false;
      await route.fulfill({ status: 500, json: { error: "internal", message: "Erreur interne." } });
      return;
    }
    await route.fulfill({ status: 204 });
  });

  await page.goto("/");
  await page.getByLabel("Adresse e-mail").fill(org.accounts.user.email);
  await page.getByLabel(/^Mot de passe maître$/).fill(org.accounts.user.password);
  await page.getByRole("button", { name: /^Se connecter$/ }).click();

  const heading = page.getByRole("heading", { level: 1, name: "Charte d'utilisation" });
  await expect(heading).toBeFocused({ timeout: KDF_TIMEOUT });
  await expect(page).toHaveTitle("Charte d'utilisation · Locksy");
  await expect(page.getByText("Article 2. Ne communiquez jamais votre mot de passe maître.")).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Navigation principale" })).toHaveCount(0);

  const accept = page.getByRole("button", { name: "J'accepte la charte" });
  await accept.click();
  await expect(page.locator("#contenu [role=alert]")).not.toBeEmpty();
  await expect(heading).toBeVisible();

  await accept.click();
  await expectShell(page);
  expect(posted).toEqual([{ version: 3 }, { version: 3 }]);
});

test("charte déjà acceptée : aucun écran intermédiaire", async ({ page, org }) => {
  await page.route("**/api/me/charter", (route) => route.fulfill({ json: { required_version: 2, accepted_version: 2 } }));
  await page.goto("/");
  await page.getByLabel("Adresse e-mail").fill(org.accounts.user.email);
  await page.getByLabel(/^Mot de passe maître$/).fill(org.accounts.user.password);
  await page.getByRole("button", { name: /^Se connecter$/ }).click();
  await expectShell(page);
  await expect(page.getByRole("heading", { name: "Charte d'utilisation" })).toHaveCount(0);
});
