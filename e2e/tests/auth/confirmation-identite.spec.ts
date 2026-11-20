// Confirmation d'identité des actions sensibles (api.withReauth, contrat
// C4.1) : mot de passe maître, puis code de vérification si le serveur le
// demande (totp_required), échange contre un jeton d'usage unique ; repli sur
// la preuve historique quand POST /auth/reauth n'existe pas (404).
//
// withReauth est appelé depuis la page (comme le feront les écrans des
// paramètres et de l'administration) ; POST /auth/reauth est simulé selon C1.3.

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { KDF_TIMEOUT, loginUi } from "../../fixtures/ui.ts";
import { preparer } from "../shell/outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(preparer);

/** Lance withReauth("vault.export") ; le résultat est lu par `resultat()`. */
async function demander(page: Page) {
  await page.evaluate(() => {
    const w = window as unknown as { __reauth: Promise<unknown> };
    w.__reauth = import("/js/api.js").then((api) => api.withReauth("vault.export", async ({ reauth }) => reauth, { title: "Exporter le coffre" }));
  });
}
const resultat = (page: Page) => page.evaluate(() => (window as unknown as { __reauth: Promise<unknown> }).__reauth);

test("mot de passe maître puis code de vérification : jeton transmis à l'action", async ({ page, org, consoleGuard }) => {
  consoleGuard.allow(/status of 401/);
  const bodies: Record<string, unknown>[] = [];
  await page.route("**/api/auth/reauth", async (route) => {
    const body = route.request().postDataJSON();
    bodies.push(body);
    if (!body.totp) await route.fulfill({ status: 401, json: { error: "totp_required", message: "Code requis." } });
    else await route.fulfill({ json: { token: "rt1.jeton-de-test", expires_in: 120, action: body.action } });
  });
  await loginUi(page, org.accounts.user);
  await demander(page);

  const first = page.getByRole("dialog", { name: "Exporter le coffre" });
  await expect(first).toBeVisible();
  await first.getByLabel(/^Mot de passe maître$/).fill(org.accounts.user.password);
  await first.getByRole("button", { name: "Confirmer" }).click();

  const second = page.getByRole("dialog", { name: "Code de vérification" });
  await expect(second).toBeVisible({ timeout: KDF_TIMEOUT });
  await expect(first).toHaveCount(0);
  await second.getByLabel("Code de vérification").pressSequentially("123456");
  expect(await resultat(page)).toBe("rt1.jeton-de-test");
  await expect(second).toHaveCount(0);
  expect(bodies).toHaveLength(2);
  expect(bodies[1]).toMatchObject({ action: "vault.export", totp: "123456" });
  expect(bodies[1].auth_key).toBe(bodies[0].auth_key);
});

test("mot de passe refusé : erreur sous le champ, rien n'est exécuté", async ({ page, org, consoleGuard }) => {
  consoleGuard.allow(/status of 403/);
  await page.route("**/api/auth/reauth", (route) => route.fulfill({ status: 403, json: { error: "invalid_credentials", message: "Refusé." } }));
  await loginUi(page, org.accounts.user);
  await demander(page);
  const dialog = page.getByRole("dialog", { name: "Exporter le coffre" });
  await dialog.getByLabel(/^Mot de passe maître$/).fill("pas-le-bon");
  await dialog.getByRole("button", { name: "Confirmer" }).click();
  await expect(dialog.getByLabel(/^Mot de passe maître$/)).toHaveAttribute("aria-invalid", "true", { timeout: KDF_TIMEOUT });
  await dialog.getByRole("button", { name: "Annuler" }).click();
  expect(await resultat(page)).toBeUndefined();
});

test("serveur sans /auth/reauth (404) : preuve historique du mot de passe maître", async ({ page, org, consoleGuard }) => {
  consoleGuard.allow(/status of 404/);
  await loginUi(page, org.accounts.user);
  await page.route("**/api/auth/reauth", (route) => route.fulfill({ status: 404, json: { error: "not_found", message: "Ressource introuvable." } }));
  await demander(page);
  const dialog = page.getByRole("dialog", { name: "Exporter le coffre" });
  await dialog.getByLabel(/^Mot de passe maître$/).fill(org.accounts.user.password);
  await dialog.getByRole("button", { name: "Confirmer" }).click();
  expect(await resultat(page)).toMatch(/^[A-Za-z0-9_-]{43}$/);
});
