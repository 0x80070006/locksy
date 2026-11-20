// Création automatique des comptes (SCIM) : jeton affiché une seule fois
// avec « Copier », adresse de base, expiration, révocation de niveau 2 avec
// gestion d'erreur (correctif de l'ancien écran, qui échouait sans rien dire).
//
// Routes simulées (contrat C1.2) : voir simulation.ts.

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { connexion, openIdentity, simulateIdentity, annonce, violationsDeLaVue, vue } from "./simulation.ts";

test.use({ textGuardMode: "strict" });

const ECHECS_ATTENDUS = /500|Failed to load resource|NetworkError|net::ERR/;
const ACTIF = { token_set: true, token_created_at: Math.floor(Date.now() / 1000) - 3 * 86400, token_expires_at: null, last_used_at: null };
const JETON_CONFIRMATION = "rt1.jeton-de-confirmation-simule";

/**
 * POST /auth/reauth (contrat C1.3, absent de l'image de test) : renvoie un
 * jeton de confirmation et note les demandes reçues.
 */
async function simulerConfirmation(page: Page) {
  const echanges: { action: string; auth_key: string }[] = [];
  await page.route("**/api/auth/reauth", (route) => {
    const body = route.request().postDataJSON();
    echanges.push(body);
    return route.fulfill({ json: { token: JETON_CONFIRMATION, expires_in: 120, action: body.action } });
  });
  return echanges;
}

test.describe("Création automatique des comptes (SCIM)", () => {
  test("création du jeton : affiché une seule fois, adresse de base à copier, sans expiration signalée", { tag: "@mobile" }, async ({ page, org }) => {
    await connexion(page, org.accounts.owner);
    await simulateIdentity(page);
    await openIdentity(page, "scim");
    await expect(page.getByRole("heading", { level: 1, name: "Création automatique des comptes (SCIM)" })).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Adresse de base à déclarer dans l'annuaire" })).toHaveValue("https://locksy.entreprise.fr/scim/v2");
    await expect(vue(page).getByText("Aucun jeton : la création automatique des comptes est désactivée.")).toBeVisible();

    await page.getByRole("button", { name: "Créer un jeton" }).click();
    await expect(vue(page).getByText("Copiez ce jeton maintenant : il ne sera plus affiché.")).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Jeton secret à copier dans l'annuaire" })).toHaveValue("scim_jeton_affiche_une_fois_0123456789");
    await expect(page.getByRole("button", { name: "Copier le jeton" })).toBeVisible();
    await expect(vue(page).getByText("Jeton actif.")).toBeVisible();
    await expect(vue(page).getByText(/^Le jeton n'expire jamais\./)).toBeVisible();
    await expect(page.getByRole("button", { name: "Révoquer le jeton" })).toBeVisible();
    expect(await violationsDeLaVue(page)).toEqual([]);
  });

  test("révocation en échec (500 puis réseau coupé) : message, jeton toujours actif ; puis réussite", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(ECHECS_ATTENDUS);
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page, { scim: { ...ACTIF } });
    await openIdentity(page, "scim");
    await expect(vue(page).getByText("Jeton actif.")).toBeVisible();

    const revoquer = async () => {
      await page.getByRole("button", { name: "Révoquer le jeton" }).click();
      const dialog = page.getByRole("dialog", { name: "Révoquer le jeton de l'annuaire ?" });
      await expect(dialog).toBeVisible();
      await expect(dialog.getByText("0 compte actif est géré par l'annuaire.")).toBeVisible();
      await dialog.getByRole("button", { name: "Révoquer le jeton" }).click();
      await expect(dialog).toBeHidden();
    };

    sim.fail("DELETE /admin/scim/token", 500);
    await revoquer();
    await expect(vue(page).getByText("Le jeton n'a pas été révoqué.")).toBeVisible();
    await expect(vue(page).getByText("Le serveur a rencontré un problème.", { exact: false })).toBeVisible();
    await expect(vue(page).getByText("Jeton actif.")).toBeVisible();

    sim.fail("DELETE /admin/scim/token", "reseau");
    await revoquer();
    await expect(vue(page).getByText("Serveur injoignable.", { exact: false })).toBeVisible();
    await expect(vue(page).getByText("Jeton actif.")).toBeVisible();

    sim.heal("DELETE /admin/scim/token");
    await revoquer();
    await expect(annonce(page, "Jeton révoqué : l'annuaire ne peut plus modifier les comptes.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Créer un jeton" })).toBeVisible();
  });

  test("régénération : confirmation d'identité par le mot de passe maître, nouveau jeton affiché une fois", async ({ loggedIn, org }) => {
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page, { scim: { ...ACTIF } });
    const echanges = await simulerConfirmation(page);
    await openIdentity(page, "scim");
    await page.getByRole("button", { name: "Régénérer le jeton" }).click();
    const dialog = page.getByRole("dialog", { name: "Régénérer le jeton de l'annuaire" });
    await expect(dialog).toBeVisible();

    // Sans mot de passe : rien n'est envoyé.
    await dialog.getByRole("button", { name: "Confirmer" }).click();
    await expect(dialog).toBeVisible();
    expect(echanges).toHaveLength(0);
    expect(sim.bodiesOf("POST /admin/scim/token")).toHaveLength(0);

    const request = page.waitForRequest((r) => r.method() === "POST" && r.url().endsWith("/api/admin/scim/token"));
    await dialog.getByLabel("Mot de passe maître").fill(org.accounts.owner.password);
    await dialog.getByRole("button", { name: "Confirmer" }).click();
    // Le jeton de confirmation, propre à l'action « scim.token », accompagne la régénération.
    expect((await request).headers()["x-locksy-reauth"]).toBe(JETON_CONFIRMATION);
    expect(echanges).toEqual([expect.objectContaining({ action: "scim.token", auth_key: expect.any(String) })]);
    await expect(annonce(page, "Nouveau jeton créé : l'ancien ne fonctionne plus.")).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Jeton secret à copier dans l'annuaire" })).toHaveValue("scim_jeton_affiche_une_fois_0123456789");
  });

  test("régénération en échec (500) : message, ancien jeton toujours actif, rien d'affiché", async ({ loggedIn, org, consoleGuard }) => {
    consoleGuard.allow(ECHECS_ATTENDUS);
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page, { scim: { ...ACTIF } });
    await simulerConfirmation(page);
    await openIdentity(page, "scim");
    sim.fail("POST /admin/scim/token", 500);
    await page.getByRole("button", { name: "Régénérer le jeton" }).click();
    const dialog = page.getByRole("dialog", { name: "Régénérer le jeton de l'annuaire" });
    await dialog.getByLabel("Mot de passe maître").fill(org.accounts.owner.password);
    await dialog.getByRole("button", { name: "Confirmer" }).click();
    await expect(dialog).toBeHidden();
    await expect(vue(page).getByText("Le serveur a rencontré un problème.", { exact: false })).toBeVisible();
    await expect(vue(page).getByText("Jeton actif.")).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Jeton secret à copier dans l'annuaire" })).toHaveCount(0);
  });

  test("réglages liés : validité du jeton et départ d'une personne, chacun dans sa section", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    await simulateIdentity(page, { scim: { ...ACTIF } });
    await openIdentity(page, "scim");
    const reglages = page.getByRole("region", { name: "Réglages liés" });
    await expect(reglages.getByRole("link", { name: "Validité du jeton de l'annuaire" })).toHaveAttribute("href", "#/admin/reglages/advanced");
    await expect(reglages.getByRole("link", { name: "Départ d'une personne de l'annuaire" })).toHaveAttribute("href", "#/admin/reglages/retention");
  });

  test("création du jeton en échec (500) : message, aucun jeton affiché", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(ECHECS_ATTENDUS);
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page);
    await openIdentity(page, "scim");
    sim.fail("POST /admin/scim/token", 500);
    await page.getByRole("button", { name: "Créer un jeton" }).click();
    await expect(vue(page).getByText("Le serveur a rencontré un problème.", { exact: false })).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Jeton secret à copier dans l'annuaire" })).toHaveCount(0);
  });

  test("jeton expiré : état et date d'expiration dits clairement", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    await simulateIdentity(page, { scim: { ...ACTIF, token_expires_at: Math.floor(Date.now() / 1000) - 86400 } });
    await openIdentity(page, "scim");
    await expect(vue(page).getByText("Jeton expiré : l'annuaire ne peut plus modifier les comptes.")).toBeVisible();
    await expect(vue(page).getByText(/^Le jeton a expiré le /)).toBeVisible();
  });
});
