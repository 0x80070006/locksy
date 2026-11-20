// Assistant de connexion d'entreprise (SSO) : fournisseur, identifiants,
// test avec le compte de l'administrateur, activation. « Imposé » n'est
// possible qu'après un test réussi de moins de 24 h (G-14). Toute saisie
// survit aux changements d'étape et de section (dirtyGuard).
//
// Routes simulées (contrat C1.2) : voir simulation.ts.

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { openIdentity, simulateIdentity, annonce, violationsDeLaVue, vue, type IdentitySim } from "./simulation.ts";

test.use({ textGuardMode: "strict" });

const ECHECS_ATTENDUS = /500|Failed to load resource|NetworkError|net::ERR/;
const ISSUER = "https://login.microsoftonline.com/0f1e2d3c/v2.0";
const EXTENSION = "abcdefghijklmnopabcdefghijklmnop";
const continuer = (page: Page) => page.getByRole("button", { name: "Continuer", exact: true });
const etape = (page: Page, nom: string) => page.getByRole("heading", { level: 2, name: new RegExp(`${nom}$`) });

/** Assistant SSO jusqu'à l'étape « Test avec votre compte » (fournisseur Entra ID). */
async function jusquAuTest(page: Page, sim: IdentitySim) {
  await openIdentity(page, "sso");
  await page.getByRole("radio", { name: /Microsoft Entra ID/ }).check({ force: true });
  await expect(page.getByRole("textbox", { name: "Adresse de retour à déclarer chez le fournisseur" })).toHaveValue("https://locksy.entreprise.fr/api/sso/callback");
  await expect(page.getByRole("button", { name: "Copier l'adresse de retour" })).toBeVisible();
  await continuer(page).click();
  await expect(etape(page, "Identifiants de l'application")).toBeFocused();
  await page.getByLabel("Adresse de l'émetteur").fill(ISSUER);
  await page.getByLabel("Identifiant client", { exact: true }).fill("locksy-web");
  await page.getByLabel("Secret client").fill("secret-de-test");
  await continuer(page).click();
  await expect(etape(page, "Test avec votre compte")).toBeVisible();
  // Le secret part une fois, au serveur, puis n'est plus affiché.
  expect(sim.bodiesOf("PUT /admin/sso")).toEqual([expect.objectContaining({ issuer: ISSUER, client_id: "locksy-web", client_secret: "secret-de-test", enabled: false, enforce: false })]);
}

test.describe("Connexion d'entreprise (SSO)", () => {
  test("assistant jusqu'au test réussi : « Imposé » fermé avant le test, ouvert après", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page);
    await jusquAuTest(page, sim);

    // Avant tout test : « Imposé » désactivé, avec la raison écrite.
    await continuer(page).click();
    await expect(etape(page, "Activation")).toBeVisible();
    await expect(page.getByRole("radio", { name: /^Imposé/ })).toBeDisabled();
    await expect(vue(page).getByText("« Imposé » sera disponible après un test réussi avec votre propre compte (moins de 24 heures).").first()).toBeVisible();
    expect(await violationsDeLaVue(page)).toEqual([]);

    // Test avec mon compte : le parcours s'ouvre dans une nouvelle fenêtre.
    await page.getByRole("button", { name: "Retour", exact: true }).click();
    const popup = page.waitForEvent("popup");
    await page.getByRole("button", { name: "Tester avec mon compte" }).click();
    await (await popup).close();
    // Le résultat est relu tout seul au retour sur l'onglet (Firefox rend le
    // focus à la page) ; sinon, « Vérifier le résultat » le demande.
    const reussi = vue(page).getByText("Test réussi : votre compte d'entreprise est bien reconnu.");
    const verifier = page.getByRole("button", { name: "Vérifier le résultat" });
    await expect(reussi.or(verifier).first()).toBeVisible();
    if (!(await reussi.isVisible())) await verifier.click({ timeout: 3000 }).catch(() => {});
    await expect(reussi).toBeVisible();
    await expect(verifier).toBeHidden();
    await expect(vue(page).getByText(/^Dernier test réussi par vous/)).toBeVisible();

    await continuer(page).click();
    const impose = page.getByRole("radio", { name: /^Imposé/ });
    await expect(impose).toBeEnabled();
    await impose.check({ force: true });
    await page.getByRole("button", { name: "Enregistrer", exact: true }).click();
    await expect(annonce(page, "Connexion d'entreprise enregistrée.")).toBeVisible();
    expect(sim.bodiesOf("PUT /admin/sso").at(-1)).toEqual(expect.objectContaining({ enabled: true, enforce: true }));

    // Page d'état : mode, dernière réussite, « Tester maintenant », détails techniques repliés.
    await expect(page.getByRole("heading", { level: 2, name: "État" })).toBeVisible();
    await expect(vue(page).getByText("Imposée à tous, sauf l'accès de secours des propriétaires.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Tester maintenant" })).toBeVisible();
    await expect(vue(page).getByText("Détails techniques")).toBeVisible();
    await expect(vue(page).getByText(ISSUER)).toBeHidden();
  });

  test("« Imposé » refusé par le serveur (test_required) : message et retour à « Proposé »", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/409/);
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page, {
      sso: { issuer: ISSUER, client_id: "locksy-web", has_secret: true, label: "Microsoft" },
      ssoOkByMe: Math.floor(Date.now() / 1000) - 60,
    });
    await openIdentity(page, "sso");
    await page.getByRole("button", { name: "Changer le mode" }).click();
    await page.getByRole("radio", { name: /^Imposé/ }).check({ force: true });
    // Entre-temps, le test a expiré côté serveur.
    sim.ssoOkByMe = null;
    await page.getByRole("button", { name: "Enregistrer", exact: true }).click();
    await expect(vue(page).getByText("Testez d'abord cette connexion avec votre propre compte", { exact: false })).toBeVisible();
    await expect(page.getByRole("radio", { name: /^Imposé/ })).toBeDisabled();
    await expect(page.getByRole("radio", { name: /^Proposé/ })).toBeChecked();
  });

  test("extensions de navigateur autorisées : identifiant invalide refusé, identifiant valide enregistré", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page);
    await openIdentity(page, "sso");
    await page.getByRole("radio", { name: /Google Workspace/ }).check({ force: true });
    await continuer(page).click();
    await page.getByLabel("Identifiant client", { exact: true }).fill("locksy-web.apps.googleusercontent.com");
    await page.getByLabel("Secret client").fill("secret-de-test");
    await vue(page).getByText("Options", { exact: true }).click();
    const extensions = page.getByLabel("Extensions de navigateur autorisées");
    await extensions.fill("pas-un-identifiant");
    await extensions.press("Enter");
    await expect(vue(page).getByText("Identifiant d'extension invalide : « pas-un-identifiant » (32 lettres de a à p).")).toBeVisible();
    await extensions.fill(EXTENSION);
    await extensions.press("Enter");
    await expect(page.getByRole("button", { name: `Retirer ${EXTENSION}` })).toBeVisible();
    await continuer(page).click();
    await expect(etape(page, "Test avec votre compte")).toBeVisible();
    expect(sim.bodiesOf("PUT /admin/sso").at(-1)).toEqual(expect.objectContaining({ issuer: "https://accounts.google.com", allowed_extension_ids: [EXTENSION] }));
  });

  test("la saisie survit aux changements d'étape et à une tentative de changer de section", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    await simulateIdentity(page);
    await openIdentity(page, "sso");
    await page.getByRole("radio", { name: /Okta/ }).check({ force: true });
    await continuer(page).click();
    await page.getByLabel("Adresse de l'émetteur").fill("https://entreprise.okta.com");
    await page.getByLabel("Identifiant client", { exact: true }).fill("0oa-locksy");

    await page.getByRole("button", { name: "Retour", exact: true }).click();
    await expect(page.getByRole("radio", { name: /Okta/ })).toBeChecked();
    await continuer(page).click();
    await expect(page.getByLabel("Adresse de l'émetteur")).toHaveValue("https://entreprise.okta.com");
    await expect(page.getByLabel("Identifiant client", { exact: true })).toHaveValue("0oa-locksy");

    // Quitter la section : confirmation, « Rester » garde tout.
    await page.evaluate(() => { location.hash = "#/admin/personnes"; });
    const dialog = page.getByRole("dialog", { name: "Quitter sans enregistrer ?" });
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Rester" }).click();
    await expect(page).toHaveURL(/#\/admin\/connexion\/sso$/);
    await expect(page.getByLabel("Adresse de l'émetteur")).toHaveValue("https://entreprise.okta.com");
  });

  test("enregistrement des identifiants en échec (500 puis réseau coupé) : message, saisie intacte", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(ECHECS_ATTENDUS);
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page);
    await openIdentity(page, "sso");
    await page.getByRole("radio", { name: /Keycloak/ }).check({ force: true });
    await continuer(page).click();
    await page.getByLabel("Adresse de l'émetteur").fill("https://sso.entreprise.fr/realms/locksy");
    await page.getByLabel("Identifiant client", { exact: true }).fill("locksy");
    await page.getByLabel("Secret client").fill("secret");

    sim.fail("PUT /admin/sso", 500);
    await continuer(page).click();
    await expect(vue(page).getByText("Le serveur a rencontré un problème.", { exact: false })).toBeVisible();
    await expect(etape(page, "Identifiants de l'application")).toBeVisible();

    sim.fail("PUT /admin/sso", "reseau");
    await continuer(page).click();
    await expect(vue(page).getByText("Serveur injoignable.", { exact: false })).toBeVisible();
    await expect(page.getByLabel("Adresse de l'émetteur")).toHaveValue("https://sso.entreprise.fr/realms/locksy");
    await expect(page.getByLabel("Secret client")).toHaveValue("secret");

    // Fournisseur refusé (adresse interne) : code stable traduit, texte technique replié.
    sim.fail("POST /admin/sso/test", 422, { code: "ssrf_blocked" });
    await continuer(page).click();
    await expect(vue(page).getByText("Cette adresse désigne le réseau interne du serveur", { exact: false })).toBeVisible();
  });

  test("lancement du test en échec (500 puis réseau coupé) : message en français", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(ECHECS_ATTENDUS);
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page, { sso: { issuer: ISSUER, client_id: "locksy-web", has_secret: true, enabled: true } });
    await openIdentity(page, "sso");
    sim.fail("POST /admin/sso/test-start", 500);
    await page.getByRole("button", { name: "Tester maintenant" }).click();
    await expect(vue(page).getByText("Le serveur a rencontré un problème.", { exact: false })).toBeVisible();
    sim.fail("POST /admin/sso/test-start", "reseau");
    await page.getByRole("button", { name: "Tester maintenant" }).click();
    await expect(vue(page).getByText("Serveur injoignable.", { exact: false })).toBeVisible();
  });

  test("retour d'un test en échec par l'adresse (?test=erreur&code=…) : raison en français, adresse nettoyée", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    await simulateIdentity(page, { sso: { issuer: ISSUER, client_id: "locksy-web", has_secret: true, enabled: true } });
    await openIdentity(page, "sso?test=erreur&code=email_mismatch");
    await expect(vue(page).getByText("Le test a échoué. Le compte utilisé pour le test n'a pas la même adresse e-mail", { exact: false })).toBeVisible();
    await expect(page).toHaveURL(/#\/admin\/connexion\/sso$/);
  });
});
