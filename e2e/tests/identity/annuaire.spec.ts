// Assistant Compte Windows (Active Directory) : serveur et compte de
// service, groupe et synchronisation à blanc (comptes ignorés et raisons),
// test avec son propre compte Windows, activation, historique.
//
// Routes simulées (contrat C1.2) : voir simulation.ts.

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { openIdentity, simulateIdentity, annonce, violationsDeLaVue, vue, type IdentitySim } from "./simulation.ts";

test.use({ textGuardMode: "strict" });

const continuer = (page: Page) => page.getByRole("button", { name: "Continuer", exact: true });
const ECHECS_ATTENDUS = /500|409|Failed to load resource|NetworkError|net::ERR/;

/** Étape 1 remplie et validée (test LDAPS et enregistrement simulés). */
async function serveurValide(page: Page, sim: IdentitySim) {
  await openIdentity(page, "ad");
  await expect(page.getByRole("heading", { level: 2, name: /Serveur et compte de service$/ })).toBeVisible();
  await page.getByLabel("Adresse du contrôleur de domaine").fill("ldaps://dc1.entreprise.local:636");
  await page.getByLabel("Compte de service (lecture seule)").fill("svc_locksy@entreprise.local");
  await page.getByLabel("Mot de passe du compte de service").fill("mot-de-passe-du-service");
  await page.getByLabel("Racine de recherche").fill("DC=entreprise,DC=local");
  await continuer(page).click();
  await expect(vue(page).getByText("Connexion réussie : 45 comptes trouvés. Configuration enregistrée.")).toBeVisible();
  await expect(page.getByRole("heading", { level: 2, name: /Qui peut se connecter$/ })).toBeVisible();
  expect(sim.bodiesOf("POST /admin/ldap/test")).toHaveLength(1);
}

test.describe("Compte Windows (Active Directory)", () => {
  test("synchronisation à blanc : comptes trouvés, comptes ignorés et leur raison, rien de modifié", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page);
    await serveurValide(page, sim);
    await page.getByLabel("Groupe autorisé à utiliser Locksy").fill("CN=GG_Locksy,OU=Groupes,DC=entreprise,DC=local");
    await page.getByRole("button", { name: "Lancer une synchronisation à blanc" }).click();

    await expect(vue(page).getByText("42 comptes trouvés, 3 ignorés")).toBeVisible();
    await expect(vue(page).getByText("Une vraie synchronisation ferait : 39 créations, 0 mise à jour, 0 désactivation. Rien n'a été modifié.")).toBeVisible();
    await vue(page).getByText("Voir pourquoi").click();
    const table = page.getByRole("table", { name: "Comptes ignorés et raison" });
    await expect(table).toBeVisible();
    await expect(table.getByRole("row", { name: /jdurand.*Aucune adresse e-mail dans l'annuaire/ })).toBeVisible();
    await expect(table.getByRole("row", { name: /stagiaire.*Domaine d'adresse non autorisé/ })).toBeVisible();
    await expect(table.getByRole("row", { name: /mpetit.*Compte désactivé dans l'annuaire/ })).toBeVisible();
    expect(await violationsDeLaVue(page)).toEqual([]);

    // Seule la synchronisation à blanc a été demandée ; le groupe a d'abord été enregistré.
    const syncs = sim.calls.filter((c) => c.key.startsWith("POST /admin/ldap/sync")).map((c) => c.key);
    expect(syncs).toEqual(["POST /admin/ldap/sync?dry_run=true"]);
    expect(sim.bodiesOf("PUT /admin/ldap").at(-1)).toEqual(expect.objectContaining({ group_dn: "CN=GG_Locksy,OU=Groupes,DC=entreprise,DC=local", enabled: false }));
  });

  test("test avec son compte Windows puis activation « Imposé », historique des synchronisations", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page);
    await serveurValide(page, sim);
    await continuer(page).click();
    await expect(page.getByRole("heading", { level: 2, name: /Test avec votre compte$/ })).toBeVisible();
    await page.getByLabel("Identifiant Windows").fill("proprietaire");
    await page.getByLabel("Mot de passe Windows").fill("mot-de-passe-windows");
    await page.getByRole("button", { name: "Tester avec mon compte" }).click();
    await expect(vue(page).getByText("Test réussi : votre compte Windows est bien reconnu.")).toBeVisible();
    await expect(page.getByLabel("Mot de passe Windows")).toHaveValue("");

    await continuer(page).click();
    await page.getByRole("radio", { name: /^Imposé/ }).check({ force: true });
    await page.getByRole("button", { name: "Enregistrer", exact: true }).click();
    await expect(annonce(page, "Configuration enregistrée.")).toBeVisible();
    expect(sim.bodiesOf("PUT /admin/ldap").at(-1)).toEqual(expect.objectContaining({ allow_login: true, enforce: true }));
    await expect(vue(page).getByText("Connexion Windows imposée à tous, sauf l'accès de secours des propriétaires.")).toBeVisible();

    // Historique : une synchronisation à blanc lancée depuis la page d'état.
    await page.getByRole("button", { name: "Lancer une synchronisation à blanc" }).click();
    await expect(vue(page).getByText("42 comptes trouvés, 3 ignorés").first()).toBeVisible();
    const history = page.getByRole("table", { name: "Historique des synchronisations" });
    await expect(history.getByRole("row", { name: /À blanc.*42 comptes trouvés, 3 ignorés.*À la demande/ })).toBeVisible();
  });

  test("« Imposé » fermé tant que l'administrateur n'a pas réussi de test", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page);
    await serveurValide(page, sim);
    await continuer(page).click();
    await continuer(page).click();
    await expect(page.getByRole("radio", { name: /^Imposé/ })).toBeDisabled();
    await expect(page.getByRole("radio", { name: /^Proposé/ })).toBeEnabled();
  });

  test("synchronisation à blanc refusée ou en échec (409, réseau coupé) : message, saisie intacte", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(ECHECS_ATTENDUS);
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page);
    await serveurValide(page, sim);
    await page.getByLabel("Groupe autorisé à utiliser Locksy").fill("CN=Tous,DC=entreprise,DC=local");

    sim.fail("POST /admin/ldap/sync", 409, { code: "too_many_deprovisions" });
    await page.getByRole("button", { name: "Lancer une synchronisation à blanc" }).click();
    await expect(vue(page).getByText("Synchronisation refusée : elle désactiverait trop de comptes d'un coup.", { exact: false })).toBeVisible();

    sim.fail("POST /admin/ldap/sync", "reseau");
    await page.getByRole("button", { name: "Lancer une synchronisation à blanc" }).click();
    await expect(vue(page).getByText("Serveur injoignable.", { exact: false })).toBeVisible();
    await expect(page.getByLabel("Groupe autorisé à utiliser Locksy")).toHaveValue("CN=Tous,DC=entreprise,DC=local");
  });

  test("serveur sans synchronisation à blanc (404 sur l'état) : le bouton est fermé, avec la raison", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/404/);
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page, { statusMissing: true });
    await serveurValide(page, sim);
    const dry = page.getByRole("button", { name: "Lancer une synchronisation à blanc" });
    await expect(dry).toHaveAttribute("aria-disabled", "true");
    await expect(vue(page).getByText("La synchronisation à blanc demande un serveur à jour", { exact: false }).first()).toBeVisible();
    await dry.click({ force: true });
    expect(sim.calls.some((c) => c.key.startsWith("POST /admin/ldap/sync"))).toBe(false);
  });
});
