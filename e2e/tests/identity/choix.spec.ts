// Connexion d'entreprise : aperçu, aide au choix et repli sur un serveur
// sans GET /admin/identity/status (cahier §3.4.7, fiche L13, R11).

import { test, expect } from "../../fixtures/index.ts";
import { connexion, openIdentity, simulateIdentity, violationsDeLaVue, vue } from "./simulation.ts";

test.use({ textGuardMode: "strict" });

const QUESTION = "Comment vos collègues se connectent-ils aujourd'hui à leur poste ?";

test.describe("Connexion d'entreprise : aide au choix", () => {
  test("rien n'est configuré : la question est posée, « Continuer » exige une réponse puis ouvre l'assistant", { tag: "@mobile" }, async ({ page, org }) => {
    await connexion(page, org.accounts.owner);
    await simulateIdentity(page);
    await openIdentity(page);
    await expect(page.getByRole("heading", { level: 1, name: "Connexion d'entreprise" })).toBeVisible();
    await expect(page).toHaveTitle(/^Connexion d'entreprise · Locksy$/);
    const group = page.getByRole("group", { name: QUESTION });
    await expect(group).toBeVisible();

    // Sans réponse : un message, pas de navigation.
    await page.getByRole("button", { name: "Continuer", exact: true }).click();
    await expect(vue(page).getByText("Choisissez une réponse pour continuer.")).toBeVisible();
    await expect(page).toHaveURL(/#\/admin\/connexion$/);

    // Compte Windows de domaine : assistant Active Directory.
    // Clic sur la carte, comme au doigt (la case radio native est masquée par la carte).
    await group.getByText("Avec un compte Windows de domaine (Active Directory sur site)").click();
    await expect(group.getByRole("radio", { name: /compte Windows de domaine/ })).toBeChecked();
    await expect(vue(page).getByText("Choisissez une réponse pour continuer.")).toHaveCount(0);
    await page.getByRole("button", { name: "Continuer", exact: true }).click();
    await expect(page).toHaveURL(/#\/admin\/connexion\/ad$/);
    await expect(page.getByRole("heading", { level: 1, name: "Compte Windows (Active Directory)" })).toBeVisible();
    await expect(page.getByRole("list", { name: "Étapes de la configuration du compte Windows" })).toBeVisible();
  });

  test("Microsoft 365, Google ou Okta : assistant de connexion d'entreprise ; aucune des deux : invitations", async ({ loggedIn, consoleGuard }) => {
    // La page Personnes (lot L12) appelle des routes absentes de l'image de test
    // (404) ; le navigateur n'écrit pas l'adresse dans le texte du message.
    consoleGuard.allow(/status of 404/);
    const page = await loggedIn("owner");
    await simulateIdentity(page);
    await openIdentity(page);
    const group = page.getByRole("group", { name: QUESTION });
    await group.getByRole("radio", { name: /Microsoft 365/ }).check({ force: true });
    await page.getByRole("button", { name: "Continuer", exact: true }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Connexion d'entreprise (SSO)" })).toBeVisible();
    await expect(page.getByRole("group", { name: "Quel est votre fournisseur d'identité ?" })).toBeVisible();

    await page.getByRole("link", { name: "Toutes les méthodes de connexion" }).click();
    await page.getByRole("group", { name: QUESTION }).getByRole("radio", { name: /Ni l'un ni l'autre/ }).check({ force: true });
    await page.getByRole("button", { name: "Continuer", exact: true }).click();
    await expect(page).toHaveURL(/#\/admin\/personnes/);
  });

  test("une méthode configurée : cartes d'état, aide au choix repliée, accessibilité", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    await simulateIdentity(page, {
      sso: { enabled: true, issuer: "https://accounts.google.com", client_id: "locksy", has_secret: true, label: "Google" },
      scim: { token_set: true, token_created_at: Math.floor(Date.now() / 1000) - 86400, token_expires_at: null, last_used_at: null },
    });
    await openIdentity(page);
    await expect(page.getByRole("heading", { level: 2, name: "Méthodes de connexion" })).toBeVisible();
    await expect(vue(page).getByText("Proposée sur la page de connexion.")).toBeVisible();
    await expect(vue(page).getByText(/Jeton actif\./)).toBeVisible();
    await expect(page.getByRole("group", { name: QUESTION })).toHaveCount(0);
    await page.getByRole("button", { name: "Afficher l'aide au choix" }).click();
    await expect(page.getByRole("group", { name: QUESTION })).toBeVisible();
    expect(await violationsDeLaVue(page)).toEqual([]);
  });

  test("serveur sans état de la connexion d'entreprise (404) : repli sur les anciennes routes", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/404/);
    const page = await loggedIn("owner");
    const sim = await simulateIdentity(page, {
      statusMissing: true,
      ldap: { url: "ldaps://dc1.entreprise.local:636", bind_dn: "svc@entreprise.local", has_password: true, base_dn: "DC=entreprise,DC=local", enabled: true },
    });
    await openIdentity(page);
    await expect(page.getByRole("heading", { level: 2, name: "Méthodes de connexion" })).toBeVisible();
    await expect(vue(page).getByText("Synchronisation des comptes active, connexion Windows non proposée.")).toBeVisible();
    expect(sim.calls.map((c) => c.key)).toEqual(expect.arrayContaining(["GET /admin/identity/status", "GET /admin/sso", "GET /admin/ldap", "GET /admin/scim"]));

    // Sans historique des tests, « Imposé » reste fermé et la raison est dite.
    await page.getByRole("link", { name: "Gérer" }).first().click();
    await expect(vue(page).getByText("Ce serveur ne conserve pas encore l'historique des tests.", { exact: false })).toBeVisible();
  });
});
