// Suite smoke sur le serveur neuf (FRESH_URL), par l'interface ACTUELLE :
// installation avec le jeton, déconnexion et connexion, ajout d'un élément.
// Gardes CSP et console strictes (automatiques).

import { FRESH_URL, SETUP_TOKEN } from "../../fixtures/env.ts";
import { freshOwner } from "../../fixtures/fresh.ts";
import { test, expect } from "../../fixtures/index.ts";
import { addPasswordItem, expectInList, expectShell, installOwner, loginUi, logoutUi } from "../../fixtures/ui.ts";

test.use({ baseURL: FRESH_URL });

test.describe("Parcours de base sur un serveur neuf", { tag: ["@smoke", "@mobile"] }, () => {
  test("installe Locksy avec le jeton d'installation", async ({ page }, testInfo) => {
    const { owner, made } = await freshOwner(testInfo.project.name, async (account) => {
      await installOwner(page, SETUP_TOKEN, account);
      // Arrivée dans le coffre, puis déconnexion : la session se ferme vraiment.
      await expectShell(page);
      await logoutUi(page);
    });
    test.skip(
      !made,
      `Serveur neuf déjà installé par le projet « ${owner.installedBy} » dans cette exécution : ` +
        "lancez un seul projet à la fois pour couvrir l'installation sur chaque navigateur.",
    );
    // Après installation, la racine propose la connexion et non plus l'installation.
    await page.goto("/");
    await expect(page.getByRole("button", { name: "Se connecter" })).toBeVisible();
    await expect(page.getByLabel("Jeton d'installation")).toHaveCount(0);
  });

  test("se connecte avec l'adresse et le mot de passe maître, puis se déconnecte", async ({ page }, testInfo) => {
    const { owner } = await freshOwner(testInfo.project.name, (a) => installOwner(page, SETUP_TOKEN, a).then(() => logoutUi(page)));
    await loginUi(page, owner.account);
    await expect(page.getByText(owner.account.email).first()).toBeAttached();
    await logoutUi(page);
    // La session est close : recharger la page ramène à la connexion.
    await page.reload();
    await expect(page.getByLabel("Adresse e-mail")).toBeVisible();
  });

  test("ajoute un élément « Mot de passe » et le retrouve dans la liste", async ({ page }, testInfo) => {
    const { owner } = await freshOwner(testInfo.project.name, (a) => installOwner(page, SETUP_TOKEN, a).then(() => logoutUi(page)));
    await loginUi(page, owner.account);
    const name = `Messagerie ${testInfo.project.name}`;
    await addPasswordItem(page, { name, username: "jeanne.martin", password: "Ceci-est-un-essai-2026" });
    await expectInList(page, name);
    // Toujours là après une nouvelle connexion (enregistré côté serveur, chiffré).
    await logoutUi(page);
    await loginUi(page, owner.account);
    await expectInList(page, name);
  });
});
