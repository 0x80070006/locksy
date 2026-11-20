// Administration › Personnes (cahier §3.4.3 et §3.4.4, fiche L12) : liste
// filtrée par l'adresse, fiche en panneau, changement de rôle confirmé
// (élévation = mot de passe maître), actions de masse avec ligne ignorée,
// invitations en 3 gestes, repli sur les routes historiques.
// Routes de la vague 2 simulées (contrat C1.1, voir outils.ts).

import { test, expect } from "../../fixtures/index.ts";
import { goHash, L, missing, PEOPLE, personDetail, simulate, simulatePeople } from "./outils.ts";

test.use({ textGuardMode: "strict" });

test.describe("Personnes", () => {
  test("liste, filtres dans l'adresse et fiche en panneau", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await simulatePeople(sim);
    await sim.on("GET", "/admin/users/u-hugo", () => personDetail(PEOPLE.hugo));
    await goHash(page, "#/admin/personnes");
    await expect(page.getByRole("heading", { level: 1, name: "Personnes · 3" })).toBeVisible();
    const table = page.getByRole("table", { name: "Personnes" });
    await expect(table.getByText("Hugo Martin")).toBeVisible();
    await expect(table.getByText(/^Invitée, expire dans/)).toBeVisible();

    await page.getByRole("button", { name: /^État/ }).click();
    await page.getByRole("menuitemradio", { name: "Actifs", exact: true }).click();
    await expect(page).toHaveURL(/etat=actif/);
    await expect.poll(() => sim.called("GET", "/admin/people").at(-1)?.query.get("etat")).toBe("actif");

    await table.getByRole("button", { name: /^Hugo Martin/ }).click();
    const panel = page.getByRole("dialog", { name: "Hugo Martin" });
    await expect(panel).toBeVisible();
    await expect(page).toHaveURL(/#\/admin\/personnes\/u-hugo/);
    await expect(panel.getByRole("tab", { name: "Sessions (2)" })).toBeVisible();
    await expect(panel.getByRole("button", { name: "Fermer la session Chrome sur Windows" })).toBeVisible();
    await panel.getByRole("tab", { name: "Coffres (2)" }).click();
    await expect(panel.getByText("Seul gestionnaire")).toBeVisible();
    await expect(panel.getByText("Le nom des coffres est chiffré")).toBeVisible();
  });

  test("changement de rôle : rien n'est envoyé avant confirmation, l'élévation exige le mot de passe maître", async ({ loggedIn, org }) => {
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await simulatePeople(sim);
    await sim.on("PUT", "/admin/users/u-hugo", () => ({}));
    await sim.on("POST", "/auth/reauth", (_r, body) => ({ token: "rt1.jeton-de-test", expires_in: 120, action: (body as { action: string }).action }));
    await goHash(page, "#/admin/personnes");

    await page.getByRole("button", { name: "Plus d'actions pour Hugo Martin" }).click();
    await page.getByRole("menuitem", { name: L.changeRole }).click();
    const dlg = page.getByRole("dialog", { name: "Changer le rôle de Hugo Martin" });
    await dlg.getByRole("radio", { name: /Administrateur/ }).check({ force: true });
    await expect(dlg.getByLabel(L.masterPassword)).toBeVisible();
    // Annuler : aucune requête.
    await dlg.getByRole("button", { name: "Annuler" }).click();
    await expect(dlg).toBeHidden();
    expect(sim.called("PUT", "/admin/users/u-hugo")).toHaveLength(0);

    await page.getByRole("button", { name: "Plus d'actions pour Hugo Martin" }).click();
    await page.getByRole("menuitem", { name: L.changeRole }).click();
    await dlg.getByRole("radio", { name: /Administrateur/ }).check({ force: true });
    await dlg.getByRole("button", { name: "Changer le rôle" }).click();
    await expect(dlg.getByText("Saisissez votre mot de passe maître pour confirmer.")).toBeVisible();
    expect(sim.called("PUT", "/admin/users/u-hugo")).toHaveLength(0);

    await dlg.getByLabel(L.masterPassword).fill(org.accounts.owner.password);
    await dlg.getByRole("button", { name: "Changer le rôle" }).click();
    await expect(dlg).toBeHidden({ timeout: 60_000 });
    const put = sim.called("PUT", "/admin/users/u-hugo");
    expect(put).toHaveLength(1);
    expect(put[0].body).toEqual({ role: "admin" });
    expect(put[0].headers["x-locksy-reauth"]).toBe("rt1.jeton-de-test");
    expect((sim.called("POST", "/auth/reauth")[0].body as { action: string }).action).toBe("admin.role");
  });

  test("rétrogradation : confirmation simple, sans mot de passe ; échec affiché dans la fenêtre", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/409|Failed to load resource|ERR_FAILED/);
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await simulatePeople(sim);
    await sim.on("PUT", "/admin/users/u-camille", () => ({}));
    await goHash(page, "#/admin/personnes");
    await page.getByRole("button", { name: "Plus d'actions pour Camille Durand" }).click();
    await page.getByRole("menuitem", { name: L.changeRole }).click();
    const dlg = page.getByRole("dialog", { name: "Changer le rôle de Camille Durand" });
    await dlg.getByRole("radio", { name: /Utilisateur/ }).check({ force: true });
    await expect(dlg.getByLabel(L.masterPassword)).toBeHidden();

    sim.fail("PUT", "/admin/users/u-camille", 409, { error: "last_owner", message: "Dernier propriétaire." });
    await dlg.getByRole("button", { name: "Changer le rôle" }).click();
    await expect(dlg.getByText("L'organisation doit garder au moins un propriétaire actif.", { exact: false })).toBeVisible();

    sim.fail("PUT", "/admin/users/u-camille", "reseau");
    await dlg.getByRole("button", { name: "Changer le rôle" }).click();
    await expect(dlg.getByText(/Serveur injoignable/)).toBeVisible();

    sim.heal("PUT", "/admin/users/u-camille");
    await dlg.getByRole("button", { name: "Changer le rôle" }).click();
    await expect(dlg).toBeHidden();
    expect(sim.called("PUT", "/admin/users/u-camille").at(-1)?.body).toEqual({ role: "user" });
  });

  test("fiche : révoquer les liens sécurisés d'une personne, puis échec affiché en français", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/500|Failed to load resource/);
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await simulatePeople(sim);
    await sim.on("GET", "/admin/users/u-hugo", () => personDetail(PEOPLE.hugo));
    await sim.on("POST", "/admin/shares/revoke", () => ({ revoked: 2 }));
    await goHash(page, "#/admin/personnes/u-hugo");
    const panel = page.getByRole("dialog", { name: "Hugo Martin" });
    await expect(panel.getByRole("tab", { name: "Sessions (2)" })).toBeVisible();

    const revoke = async () => {
      await panel.getByRole("button", { name: "Plus d'actions pour Hugo Martin" }).click();
      await page.getByRole("menuitem", { name: "Révoquer ses liens sécurisés" }).click();
      await page.getByRole("dialog", { name: "Révoquer les liens sécurisés de Hugo Martin ?" }).getByRole("button", { name: "Révoquer ses liens sécurisés" }).click();
    };
    await revoke();
    await expect(page.locator(".c-toast").filter({ hasText: "2 liens sécurisés de Hugo Martin révoqués." })).toBeVisible();
    expect(sim.called("POST", "/admin/shares/revoke")[0].body).toEqual({ owner_id: "u-hugo" });

    sim.fail("POST", "/admin/shares/revoke", 500);
    await revoke();
    await expect(page.locator(".c-toast").filter({ hasText: /erreur|serveur/i }).first()).toBeVisible();
    expect(sim.called("POST", "/admin/shares/revoke")).toHaveLength(2);
  });

  test("action de masse : rapport avec la ligne ignorée et sa raison", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await simulatePeople(sim);
    await sim.on("POST", "/admin/users/bulk", () => ({ done: ["u-hugo"], skipped: [{ id: "u-camille", reason: "self" }] }));
    await goHash(page, "#/admin/personnes");
    await page.getByRole("checkbox", { name: "Sélectionner Hugo Martin" }).check();
    await page.getByRole("checkbox", { name: "Sélectionner Camille Durand" }).check();
    await page.getByRole("region", { name: "Actions sur la sélection" }).getByRole("button", { name: "Désactiver" }).click();
    await page.getByRole("dialog", { name: "Désactiver 2 comptes ?" }).getByRole("button", { name: "Désactiver" }).click();
    await expect(page.getByText("1 effectuée, 1 ignorée :")).toBeVisible();
    await expect(page.getByText("Camille Durand (vous ne pouvez pas faire cette action sur votre propre compte)")).toBeVisible();
    expect(sim.called("POST", "/admin/users/bulk")[0].body).toEqual({ ids: ["u-hugo", "u-camille"], action: "disable" });
  });

  test("action de masse en échec : message français, sélection gardée", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/500|Failed to load resource/);
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await simulatePeople(sim);
    await sim.on("POST", "/admin/users/bulk", () => ({ done: [], skipped: [] }));
    sim.fail("POST", "/admin/users/bulk", 500);
    await goHash(page, "#/admin/personnes");
    await page.getByRole("checkbox", { name: "Sélectionner Hugo Martin" }).check();
    const bar = page.getByRole("region", { name: "Actions sur la sélection" });
    await bar.getByRole("button", { name: "Déconnecter partout" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Déconnecter partout" }).click();
    await expect(page.locator(".c-toast").filter({ hasText: /erreur|serveur/i }).first()).toBeVisible();
    await expect(page.getByRole("checkbox", { name: "Sélectionner Hugo Martin" })).toBeChecked();
  });

  test("inviter 3 personnes en 3 gestes, liens à copier si l'e-mail n'est pas parti", async ({ loggedIn, clicks }) => {
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await simulatePeople(sim);
    await sim.on("POST", "/admin/invites/batch", (_r, body) => {
      const b = body as { emails: string[] };
      return {
        created: b.emails.slice(0, 2).map((email, i) => ({ id: `i${i}`, email, link: `http://locksy:8743/#/inscription/jeton${i}`, mailed: false, expires_at: Math.floor(Date.now() / 1000) + 7 * 86400 })),
        skipped: [{ email: b.emails[2], reason: "domain_not_allowed" }],
      };
    });
    await goHash(page, "#/admin/personnes");
    await expect(page.getByRole("button", { name: L.invite })).toBeVisible();
    const n = await clicks.measure(async () => {
      await clicks.click(page.getByRole("button", { name: L.invite }));
      await clicks.fill(page.getByLabel("Adresses e-mail"), "a.durand@exemple.fr, b.martin@exemple.fr\nc.petit@autre.fr");
      await clicks.click(page.getByRole("dialog").getByRole("button", { name: "Inviter", exact: true }));
    });
    expect(n).toBeLessThanOrEqual(3);
    const dlg = page.getByRole("dialog", { name: "Inviter des personnes" });
    await expect(dlg.getByText("2 invitations créées")).toBeVisible();
    await expect(dlg.getByText("c.petit@autre.fr : domaine non autorisé par votre organisation")).toBeVisible();
    await expect(dlg.getByRole("button", { name: "Copier toutes les invitations" })).toBeVisible();
    expect(sim.called("POST", "/admin/invites/batch")[0].body).toMatchObject({ emails: ["a.durand@exemple.fr", "b.martin@exemple.fr", "c.petit@autre.fr"], role: "user" });
  });

  test("invitations en échec : saisie conservée, message français", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/500|Failed to load resource|ERR_FAILED/);
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await simulatePeople(sim);
    await sim.on("POST", "/admin/invites/batch", () => ({ created: [], skipped: [] }));
    await goHash(page, "#/admin/personnes");
    await page.getByRole("button", { name: L.invite }).click();
    const dlg = page.getByRole("dialog", { name: "Inviter des personnes" });
    await dlg.getByLabel("Adresses e-mail").fill("a.durand@exemple.fr");
    sim.fail("POST", "/admin/invites/batch", 500);
    await dlg.getByRole("button", { name: "Inviter", exact: true }).click();
    await expect(dlg.getByText(/Erreur|serveur/i).first()).toBeVisible();
    sim.fail("POST", "/admin/invites/batch", "reseau");
    await dlg.getByRole("button", { name: "Inviter", exact: true }).click();
    await expect(dlg.getByText(/Serveur injoignable/)).toBeVisible();
    await expect(dlg.getByLabel("Adresses e-mail")).toHaveValue("a.durand@exemple.fr");
  });

  test("repli : serveur sans /admin/people, liste construite depuis les routes historiques", async ({ loggedIn, org, consoleGuard }) => {
    consoleGuard.allow(/404/);
    const page = await loggedIn("owner");
    await missing(page, "GET", "/admin/people");
    await goHash(page, "#/admin/personnes");
    const table = page.getByRole("table", { name: "Personnes" });
    await expect(table.getByText(org.accounts.admin.email)).toBeVisible();
    await expect(table.getByText(`${org.accounts.owner.name} (vous)`)).toBeVisible();
  });
});
