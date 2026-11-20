// Parcours chiffrés (cahier §3.6, critère G6) : nombre d'interactions
// (clics et touches spéciales ; la saisie de texte n'est pas comptée) de
// chaque tâche, mesuré avec la fixture `clicks`. Tolérance de ± 1 sur la
// cible ; au-delà, échec avec le relevé des gestes.
//
// Ici, les tâches qui ne modifient pas l'organisation : 1, 3, 4, 5 (web), 6,
// A1 (inviter 3 collègues, adresses uniques) et A3 (départ d'un compte créé
// par le test). A2 et A4 changent des réglages : parcours-admin.isole.ts.
// La tâche 2 (extension) est mesurée par la suite de l'extension.

import type { Locator, Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import type { Clicks } from "../../fixtures/clicks.ts";
import {
  KDF_TIMEOUT, connexion, creerCoffre, creerElement, fenetre, goHash, nouveauCompte, pressePapiers, titre, toast, unique,
} from "./outils.ts";

test.use({ textGuardMode: "strict" });

const TOLERANCE = 1;

/** Relevé lisible des gestes d'un parcours. */
class Releve {
  gestes: string[] = [];
  constructor(private clicks: Clicks) {}
  async clic(cible: Locator, nom: string) {
    this.gestes.push(`clic « ${nom} »`);
    await this.clicks.click(cible);
  }
  async touche(cible: Locator, touche: string) {
    this.gestes.push(`touche ${touche}`);
    await this.clicks.press(cible, touche);
  }
  async coller(cible: Locator, texte: string) {
    this.gestes.push("coller");
    await this.clicks.fill(cible, texte);
  }
  verifier(tache: string, cible: number) {
    expect(this.gestes.length, `${tache} : ${this.gestes.length} gestes pour une cible de ${cible} (± ${TOLERANCE}) : ${this.gestes.join(", ")}`)
      .toBeLessThanOrEqual(cible + TOLERANCE);
  }
}

test.describe("Parcours chiffrés (§3.6)", () => {
  test("tâche 1 : copier un mot de passe, saisie dans la recherche puis 1 clic", async ({ page, org, clicks }) => {
    await pressePapiers(page);
    await connexion(page, org.accounts.user);
    const nom = unique("Messagerie");
    await creerElement(page, { name: nom, username: "camille", password: "Tache-Une-2026" });
    const r = new Releve(clicks);
    // La recherche a le focus à l'ouverture du coffre (Ctrl K sinon) : la saisie n'est pas comptée.
    await page.getByLabel("Rechercher dans tout le coffre").first().fill(nom);
    const directe = page.getByRole("button", { name: `Copier le mot de passe de ${nom}` });
    if (await directe.first().isVisible().catch(() => false)) await r.clic(directe.first(), "Copier le mot de passe de …");
    else {
      await r.clic(page.getByRole("link", { name: new RegExp(nom) }).first(), nom);
      await r.clic(page.getByRole("button", { name: "Copier le mot de passe", exact: true }).first(), "Copier le mot de passe");
    }
    await expect(toast(page, /Mot de passe copié/).first()).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("Tache-Une-2026");
    r.verifier("Tâche 1", 1);
  });

  test("tâche 3 : enregistrer un nouveau mot de passe en 2 clics", async ({ page, org, clicks }) => {
    await connexion(page, org.accounts.user);
    const nom = unique("Fournisseur énergie");
    const r = new Releve(clicks);
    await r.clic(page.getByRole("button", { name: "Nouveau", exact: true }).first(), "Nouveau");
    await expect(page.getByLabel("Nom", { exact: true })).toBeFocused();
    await page.getByLabel("Nom", { exact: true }).fill(nom);
    await page.getByLabel("Identifiant", { exact: true }).fill("c.durand");
    await r.clic(page.getByRole("button", { name: "Enregistrer", exact: true }), "Enregistrer");
    await expect(page.getByText(/Élément enregistré/).first()).toBeVisible();
    await expect(titre(page, nom)).toBeVisible();
    r.verifier("Tâche 3", 2);
  });

  test("tâche 4 : partager un mot de passe avec un collègue en 3 clics, une fenêtre", async ({ page, org, clicks }) => {
    await connexion(page, org.accounts.user);
    const adam = org.accounts.admin;
    const nomCoffre = unique("Alice et Adam");
    await creerCoffre(page, nomCoffre, [adam.email]);
    const nom = unique("Serveur de fichiers");
    const id = await creerElement(page, { name: nom, username: "nas", password: "Tache-Quatre-2026" });
    await goHash(page, `#/element/${id}`);
    await expect(titre(page, nom)).toBeVisible();
    const r = new Releve(clicks);
    await r.clic(page.getByRole("button", { name: "Partager", exact: true }).first(), "Partager");
    const dlg = fenetre(page, /^Partager « /);
    await dlg.getByLabel("Avec qui ?").fill("Adam");
    await r.clic(dlg.getByRole("button", { name: `Ajouter ${adam.name}` }), `Ajouter ${adam.name}`);
    await r.clic(dlg.getByRole("button", { name: "Partager", exact: true }), "Partager");
    await expect(dlg).toBeHidden();
    await expect(toast(page, new RegExp(`est partagé dans`)).first()).toBeVisible();
    r.verifier("Tâche 4", 3);
  });

  test("tâche 5 : déverrouiller après inactivité en 1 touche (web)", async ({ page, org, clicks }) => {
    await connexion(page, org.accounts.user);
    // Verrouillage (inactivité simulée par le raccourci) : hors du parcours compté.
    await page.keyboard.press("Control+Alt+l");
    const champ = page.getByLabel("Mot de passe maître", { exact: true });
    await expect(champ).toBeVisible();
    await expect(champ, "Le champ du mot de passe maître a le focus à l'écran verrouillé").toBeFocused();
    const r = new Releve(clicks);
    await champ.fill(org.accounts.user.password);
    await r.touche(champ, "Enter");
    await expect(page.getByRole("navigation", { name: "Navigation principale" })).toBeVisible({ timeout: KDF_TIMEOUT });
    r.verifier("Tâche 5", 1);
  });

  test("tâche 6 : corriger un mot de passe faible en 3 clics", async ({ page, apiAs, clicks }) => {
    test.setTimeout(150_000);
    await nouveauCompte(page, await apiAs("owner"), "parcours-bilan");
    const nom = unique("Banque en ligne");
    const id = await creerElement(page, { name: nom, username: "camille", password: "azerty123" });
    await goHash(page, "#/coffre");
    await expect(titre(page, "Tout")).toBeVisible();
    const r = new Releve(clicks);
    await r.clic(page.getByRole("navigation", { name: "Navigation principale" }).getByRole("link", { name: /^Bilan de sécurité/ }), "Bilan de sécurité");
    await expect(titre(page, "Bilan de sécurité")).toBeVisible();
    await r.clic(page.getByRole("button", { name: `Corriger ${nom}` }), "Corriger");
    await expect(page.getByLabel(/^Mot de passe$/).first()).not.toHaveValue("azerty123");
    await r.clic(page.getByRole("button", { name: "Enregistrer", exact: true }), "Enregistrer");
    await expect(page.getByText(/Élément enregistré/).first()).toBeVisible();
    // La correction ouvre aussi le site dans un nouvel onglet : on le referme.
    for (const p of page.context().pages()) if (p !== page) await p.close();
    expect(await page.evaluate(async (i) => (await import("/js/vault.js")).state.items.get(i)?.data?.password, id)).not.toBe("azerty123");
    r.verifier("Tâche 6", 3);
  });

  test("A1 : inviter 3 collègues en 3 gestes (bouton, coller, « Inviter »)", async ({ loggedIn, clicks }) => {
    const page = await loggedIn("owner");
    await goHash(page, "#/admin/personnes");
    await expect(titre(page, "Personnes")).toBeVisible();
    const t0 = Date.now();
    const adresses = [`a1-lea-${t0}@e2e.test`, `a1-hugo-${t0}@e2e.test`, `a1-ines-${t0}@e2e.test`];
    const r = new Releve(clicks);
    await r.clic(page.getByRole("button", { name: "Inviter des personnes" }).first(), "Inviter des personnes");
    const dlg = fenetre(page, "Inviter des personnes");
    await r.coller(dlg.getByLabel("Adresses e-mail"), adresses.join("\n"));
    await r.clic(dlg.getByRole("button", { name: "Inviter", exact: true }), "Inviter");
    await expect(dlg.getByText(/3 invitations créées/)).toBeVisible();
    r.verifier("A1", 3);
  });

  test("A3 : départ d'un collaborateur en 6 gestes au plus, rapport inclus", async ({ page, apiAs, loggedIn, org, clicks }) => {
    test.setTimeout(180_000);
    const partant = await nouveauCompte(page, await apiAs("owner"), "depart-parcours");
    // Deux coffres partagés avec Alice : la reprise ne doit pas coûter de geste par coffre.
    for (const n of ["Projets", "Clients"]) await creerCoffre(page, unique(n), [org.accounts.user.email]);
    const admin = await loggedIn("owner");
    await goHash(admin, `#/admin/personnes?q=${encodeURIComponent(partant.email)}`);
    await expect(admin.getByText(partant.email).first()).toBeVisible();
    // Le départ se lance depuis le menu ⋯ de la ligne de la liste.
    const plus = admin.getByRole("button", { name: `Plus d'actions pour ${partant.name}` }).first();
    await expect(plus).toBeVisible();
    const r = new Releve(clicks);
    await r.clic(plus, "Plus d'actions");
    await r.clic(admin.getByRole("menuitem", { name: /^Départ de l'entreprise/ }), "Départ de l'entreprise…");
    await expect(titre(admin, /^Départ de /)).toBeVisible();
    for (let etape = 0; etape < 5; etape++) {
      const confirmer = admin.getByRole("button", { name: "Confirmer le départ" });
      if (await confirmer.isVisible()) break;
      await r.clic(admin.getByRole("button", { name: "Continuer", exact: true }), "Continuer");
    }
    await r.clic(admin.getByRole("button", { name: "Confirmer le départ" }), "Confirmer le départ");
    const dlg = admin.getByRole("dialog", { name: /^Confirmer le départ/ });
    await dlg.getByLabel("Mot de passe maître", { exact: true }).fill(org.accounts.owner.password);
    await r.clic(dlg.getByRole("button", { name: "Confirmer le départ" }), "Confirmer le départ (fenêtre)");
    await expect(admin.getByRole("button", { name: "Télécharger le rapport (CSV)" })).toBeVisible({ timeout: KDF_TIMEOUT });
    r.verifier("A3", 6);
  });
});
