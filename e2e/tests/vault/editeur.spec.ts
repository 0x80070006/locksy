// Création et modification dans le panneau de la fiche (cahier §3.3.3,
// fiche L10) : les 5 types avec le focus sur « Nom », mot de passe pré-généré
// et « Saisir mon mot de passe actuel », type SSH complet relu après
// rechargement, case « Remplir aussi le code de vérification », garde de
// sortie (Échap, navigation, fermeture d'onglet), Ctrl+Entrée, panne réseau
// et conflit sans perte de saisie, refus rekey_required rattrapé.

import { test, expect } from "../../fixtures/index.ts";
import { KDF_TIMEOUT } from "../../fixtures/ui.ts";
import { aller, connexion, creerElement, enregistrer, LIB, ouvrirCreation, tolererPannes, pressePapiers, tolererPrefs, unique } from "./outils.ts";

test.use({ textGuardMode: "strict" });

test.beforeEach(async ({ page, org, consoleGuard }) => {
  tolererPrefs(consoleGuard);
  await pressePapiers(page);
  await connexion(page, org.accounts.user);
});

test.describe("Éditeur d'élément", () => {
  test("crée les 5 types, chacun avec le focus sur « Nom »", async ({ page }) => {
    const base = unique("Essai");
    // Mot de passe d'un site (type par défaut).
    let nom = await ouvrirCreation(page);
    await nom.fill(`${base} site`);
    await page.getByLabel("Adresse du site", { exact: true }).fill("https://intranet.exemple.fr");
    await page.getByLabel("Identifiant", { exact: true }).fill("camille.durand");
    await enregistrer(page, `${base} site`);

    nom = await ouvrirCreation(page, "Note secrète");
    await nom.fill(`${base} note`);
    await page.getByLabel("Notes", { exact: true }).fill("Code de la porte : 4521");
    await enregistrer(page, `${base} note`);

    nom = await ouvrirCreation(page, "Carte bancaire");
    await nom.fill(`${base} carte`);
    await page.getByLabel("Titulaire").fill("Camille Durand");
    await page.getByLabel("Numéro de carte").fill("4970 1012 3456 0063");
    await enregistrer(page, `${base} carte`);
    await expect(page.getByText("Numéro de carte", { exact: true })).toBeVisible();

    nom = await ouvrirCreation(page, "Identité");
    await nom.fill(`${base} identité`);
    await page.getByLabel("Prénom").fill("Camille");
    await page.getByLabel("Nom de famille").fill("Durand");
    await enregistrer(page, `${base} identité`);

    nom = await ouvrirCreation(page, "Clé SSH");
    await nom.fill(`${base} ssh`);
    await page.getByLabel("Hôte").fill("srv-01.exemple.fr");
    await enregistrer(page, `${base} ssh`);
  });

  test("mot de passe pré-généré avec la mention, puis « Saisir mon mot de passe actuel »", { tag: "@mobile" }, async ({ page }) => {
    await ouvrirCreation(page);
    const mdp = page.getByLabel("Mot de passe", { exact: true });
    await expect(mdp).not.toHaveValue("");
    expect((await mdp.inputValue()).length).toBeGreaterThanOrEqual(12);
    await expect(page.getByText("Mot de passe généré. Si le compte existe déjà")).toBeVisible();
    await page.getByRole("button", { name: "Saisir mon mot de passe actuel" }).click();
    await expect(mdp).toHaveValue("");
    await expect(mdp).toBeFocused();
    await expect(page.getByText("Mot de passe généré. Si le compte existe déjà")).toBeHidden();
  });

  test("type SSH complet (hôte, identifiant, port, mot de passe) relu après rechargement", async ({ page, org }) => {
    const nomSsh = unique("Serveur de déploiement");
    const nom = await ouvrirCreation(page, "Clé SSH");
    await nom.fill(nomSsh);
    await page.getByLabel("Hôte").fill("deploiement.exemple.fr");
    await page.getByLabel("Identifiant", { exact: true }).fill("deploy");
    await page.getByLabel("Port", { exact: true }).fill("2222");
    await page.getByLabel("Mot de passe", { exact: true }).fill("Ssh-Mot-De-Passe-2026");
    await page.getByLabel("Clé publique").fill("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemple deploy@exemple");
    await enregistrer(page, nomSsh);
    const adresse = page.url();
    // Rechargement : le coffre se verrouille (clés effacées), on le rouvre.
    await page.reload();
    await page.getByLabel("Mot de passe maître").fill(org.accounts.user.password);
    await page.getByRole("button", { name: "Déverrouiller" }).click();
    await expect(page.getByRole("heading", { level: 1, name: nomSsh })).toBeVisible({ timeout: KDF_TIMEOUT });
    expect(page.url()).toBe(adresse);
    const fiche = page.getByRole("article");
    await expect(fiche.getByText("deploiement.exemple.fr", { exact: true })).toBeVisible();
    await expect(fiche.getByText("2222", { exact: true })).toBeVisible();
    await expect(fiche.getByText("deploy", { exact: true })).toBeVisible();
    // Bouton de la fiche (les lignes de la liste portent « Copier le mot de passe de <nom> »).
    await expect(fiche.getByRole("button", { name: "Copier le mot de passe", exact: true })).toBeVisible();
    // Données relues : port gardé en texte, champs SSH complets.
    const ssh = await page.evaluate(async () => {
      const V = await import("/js/vault.js");
      const id = decodeURIComponent(location.hash.split("/")[2]);
      return V.state.items.get(id)?.data?.ssh;
    });
    expect(ssh).toMatchObject({ host: "deploiement.exemple.fr", username: "deploy", port: "2222", password: "Ssh-Mot-De-Passe-2026" });
  });

  test("« Remplir aussi le code de vérification » est enregistré dans l'élément", async ({ page }) => {
    const nomSite = unique("Portail RH");
    const nom = await ouvrirCreation(page);
    await nom.fill(nomSite);
    await page.getByText("Code de vérification", { exact: true }).first().click();
    await page.getByLabel("Clé du code de vérification").fill("JBSWY3DPEHPK3PXP");
    await expect(page.getByText(/Code actuel : \d{6}/)).toBeVisible();
    await page.getByLabel("Remplir aussi le code de vérification dans la page").check();
    await enregistrer(page, nomSite);
    const data = await page.evaluate(async () => {
      const V = await import("/js/vault.js");
      const id = decodeURIComponent(location.hash.split("/")[2]);
      return V.state.items.get(id)?.data;
    });
    expect(data?.totp_fill).toBe(true);
    expect(data && "favorite" in data).toBe(false);
  });

  test("Ctrl+Entrée enregistre", async ({ page }) => {
    const nomRapide = unique("Wifi invités");
    const nom = await ouvrirCreation(page);
    await nom.fill(nomRapide);
    await nom.press("Control+Enter");
    await expect(page.getByText(LIB.sauve).first()).toBeVisible();
    await expect(page.getByRole("heading", { level: 1, name: nomRapide })).toBeVisible();
  });

  test("garde de sortie : Échap, navigation et fermeture d'onglet", async ({ page }) => {
    const nom = await ouvrirCreation(page);
    await nom.fill("Brouillon à ne pas perdre");
    // Échap : la garde demande ; « Rester » garde la saisie.
    await nom.press("Escape");
    const garde = page.getByRole("dialog", { name: LIB.quitter });
    await expect(garde).toBeVisible();
    await garde.getByRole("button", { name: "Rester" }).click();
    await expect(garde).toBeHidden();
    await expect(nom).toHaveValue("Brouillon à ne pas perdre");
    // Clic à l'extérieur, sur la navigation : même garde.
    await page.getByRole("navigation", { name: "Navigation principale" }).getByRole("link", { name: /^Corbeille/ }).click();
    await expect(garde).toBeVisible();
    await garde.getByRole("button", { name: "Rester" }).click();
    await expect(nom).toHaveValue("Brouillon à ne pas perdre");
    expect(page.url()).toContain("#/nouveau");
    // Fermeture de l'onglet : le navigateur demande confirmation (beforeunload).
    const demande = new Promise<string>((resolve) => page.once("dialog", (d) => { resolve(d.type()); void d.dismiss(); }));
    await page.close({ runBeforeUnload: true });
    expect(await demande).toBe("beforeunload");
  });

  test("« Abandonner » quitte sans enregistrer", async ({ page }) => {
    const brouillon = unique("Brouillon abandonné");
    const nom = await ouvrirCreation(page);
    await nom.fill(brouillon);
    await page.getByRole("button", LIB.annuler).first().click();
    await page.getByRole("dialog", { name: LIB.quitter }).getByRole("button", { name: "Abandonner" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Tout" })).toBeVisible();
    await expect(page.getByText(brouillon)).toHaveCount(0);
  });

  test("panne réseau à l'enregistrement : message français, saisie intacte", async ({ page, consoleGuard }) => {
    tolererPannes(consoleGuard);
    const nomPanne = unique("Compte fournisseur");
    const nom = await ouvrirCreation(page);
    await nom.fill(nomPanne);
    // Réponse 500, puis réseau coupé.
    await page.route("**/api/items", (r) => r.fulfill({ status: 500, json: { error: "internal", message: "panne" } }));
    await page.getByRole("button", LIB.enregistrer).click();
    await expect(page.getByRole("alert").filter({ hasText: /Réessayez|contactez/ }).first()).toBeVisible();
    await expect(nom).toHaveValue(nomPanne);
    await page.unroute("**/api/items");
    await page.route("**/api/items", (r) => r.abort("failed"));
    await page.getByRole("button", LIB.enregistrer).click();
    await expect(page.getByRole("alert").filter({ hasText: "Serveur injoignable" }).first()).toBeVisible();
    await expect(nom).toHaveValue(nomPanne);
    expect(page.url()).toContain("#/nouveau");
    // Le réseau revient : l'enregistrement aboutit.
    await page.unroute("**/api/items");
    await enregistrer(page, nomPanne);
  });

  test("conflit 409 : la saisie est conservée, « Garder la mienne » enregistre", async ({ page, consoleGuard }) => {
    tolererPannes(consoleGuard);
    const nomConflit = unique("Routeur");
    const id = await creerElement(page, { name: nomConflit, username: "gestion", password: "Ancien-Mot-2026" });
    await aller(page, `#/element/${id}/modifier`);
    const mdp = page.getByLabel("Mot de passe", { exact: true });
    await mdp.fill("Ma-Version-2026");
    // Quelqu'un d'autre enregistre entre-temps.
    await page.evaluate(async (itemId) => {
      const V = await import("/js/vault.js");
      const it = V.state.items.get(itemId);
      await V.updateItem(it, { ...it.data, notes: "modifié ailleurs" });
    }, id);
    await page.getByRole("button", LIB.enregistrer).click();
    await expect(page.getByText(/a été modifié .*par quelqu'un d'autre/)).toBeVisible();
    await expect(mdp).toHaveValue("Ma-Version-2026");
    await page.getByRole("button", { name: "Garder la mienne" }).click();
    await expect(page.getByRole("heading", { level: 1, name: nomConflit })).toBeVisible();
    const data = await page.evaluate(async (itemId) => {
      const V = await import("/js/vault.js");
      await V.sync();
      return V.state.items.get(itemId)?.data;
    }, id);
    expect(data?.password).toBe("Ma-Version-2026");
  });

  test("refus rekey_required : resynchronisation puis nouvel envoi, sans perte", async ({ page, consoleGuard }) => {
    tolererPannes(consoleGuard);
    const nomRekey = unique("Imprimante");
    const id = await creerElement(page, { name: nomRekey, password: "Imprimante-2026" });
    await aller(page, `#/element/${id}/modifier`);
    await page.getByLabel("Identifiant", { exact: true }).fill("impression");
    let refus = 0;
    const envois: string[] = [];
    // Contrat C1.4 : la clé du coffre a changé (route simulée, absente de l'image de test).
    await page.route(`**/api/items/${id}`, async (r) => {
      if (r.request().method() !== "PUT") return r.continue();
      envois.push(r.request().postData() || "");
      if (refus++ === 0) return r.fulfill({ status: 409, json: { error: "rekey_required", message: "Clé renouvelée.", collection_id: "x", key_version: 2 } });
      return r.continue();
    });
    await page.getByRole("button", LIB.enregistrer).click();
    await expect(page.getByText(LIB.sauve).first()).toBeVisible();
    expect(envois).toHaveLength(2);
    await expect(page.getByRole("article").getByText("impression", { exact: true })).toBeVisible();
  });
});
