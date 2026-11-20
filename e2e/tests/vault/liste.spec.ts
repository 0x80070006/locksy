// Liste et fiche du coffre (cahier §3.3.2, fiche L10) : recherche sans
// accents dans tous les coffres, copie en 2 interactions, favori personnel,
// corbeille annulable avec auteur et compte à rebours, panne réseau sur
// chaque action (message français, état inchangé), téléphone de 375 px.

import { test, expect } from "../../fixtures/index.ts";
import {
  aller, coffreDe, connexion, creerCoffre, creerElement, liste, lirePressePapiers, LIB, pressePapiers, toast, tolererPannes, tolererPrefs, unique,
} from "./outils.ts";

test.use({ textGuardMode: "strict" });

test.beforeEach(async ({ page, consoleGuard }) => {
  tolererPrefs(consoleGuard);
  await pressePapiers(page);
});

test.describe("Liste et fiche", () => {
  test("la recherche « societe » trouve « Société » dans tous les coffres", async ({ page, org }) => {
    await connexion(page, org.accounts.user);
    const mot = unique("x").split(" ")[1];
    const coffre = await creerCoffre(page, unique("Équipe compta"), [org.accounts.admin.email]);
    await creerElement(page, { name: `Société Générale ${mot}`, username: "compta" });
    await creerElement(page, { name: `SOCIÉTÉ civile ${mot}`, username: "sci" }, coffre);
    await page.getByRole("searchbox", { name: LIB.recherche }).or(page.getByLabel(LIB.recherche)).first().fill(`societe ${mot}`);
    await expect(page.getByRole("link", { name: new RegExp(`Société Générale ${mot}`) })).toBeVisible();
    await expect(page.getByRole("link", { name: new RegExp(`SOCIÉTÉ civile ${mot}`) })).toBeVisible();
  });

  test("copie du mot de passe en 2 interactions depuis la recherche", async ({ page, org, clicks }) => {
    await connexion(page, org.accounts.user);
    const nom = unique("Messagerie");
    await creerElement(page, { name: nom, username: "camille", password: "Copie-En-Deux-Gestes-2026" });
    await page.getByLabel(LIB.recherche).first().fill(nom);
    const gestes = await clicks.measure(async () => {
      await clicks.click(page.getByRole("link", { name: new RegExp(nom) }));
      await clicks.click(page.getByRole("button", { name: "Copier le mot de passe", exact: true }).first());
    });
    expect(gestes).toBe(2);
    await expect(toast(page, /Mot de passe copié/)).toBeVisible();
    expect(await lirePressePapiers(page)).toBe("Copie-En-Deux-Gestes-2026");
  });

  test("copie depuis la ligne de la liste : « Copier le mot de passe de <nom> »", async ({ page, org }) => {
    await connexion(page, org.accounts.user);
    const nom = unique("Banque en ligne");
    await creerElement(page, { name: nom, password: "Ligne-De-Liste-2026" });
    await aller(page, "#/coffre/favoris");
    await aller(page, "#/coffre");
    await liste(page).getByRole("button", { name: `Copier le mot de passe de ${nom}` }).click();
    await expect(toast(page, /Mot de passe copié/)).toBeVisible();
    expect(await lirePressePapiers(page)).toBe("Ligne-De-Liste-2026");
  });

  test("favori personnel : Alice le met en favori, Adam ne le voit pas en favori", async ({ page, org, loggedIn }) => {
    await connexion(page, org.accounts.user);
    const coffre = await creerCoffre(page, unique("Projet commun"), [org.accounts.admin.email]);
    const nom = unique("Accès partagé");
    const id = await creerElement(page, { name: nom, password: "Partage-Favori-2026" }, coffre);
    await aller(page, `#/element/${id}`);
    const etoile = page.getByRole("button", { name: "Ajouter aux favoris" });
    await expect(etoile).toHaveAttribute("aria-pressed", "false");
    await etoile.click();
    await expect(page.getByRole("button", { name: "Retirer des favoris" })).toHaveAttribute("aria-pressed", "true");
    await aller(page, "#/coffre/favoris");
    await expect(liste(page).getByText(nom, { exact: true })).toBeVisible();
    // Le favori n'est pas écrit dans l'élément : Adam ne le voit pas.
    const adam = await loggedIn("admin");
    await adam.evaluate((h) => { location.hash = h; }, `#/element/${id}`);
    await expect(adam.getByRole("heading", { level: 1, name: nom })).toBeVisible();
    await expect(adam.getByRole("button", { name: "Ajouter aux favoris" })).toHaveAttribute("aria-pressed", "false");
    await adam.evaluate((h) => { location.hash = h; }, "#/coffre/favoris");
    await expect(adam.getByRole("heading", { level: 1, name: "Favoris" })).toBeVisible();
    await expect(adam.getByText(nom, { exact: true })).toHaveCount(0);
  });

  test("corbeille : mise à la corbeille puis « Annuler » dans le message", async ({ page, org }) => {
    await connexion(page, org.accounts.user);
    const nom = unique("Carte cantine");
    const id = await creerElement(page, { name: nom, password: "Corbeille-2026" });
    await aller(page, `#/element/${id}`);
    await page.getByRole("button", { name: "Plus d'actions", exact: true }).click();
    await page.getByRole("menuitem", { name: "Mettre à la corbeille" }).click();
    await expect(toast(page, `« ${nom} » mis à la corbeille`)).toBeVisible();
    expect((await coffreDe(page, id)).deleted).toBe(true);
    await page.getByRole("button", { name: "Annuler", exact: true }).click();
    await expect(page.getByRole("heading", { level: 1, name: nom })).toBeVisible();
    expect((await coffreDe(page, id)).deleted).toBe(false);
  });

  test("corbeille : auteur de la suppression et compte à rebours, puis « Restaurer »", async ({ page, org }) => {
    await connexion(page, org.accounts.user);
    const nom = unique("Ancien VPN");
    const id = await creerElement(page, { name: nom, password: "Vpn-2026" });
    // Contrat C1.4 : /sync porte deleted_by et purge_at (simulés : absents de l'image de test).
    const moi = org.accounts.user.id;
    await page.route("**/api/sync*", async (r) => {
      const res = await r.fetch();
      const body = await res.json();
      for (const it of body.items || []) {
        if (it.deleted_at) Object.assign(it, { deleted_by: moi, purge_at: it.deleted_at + 30 * 86400 });
      }
      await r.fulfill({ response: res, json: body });
    });
    await page.evaluate(async (itemId) => {
      const { api } = await import("/js/api.js");
      const V = await import("/js/vault.js");
      await api("DELETE", `/items/${itemId}`);
      await V.sync();
    }, id);
    await aller(page, "#/corbeille");
    const ligne = page.getByRole("list", { name: "Éléments de la corbeille" }).getByRole("listitem").filter({ hasText: nom });
    await expect(ligne).toContainText("Mis à la corbeille par vous");
    await expect(ligne).toContainText(/supprimé dans (29|30) jours/);
    await ligne.getByRole("button", { name: `Plus d'actions pour ${nom}` }).click();
    await page.getByRole("menuitem", { name: "Restaurer" }).click();
    await expect(toast(page, `« ${nom} » restauré`)).toBeVisible();
    expect((await coffreDe(page, id)).deleted).toBe(false);
  });

  test("panne réseau sur chaque action : message français, état inchangé", async ({ page, org, consoleGuard }) => {
    tolererPannes(consoleGuard);
    await connexion(page, org.accounts.user);
    const nom = unique("Logiciel de paie");
    const id = await creerElement(page, { name: nom, password: "Panne-2026" });
    await aller(page, `#/element/${id}`);
    const panne = (mode: "500" | "coupure") => (r: import("@playwright/test").Route) =>
      (mode === "500" ? r.fulfill({ status: 500, json: { error: "internal", message: "panne" } }) : r.abort("failed"));
    /** Attend un message de plus que `avant` (les messages précédents peuvent être encore affichés). */
    const unDePlus = async (motif: RegExp, avant: number) => {
      await expect.poll(() => page.locator(".c-toast").filter({ hasText: motif }).count()).toBeGreaterThan(avant);
    };
    for (const mode of ["500", "coupure"] as const) {
      const attendu = mode === "500" ? /Le serveur a rencontré un problème/ : /Serveur injoignable/;
      const toasts = () => page.locator(".c-toast").filter({ hasText: attendu }).count();
      // Favori : préférences non enregistrées, étoile inchangée.
      await page.route("**/api/me/prefs", panne(mode));
      let avant = await toasts();
      await page.getByRole("button", { name: "Ajouter aux favoris" }).click();
      await unDePlus(attendu, avant);
      await expect(page.getByRole("button", { name: "Ajouter aux favoris" })).toHaveAttribute("aria-pressed", "false");
      await page.unroute("**/api/me/prefs");
      // Corbeille : l'élément reste en place.
      await page.route(`**/api/items/${id}`, panne(mode));
      avant = await toasts();
      await page.getByRole("button", { name: "Plus d'actions", exact: true }).click();
      await page.getByRole("menuitem", { name: "Mettre à la corbeille" }).click();
      await unDePlus(attendu, avant);
      await expect(page.getByRole("heading", { level: 1, name: nom })).toBeVisible();
      await page.unroute(`**/api/items/${id}`);
      expect((await coffreDe(page, id)).deleted).toBe(false);
    }
    // Restaurer et supprimer définitivement, depuis la corbeille.
    await page.evaluate(async (itemId) => {
      const { api } = await import("/js/api.js");
      const V = await import("/js/vault.js");
      await api("DELETE", `/items/${itemId}`);
      await V.sync();
    }, id);
    await aller(page, "#/corbeille");
    await aller(page, `#/element/${id}`);
    await page.route(`**/api/items/${id}/restore`, (r) => r.abort("failed"));
    await page.getByRole("button", { name: "Restaurer", exact: true }).click();
    await expect(toast(page, /Serveur injoignable/).first()).toBeVisible();
    expect((await coffreDe(page, id)).deleted).toBe(true);
    await page.route(`**/api/items/${id}/purge`, (r) => r.fulfill({ status: 500, json: { error: "internal", message: "panne" } }));
    await page.getByRole("button", { name: "Supprimer définitivement", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Supprimer définitivement" }).click();
    await expect(toast(page, /Le serveur a rencontré un problème/).first()).toBeVisible();
    expect((await coffreDe(page, id)).collectionId).not.toBeNull();
  });

  test("filtre « Type » et « Tri » (préférence synchronisée)", async ({ page, org }) => {
    await connexion(page, org.accounts.user);
    const mot = unique("t").split(" ")[1];
    await creerElement(page, { kind: "note", name: `Note ${mot}`, notes: "Contenu" });
    // Dates à la seconde : le second élément doit être strictement plus récent.
    await page.waitForTimeout(1100);
    await creerElement(page, { name: `Site ${mot}`, password: "Filtre-2026" });
    await aller(page, "#/coffre/favoris");
    await aller(page, "#/coffre");
    await page.getByLabel("Type", { exact: true }).selectOption({ label: "Notes secrètes" });
    await expect(liste(page).getByText(`Note ${mot}`, { exact: true })).toBeVisible();
    await expect(liste(page).getByText(`Site ${mot}`, { exact: true })).toHaveCount(0);
    expect(page.url()).toContain("type=note");
    await page.getByLabel("Type", { exact: true }).selectOption({ label: "Tous les types" });
    await page.getByLabel("Tri", { exact: true }).selectOption({ label: "Modifiés récemment" });
    await expect(liste(page).getByRole("listitem").first()).toContainText(`Site ${mot}`);
    const tri = await page.evaluate(async () => (await import("/js/settings-client.js")).prefs().ui.sort);
    expect(tri).toBe("recent");
    await page.getByLabel("Tri", { exact: true }).selectOption({ label: "A → Z" });
  });

  test("téléphone : liste plein écran, fiche avec barre d'action et retour", { tag: "@mobile" }, async ({ page, org }) => {
    test.skip((page.viewportSize()?.width ?? 1280) >= 600, "Disposition du téléphone : projet mobile (375 px) seulement.");
    await connexion(page, org.accounts.user);
    const nom = unique("Badge parking");
    const id = await creerElement(page, { name: nom, username: "camille", password: "Mobile-2026" });
    await aller(page, `#/element/${id}`);
    await expect(page.getByRole("heading", { level: 1, name: nom })).toBeVisible();
    await expect(liste(page)).toBeHidden();
    const barre = page.locator(".l-actionbar");
    await expect(barre.getByRole("button", { name: "Copier le mot de passe" })).toBeVisible();
    await expect(barre.getByRole("button", { name: "Modifier", exact: true })).toBeVisible();
    await expect(barre.getByRole("button", { name: "Partager", exact: true })).toBeVisible();
    const box = await barre.boundingBox();
    const vp = page.viewportSize();
    expect(box && vp ? box.y + box.height : 0).toBeGreaterThan((vp?.height ?? 0) - 4);
    await page.getByRole("link", { name: "Retour à la liste" }).click();
    await expect(liste(page)).toBeVisible();
    await expect(page.getByRole("heading", { level: 1, name: nom })).toHaveCount(0);
  });
});
