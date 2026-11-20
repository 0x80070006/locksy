// Partage (cahier §3.3.4 et §3.3.5, fiche L10) : avec des collègues en
// 3 clics vers le coffre existant qui a exactement ces membres, retour arrière
// complet quand une étape échoue, élément déjà partagé ; lien sécurisé qui
// n'envoie pas le nom tant que « Inclure le nom » n'est pas coché, rattaché
// à l'élément, révocable ; politique share.enabled ; panne réseau.

import type { Page, Request } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { KDF_TIMEOUT } from "../../fixtures/ui.ts";
import {
  aller, coffreDe, connexion, creerCoffre, creerElement, LIB, lirePressePapiers, nomsDesCoffres, pressePapiers, toast, tolererPannes, tolererPrefs, unique,
} from "./outils.ts";

test.use({ textGuardMode: "strict" });

test.beforeEach(async ({ page, org, consoleGuard }) => {
  tolererPrefs(consoleGuard);
  await pressePapiers(page);
  await connexion(page, org.accounts.user);
});

const fenetre = (page: Page) => page.getByRole("dialog", { name: /^Partager « / });

/** Déchiffre la charge d'un lien sécurisé avec la clé de son fragment, dans la page. */
async function chargeDuLien(page: Page, url: string, data: string): Promise<Record<string, unknown>> {
  return page.evaluate(async ({ key, cipher }) => {
    const W = await import("/js/wasm.js");
    const A = await import("/js/aad.js");
    const k = W.call("import_key", { key });
    try {
      return JSON.parse(W.call("decrypt", { key: k, data: cipher, aad: A.share() }));
    } finally {
      W.call("drop_key", { key: k });
    }
  }, { key: url.split("#")[1], cipher: data });
}

test.describe("Partager avec des collègues", () => {
  test("3 clics : « Partager », « Ajouter », « Partager » vers le coffre existant avec les mêmes membres", async ({ page, org, clicks }) => {
    const adam = org.accounts.admin;
    const nomCoffre = unique("Alice et Adam");
    const coffre = await creerCoffre(page, nomCoffre, [adam.email]);
    const nom = unique("Serveur NAS");
    const id = await creerElement(page, { name: nom, username: "gestion-nas", password: "Nas-Partage-2026" });
    await aller(page, `#/element/${id}`);
    const gestes = await clicks.measure(async () => {
      await clicks.click(page.getByRole("button", LIB.partager));
      // Saisie de texte : pas comptée (§3.6), d'où page.fill et non clicks.fill.
      await fenetre(page).getByLabel("Avec qui ?").fill("Adam");
      await clicks.click(fenetre(page).getByRole("button", { name: `Ajouter ${adam.name}` }));
      await expect(fenetre(page).getByRole("radio", { name: new RegExp(nomCoffre) })).toBeChecked();
      await expect(fenetre(page).getByText(`« ${nom} » quittera votre coffre personnel.`)).toBeVisible();
      await clicks.click(fenetre(page).getByRole("button", LIB.partager));
    });
    expect(gestes).toBe(3);
    await expect(toast(page, `« ${nom} » est partagé dans ${nomCoffre}`)).toBeVisible();
    await expect(fenetre(page)).toBeHidden();
    expect((await coffreDe(page, id)).collectionId).toBe(coffre);
  });

  test("échec au 2e appel : retour arrière complet, rien n'est modifié", async ({ page, org, consoleGuard }) => {
    tolererPannes(consoleGuard);
    const paule = org.accounts.owner;
    const nom = unique("Compte bancaire");
    const id = await creerElement(page, { name: nom, password: "Retour-Arriere-2026" });
    await aller(page, `#/element/${id}`);
    const appels: string[] = [];
    page.on("request", (r: Request) => { if (/\/api\/collections/.test(r.url())) appels.push(`${r.method()} ${new URL(r.url()).pathname}`); });
    await page.route("**/api/collections/*/members", (r) =>
      (r.request().method() === "POST" ? r.fulfill({ status: 500, json: { error: "internal", message: "panne" } }) : r.continue()));
    await page.getByRole("button", LIB.partager).click();
    await fenetre(page).getByLabel("Avec qui ?").fill("Paule");
    await fenetre(page).getByRole("button", { name: `Ajouter ${paule.name}` }).click();
    const nouveau = fenetre(page).getByRole("radio", { name: /Un nouveau coffre/ });
    await expect(nouveau).toBeChecked();
    const nomCoffre = unique("Coffre annulé");
    await fenetre(page).getByLabel("Nom du nouveau coffre").fill(nomCoffre);
    await fenetre(page).getByRole("button", LIB.partager).click();
    await expect(fenetre(page).getByRole("alert")).toContainText("Le partage n'a pas abouti");
    await expect(fenetre(page).getByRole("alert")).toContainText("Rien n'a été modifié.");
    // Créé, ajout refusé, puis coffre supprimé ; l'élément n'a pas bougé.
    expect(appels.filter((a) => a.startsWith("POST /api/collections") || a.startsWith("DELETE"))).toEqual([
      "POST /api/collections", expect.stringMatching(/^POST \/api\/collections\/.+\/members$/), expect.stringMatching(/^DELETE \/api\/collections\/[^/]+$/),
    ]);
    expect(await nomsDesCoffres(page)).not.toContain(nomCoffre);
    expect((await coffreDe(page, id)).personal).toBe(true);
  });

  test("élément déjà dans un coffre partagé : qui y a accès et « Gérer le coffre »", async ({ page, org }) => {
    const nomCoffre = unique("Support");
    const coffre = await creerCoffre(page, nomCoffre, [org.accounts.admin.email]);
    const id = await creerElement(page, { name: unique("Console support"), password: "Support-2026" }, coffre);
    await aller(page, `#/element/${id}`);
    await page.getByRole("button", LIB.partager).click();
    await expect(fenetre(page).getByText(`Partagé avec : ${org.accounts.admin.name}`)).toBeVisible();
    await fenetre(page).getByRole("button", { name: `Gérer le coffre ${nomCoffre}` }).click();
    const gerer = page.getByRole("dialog", { name: `Gérer le coffre « ${nomCoffre} »` });
    await expect(gerer.getByRole("list", { name: "Membres" })).toContainText(org.accounts.admin.name);
    // Rôle en mots, dans la liste déroulante de la personne (le gestionnaire peut le changer).
    const droits = gerer.getByLabel(`Droits de ${org.accounts.admin.name}`, { exact: true });
    await expect(droits).toHaveValue("editor");
    await expect(droits.locator("option:checked")).toHaveText("Peut modifier");
  });
});

test.describe("Lien sécurisé", () => {
  test("« Inclure le nom » décoché par défaut : le nom n'est pas dans la charge chiffrée", async ({ page }) => {
    const nom = unique("Wifi bureau");
    const id = await creerElement(page, { name: nom, username: "invite", password: "Lien-Sans-Nom-2026", notes: "Étage 3" });
    await aller(page, `#/element/${id}`);
    await page.getByRole("button", LIB.partager).click();
    await fenetre(page).getByRole("tab", { name: "Par lien sécurisé" }).click();
    const inclure = fenetre(page).getByLabel("Inclure le nom");
    await expect(inclure).not.toBeChecked();
    const envoi = page.waitForRequest((r) => r.url().endsWith("/api/shares") && r.method() === "POST");
    await fenetre(page).getByRole("button", { name: "Créer et copier le lien" }).click();
    const corps = (await envoi).postDataJSON() as { data: string; item_id?: string; verifier?: string };
    expect(corps.item_id).toBe(id);
    if (corps.verifier) expect(corps.verifier).toMatch(/^[0-9a-f]{64}$/);
    // exact : le panneau de l'onglet « Par lien sécurisé » porte aussi ces mots.
    const lien = await fenetre(page).getByLabel("Lien sécurisé", { exact: true }).inputValue();
    expect(lien).toMatch(/\/s\/[^#]+#.+/);
    const charge = await chargeDuLien(page, lien, corps.data);
    expect(charge).not.toHaveProperty("name");
    expect(JSON.stringify(charge)).not.toContain(nom);
    expect(charge).toMatchObject({ username: "invite", password: "Lien-Sans-Nom-2026" });
    expect(charge).not.toHaveProperty("notes");
    await expect(toast(page, /Lien copié/).first()).toBeVisible();
    expect(await lirePressePapiers(page)).toBe(lien);
    // Correspondance lien -> élément gardée dans les préférences chiffrées.
    const shareId = new URL(lien).pathname.split("/").pop() as string;
    await expect.poll(() => page.evaluate(async (s) => (await import("/js/settings-client.js")).prefs().links?.[s]?.item_id ?? null, shareId)).toBe(id);
    // Coché : le nom est envoyé.
    await inclure.check();
    const envoi2 = page.waitForRequest((r) => r.url().endsWith("/api/shares") && r.method() === "POST");
    await fenetre(page).getByRole("button", { name: "Créer et copier le lien" }).click();
    const corps2 = (await envoi2).postDataJSON() as { data: string };
    // Le champ affiche le nouveau lien une fois la réponse reçue : on l'attend.
    await expect(fenetre(page).getByLabel("Lien sécurisé", { exact: true })).not.toHaveValue(lien);
    const lien2 =await fenetre(page).getByLabel("Lien sécurisé", { exact: true }).inputValue();
    expect(await chargeDuLien(page, lien2, corps2.data)).toMatchObject({ name: nom });
    // Révocation.
    await fenetre(page).getByRole("button", { name: "Révoquer", exact: true }).click();
    await page.getByRole("dialog", { name: "Révoquer ce lien ?" }).getByRole("button", { name: "Révoquer" }).click();
    await expect(fenetre(page).getByText("Lien révoqué")).toBeVisible();
  });

  test("panne à la création du lien : message français, aucun lien affiché", async ({ page, consoleGuard }) => {
    tolererPannes(consoleGuard);
    const id = await creerElement(page, { name: unique("Extranet"), password: "Extranet-2026" });
    await aller(page, `#/element/${id}`);
    await page.route("**/api/shares", (r) => r.fulfill({ status: 500, json: { error: "internal", message: "panne" } }));
    await page.getByRole("button", LIB.partager).click();
    await fenetre(page).getByRole("tab", { name: "Par lien sécurisé" }).click();
    await fenetre(page).getByRole("button", { name: "Créer et copier le lien" }).click();
    await expect(toast(page, /Le lien n'a pas été créé/)).toBeVisible();
    await expect(fenetre(page).getByLabel("Lien sécurisé", { exact: true })).toHaveCount(0);
  });

  test("liens désactivés par l'organisation : onglet visible, raison affichée", async ({ page, org }) => {
    // Politique simulée (A.4) : share.enabled imposé à false.
    await page.route("**/api/settings/policy", async (r) => {
      const res = await r.fetch();
      const body = res.ok() ? await res.json() : { revision: 1, policy: {} };
      body.policy = { ...(body.policy || {}), "share.enabled": { value: false } };
      await r.fulfill({ json: body, headers: { etag: "\"simule\"" } });
    });
    await page.reload();
    await page.getByLabel("Mot de passe maître").fill(org.accounts.user.password);
    await page.getByRole("button", { name: "Déverrouiller" }).click();
    await expect(page.getByRole("navigation", { name: "Navigation principale" })).toBeVisible({ timeout: KDF_TIMEOUT });
    const id = await creerElement(page, { name: unique("Messagerie pro"), password: "Politique-2026" });
    await aller(page, `#/element/${id}`);
    await page.getByRole("button", LIB.partager).click();
    await fenetre(page).getByRole("tab", { name: "Par lien sécurisé" }).click();
    await expect(fenetre(page).getByText("Votre organisation a désactivé les liens sécurisés.")).toBeVisible();
    await expect(fenetre(page).getByRole("button", { name: "Créer et copier le lien" })).toHaveCount(0);
  });
});
