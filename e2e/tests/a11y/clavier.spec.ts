// Parcours au clavier seul (cahier §2.10 A3, A4, A6 et §3.6, critère G4
// partie automatique) : les tâches web 1, 3, 4, 5 et 6 avec Tab, flèches,
// Entrée, Échap et les raccourcis documentés (Ctrl K, Ctrl Maj C,
// Ctrl Entrée, Ctrl Alt L). Après chaque action, le focus n'est jamais sur
// <body> ; à la fermeture d'une fenêtre, il revient sur son déclencheur.
// La tâche 2 (extension) est couverte par la suite de l'extension.

import type { Locator, Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { KDF_TIMEOUT, expectShell } from "../../fixtures/ui.ts";

test.use({ textGuardMode: "strict" });

const unique = (base: string) => `${base} ${Math.random().toString(36).slice(2, 7)}`;

/** Le focus n'est jamais perdu sur <body> (A3). */
async function focusGarde(page: Page, apres: string) {
  await expect.poll(() => page.evaluate(() => document.activeElement !== document.body && document.activeElement !== null), {
    message: `Focus perdu sur <body> après : ${apres}`,
  }).toBe(true);
}

/** Tabulations jusqu'à `cible` (au plus `max`), comme une personne au clavier. */
async function tabulerJusqua(page: Page, cible: Locator, max = 60, arriere = false) {
  for (let i = 0; i < max; i++) {
    if (await cible.evaluate((el) => el === document.activeElement).catch(() => false)) return;
    await page.keyboard.press(arriere ? "Shift+Tab" : "Tab");
  }
  await expect(cible, `Atteint au clavier en ${max} tabulations au plus`).toBeFocused();
}

/** Connexion au clavier : saisie, Entrée. */
async function connexionClavier(page: Page, a: { email: string; password: string }) {
  await page.goto("/");
  await page.getByLabel("Adresse e-mail").focus();
  await page.keyboard.type(a.email);
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Mot de passe maître", { exact: true })).toBeFocused();
  await page.keyboard.type(a.password);
  await page.keyboard.press("Enter");
  await expectShell(page);
  await expect(page.locator("#contenu h1").first()).toBeVisible({ timeout: KDF_TIMEOUT });
  await focusGarde(page, "connexion");
}

async function creerElement(page: Page, data: Record<string, unknown>): Promise<string> {
  return page.evaluate(async (d) => {
    const V = await import("/js/vault.js");
    if (!V.state.collections.size) await V.sync();
    const perso = [...V.state.collections.values()].find((c: { personal?: boolean }) => c.personal);
    const id = await V.createItem(perso!.id, { ...V.emptyItem("login"), ...d, password_changed_at: V.now() });
    await V.sync();
    return id;
  }, data);
}

/** Presse-papiers en mémoire (HTTP sur un nom d'hôte : pas de navigator.clipboard). */
async function pressePapiers(page: Page) {
  await page.addInitScript(() => {
    if (window.isSecureContext && navigator.clipboard) return;
    let contenu = "";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async (v: string) => { contenu = String(v); }, readText: async () => contenu },
    });
  });
}

test.describe("Clavier seul : les tâches web du §3.6", () => {
  test("tâche 1 : Ctrl K, saisie, ↓, Ctrl Maj C copie le mot de passe", async ({ page, org }) => {
    await pressePapiers(page);
    await connexionClavier(page, org.accounts.user);
    const nom = unique("Messagerie clavier");
    await creerElement(page, { name: nom, username: "camille", password: "Clavier-Copie-2026" });
    await page.locator("#contenu").focus();
    await page.keyboard.press("Control+k");
    const recherche = page.getByRole("combobox", { name: "Rechercher dans tout le coffre" })
      .or(page.getByRole("searchbox", { name: "Rechercher dans tout le coffre" }))
      .or(page.getByRole("textbox", { name: "Rechercher dans tout le coffre" })).first();
    await expect(recherche).toBeFocused();
    await page.keyboard.type(nom.toLowerCase());
    await expect(page.getByRole("link", { name: new RegExp(nom) }).first()).toBeVisible();
    await page.keyboard.press("ArrowDown");
    await focusGarde(page, "↓ dans les résultats");
    await page.keyboard.press("Control+Shift+C");
    await expect(page.locator("#status")).toContainText("Mot de passe copié");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("Clavier-Copie-2026");
    await focusGarde(page, "Ctrl Maj C");
  });

  test("tâche 3 : nouvel élément au clavier, Ctrl Entrée enregistre", async ({ page, org }) => {
    await connexionClavier(page, org.accounts.user);
    const nouveau = page.getByRole("button", { name: "Nouveau", exact: true }).first();
    await tabulerJusqua(page, nouveau);
    await page.keyboard.press("Enter");
    const nomChamp = page.getByLabel("Nom", { exact: true });
    await expect(nomChamp).toBeFocused();
    const nom = unique("Fournisseur clavier");
    await page.keyboard.type(nom);
    await tabulerJusqua(page, page.getByLabel("Identifiant", { exact: true }), 20);
    await page.keyboard.type("c.durand");
    await page.keyboard.press("Control+Enter");
    await expect(page.getByText(/Élément enregistré/).first()).toBeVisible();
    await expect(page.getByRole("heading", { level: 1, name: nom })).toBeVisible();
    await focusGarde(page, "Ctrl Entrée");
  });

  test("tâche 4 : partager au clavier, puis retour du focus sur « Partager » à la fermeture", async ({ page, org }) => {
    await connexionClavier(page, org.accounts.user);
    const nom = unique("Serveur clavier");
    const id = await creerElement(page, { name: nom, username: "nas", password: "Clavier-Partage-2026" });
    await page.evaluate((h) => { location.hash = h; }, `#/element/${id}`);
    await expect(page.getByRole("heading", { level: 1, name: nom })).toBeVisible();
    await focusGarde(page, "ouverture de la fiche");
    const partager = page.getByRole("button", { name: "Partager", exact: true }).first();
    await tabulerJusqua(page, partager);
    await page.keyboard.press("Enter");
    const dlg = page.getByRole("dialog", { name: /^Partager « / });
    await expect(dlg).toBeVisible();
    await focusGarde(page, "ouverture de la fenêtre");
    // Échap ferme la fenêtre (rien n'est saisi) et rend le focus au déclencheur (A4).
    await page.keyboard.press("Escape");
    await expect(dlg).toBeHidden();
    await expect(partager, "Retour du focus sur le déclencheur").toBeFocused();
    // Partage complet au clavier.
    await page.keyboard.press("Enter");
    await expect(dlg).toBeVisible();
    await tabulerJusqua(page, dlg.getByLabel("Avec qui ?"), 20);
    await page.keyboard.type("Adam");
    const ajouter = dlg.getByRole("button", { name: `Ajouter ${org.accounts.admin.name}` });
    await expect(ajouter).toBeVisible();
    await tabulerJusqua(page, ajouter, 20);
    await page.keyboard.press("Enter");
    await focusGarde(page, "« Ajouter »");
    await tabulerJusqua(page, dlg.getByRole("button", { name: "Partager", exact: true }), 30);
    await page.keyboard.press("Enter");
    await expect(dlg).toBeHidden({ timeout: KDF_TIMEOUT });
    await focusGarde(page, "partage enregistré");
  });

  test("tâche 5 : Ctrl Alt L verrouille, le mot de passe et Entrée déverrouillent", async ({ page, org }) => {
    await connexionClavier(page, org.accounts.user);
    await page.keyboard.press("Control+Alt+l");
    const champ = page.getByLabel("Mot de passe maître", { exact: true });
    await expect(champ).toBeFocused();
    await page.keyboard.type(org.accounts.user.password);
    await page.keyboard.press("Enter");
    await expectShell(page);
    await focusGarde(page, "déverrouillage");
  });

  test("tâche 6 : bilan, « Corriger » et Ctrl Entrée au clavier", async ({ page, org }) => {
    await connexionClavier(page, org.accounts.user);
    const nom = unique("Compte faible");
    await creerElement(page, { name: nom, username: "camille", password: "azerty123" });
    const bilan = page.getByRole("navigation", { name: "Navigation principale" }).getByRole("link", { name: /^Bilan de sécurité/ });
    await tabulerJusqua(page, bilan, 80);
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { level: 1, name: "Bilan de sécurité" })).toBeVisible();
    await focusGarde(page, "ouverture du bilan");
    const corriger = page.getByRole("button", { name: `Corriger ${nom}` });
    await tabulerJusqua(page, corriger, 80);
    const onglet = page.context().waitForEvent("page", { timeout: 5_000 }).catch(() => null);
    await page.keyboard.press("Enter");
    await expect(page.getByLabel(/^Mot de passe$/).first()).not.toHaveValue("azerty123");
    (await onglet)?.close();
    await page.bringToFront();
    await focusGarde(page, "« Corriger »");
    await page.keyboard.press("Control+Enter");
    await expect(page.getByText(/Élément enregistré/).first()).toBeVisible();
    await focusGarde(page, "enregistrement de la correction");
  });

  test("fenêtre « Générer un mot de passe » : piège du focus, Échap, retour sur « Générer »", async ({ page, org }) => {
    await connexionClavier(page, org.accounts.user);
    const generer = page.getByRole("button", { name: "Générer", exact: true }).first();
    await tabulerJusqua(page, generer);
    await page.keyboard.press("Enter");
    const panneau = page.getByRole("dialog", { name: "Générer un mot de passe" });
    await expect(panneau).toBeVisible();
    // Le focus reste dans la fenêtre en tabulant (A4).
    for (let i = 0; i < 12; i++) {
      await page.keyboard.press("Tab");
      expect(await panneau.evaluate((d) => d.contains(document.activeElement)), "Focus piégé dans la fenêtre").toBe(true);
    }
    await page.keyboard.press("Escape");
    await expect(panneau).toBeHidden();
    await expect(generer, "Retour du focus sur le déclencheur").toBeFocused();
  });
});
