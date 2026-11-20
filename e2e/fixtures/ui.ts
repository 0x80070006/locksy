// Parcours élémentaires par l'interface (installation, inscription, connexion,
// déconnexion, ajout d'un élément), partagés par les fixtures et les tests.

import { expect, type Locator, type Page } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { L } from "./libelles.ts";

/** Temps maximal d'une opération qui dérive la clé maîtresse (Argon2 dans le navigateur). */
export const KDF_TIMEOUT = 60_000;

export interface Account {
  email: string;
  password: string;
  name: string;
  id: string;
}

/** Mot de passe maître de test : long et aléatoire (jauge de robustesse au maximum). */
export function testPassword(): string {
  return `Essai-${randomBytes(18).toString("base64url")}-Locksy`;
}

/**
 * Attend la coquille du coffre (après connexion ou inscription). Sous 900 px,
 * la navigation principale est repliée dans le tiroir (inert, hidden) : on
 * reconnaît alors la coquille au bouton « Menu » ou à « Menu du compte ».
 */
export async function expectShell(page: Page) {
  const shell = page
    .getByRole("navigation", { name: L.mainNav })
    .or(page.getByRole("button", { name: L.mobileMenu }))
    .or(page.getByRole("button", { name: L.accountMenu }));
  await expect(shell.first()).toBeVisible({ timeout: KDF_TIMEOUT });
}

/** Remplit le formulaire d'inscription (installation ou invitation) et confirme la clé de récupération. */
async function fillRegistration(page: Page, a: { email?: string; name: string; password: string }) {
  if (a.email !== undefined) await page.getByLabel(L.email).fill(a.email);
  await page.getByLabel(L.displayName).fill(a.name);
  await page.getByLabel(L.masterPassword).fill(a.password);
  await page.getByLabel(L.confirmMasterPassword).fill(a.password);
  await page.getByRole("button", { name: L.createVault }).click();
  // Clé de récupération : affichée une seule fois, à confirmer.
  await page.getByLabel(L.recoveryAck).check({ timeout: KDF_TIMEOUT });
  await page.getByRole("button", { name: L.continue }).click();
  await expectShell(page);
}

/** Installation par le jeton sur un serveur neuf ; la page doit être sur la racine du serveur. */
export async function installOwner(page: Page, setupToken: string, a: { email: string; name: string; password: string }) {
  await page.goto("/");
  const token = page.getByLabel(L.setupToken);
  await expect(token).toBeVisible();
  await token.fill(setupToken);
  await fillRegistration(page, a);
}

/** Inscription par un lien d'invitation (adresse imposée par l'invitation). */
export async function registerInvite(page: Page, inviteToken: string, a: { name: string; password: string }) {
  await page.goto(`/#/register?token=${encodeURIComponent(inviteToken)}`);
  await expect(page.getByLabel(L.setupToken)).toHaveCount(0);
  await fillRegistration(page, a);
}

/** Connexion par adresse et mot de passe maître. */
export async function loginUi(page: Page, a: { email: string; password: string }) {
  await page.goto("/");
  await page.getByLabel(L.email).fill(a.email);
  await page.getByLabel(L.masterPassword).fill(a.password);
  await page.getByRole("button", { name: L.login }).click();
  await expectShell(page);
}

/** Jeton de session de la page (sessionStorage « locksy.session »). */
export async function sessionToken(page: Page): Promise<string> {
  const token = await page.evaluate(() => sessionStorage.getItem("locksy.session"));
  if (!token) throw new Error("Aucun jeton de session dans sessionStorage « locksy.session ».");
  return token;
}

/**
 * Vrai si l'élément est visible ET dans la fenêtre : sur téléphone, le tiroir
 * de navigation fermé est hors écran, mais « visible » au sens de Playwright.
 */
async function onScreen(page: Page, target: Locator): Promise<boolean> {
  if (!(await target.isVisible())) return false;
  const box = await target.boundingBox();
  const vp = page.viewportSize();
  if (!box || !vp) return !!box;
  return box.x + box.width > 0 && box.x < vp.width && box.y + box.height > 0 && box.y < vp.height;
}

/** Ouvre le menu qui contient `target` s'il est replié (téléphone, menu du compte). */
async function reveal(page: Page, target: Locator) {
  if (await onScreen(page, target)) return;
  for (const name of [L.accountMenu, L.mobileMenu]) {
    const toggle = page.getByRole("button", { name });
    if (await onScreen(page, toggle)) {
      await toggle.click();
      await expect.poll(() => onScreen(page, target)).toBe(true);
      return;
    }
  }
}

/** Déconnexion complète, jusqu'à l'écran de connexion. */
export async function logoutUi(page: Page) {
  const button = page.getByRole("button", { name: L.logout }).or(page.getByRole("menuitem", { name: L.logout }));
  await reveal(page, button.first());
  await button.first().click();
  await expect(page.getByRole("button", { name: L.login })).toBeVisible();
}

/** Liste des éléments du coffre (interface actuelle ou refondue). */
export function itemList(page: Page): Locator {
  return page.getByRole("region", { name: L.itemList.region }).or(page.getByRole("list", { name: L.itemList.list }));
}

/**
 * Vérifie qu'un élément figure dans la liste. Sur téléphone, la fiche ouverte
 * remplace la liste : on revient d'abord à la liste.
 */
export async function expectInList(page: Page, name: string) {
  const back = page.getByRole("button", { name: L.backToList }).or(page.getByRole("link", { name: L.backToList }));
  if (await onScreen(page, back.first())) await back.first().click();
  await expect(itemList(page).getByText(name, { exact: true })).toBeVisible();
}

/**
 * Ajoute un élément « Mot de passe d'un site » par l'éditeur du panneau :
 * « Nouveau », le champ « Nom » a le focus, carte du type, saisie de
 * l'identifiant et du mot de passe (qui remplace le mot de passe
 * pré-généré), « Enregistrer », puis le message et la fiche (titre h1).
 */
export async function addPasswordItem(page: Page, item: { name: string; username: string; password: string }) {
  await page.getByRole("button", { name: L.newItem }).first().click();
  const name = page.getByLabel(L.itemName);
  await expect(name).toBeFocused();
  const type = page.getByRole("radio", { name: L.passwordType });
  if (!(await type.isChecked())) {
    await page.getByRole("group", { name: L.itemTypeGroup }).getByText(L.passwordType).click();
    await expect(type).toBeChecked();
  }
  await name.fill(item.name);
  await page.getByLabel(L.itemUsername).fill(item.username);
  await page.getByLabel(L.itemPassword).fill(item.password);
  await page.getByRole("button", { name: L.save }).click();
  await expect(page.getByText(L.itemSaved).first()).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: item.name })).toBeVisible();
}
