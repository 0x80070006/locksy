// Outils des tests de l'extension (lot L14) : variante des tests construite par
// `node extension/build.mjs --test` (accès aux sites fixé dans le manifeste,
// serveur http accepté, onglet visé par ?tab=<id>), pages de connexion
// simulées par context.route(), comptes créés depuis le popup lui-même.

import type { BrowserContext, Page } from "@playwright/test";
import { cpSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect } from "../../fixtures/index.ts";
import { BASE_URL } from "../../fixtures/env.ts";
import type { Account } from "../../fixtures/ui.ts";

export const KDF_TIMEOUT = 60_000;

/** Libellés contractuels du popup (annexe C) et textes du catalogue extension.*. */
export const L = {
  email: "Adresse e-mail",
  master: "Mot de passe maître",
  unlock: "Déverrouiller",
  forSite: "Pour ce site",
  save: "Enregistrer le compte saisi sur ce site",
  createPassword: "Créer un mot de passe pour ce site",
  lock: "Verrouiller",
  open: "Ouvrir",
  prefs: "Préférences",
  clipboardAfter: "Effacer le presse-papiers après",
  fill: (name: string) => `Remplir ${name}`,
  fillCode: (name: string) => `Remplir et copier le code ${name}`,
};

/** Page de connexion d'un site de test (formulaire classique, champ de code facultatif). */
export function loginPage({ code = false, title = "Connexion à l'intranet" } = {}): string {
  return `<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>${title}</title></head><body>
<main><h1>${title}</h1>
<form id="f">
  <label for="identifiant">Identifiant</label><input id="identifiant" name="username" autocomplete="username">
  <label for="mdp">Mot de passe</label><input id="mdp" name="password" type="password" autocomplete="current-password">
  ${code ? '<label for="code">Code reçu</label><input id="code" name="code" inputmode="numeric" maxlength="6" autocomplete="one-time-code">' : ""}
  <button type="button">Valider</button>
</form></main></body></html>`;
}

let counter = 0;
/** Site de test unique (aucune collision entre tests ni entre exécutions). */
export function uniqueSite(scheme: "https" | "http" = "https"): string {
  counter += 1;
  return `${scheme}://site-${process.pid}-${Date.now().toString(36)}-${counter}.exemple.test`;
}

/** Sert la page de connexion pour toutes les adresses du site. */
export async function serveSite(ctx: BrowserContext, origin: string, html = loginPage()) {
  await ctx.route(`${origin}/**`, (route) => route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: html }));
}

/**
 * Extension chargée : identifiant (adresse du service worker) et page de
 * contrôle de l'extension. Les API chrome.* ne sont pas exposées à
 * worker.evaluate (Playwright 1.49) : on les appelle depuis une page de
 * l'extension (offscreen.html, qui n'affiche rien et n'agit que sur message
 * du service worker).
 */
export async function extension(ctx: BrowserContext): Promise<{ id: string; control: Page }> {
  let [sw] = ctx.serviceWorkers();
  sw ??= await ctx.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host;
  const control = await ctx.newPage();
  await control.goto(`chrome-extension://${id}/offscreen.html`);
  return { id, control };
}

/** Préconfigure l'adresse du serveur (sans passer par l'écran « Adresse de votre serveur »). */
export async function configureServer(control: Page) {
  await control.evaluate((url) => chrome.storage.local.set({ server: url }), BASE_URL);
}

/** Identifiant d'onglet d'une page déjà ouverte. */
export async function tabIdOf(control: Page, page: Page): Promise<number> {
  const id = await control.evaluate(async (url) => (await chrome.tabs.query({})).find((t: { url: string }) => t.url === url)?.id ?? 0, page.url());
  expect(id, `onglet de ${page.url()}`).toBeGreaterThan(0);
  return id;
}

/**
 * Copie de l'extension construite hors du dossier partagé /work : Chromium lit
 * très lentement une extension non empaquetée sur un montage du poste (plusieurs
 * secondes par module). Renvoie le chemin à charger, ou "" sans EXT_PATH.
 */
export function localCopy(): string {
  const source = process.env.EXT_PATH ? resolve(process.env.EXT_PATH) : "";
  if (!source || !existsSync(source)) return "";
  const target = join(tmpdir(), `locksy-extension-${process.pid}`);
  rmSync(target, { recursive: true, force: true });
  cpSync(source, target, { recursive: true });
  return target;
}

/** Ouvre le popup visant l'onglet `tabId` ; relève les violations de CSP du popup. */
export async function openPopup(ctx: BrowserContext, id: string, tabId: number): Promise<{ popup: Page; csp: string[] }> {
  const popup = await ctx.newPage();
  const csp: string[] = [];
  popup.on("console", (m) => { if (/Refused to |Content[- ]Security[- ]Policy/i.test(m.text())) csp.push(m.text()); });
  await popup.goto(`chrome-extension://${id}/popup.html?tab=${tabId}`);
  return { popup, csp };
}

/** Connexion par mot de passe maître dans le popup ; attend l'écran principal. */
export async function unlock(popup: Page, account: Account) {
  // Premier affichage : chargement du module cryptographique (lent sur un poste chargé).
  await expect(popup.getByLabel(L.email)).toBeVisible({ timeout: KDF_TIMEOUT });
  await popup.getByLabel(L.email).fill(account.email);
  await popup.getByLabel(L.master, { exact: true }).fill(account.password);
  await popup.getByRole("button", { name: L.unlock }).click();
  await expect(popup.getByRole("heading", { name: L.forSite })).toBeVisible({ timeout: KDF_TIMEOUT });
}

export interface NewItem {
  name: string;
  url: string;
  username?: string;
  password?: string;
  totp?: string;
  totpFill?: boolean;
}

/**
 * Crée un compte avec le module du coffre déjà déverrouillé dans le popup
 * (même instance de module), puis recharge le popup.
 */
export async function createItem(popup: Page, item: NewItem) {
  await popup.evaluate(async (it) => {
    const V = await import("./lib/vault.js");
    const cols = [...V.state.collections.values()].filter((c) => !c.error && (c.personal || ["manager", "editor"].includes(c.role)));
    const target = cols.find((c) => c.personal) || cols[0];
    await V.createItem(target.id, {
      ...V.emptyItem("login"), name: it.name, username: it.username ?? "camille.durand", password: it.password ?? "Mdp-Essai-2024-x",
      urls: [it.url], totp: it.totp ?? "", totp_fill: it.totpFill === true,
    });
  }, item);
  await popup.reload();
  await expect(popup.getByRole("heading", { name: L.forSite })).toBeVisible();
}

/** Contenu du presse-papiers lu depuis une page de l'extension (permission clipboardRead de la variante des tests). */
export async function clipboardText(page: Page): Promise<string> {
  await page.bringToFront();
  return page.evaluate(() => navigator.clipboard.readText());
}

/** Centile p (0..1) d'une série de mesures. */
export function percentile(values: number[], p: number): number {
  const s = [...values].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)];
}

declare const chrome: any;
