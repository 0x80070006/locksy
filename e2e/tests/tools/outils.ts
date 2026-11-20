// Outils communs aux tests des pages utilisateur (lot L11) : compte neuf,
// politique simulée, éléments créés par le module de la page, déverrouillage
// après rechargement, module WebAssembly courant pour la page de partage.

import { existsSync } from "node:fs";
import { join } from "node:path";
import type { APIRequestContext, Page } from "@playwright/test";
import { expect } from "../../fixtures/index.ts";
import { stateDir } from "../../fixtures/env.ts";
import { KDF_TIMEOUT, expectShell, registerInvite, testPassword } from "../../fixtures/ui.ts";

/** Garde de console du harnais (fixture `consoleGuard`). */
interface ConsoleGuard {
  allow(re: RegExp): void;
}

export interface Compte {
  email: string;
  password: string;
  name: string;
}

/**
 * Bruits connus de la transition (règle R11) : GET /api/me/prefs répond 404
 * tant qu'aucun document de préférences n'existe ; le serveur de l'image e2e
 * n'a pas encore les routes de la vague 2 (les vues se replient). Le
 * navigateur journalise « … status of 404 (Not Found) » sans l'adresse dans
 * le texte du message : le motif ne peut viser que le statut.
 */
export function tolerer(consoleGuard: ConsoleGuard) {
  consoleGuard.allow(/status of 404 \(Not Found\)/);
}

/**
 * Compte neuf (invitation du propriétaire, inscription par l'interface) :
 * les tests qui écrivent des préférences ou des éléments n'interfèrent pas
 * avec les comptes partagés de l'organisation.
 */
export async function nouveauCompte(page: Page, owner: APIRequestContext, prefixe: string): Promise<Compte> {
  const email = `${prefixe}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@e2e.test`;
  const res = await owner.post("/api/admin/invites", { data: { email, role: "user" } });
  expect(res.ok(), await res.text()).toBe(true);
  const { token } = await res.json();
  // Nom sans « Essai » ni « Locksy » : testPassword() les contient, et la
  // politique refuse un mot de passe maître qui reprend le nom.
  const compte = { email, password: testPassword(), name: "Camille Durand" };
  await registerInvite(page, token, { name: compte.name, password: compte.password });
  // Démarrage terminé (synchronisation, politique, préférences) : la vue du
  // coffre a son titre. Naviguer avant laisse la page de destination en
  // attente sur un poste chargé.
  await expect(page.locator("#contenu h1").first()).toBeVisible({ timeout: KDF_TIMEOUT });
  return compte;
}

/**
 * Connexion par l'interface, aussi sur téléphone : sous 900 px la navigation
 * principale est dans un tiroir fermé (invisible), seul « Menu » est affiché.
 */
export async function connecter(page: Page, compte: { email: string; password: string }) {
  await page.goto("/");
  await page.getByLabel("Adresse e-mail").fill(compte.email);
  await page.getByLabel("Mot de passe maître", { exact: true }).fill(compte.password);
  await page.getByRole("button", { name: "Se connecter", exact: true }).click();
  const arrivee = page.getByRole("navigation", { name: "Navigation principale" })
    .or(page.getByRole("button", { name: "Menu", exact: true }));
  await expect(arrivee.first()).toBeVisible({ timeout: KDF_TIMEOUT });
}

/** Aller à une route de l'application sans recharger la page (fragment seulement). */
export async function aller(page: Page, route: string) {
  await page.evaluate((r) => { location.hash = r; }, `#${route}`);
}

/** Après un rechargement : déverrouille avec le mot de passe maître, attend la coquille. */
export async function deverrouiller(page: Page, password: string) {
  const champ = page.getByLabel(/^Mot de passe maître$/);
  await expect(champ).toBeVisible({ timeout: KDF_TIMEOUT });
  await champ.fill(password);
  await page.getByRole("button", { name: /^(Déverrouiller|Se connecter)$/ }).click();
  await expectShell(page);
}

/** Entrées de politique remplacées dans GET /api/settings/policy (réponse réelle complétée). */
export async function politique(page: Page, entrees: Record<string, Record<string, unknown>>) {
  await page.route("**/api/settings/policy", async (route) => {
    const res = await route.fetch();
    const body = res.ok() ? await res.json() : { revision: 1, policy: {} };
    await route.fulfill({ json: { ...body, revision: (Number(body.revision) || 0) + 1000, policy: { ...body.policy, ...entrees } } });
  });
}

export interface ElementTest {
  name: string;
  username?: string;
  password?: string;
  urls?: string[];
}

/** Crée des éléments dans le coffre personnel par le module de la page, puis synchronise. */
export async function creerElements(page: Page, elements: ElementTest[]): Promise<string[]> {
  return page.evaluate(async (list) => {
    const V = await import("/js/vault.js");
    const personal = [...V.state.collections.values()].find((c: { personal?: boolean }) => c.personal);
    if (!personal) throw new Error("Coffre personnel introuvable.");
    const ids: string[] = [];
    for (const e of list) {
      const data = { ...V.emptyItem("login"), username: "", password: "", urls: [], ...e, password_changed_at: V.now() };
      ids.push(await V.createItem(personal.id, data));
    }
    await V.sync();
    return ids;
  }, elements);
}

/** Module WebAssembly compilé depuis les sources (e2e/.state/<clé>/locksy-courant.wasm), s'il existe. */
export function moduleCourant(): string | null {
  const file = join(stateDir(), "locksy-courant.wasm");
  return existsSync(file) ? file : null;
}

/**
 * Sert le module courant à la place de celui de l'image (antérieur à la
 * vague 2, sans l'opération share_proof). Renvoie faux s'il n'existe pas.
 */
export async function servirModuleCourant(page: Page): Promise<boolean> {
  const file = moduleCourant();
  if (!file) return false;
  await page.route("**/locksy.wasm", (route) => route.fulfill({ path: file, contentType: "application/wasm" }));
  return true;
}

/** Vrai si le module chargé par la page calcule la preuve de possession (op share_proof). */
export async function preuveDisponible(page: Page): Promise<boolean> {
  return page.evaluate(async () => {
    const W = await import("/js/wasm.js");
    await W.loadCrypto();
    try {
      return typeof W.call("share_proof", { key: "abc" }).proof === "string";
    } catch {
      return false;
    }
  });
}

/**
 * Déplace un curseur (input type=range) comme le ferait la souris : la valeur
 * est bornée par le navigateur, puis « input » et « change » sont émis.
 */
export async function glisser(curseur: import("@playwright/test").Locator, valeur: number) {
  await curseur.evaluate((el: HTMLInputElement, v: number) => {
    el.value = String(v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }, valeur);
}

/**
 * Message passager (notify) : le texte est aussi recopié dans la région
 * annoncée (#status ou #alert), d'où la recherche dans la notification seule.
 */
export function notification(page: Page, texte: string | RegExp) {
  return page.locator(".c-toast__text").filter({ hasText: texte });
}
