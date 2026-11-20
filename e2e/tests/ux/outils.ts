// Outils des suites transverses « ux » (lot Q3b) : libellés lus dans le
// catalogue généré, navigation sans rechargement, pannes simulées,
// réauthentification, compte neuf, éléments et coffres créés par le module
// de la page. Ce fichier n'importe aucun utilitaire d'un autre lot de la
// vague 3 (règle V0.1) ; il ne sert qu'aux suites de tests/ux et
// tests/confidentialite.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import type { APIRequestContext, Locator, Page, Route } from "@playwright/test";
import { expect } from "../../fixtures/index.ts";
import { E2E_DIR } from "../../fixtures/env.ts";
import { KDF_TIMEOUT, expectShell, registerInvite, testPassword } from "../../fixtures/ui.ts";

// ------------------------------------------------------------------ Libellés

type Entree = string | { one?: string; other: string };
let catalogue: Record<string, Entree> | null = null;

/** Catalogue français généré (design/i18n/fr.gen.json), lu une fois. */
export function catalogueFr(): Record<string, Entree> {
  catalogue ??= JSON.parse(readFileSync(resolve(E2E_DIR, "../design/i18n/fr.gen.json"), "utf8"));
  return catalogue!;
}

/**
 * Texte d'une clé du catalogue, paramètres remplacés ; pluriel : `one` si
 * n = 1, sinon `other`. Une clé absente fait échouer le test (jamais de
 * libellé recopié à la main).
 */
export function libelle(cle: string, params: Record<string, string | number> = {}): string {
  const v = catalogueFr()[cle];
  if (v === undefined) throw new Error(`Clé absente du catalogue : ${cle}`);
  const brut = typeof v === "string" ? v : Number(params.n) === 1 && v.one !== undefined ? v.one : v.other;
  return brut.replace(/\{([a-z0-9_]+)\}/g, (m, p) => (p in params ? String(params[p]) : m));
}

const echapper = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Expression exacte d'un libellé (espaces souples : U+202F, U+00A0). */
export function exact(cle: string, params?: Record<string, string | number>): RegExp {
  return new RegExp(`^${echapper(libelle(cle, params)).replace(/ /g, "\\s")}$`);
}

/** Expression « commence par » d'un libellé (texte suivi d'autre chose). */
export function debut(cle: string, params?: Record<string, string | number>): RegExp {
  return new RegExp(`^${echapper(libelle(cle, params)).replace(/ /g, "\\s")}`);
}

// ------------------------------------------------------------------ Navigation

/** Va à une route de l'application sans recharger la page (le coffre reste ouvert). */
export async function goHash(page: Page, hash: string) {
  // Changer d'adresse pendant le tout premier rendu laisse parfois la zone de
  // contenu sur le squelette du routeur : on attend d'abord un titre.
  await expect(page.locator("#contenu h1, main h1").first()).toBeAttached({ timeout: KDF_TIMEOUT });
  await page.evaluate((h) => { location.hash = h; }, hash.startsWith("#") ? hash : `#${hash}`);
}

/** Titre de niveau 1 de l'écran courant. */
export const titre = (page: Page, nom: string | RegExp) => page.getByRole("heading", { level: 1, name: nom });

/** Message passager (toast) contenant le texte. */
export const toast = (page: Page, texte: string | RegExp): Locator => page.locator(".c-toast").filter({ hasText: texte });

/** Fenêtre ouverte (dialog natif) par son nom accessible. */
export const fenetre = (page: Page, nom: string | RegExp) => page.getByRole("dialog", { name: nom });

// ------------------------------------------------------------------ Pannes

export type Panne = 500 | "reseau";

/** Corps d'erreur générique du serveur (annexe A). */
export const ERREUR_500 = { error: "internal", message: "Erreur interne du serveur." };

/** Textes d'erreur attendus après une panne (repli d'api.js et catalogue). */
export const MESSAGE_PANNE: Record<Panne, RegExp> = {
  500: /Le serveur a rencontré un problème|Erreur interne|Réessayez/,
  reseau: /Serveur injoignable|connexion|Réessayez/,
};

/**
 * Force l'échec des requêtes `methode /api<chemin>` : `chemin` est une
 * expression sur le chemin SANS le préfixe /api (« ^/items/[^/]+$ »).
 * Renvoie la liste des requêtes interceptées et une fonction de levée.
 */
export async function panne(page: Page, methode: string, chemin: RegExp, comment: Panne) {
  const vues: string[] = [];
  const motif = (url: URL) => url.pathname.startsWith("/api/") && chemin.test(url.pathname.slice(4));
  const gestion = (route: Route) => {
    if (route.request().method() !== methode) return route.fallback();
    vues.push(`${methode} ${new URL(route.request().url()).pathname}`);
    if (comment === "reseau") return route.abort("failed");
    return route.fulfill({ status: 500, json: ERREUR_500 });
  };
  await page.route(motif, gestion);
  return {
    vues,
    lever: () => page.unroute(motif, gestion),
  };
}

/** Garde de console du harnais (fixture `consoleGuard`). */
interface ConsoleGuard {
  allow(re: RegExp): void;
}

/**
 * Erreurs de console attendues : pannes voulues (500, requête coupée) et
 * 404 de GET /api/me/prefs tant qu'aucun document de préférences n'existe.
 */
export function tolererPannes(consoleGuard: ConsoleGuard) {
  consoleGuard.allow(/status of (?:404|409|500)|Failed to load resource|NetworkError|ERR_FAILED|net::ERR/);
}

// ------------------------------------------------------------------ Réauthentification (C4.1)

/**
 * Jeton de réauthentification (rt1) obtenu par la page connectée, avec les
 * mêmes modules que l'application (même URL, même instance).
 */
export async function reauthToken(page: Page, password: string, action: string): Promise<string> {
  return page.evaluate(async ({ pwd, act }) => {
    const V = await import("/js/vault.js");
    const A = await import("/js/api.js");
    return A.exchangeReauth(act, await V.authProof(pwd));
  }, { pwd: password, act: action });
}

/**
 * Remet des clés au défaut DEPUIS la page connectée (If-Match et jeton
 * « settings ») : le jeton de réauthentification est lié à la session qui
 * l'a demandé. Un conflit de révision est rejoué. Renvoie « ok » ou la raison.
 */
export async function retablirReglages(page: Page, cles: string[], password: string, code?: () => Promise<string>): Promise<string> {
  const totpCode = code ? await code() : undefined;
  return page.evaluate(async ({ keys, pwd, otp }) => {
    const V = await import("/js/vault.js");
    const A = await import("/js/api.js");
    const reauth = await A.exchangeReauth("settings", await V.authProof(pwd), otp);
    let dernier = "";
    for (let essai = 0; essai < 3; essai++) {
      const cur = await A.apiFull("GET", "/admin/settings");
      try {
        await A.apiFull("POST", "/admin/settings/reset", { keys }, { ifMatch: cur.etag, reauth });
        return "ok";
      } catch (e) {
        const err = e as { status?: number; code?: string; message?: string };
        dernier = `${err.status} ${err.code} : ${err.message}`;
        if (err.status !== 409) break;
      }
    }
    return dernier;
  }, { keys: cles, pwd: password, otp: totpCode });
}

// ------------------------------------------------------------------ Comptes et données

export interface Compte {
  email: string;
  password: string;
  name: string;
  id?: string;
}

/** Suffixe aléatoire court (noms uniques sur le serveur partagé). */
export const alea = () => randomBytes(4).toString("hex");

/** Nom unique pour un test. */
export const unique = (base: string) => `${base} ${alea()}`;

/**
 * Compte neuf : invitation par l'API (`admin`, rôle donné), puis inscription
 * par l'interface dans `page`. Les tests qui écrivent n'abîment ainsi pas
 * les comptes partagés de l'organisation.
 */
export async function nouveauCompte(page: Page, admin: APIRequestContext, prefixe: string, role: "user" | "admin" = "user"): Promise<Compte> {
  const email = `${prefixe}-${Date.now()}-${alea()}@e2e.test`;
  const res = await admin.post("/api/admin/invites", { data: { email, role } });
  expect(res.ok(), await res.text()).toBe(true);
  const { token } = await res.json();
  // Nom sans « Essai » ni « Locksy » : testPassword() les contient, et la
  // politique refuse un mot de passe maître qui reprend le nom.
  const compte: Compte = { email, password: testPassword(), name: `Camille Durand ${alea().slice(0, 4)}` };
  await registerInvite(page, token, { name: compte.name, password: compte.password });
  await expect(page.locator("#contenu h1").first()).toBeVisible({ timeout: KDF_TIMEOUT });
  const users = await (await admin.get("/api/admin/users")).json();
  compte.id = users.find((u: { email: string }) => u.email === email)?.id;
  return compte;
}

/** Jeton d'invitation neuf (adresse unique), sans inscription. */
export async function invitation(admin: APIRequestContext, prefixe: string, role = "user"): Promise<{ email: string; token: string }> {
  const email = `${prefixe}-${Date.now()}-${alea()}@e2e.test`;
  const res = await admin.post("/api/admin/invites", { data: { email, role } });
  expect(res.ok(), await res.text()).toBe(true);
  return { email, token: (await res.json()).token };
}

/** Connexion par l'interface (adresse et mot de passe maître). */
export async function connexion(page: Page, a: { email: string; password: string }) {
  await page.goto("/");
  await page.getByLabel("Adresse e-mail").fill(a.email);
  await page.getByLabel("Mot de passe maître", { exact: true }).fill(a.password);
  await page.getByRole("button", { name: "Se connecter", exact: true }).click();
  await expectShell(page);
}

/** Données d'un élément (forme de vault.emptyItem). */
export type Donnees = Record<string, unknown> & { name: string };

/** Crée un élément par vault.js (coffre personnel par défaut), synchronise, renvoie son identifiant. */
export async function creerElement(page: Page, data: Donnees, collectionId?: string): Promise<string> {
  return page.evaluate(async ({ d, cid }) => {
    const V = await import("/js/vault.js");
    if (!V.state.collections.size) await V.sync();
    const target = cid || [...V.state.collections.values()].find((c: { personal?: boolean }) => c.personal)?.id;
    if (!target) throw new Error("Coffre personnel introuvable.");
    const id = await V.createItem(target, { ...V.emptyItem(String(d.kind || "login")), ...d, password_changed_at: V.now() });
    await V.sync();
    return id;
  }, { d: data, cid: collectionId });
}

/** Crée un coffre partagé (membres `emails`, rôle editor) par vault.js ; renvoie son identifiant. */
export async function creerCoffre(page: Page, nom: string, emails: string[] = []): Promise<string> {
  return page.evaluate(async ({ n, mails }) => {
    const V = await import("/js/vault.js");
    const { api } = await import("/js/api.js");
    const id = await V.createCollection(n);
    await V.sync();
    if (mails.length) {
      const dir = await api("GET", "/directory");
      for (const mail of mails) {
        const u = dir.find((x: { email: string }) => x.email === mail);
        if (!u) throw new Error(`Personne absente de l'annuaire : ${mail}`);
        await V.addMember(id, u, "editor");
      }
      await V.sync();
    }
    return id;
  }, { n: nom, mails: emails });
}

/** État d'un élément après une nouvelle synchronisation (null s'il n'existe plus). */
export async function etatElement(page: Page, itemId: string) {
  return page.evaluate(async (id) => {
    const V = await import("/js/vault.js");
    await V.sync();
    const it = V.state.items.get(id);
    if (!it) return null;
    const c = V.state.collections.get(it.collection_id);
    return {
      name: String(it.data?.name ?? ""),
      password: String(it.data?.password ?? ""),
      collectionId: String(it.collection_id),
      personal: !!c?.personal,
      deleted: !!it.deleted_at,
      attachments: Array.isArray(it.data?.attachments) ? it.data.attachments.length : 0,
    };
  }, itemId);
}

/** Coffres visibles (nom, membres) après une nouvelle synchronisation. */
export async function coffres(page: Page) {
  return page.evaluate(async () => {
    const V = await import("/js/vault.js");
    await V.sync();
    return [...V.state.collections.values()].map((c: { id: string; name: unknown; personal?: boolean; members?: unknown[] }) => ({
      id: c.id, name: String(c.name), personal: !!c.personal, members: Array.isArray(c.members) ? c.members.length : 0,
    }));
  });
}

/**
 * Presse-papiers de test : le réseau d'essai sert Locksy en HTTP sur un nom
 * d'hôte (contexte non sécurisé), où navigator.clipboard n'existe pas ; on le
 * remplace, avant le chargement, par un presse-papiers en mémoire.
 */
export async function pressePapiers(page: Page) {
  await page.addInitScript(() => {
    if (window.isSecureContext && navigator.clipboard) return;
    let contenu = "";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async (v: string) => { contenu = String(v); },
        readText: async () => contenu,
      },
    });
  });
}

export { KDF_TIMEOUT, testPassword };
