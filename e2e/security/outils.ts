// Utilitaires propres aux tests de sécurité (lot Q4) : serveurs de la
// surcouche, adresses X-Forwarded-For, comptes dédiés créés par l'interface,
// corps de requêtes forgés et statistiques des mesures de temps.

import { expect, request, type APIRequestContext, type APIResponse, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { randomBytes, randomUUID } from "node:crypto";
import { BASE_URL } from "../fixtures/env.ts";
import { loginUi, registerInvite, sessionToken, testPassword } from "../fixtures/ui.ts";

/** Production sans proxy de confiance (X-Forwarded-For ignoré, plafond de connexions à 5). */
export const DIRECT_URL = (process.env.SECURITY_DIRECT_URL || "").replace(/\/+$/, "");
/** Serveur neuf réservé à installation.spec.ts. */
export const VIERGE_URL = (process.env.SECURITY_VIERGE_URL || "").replace(/\/+$/, "");
/** Jetons d'installation imposés par docker-compose.securite.yml. */
export const DIRECT_SETUP_TOKEN = "e2e-jeton-installation-direct-0123456789";
export const VIERGE_SETUP_TOKEN = "e2e-jeton-installation-vierge-0123456789";
/** Raison des tests sautés hors de e2e/security/run.sh. */
export const SANS_SURCOUCHE = "Services de docker-compose.securite.yml absents : lancer par bash e2e/security/run.sh -p <cle>.";

// ------------------------------------------------------------ Adresses

let compteur = 0;

/**
 * Adresse X-Forwarded-For neuve : 10.(201 + worker).x.y. Les fixtures communes
 * prennent 10.1 à 10.200 et l'amorçage 10.250 : aucune collision de compteur.
 */
export function adresse(): string {
  compteur++;
  const w = 201 + ((Number(process.env.TEST_WORKER_INDEX) || 0) % 48);
  return `10.${w}.${(compteur >> 8) & 255}.${compteur & 255}`;
}

// ------------------------------------------------------------ Corps forgés

/** Octets aléatoires en base64 URL sans remplissage (alphabet du noyau). */
export const b64 = (octets: number) => randomBytes(octets).toString("base64url");
/** Chiffré bien formé (« v1. », nonce + étiquette au moins) : le serveur n'en vérifie que la forme. */
export const chiffre = (octets = 60) => `v1.${b64(octets)}`;
/** Clé scellée bien formée (« s1. »). */
export const scellee = () => `s1.${b64(80)}`;

/** Corps d'inscription complet et bien formé (clés aléatoires) : passe toutes les validations de forme. */
export function corpsInscription(email: string, extra: Record<string, unknown> = {}) {
  return {
    user_id: randomUUID(),
    email,
    name: "Essai de sécurité",
    auth_key: b64(32),
    recovery_auth: b64(32),
    public_key: b64(32),
    kdf: { alg: "argon2id", m_kib: 65_536, t: 3, p: 1, salt: b64(16) },
    wrapped_user_key: chiffre(),
    recovery_wrapped_user_key: chiffre(),
    wrapped_private_key: chiffre(),
    personal_collection: { id: randomUUID(), enc_name: chiffre(), sealed_key: scellee() },
    ...extra,
  };
}

/** Adresse e-mail inconnue du serveur. */
export const inconnu = (prefixe = "inconnu") => `${prefixe}-${randomBytes(6).toString("hex")}@e2e.test`;

// ------------------------------------------------------------ Réponses

/** Corps JSON d'une réponse (null s'il n'est pas du JSON). */
export async function json(res: APIResponse): Promise<Record<string, unknown> | null> {
  try {
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Vérifie un refus de l'API : statut, code stable et message en français. */
export async function refus(res: APIResponse, statut: number, code: string) {
  const corps = await json(res);
  expect(res.status(), `${res.url()} : ${JSON.stringify(corps)}`).toBe(statut);
  expect(corps?.error, `code d'erreur de ${res.url()}`).toBe(code);
  expect(typeof corps?.message === "string" && (corps.message as string).length > 0, "message absent").toBe(true);
  return corps as { error: string; message: string; retry_after?: number };
}

/** Vérifie un 429 complet : code, Retry-After et retry_after numériques et égaux, message français. */
export async function bloque(res: APIResponse) {
  const corps = await refus(res, 429, "rate_limited");
  const entete = res.headers()["retry-after"];
  expect(entete, "en-tête Retry-After absent").toMatch(/^\d+$/);
  expect(corps.retry_after, "champ retry_after").toBe(Number(entete));
  expect(Number(entete)).toBeGreaterThan(0);
  expect(corps.message).toMatch(/^Trop de tentatives\. Réessayez dans \d+ secondes\.$/);
}

// ------------------------------------------------------------ Comptes dédiés

export interface Compte {
  email: string;
  password: string;
  id: string;
  /** Jeton de session de la page d'inscription. */
  token: string;
  /** Jeton d'invitation, consommé par l'inscription. */
  invitation: string;
  page: Page;
  context: BrowserContext;
}

/**
 * Compte « user » créé pour le test : invitation par un administrateur, puis
 * inscription par l'interface (dérivation de la clé dans la page). Un test qui
 * modifie un compte (mot de passe, désactivation) n'utilise jamais ceux de
 * l'organisation partagée.
 */
export async function nouveauCompte(browser: Browser, admin: APIRequestContext, prefixe = "securite"): Promise<Compte> {
  const email = inconnu(prefixe);
  const res = await admin.post("/api/admin/invites", { data: { email, role: "user" } });
  expect(res.ok(), `invitation de ${email} : ${res.status()} ${await res.text()}`).toBe(true);
  const { token: invitation } = (await res.json()) as { token: string };
  const context = await browser.newContext({
    baseURL: BASE_URL,
    locale: "fr-FR",
    timezoneId: "Europe/Paris",
    extraHTTPHeaders: { "X-Forwarded-For": adresse() },
  });
  const page = await context.newPage();
  const password = testPassword();
  await registerInvite(page, invitation, { name: "Compte de sécurité", password });
  const token = await sessionToken(page);
  const me = await page.request.get("/api/me", { headers: { Authorization: `Bearer ${token}` } });
  expect(me.status()).toBe(200);
  const { id } = (await me.json()) as { id: string };
  return { email, password, id, token, invitation, page, context };
}

/**
 * API d'un compte de l'organisation (souvent l'administrateur), connecté par
 * l'interface : utilisable dans un beforeAll, où apiAs n'existe pas.
 */
export async function connecte(browser: Browser, compte: { email: string; password: string }) {
  const ctx = await browser.newContext({ baseURL: BASE_URL, locale: "fr-FR", timezoneId: "Europe/Paris", extraHTTPHeaders: { "X-Forwarded-For": adresse() } });
  const page = await ctx.newPage();
  await loginUi(page, compte);
  const api = await request.newContext({ baseURL: BASE_URL, extraHTTPHeaders: avec(await sessionToken(page)) });
  return {
    api,
    fermer: async () => {
      await api.dispose();
      await ctx.close();
    },
  };
}

/** En-têtes d'une requête authentifiée, depuis une adresse neuve. */
export const avec = (token?: string, xff = adresse()): Record<string, string> => ({
  "X-Forwarded-For": xff,
  ...(token ? { Authorization: `Bearer ${token}` } : {}),
});

// ------------------------------------------------------------ Statistiques

export const mediane = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

/** Retire les 10 % extrêmes (5 % de chaque côté). */
export function rogne(xs: number[]): number[] {
  const s = [...xs].sort((a, b) => a - b);
  const k = Math.floor(s.length * 0.05);
  return s.slice(k, s.length - k);
}

/** Fonction de répartition de la loi normale centrée réduite (Abramowitz et Stegun 7.1.26). */
function phi(z: number): number {
  const x = Math.abs(z) / Math.SQRT2;
  const t = 1 / (1 + 0.3275911 * x);
  const erf = 1 - ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x);
  return z >= 0 ? (1 + erf) / 2 : (1 - erf) / 2;
}

/**
 * Test de Mann-Whitney bilatéral, approximation normale avec correction des
 * ex aequo et de continuité. Renvoie U (de l'échantillon a) et p.
 */
export function mannWhitney(a: number[], b: number[]): { u: number; z: number; p: number } {
  const tous = [...a.map((v) => ({ v, g: 0 })), ...b.map((v) => ({ v, g: 1 }))].sort((x, y) => x.v - y.v);
  const rangs = new Array<number>(tous.length);
  let liens = 0;
  for (let i = 0; i < tous.length; ) {
    let j = i;
    while (j + 1 < tous.length && tous[j + 1].v === tous[i].v) j++;
    const r = (i + j) / 2 + 1;
    for (let k = i; k <= j; k++) rangs[k] = r;
    const t = j - i + 1;
    liens += t ** 3 - t;
    i = j + 1;
  }
  const n1 = a.length;
  const n2 = b.length;
  const r1 = tous.reduce((s, x, i) => (x.g === 0 ? s + rangs[i] : s), 0);
  const u = r1 - (n1 * (n1 + 1)) / 2;
  const mu = (n1 * n2) / 2;
  const n = n1 + n2;
  const sigma = Math.sqrt(((n1 * n2) / 12) * (n + 1 - liens / (n * (n - 1))));
  const z = sigma === 0 ? 0 : (Math.abs(u - mu) - 0.5) / sigma;
  return { u, z, p: Math.min(1, 2 * (1 - phi(Math.max(0, z)))) };
}
