// Anti-énumération (G11). Un compte inconnu et un compte existant doivent
// être indiscernables : même forme de réponse, même code, même message,
// même temps. Temps : essais ENTRELACÉS (l'ordre alterne d'un essai à
// l'autre), essais de chauffe écartés, 10 % extrêmes retirés (5 % de chaque
// côté), écart des médianes < 15 ms et test de Mann-Whitney non significatif
// (p > 0,01). Une adresse X-Forwarded-For neuve par essai : aucun plafond par
// adresse ne fausse la mesure. Médianes et statistiques en annotations.

import { test, expect } from "../fixtures/index.ts";
import type { APIRequestContext, APIResponse } from "@playwright/test";
import { performance } from "node:perf_hooks";
import { PROFILES } from "../fixtures/env.ts";
import { adresse, b64, inconnu, json, mannWhitney, mediane, nouveauCompte, rogne, type Compte } from "./outils.ts";

const CHAUFFE = 20;
const ESSAIS = 200;
const ECART_MAX_MS = 15;
const P_MIN = 0.01;
/** Comptes réels pour les mesures : au plus 44 échecs chacun, sous le blocage par adresse e-mail (50). */
const COMPTES = 5;

test.describe.configure({ mode: "serial" });

let comptes: Compte[] = [];

test.afterAll(async () => {
  for (const c of comptes) await c.context.close();
});

/** Durée d'une requête, en millisecondes. */
async function chrono(f: () => Promise<APIResponse>): Promise<[number, APIResponse]> {
  const debut = performance.now();
  const res = await f();
  await res.body();
  return [performance.now() - debut, res];
}

/**
 * Mesure entrelacée de deux cas (`n` essais de chaque après `chauffe`
 * essais de chaque non comptés) ; vérifie et annote le verdict.
 */
async function compare(nom: string, n: number, chauffe: number, a: (i: number) => Promise<APIResponse>, b: (i: number) => Promise<APIResponse>) {
  const ta: number[] = [];
  const tb: number[] = [];
  for (let i = 0; i < n + chauffe; i++) {
    // L'ordre alterne : une dérive de charge touche les deux cas pareillement.
    const paire = i % 2 ? [[a, ta], [b, tb]] as const : [[b, tb], [a, ta]] as const;
    for (const [f, t] of paire) {
      const [ms, res] = await chrono(() => f(i));
      expect(res.status(), `${nom}, essai ${i} : ${await res.text()}`).not.toBe(429);
      if (i >= chauffe) t.push(ms);
    }
  }
  const [ra, rb] = [rogne(ta), rogne(tb)];
  const [ma, mb] = [mediane(ra), mediane(rb)];
  const { u, p } = mannWhitney(ra, rb);
  const verdict = `${nom} : médianes ${ma.toFixed(1)} ms (compte inconnu) et ${mb.toFixed(1)} ms (compte réel), écart ${Math.abs(ma - mb).toFixed(1)} ms ; Mann-Whitney U = ${u}, p = ${p.toFixed(3)} (n = ${ra.length} + ${rb.length})`;
  test.info().annotations.push({ type: "temps", description: verdict });
  console.log(verdict);
  expect(Math.abs(ma - mb), verdict).toBeLessThan(ECART_MAX_MS);
  expect(p, verdict).toBeGreaterThan(P_MIN);
}

/** Statut, code et message d'une réponse. */
async function forme(res: APIResponse) {
  const c = await json(res);
  return { statut: res.status(), code: c?.error, message: c?.message };
}

const post = (api: APIRequestContext, url: string, data: unknown) => api.post(url, { data, headers: { "X-Forwarded-For": adresse() } });

test("pré-connexion : un e-mail inconnu reçoit des paramètres de même forme, stables et propres à l'adresse", async ({ request, org }) => {
  const kdf = async (email: string) => {
    const res = await post(request, "/api/auth/prelogin", { email });
    expect(res.status()).toBe(200);
    return ((await res.json()) as { kdf: Record<string, unknown> }).kdf;
  };
  const reels = await Promise.all((["owner", "admin", "user"] as const).map((r) => kdf(org.accounts[r].email)));
  const x = inconnu("prelogin");
  const [faux, encore, autre] = [await kdf(x), await kdf(x), await kdf(inconnu("prelogin"))];
  const sel = (k: Record<string, unknown>) => Buffer.from(String(k.salt), "base64url").length;
  for (const r of reels) {
    expect(Object.keys(faux).sort(), "mêmes champs").toEqual(Object.keys(r).sort());
    // fake_kdf aligné sur la politique : mêmes paramètres qu'un compte créé avec les réglages actuels.
    expect({ alg: faux.alg, m_kib: faux.m_kib, t: faux.t, p: faux.p }).toEqual({ alg: r.alg, m_kib: r.m_kib, t: r.t, p: r.p });
    expect(sel(faux), "longueur du sel").toBe(sel(r));
  }
  expect(encore, "stable d'un appel à l'autre").toEqual(faux);
  expect(autre.salt, "différent d'une adresse à l'autre").not.toBe(faux.salt);
});

test("connexion : compte inconnu et mauvais mot de passe sont indiscernables", async ({ request, org, browser, apiAs }) => {
  test.setTimeout(600_000);
  const vrai = await forme(await post(request, "/api/auth/login", { email: org.accounts.user.email, auth_key: b64(32) }));
  const faux = await forme(await post(request, "/api/auth/login", { email: inconnu("login"), auth_key: b64(32) }));
  expect(faux).toEqual(vrai);
  expect(vrai).toMatchObject({ statut: 401, code: "invalid_credentials" });

  // Comptes réels propres à la mesure (les échecs ne touchent pas l'organisation).
  const admin = await apiAs("admin");
  for (let i = comptes.length; i < COMPTES; i++) comptes.push(await nouveauCompte(browser, admin, "mesure"));
  await compare(
    "POST /api/auth/login",
    ESSAIS,
    CHAUFFE,
    () => post(request, "/api/auth/login", { email: inconnu("login"), auth_key: b64(32) }),
    (i) => post(request, "/api/auth/login", { email: comptes[i % COMPTES].email, auth_key: b64(32) }),
  );
});

test("récupération : compte inconnu et mauvaise clé sont indiscernables (ADAPTATION : 20 essais)", async ({ request }) => {
  test.skip(comptes.length < COMPTES, "les comptes de mesure sont créés par le test de connexion");
  const vrai = await forme(await post(request, "/api/auth/recover/start", { email: comptes[0].email, recovery_auth: b64(32) }));
  const faux = await forme(await post(request, "/api/auth/recover/start", { email: inconnu("recup"), recovery_auth: b64(32) }));
  expect(faux).toEqual(vrai);
  expect(vrai).toMatchObject({ statut: 401, code: "unauthorized" });
  // (ADAPTATION) 5 essais par compte au plus avant blocage (recover:<e-mail>),
  // dont un consommé ci-dessus : 4 × 5 comptes = 20 mesures, sans chauffe.
  await compare(
    "POST /api/auth/recover/start",
    4 * COMPTES,
    0,
    () => post(request, "/api/auth/recover/start", { email: inconnu("recup"), recovery_auth: b64(32) }),
    (i) => post(request, "/api/auth/recover/start", { email: comptes[i % COMPTES].email, recovery_auth: b64(32) }),
  );
});

test("invitation : un jeton inconnu et un jeton déjà utilisé sont indiscernables", async ({ request }) => {
  test.skip(comptes.length < COMPTES, "les invitations utilisées viennent des comptes de mesure");
  const lire = (jeton: string) => request.get(`/api/invites/${encodeURIComponent(jeton)}`, { headers: { "X-Forwarded-For": adresse() } });
  const vrai = await forme(await lire(comptes[0].invitation));
  const faux = await forme(await lire(b64(32)));
  expect(faux).toEqual(vrai);
  expect(vrai).toMatchObject({ statut: 404, code: "not_found" });
  await compare(
    "GET /api/invites/:jeton",
    ESSAIS,
    CHAUFFE,
    () => lire(b64(32)),
    (i) => lire(comptes[i % COMPTES].invitation),
  );
});

test("connexion Active Directory : compte inconnu et mauvais mot de passe sont indiscernables", async () => {
  test.skip(!PROFILES.has("ldap"), "Profil ldap non démarré (run.sh --profile ldap) : connexion Active Directory non testée ici.");
});
