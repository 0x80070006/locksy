// Sessions : un jeton absent, mal formé, trop long, déconnecté, révoqué ou
// celui d'un compte désactivé ne donne jamais accès, et jamais de 500. Le
// changement du mot de passe maître ferme les autres sessions.
// Compte dédié (jamais ceux de l'organisation partagée) : son mot de passe et
// son état changent ici.

import { test, expect } from "../fixtures/index.ts";
import type { APIRequestContext, Browser, BrowserContext } from "@playwright/test";
import { BASE_URL } from "../fixtures/env.ts";
import { loginUi, sessionToken, testPassword } from "../fixtures/ui.ts";
import { adresse, avec, b64, connecte, json, nouveauCompte, refus, type Compte } from "./outils.ts";

/** Session supplémentaire du compte, ouverte par l'interface dans un contexte neuf. */
async function connexion(browser: Browser, compte: { email: string; password: string }, contextes: BrowserContext[]) {
  const ctx = await browser.newContext({ baseURL: BASE_URL, locale: "fr-FR", timezoneId: "Europe/Paris", extraHTTPHeaders: { "X-Forwarded-For": adresse() } });
  contextes.push(ctx);
  const page = await ctx.newPage();
  await loginUi(page, compte);
  return { page, token: await sessionToken(page) };
}

/** Statut de /api/me pour un jeton (requête depuis une adresse neuve). */
const statut = async (api: APIRequestContext, token: string) => (await api.get("/api/me", { headers: avec(token) })).status();

test.describe("Jetons de session", () => {
  test("jeton absent, « Bearer null », inconnu ou trop long : 401 sans 500", async ({ request }) => {
    const essais: [string, Record<string, string>][] = [
      ["sans en-tête", {}],
      ["Bearer null", { Authorization: "Bearer null" }],
      ["Bearer vide", { Authorization: "Bearer " }],
      ["jeton inconnu", { Authorization: `Bearer ${b64(32)}` }],
      ["129 caractères", { Authorization: `Bearer ${"a".repeat(129)}` }],
      ["8 Kio", { Authorization: `Bearer ${"b".repeat(8192)}` }],
      ["autre schéma", { Authorization: `Basic ${Buffer.from("a:b").toString("base64")}` }],
    ];
    for (const route of ["/api/me", "/api/sync", "/api/admin/users", "/api/me/prefs"]) {
      for (const [cas, entetes] of essais) {
        const res = await request.get(route, { headers: { ...entetes, "X-Forwarded-For": adresse() } });
        expect(res.status(), `${route} (${cas}) : ${await res.text()}`).toBe(401);
        expect((await json(res))?.error, `${route} (${cas})`).toBe("unauthorized");
      }
    }
  });
});

test.describe("Fin de session", () => {
  test.describe.configure({ mode: "serial" });

  let compte: Compte;
  const contextes: BrowserContext[] = [];

  test.beforeAll(async ({ browser, org }) => {
    test.setTimeout(240_000);
    // Invitation par l'administrateur de l'organisation, connecté pour ce bloc.
    const admin = await connecte(browser, org.accounts.admin);
    try {
      compte = await nouveauCompte(browser, admin.api, "session");
    } finally {
      await admin.fermer();
    }
  });

  test.afterAll(async () => {
    await compte?.context.close();
    for (const c of contextes) await c.close();
  });

  test("le changement du mot de passe maître ferme les autres sessions", async ({ browser, request }) => {
    const deux = await connexion(browser, compte, contextes);
    const trois = await connexion(browser, compte, contextes);
    expect(await statut(request, deux.token)).toBe(200);
    const nouveau = testPassword();
    await compte.page.evaluate(
      async ([ancien, suivant]) => {
        await (await import("/js/vault.js")).changePassword(ancien, suivant);
      },
      [compte.password, nouveau],
    );
    compte.password = nouveau;
    expect(await statut(request, deux.token), "autre session après changement").toBe(401);
    expect(await statut(request, trois.token), "autre session après changement").toBe(401);
    expect(await statut(request, compte.token), "la session qui a changé le mot de passe reste ouverte").toBe(200);
  });

  test("après déconnexion, le jeton ne sert plus", async ({ request }) => {
    const res = await request.post("/api/auth/logout", { headers: avec(compte.token) });
    expect(res.status()).toBeLessThan(300);
    expect(await statut(request, compte.token)).toBe(401);
    await refus(await request.get("/api/sync", { headers: avec(compte.token) }), 401, "unauthorized");
  });

  test("une session révoquée par son titulaire, puis toutes par un administrateur", async ({ browser, request, apiAs }) => {
    const a = await connexion(browser, compte, contextes);
    const b = await connexion(browser, compte, contextes);
    const sessions = (await (await request.get("/api/me/sessions", { headers: avec(b.token) })).json()) as { id: string; current: boolean }[];
    const idB = sessions.find((s) => s.current)?.id;
    expect(idB, "session courante listée").toBeTruthy();
    expect((await request.delete(`/api/me/sessions/${idB}`, { headers: avec(a.token) })).status()).toBeLessThan(300);
    expect(await statut(request, b.token), "session révoquée par le titulaire").toBe(401);
    expect(await statut(request, a.token)).toBe(200);
    const admin = await apiAs("admin");
    expect((await admin.post(`/api/admin/users/${compte.id}/revoke-sessions`)).status()).toBeLessThan(300);
    expect(await statut(request, a.token), "sessions révoquées par l'administrateur").toBe(401);
  });

  test("compte désactivé : sessions fermées, jamais d'accès (ADAPTATION)", async ({ browser, request, apiAs }) => {
    const s = await connexion(browser, compte, contextes);
    const admin = await apiAs("admin");
    expect((await admin.put(`/api/admin/users/${compte.id}`, { data: { disabled: true } })).status()).toBeLessThan(300);
    // (ADAPTATION) La désactivation par l'administration ferme aussitôt les
    // sessions : 401. Le 403 account_disabled (vague 2, #50) ne concerne
    // qu'une session encore ouverte au moment où le compte se ferme (accès
    // échu, annuaire) ; il est couvert par les tests Rust du serveur.
    const premier = await request.get("/api/me", { headers: avec(s.token) });
    const corps = await json(premier);
    expect([`${premier.status()} ${corps?.error}`]).toEqual([expect.stringMatching(/^(401 unauthorized|403 account_disabled)$/)]);
    await refus(await request.get("/api/me", { headers: avec(s.token) }), 401, "unauthorized");
    // Réactivé, l'ancien jeton reste fermé.
    expect((await admin.put(`/api/admin/users/${compte.id}`, { data: { disabled: false } })).status()).toBeLessThan(300);
    expect(await statut(request, s.token)).toBe(401);
  });
});
