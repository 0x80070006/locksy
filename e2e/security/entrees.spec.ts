// Entrées hostiles : JSON invalide, corps trop gros, chiffrés et identifiants
// mal formés, Unicode extrême, requête lente (slowloris). Attendu : un refus
// propre (400, 404, 413, 415 ou 422), jamais de 500, jamais de connexion
// retenue au-delà du délai de lecture des en-têtes.
//
// Les rejets des corps JSON (corps illisible, mauvais Content-Type, type de
// donnée) passent par l'extracteur de l'API (error.rs, handoff Q4-H2 corrigé) :
// statut dans {400, 413, 415, 422}, jamais 500, et toujours {error,message}.

import { test, expect } from "../fixtures/index.ts";
import type { APIResponse } from "@playwright/test";
import { randomUUID } from "node:crypto";
import net from "node:net";
import { adresse, avec, b64, DIRECT_URL, json, refus, SANS_SURCOUCHE } from "./outils.ts";

const MIO = 1024 * 1024;
const REFUS_PROPRES = [400, 413, 415, 422];

/** Corps brut, envoyé octet pour octet (une chaîne serait réencodée en JSON). */
const brut = (texte: string) => Buffer.from(texte, "utf8");

/** Refus propre : statut attendu, jamais 500, corps {error,message} en français. */
async function refusPropre(res: APIResponse, cas: string) {
  expect(res.status(), `${cas} : ${(await res.text()).slice(0, 200)}`).toBeLessThan(500);
  expect(REFUS_PROPRES, `${cas} : statut ${res.status()}`).toContain(res.status());
  const corps = await json(res);
  expect(typeof corps?.error, `${cas} : corps {error,message} attendu, reçu « ${(await res.text()).slice(0, 120)} »`).toBe("string");
  expect(String(corps?.message || ""), `${cas} : message en français`).not.toMatch(/Failed to|deserialize|Expected request/);
}

test.describe("Corps de requête", () => {
  test("JSON invalide, mauvais type de contenu ou champs manquants : refus propre", async ({ request, apiAs }) => {
    const user = await apiAs("user");
    const routes: [string, "public" | "session"][] = [
      ["/api/auth/prelogin", "public"],
      ["/api/auth/login", "public"],
      ["/api/auth/register", "public"],
      ["/api/auth/recover/start", "public"],
      ["/api/sso/redeem", "public"],
      ["/api/items", "session"],
      ["/api/collections", "session"],
      ["/api/shares", "session"],
    ];
    const corps: [string, string, string][] = [
      ["JSON tronqué", "application/json", '{"email": "a@b.fr"'],
      ["pas du JSON", "application/json", "pas du json"],
      ["mauvais type de contenu", "text/plain", '{"email":"a@b.fr"}'],
      ["types inattendus", "application/json", '{"email": 12, "id": [], "data": {"x": 1}}'],
      ["objet vide", "application/json", "{}"],
      ["tableau", "application/json", "[1, 2, 3]"],
      ["profondeur extrême", "application/json", `${"[".repeat(5000)}${"]".repeat(5000)}`],
    ];
    for (const [route, acces] of routes) {
      const api = acces === "public" ? request : user;
      for (const [cas, type, data] of corps) {
        const res = await api.post(route, { data: brut(data), headers: { "Content-Type": type, "X-Forwarded-For": adresse() } });
        await refusPropre(res, `${route}, ${cas}`);
      }
    }
  });

  test("corps de plus de 16 Mio sur l'API : 413", async ({ request, apiAs }) => {
    const gros = JSON.stringify({ email: "x".repeat(16 * MIO + 1024) });
    const pub = await request.post("/api/auth/prelogin", { data: brut(gros), headers: { "Content-Type": "application/json", "X-Forwarded-For": adresse() } });
    expect(pub.status()).toBe(413);
    const user = await apiAs("user");
    const item = await user.post("/api/items", { data: brut(JSON.stringify({ id: randomUUID(), collection_id: randomUUID(), data: `v1.${"A".repeat(16 * MIO + 1024)}` })), headers: { "Content-Type": "application/json" } });
    expect(item.status()).toBe(413);
    // Pièces jointes : limite propre (environ 21 Mo), au-delà, 413 aussi. Le
    // serveur répond dès l'en-tête Content-Length, sans lire le corps : le
    // client peut alors voir la connexion fermée pendant l'envoi (EPIPE), un
    // refus tout aussi propre (jamais de 500, rien d'écrit).
    try {
      const pj = await user.put(`/api/items/${randomUUID()}/attachments/${randomUUID()}`, {
        data: brut(JSON.stringify({ data: `v1.${"A".repeat(22 * MIO)}` })),
        headers: { "Content-Type": "application/json" },
      });
      expect(pj.status()).toBe(413);
    } catch (e) {
      expect(String(e), "seule une fermeture de connexion pendant l'envoi est admise").toMatch(/EPIPE|ECONNRESET|socket hang up/);
      test.info().annotations.push({ type: "refus", description: "pièce jointe de 22 Mo : connexion fermée par le serveur pendant l'envoi (refus avant lecture du corps)" });
    }
  });

  test("corps de plus de 1 Mio sur /scim/v2 : 413", async ({ request, apiAs }) => {
    const owner = await apiAs("owner");
    const cree = await owner.post("/api/admin/scim/token");
    expect(cree.status(), await cree.text()).toBe(200);
    const { token } = (await cree.json()) as { token: string };
    const scim = (data: string) =>
      request.post("/scim/v2/Users", { data: brut(data), headers: { ...avec(token), "Content-Type": "application/scim+json" } });
    const utilisateur = (nom: string) => JSON.stringify({ schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: nom });
    expect((await scim(utilisateur(`${"x".repeat(MIO + 1024)}@e2e.test`))).status()).toBe(413);
    // Témoin : sous la limite, la requête est jugée sur son contenu (jamais 413 ni 500).
    const petit = await scim(utilisateur(`${"y".repeat(512 * 1024)}@e2e.test`));
    expect(petit.status()).not.toBe(413);
    expect(petit.status()).toBeLessThan(500);
  });
});

test.describe("Données mal formées", () => {
  test("chiffrés mal formés (préfixe, alphabet, longueur) : 400", async ({ apiAs }) => {
    const user = await apiAs("user");
    const mauvais: [string, string][] = [
      ["préfixe inconnu", `v2.${b64(60)}`],
      ["sans préfixe", b64(60)],
      ["alphabet hors base64 URL", `v1.${b64(57)}+/=!`],
      ["trop court", `v1.${b64(8)}`],
      ["vide", ""],
      ["trop long", `v1.${"A".repeat(300_000)}`],
    ];
    for (const [cas, data] of mauvais) {
      await test.step(cas, async () => {
        await refus(await user.post("/api/items", { data: { id: randomUUID(), collection_id: randomUUID(), data } }), 400, "bad_request");
        await refus(await user.put(`/api/collections/${randomUUID()}`, { data: { enc_name: data } }), 400, "bad_request");
      });
    }
  });

  test("identifiants mal formés : 400 ou 404, jamais 500", async ({ apiAs }) => {
    const user = await apiAs("user");
    const ids = ["pas-un-uuid", "00000000-0000-0000-0000-00000000000Z", "' OR 1=1 --", "..%2F..%2Fetc%2Fpasswd", "%00", "A".repeat(4096), randomUUID().toUpperCase()];
    for (const id of ids) {
      const chemin = encodeURIComponent(id);
      for (const res of [
        await user.put(`/api/items/${chemin}`, { data: { collection_id: randomUUID(), data: `v1.${b64(60)}`, revision: 1 } }),
        await user.delete(`/api/items/${chemin}/purge`),
        await user.get(`/api/attachments/${chemin}`),
        await user.get(`/api/collections/${chemin}/members`),
        await user.delete(`/api/shares/${chemin}`),
        await user.get(`/api/admin/users/${chemin}`),
      ]) {
        expect([400, 403, 404], `${res.url()} : ${res.status()}`).toContain(res.status());
      }
      const corps = await user.post("/api/items", { data: { id, collection_id: randomUUID(), data: `v1.${b64(60)}` } });
      await refus(corps, 400, "bad_request");
    }
  });

  test("Unicode extrême dans un nom : accepté tel quel ou refusé proprement", async ({ apiAs, org }) => {
    const user = await apiAs("user");
    const noms: [string, string][] = [
      ["lettres mathématiques et emoji", "𝔏𝔬𝔠𝔨𝔰𝔶 🔐👩‍👩‍👧"],
      ["renversement droite-gauche", "‮gnp.exe"],
      ["diacritiques combinés", "é́́́́"],
      ["espace sans chasse", "​"],
      ["caractère nul", "a\u0000b"],
      ["101 caractères", "é".repeat(101)],
      ["100 caractères", "é".repeat(100)],
      ["moitié de paire de substitution", "\uD800"],
    ];
    try {
      for (const [cas, nom] of noms) {
        const res = await user.put("/api/me", { data: { name: nom } });
        expect([200, 400, 422], `${cas} : ${res.status()}`).toContain(res.status());
        // Nom fait seulement d'un caractère invisible : il s'afficherait vide (Q4-H7 corrigé).
        if (cas === "espace sans chasse") expect(res.status(), cas).toBe(400);
        if (res.status() === 200) {
          const me = (await (await user.get("/api/me")).json()) as { name: string };
          expect(me.name, cas).toBe(nom.trim());
        }
      }
    } finally {
      expect((await user.put("/api/me", { data: { name: org.accounts.user.name } })).status()).toBe(200);
    }
  });
});

test.describe("Requête lente", () => {
  test("slowloris : en-têtes à 1 octet par seconde, connexion coupée en moins de 3 s + 5 s", async ({ request }) => {
    test.skip(!DIRECT_URL, SANS_SURCOUCHE);
    const { hostname, port } = new URL(DIRECT_URL);
    const duree = await new Promise<number>((resolve, reject) => {
      const debut = Date.now();
      const s = net.connect(Number(port), hostname);
      let goutte: ReturnType<typeof setInterval> | undefined;
      const garde = setTimeout(() => {
        s.destroy();
        reject(new Error("connexion toujours ouverte après 20 s"));
      }, 20_000);
      s.on("connect", () => {
        s.write(`GET /api/health HTTP/1.1\r\nHost: ${hostname}\r\n`);
        const reste = `X-Lent: ${"a".repeat(60)}`;
        let i = 0;
        goutte = setInterval(() => {
          if (i < reste.length && !s.destroyed) s.write(reste[i++]);
        }, 1000);
      });
      s.on("error", () => undefined);
      s.on("close", () => {
        clearInterval(goutte);
        clearTimeout(garde);
        resolve(Date.now() - debut);
      });
    });
    test.info().annotations.push({ type: "slowloris", description: `connexion coupée après ${duree} ms (LOCKSY_HEADER_TIMEOUT_SECS=3)` });
    expect(duree).toBeLessThan(8_000);
    // Le serveur répond toujours normalement.
    expect((await request.get(`${DIRECT_URL}/api/health`)).status()).toBe(200);
  });
});
