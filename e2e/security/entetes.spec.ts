// En-têtes de sécurité (G8) : EXACTEMENT ceux de main.rs (security_headers),
// lus dans la source à l'exécution, sur des pages, des fichiers statiques,
// l'API, un 404 et un 401. Cache : no-store pour l'API, no-cache pour
// l'interface. Pas de HSTS en HTTP sans proxy, aucun en-tête Server
// révélant une version, aucune réponse CORS à une origine étrangère.
// Cible principale : locksy-direct (production sans proxy de confiance).

import { test, expect, type APIResponse } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { BASE_URL, E2E_DIR } from "../fixtures/env.ts";
import { DIRECT_URL, SANS_SURCOUCHE } from "./outils.ts";

/** Tableau `headers` de security_headers() dans main.rs : nom → valeur. */
function entetesDeMainRs(): Record<string, string> {
  const src = readFileSync(resolve(E2E_DIR, "../crates/locksy-server/src/main.rs"), "utf8");
  const debut = src.indexOf("let headers: [");
  if (debut < 0) throw new Error("Tableau des en-têtes introuvable dans main.rs (security_headers).");
  const bloc = src.slice(debut, src.indexOf("];", debut));
  const out: Record<string, string> = {};
  for (const m of bloc.matchAll(/\(\s*"([a-z-]+)",\s*"((?:[^"\\]|\\[\s\S])*)"\s*,?\s*\)/g)) {
    // Chaîne Rust sur plusieurs lignes : « \ » en fin de ligne retire le saut et l'indentation.
    out[m[1]] = m[2].replace(/\\\r?\n[ \t]*/g, "");
  }
  return out;
}

const ATTENDUS = entetesDeMainRs();
const { "cache-control": CACHE_STATIQUE, ...SECURITE } = ATTENDUS;

const CIBLES: { nom: string; chemin: string; statut: number; cache: string }[] = [
  { nom: "page d'accueil", chemin: "/", statut: 200, cache: "no-cache" },
  { nom: "page des liens", chemin: "/share.html", statut: 200, cache: "no-cache" },
  { nom: "script", chemin: "/js/app.js", statut: 200, cache: "no-cache" },
  { nom: "module WebAssembly", chemin: "/locksy.wasm", statut: 200, cache: "no-cache" },
  { nom: "API publique", chemin: "/api/health", statut: 200, cache: "no-store" },
  { nom: "API sans session (401)", chemin: "/api/me", statut: 401, cache: "no-store" },
  { nom: "fichier absent (404)", chemin: "/introuvable-securite.html", statut: 404, cache: "no-cache" },
  { nom: "route d'API absente (404)", chemin: "/api/introuvable-securite", statut: 404, cache: "no-store" },
];

function verifieSecurite(res: APIResponse, nom: string) {
  const h = res.headers();
  for (const [k, v] of Object.entries(SECURITE)) expect(h[k], `${nom} : en-tête ${k}`).toBe(v);
  expect(h["server"] ?? "", `${nom} : en-tête Server`).not.toMatch(/\d/);
  expect(h["x-powered-by"], `${nom} : X-Powered-By`).toBeUndefined();
}

test.describe("En-têtes de sécurité", () => {
  test("la source déclare la politique attendue par le cahier", () => {
    expect(Object.keys(ATTENDUS)).toHaveLength(9);
    expect(SECURITE["content-security-policy"]).toBe(
      "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; " +
        "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    );
    expect(CACHE_STATIQUE).toBe("no-cache");
  });

  for (const c of CIBLES) {
    test(`en-têtes exacts : ${c.nom} (${c.chemin})`, async ({ request }) => {
      test.skip(!DIRECT_URL, SANS_SURCOUCHE);
      const res = await request.get(`${DIRECT_URL}${c.chemin}`, { maxRedirects: 0 });
      expect(res.status(), c.chemin).toBe(c.statut);
      verifieSecurite(res, c.nom);
      expect(res.headers()["strict-transport-security"], `${c.nom} : pas de HSTS en HTTP sans proxy`).toBeUndefined();
      const cache = res.headers()["cache-control"];
      if (c.cache) expect(cache, `${c.nom} : cache`).toBe(c.cache);
      else test.info().annotations.push({ type: "cache", description: `${c.chemin} : cache-control « ${cache} »` });
    });
  }

  test("aucune réponse CORS à une origine étrangère", async ({ request }) => {
    test.skip(!DIRECT_URL, SANS_SURCOUCHE);
    const origine = { Origin: "https://evil.test" };
    const simple = await request.get(`${DIRECT_URL}/api/health`, { headers: origine });
    const preflight = await request.fetch(`${DIRECT_URL}/api/auth/login`, {
      method: "OPTIONS",
      headers: { ...origine, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type, authorization" },
    });
    for (const res of [simple, preflight]) {
      const cors = Object.keys(res.headers()).filter((k) => k.startsWith("access-control-"));
      expect(cors, `${res.url()} (${res.status()})`).toEqual([]);
    }
    expect(preflight.status()).toBeGreaterThanOrEqual(400);
    expect(preflight.status()).toBeLessThan(500);
  });

  test("les compteurs de test n'existent pas en production", async ({ request }) => {
    test.skip(!DIRECT_URL, SANS_SURCOUCHE);
    const res = await request.get(`${DIRECT_URL}/api/test/counters`);
    expect(res.status()).toBe(404);
    expect(await res.json()).toMatchObject({ error: "not_found" });
    // Témoin : le serveur de test (LOCKSY_ENV=test) les expose.
    expect((await request.get(`${BASE_URL}/api/test/counters`)).status()).toBe(200);
  });

  test("derrière un proxy TLS déclaré, HSTS est posé (deux ans, sans sous-domaines)", async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/health`);
    expect(res.headers()["strict-transport-security"]).toBe("max-age=63072000");
    verifieSecurite(res, "serveur derrière proxy");
  });
});
