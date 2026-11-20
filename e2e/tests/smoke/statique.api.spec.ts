// Le serveur statique de la galerie (tools/static.mjs) doit servir les mêmes
// en-têtes de sécurité que Locksy, CSP comprise, sinon une page de la galerie
// pourrait passer ici et casser en production.

import { test, expect } from "../../fixtures/index.ts";
import { FRESH_URL } from "../../fixtures/env.ts";

const STATIC = "http://127.0.0.1:4173";
const HEADERS = [
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
];

test.describe("Serveur statique de la galerie", { tag: "@smoke" }, () => {
  test("sert /js/app.js avec les en-têtes de sécurité de Locksy", async ({ request }) => {
    const local = await request.get(`${STATIC}/js/app.js`);
    expect(local.status()).toBe(200);
    expect(local.headers()["content-type"]).toMatch(/^text\/javascript/);
    const real = await request.get(`${FRESH_URL}/js/app.js`);
    expect(real.status()).toBe(200);
    for (const h of HEADERS) expect(local.headers()[h], h).toBe(real.headers()[h]);
  });

  test("refuse de sortir des dossiers servis", async ({ request }) => {
    expect((await request.get(`${STATIC}/../Cargo.toml`)).status()).toBe(404);
    expect((await request.get(`${STATIC}/%2e%2e/Cargo.toml`)).status()).toBe(404);
    expect((await request.get(`${STATIC}/gallery/..%2f..%2fCargo.toml`)).status()).toBe(404);
  });

  test("sert le module de chiffrement avec le bon type", async ({ request }) => {
    const res = await request.head(`${STATIC}/locksy.wasm`);
    test.skip(res.status() === 404, "locksy.wasm absent (E2E_WASM non fourni : exécution hors de run.sh).");
    expect(res.headers()["content-type"]).toBe("application/wasm");
  });
});
