// Garde-fou de la matrice du paramétrage (critère G2, contrat V2.2) :
//   1. les clés de GET /api/admin/settings/schema sont EXACTEMENT celles de
//      MATRICE (une clé ajoutée au registre sans entrée fait échouer) ;
//   2. chaque preuve citée existe : fichier présent sous /work, fonction
//      `fn <nom>` ou titre exact, et chaque preuve « ici » a sa vérification
//      dans effets.ts ;
//   3. chaque clé diffusée aux clients a une preuve web (e2e) ET une preuve
//      pour le client Windows (« v1.2 » comprise, V1.5) ;
//   4. chaque clé a une preuve d'application : ce test reste ROUGE tant
//      qu'une entrée « manquant » subsiste (G2 bloquant, jamais annoté).

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test, expect } from "../../fixtures/index.ts";
import { BASE_URL, E2E_DIR } from "../../fixtures/env.ts";
import { loginUi, sessionToken } from "../../fixtures/ui.ts";
import { EFFETS } from "./effets.ts";
import { MATRICE, type Preuve } from "./matrice.ts";

const DEPOT = resolve(E2E_DIR, "..");

interface DefSchema {
  key: string;
  client: boolean;
  section: string;
}

const lire = (rel: string) => readFileSync(resolve(DEPOT, rel), "utf8");

/** Problème d'une preuve (null si elle existe). */
function verifierPreuve(cle: string, p: Preuve): string | null {
  if ("manquant" in p) return null;
  if ("rust" in p || ("windows" in p && p.windows !== "v1.2")) {
    const ref = "rust" in p ? p.rust : p.windows;
    const [fichier, fn] = ref.split("::");
    if (!fn) return `${cle} : référence sans fonction (${ref})`;
    if (!existsSync(resolve(DEPOT, fichier))) return `${cle} : fichier absent ${fichier}`;
    const src = lire(fichier);
    if (!new RegExp(`\\bfn ${fn}\\s*[<(]`).test(src)) return `${cle} : fn ${fn} absente de ${fichier}`;
    return null;
  }
  if ("e2e" in p && p.e2e === "ici") return EFFETS[cle] ? null : `${cle} : preuve « ici » sans vérification dans effets.ts`;
  if ("e2e" in p || "extension" in p) {
    const fichier = "e2e" in p ? `e2e/${p.e2e}` : p.extension;
    const titre = (p as { titre: string }).titre;
    if (!existsSync(resolve(DEPOT, fichier))) return `${cle} : fichier absent ${fichier}`;
    if (!lire(fichier).includes(`"${titre}"`)) return `${cle} : titre absent de ${fichier} : « ${titre} »`;
    return null;
  }
  return null;
}

test.describe("Matrice du paramétrage : garde-fou", () => {
  let schema: DefSchema[] = [];

  test.beforeAll(async ({ org, browser, playwright }) => {
    // Schéma lu par le propriétaire de l'organisation de test.
    const ctx = await browser.newContext({ baseURL: BASE_URL, extraHTTPHeaders: { "X-Forwarded-For": "10.249.0.1" } });
    const page = await ctx.newPage();
    await loginUi(page, org.accounts.owner);
    const api = await playwright.request.newContext({
      baseURL: BASE_URL,
      extraHTTPHeaders: { Authorization: `Bearer ${await sessionToken(page)}`, "X-Forwarded-For": "10.249.0.2" },
    });
    const res = await api.get("/api/admin/settings/schema");
    expect(res.ok(), `GET /api/admin/settings/schema : ${res.status()}`).toBe(true);
    schema = (await res.json()).settings;
    await api.dispose();
    await ctx.close();
  });

  test("les clés du registre sont exactement celles de la matrice", () => {
    const registre = new Set(schema.map((d) => d.key));
    const table = new Set(Object.keys(MATRICE));
    const sansEntree = [...registre].filter((k) => !table.has(k)).sort();
    const perimees = [...table].filter((k) => !registre.has(k)).sort();
    expect(sansEntree, "Clés du registre sans entrée dans matrice.ts").toEqual([]);
    expect(perimees, "Entrées de matrice.ts absentes du registre").toEqual([]);
    expect(registre.size, "Le registre n'est pas vide").toBeGreaterThan(0);
  });

  test("chaque preuve citée existe (fonction Rust, titre exact, vérification « ici »)", () => {
    const problemes: string[] = [];
    for (const [cle, entree] of Object.entries(MATRICE)) {
      if (!entree.preuves.length) problemes.push(`${cle} : aucune preuve`);
      for (const p of entree.preuves) {
        const pb = verifierPreuve(cle, p);
        if (pb) problemes.push(pb);
      }
    }
    expect(problemes, "Preuves introuvables").toEqual([]);
  });

  test("chaque clé diffusée aux clients a une preuve web et une preuve Windows", () => {
    const problemes: string[] = [];
    for (const d of schema.filter((x) => x.client)) {
      const preuves = MATRICE[d.key]?.preuves || [];
      if (!preuves.some((p) => "e2e" in p)) problemes.push(`${d.key} : aucune preuve web (e2e)`);
      if (!preuves.some((p) => "windows" in p)) problemes.push(`${d.key} : aucune preuve Windows (« v1.2 » si le client actuel ne la lit pas)`);
    }
    // Inversement, une preuve Windows réelle ne vise qu'une clé diffusée.
    const clients = new Set(schema.filter((x) => x.client).map((x) => x.key));
    for (const [cle, e] of Object.entries(MATRICE)) {
      if (e.preuves.some((p) => "windows" in p) && !clients.has(cle)) problemes.push(`${cle} : preuve Windows sur une clé non diffusée aux clients`);
    }
    expect(problemes, "Clés diffusées sans preuve côté client").toEqual([]);
  });

  test("chaque clé a une preuve d'application", () => {
    const manquants = Object.entries(MATRICE)
      .flatMap(([cle, e]) => e.preuves.filter((p): p is { manquant: string } => "manquant" in p).map((p) => `${cle} (handoff ${p.manquant})`));
    const sansApplication = Object.entries(MATRICE)
      .filter(([, e]) => !e.preuves.some((p) => !("manquant" in p) && !("windows" in p)))
      .map(([cle]) => cle);
    expect.soft(sansApplication.filter((k) => !manquants.some((m) => m.startsWith(`${k} `))), "Clés sans preuve ni handoff").toEqual([]);
    expect(manquants, "Clés dont l'application n'est prouvée par aucun test (G2)").toEqual([]);
  });
});
