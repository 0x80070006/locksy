// Politique de sécurité du contenu (G8). Un script en ligne, un eval, un
// gestionnaire d'événement en attribut et un style en ligne, injectés par
// l'outil de test dans la vraie page, sont refusés et lèvent
// securitypolicyviolation. Puis les règles R1 sur les sources (lues dans le
// dépôt monté en /work) : aucun innerHTML ni équivalent, aucun script ni
// style en ligne dans les pages HTML.
//
// Ce fichier n'utilise pas les fixtures communes : leur garde cspGuard
// compterait les violations provoquées ici exprès.

import { test, expect } from "@playwright/test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { E2E_DIR } from "../fixtures/env.ts";

interface Violation {
  directive: string;
  bloque: string;
}

test.describe("CSP appliquée par le navigateur", () => {
  test.beforeEach(async ({ page }) => {
    // Relevé posé avant les scripts de la page (script d'initialisation de l'outil).
    await page.addInitScript(() => {
      const w = window as unknown as { __violations: Violation[] };
      w.__violations = [];
      document.addEventListener("securitypolicyviolation", (e) => {
        w.__violations.push({ directive: e.effectiveDirective || e.violatedDirective, bloque: e.blockedURI });
      });
    });
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  });

  const violations = (page: import("@playwright/test").Page) =>
    page.evaluate(() => (window as unknown as { __violations: Violation[] }).__violations);

  test("un script en ligne injecté n'est pas exécuté", async ({ page }) => {
    await page.evaluate(() => {
      const s = document.createElement("script");
      s.textContent = "window.__injecte = true;";
      document.head.append(s);
    });
    await expect.poll(() => violations(page)).toContainEqual({ directive: "script-src-elem", bloque: "inline" });
    expect(await page.evaluate(() => (window as unknown as { __injecte?: boolean }).__injecte)).toBeUndefined();
  });

  test("un gestionnaire d'événement en attribut n'est pas exécuté", async ({ page }) => {
    await page.evaluate(() => {
      const b = document.createElement("button");
      b.setAttribute("onclick", "window.__clic = true;");
      document.body.append(b);
      b.click();
    });
    await expect.poll(() => violations(page)).toContainEqual({ directive: "script-src-attr", bloque: "inline" });
    expect(await page.evaluate(() => (window as unknown as { __clic?: boolean }).__clic)).toBeUndefined();
  });

  test("eval et new Function sont refusés", async ({ page }) => {
    // Le code évalué par l'outil (page.evaluate) échappe à la CSP dans
    // Chromium : l'essai est donc ajouté à la fin du vrai script de
    // l'application, servi tel quel par ailleurs, et s'exécute dans la page.
    const essai = [
      "const __essai = (f) => { try { return String(f()); } catch (e) { return e.name; } };",
      'window.__evalEssais = [__essai(() => (0, eval)("6 * 7")), __essai(() => new Function("return 6 * 7")())];',
    ].join("\n");
    await page.route("**/js/app.js", async (route) => {
      const res = await route.fetch();
      await route.fulfill({ response: res, body: `${await res.text()}\n${essai}\n` });
    });
    await page.reload();
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    const essais = await page.evaluate(() => (window as unknown as { __evalEssais?: string[] }).__evalEssais);
    expect(essais).toEqual(["EvalError", "EvalError"]);
    await expect.poll(() => violations(page)).toContainEqual({ directive: "script-src", bloque: "eval" });
  });

  test("un style en ligne injecté n'est pas appliqué", async ({ page }) => {
    const couleurs = await page.evaluate(() => {
      const p = document.createElement("p");
      p.textContent = "essai";
      p.setAttribute("style", "color: rgb(255, 0, 0)");
      const q = document.createElement("p");
      q.className = "essai-csp";
      q.textContent = "essai";
      const feuille = document.createElement("style");
      feuille.textContent = ".essai-csp { color: rgb(0, 128, 0); }";
      document.head.append(feuille);
      document.body.append(p, q);
      return [getComputedStyle(p).color, getComputedStyle(q).color];
    });
    expect(couleurs).not.toContain("rgb(255, 0, 0)");
    expect(couleurs).not.toContain("rgb(0, 128, 0)");
    await expect.poll(() => violations(page)).toEqual(
      expect.arrayContaining([
        { directive: "style-src-attr", bloque: "inline" },
        { directive: "style-src-elem", bloque: "inline" },
      ]),
    );
  });

  test("la page normale ne provoque aucune violation", async ({ page }) => {
    // Le formulaire de connexion est affiché (beforeEach) : relevé vide.
    await page.waitForLoadState("networkidle");
    expect(await violations(page)).toEqual([]);
  });
});

// ------------------------------------------------------------ Règles R1 sur les sources

const DEPOT = resolve(E2E_DIR, "..");

function fichiers(dossier: string): string[] {
  return readdirSync(dossier).flatMap((nom) => {
    const chemin = join(dossier, nom);
    return statSync(chemin).isDirectory() ? fichiers(chemin) : [chemin];
  });
}

/** Lignes d'un ensemble de fichiers texte qui vérifient le motif (fichiers binaires ignorés, comme rg). */
function lignes(dossiers: string[], motif: RegExp, extensions = /\.(m?js|html|json|css)$/): string[] {
  return dossiers.flatMap((d) =>
    fichiers(resolve(DEPOT, d))
      .filter((f) => extensions.test(f))
      .flatMap((f) => {
        const texte = readFileSync(f, "utf8");
        if (texte.includes("\0")) return [];
        return texte.split(/\r?\n/).flatMap((l, i) => (motif.test(l) ? [`${relative(DEPOT, f)}:${i + 1}: ${l.trim()}`] : []));
      }),
  );
}

test.describe("Règles R1 sur les sources du web et de l'extension", () => {
  test("aucun innerHTML, outerHTML, insertAdjacentHTML, eval( ni new Function", () => {
    expect(lignes(["web/js", "extension/src"], /innerHTML|outerHTML|insertAdjacentHTML|eval\(|new Function/)).toEqual([]);
  });

  test("aucun script ni style en ligne dans les pages HTML", () => {
    const pages = ["web", "extension/src"];
    expect(lignes(pages, /<script(?![^>]*\bsrc=)[^>]*>/i, /\.html$/), "script sans src").toEqual([]);
    expect(lignes(pages, /<style\b|\sstyle\s*=/i, /\.html$/), "style en ligne").toEqual([]);
    expect(lignes(pages, /\son[a-z]+\s*=/i, /\.html$/), "gestionnaire d'événement en attribut").toEqual([]);
  });
});
