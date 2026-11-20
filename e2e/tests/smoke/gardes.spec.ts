// Les gardes automatiques détectent vraiment ce qu'elles doivent détecter :
// sans ce contrôle, une garde muette laisserait passer toutes les régressions.
// La page d'essai est servie avec les en-têtes de sécurité de Locksy, sur
// l'origine de la galerie (jugée comme une page de Locksy).

import { test, expect } from "../../fixtures/index.ts";
import { SECURITY_HEADERS } from "../../tools/static.mjs";

const PAGE = "http://127.0.0.1:4173/essai-gardes.html";
const SCRIPT = "http://127.0.0.1:4173/essai-gardes.js";
// Le code fautif vient d'un fichier servi, comme le code du produit : une
// violation provoquée par page.evaluate seul serait attribuée à l'outillage.
const SCRIPT_BODY = `window.essaiCsp = () => {
  const img = document.createElement("img");
  img.src = "https://exemple.invalid/image.png";
  document.body.append(img);
};`;

test.beforeEach(async ({ page }) => {
  const serve = (body: string, type: string) => (route: import("@playwright/test").Route) =>
    route.fulfill({ status: 200, headers: { ...SECURITY_HEADERS, "content-type": type }, body });
  await page.route(SCRIPT, serve(SCRIPT_BODY, "text/javascript; charset=utf-8"));
  await page.route(
    PAGE,
    serve(
      `<!doctype html><html lang="fr"><title>Essai des gardes</title><script src="${SCRIPT}"></script><main><p>Page d'essai</p></main></html>`,
      "text/html; charset=utf-8",
    ),
  );
  await page.goto(PAGE);
});

test.describe("Gardes automatiques", { tag: "@smoke" }, () => {
  test("cspGuard relève une ressource refusée par la CSP", async ({ page, cspGuard }) => {
    await page.evaluate(() => (window as unknown as { essaiCsp: () => void }).essaiCsp());
    // Une violation arrive par deux voies (événement et console), dans un ordre
    // quelconque : on attend que le relevé ne bouge plus avant de le vider.
    let last = -1;
    await expect.poll(() => {
      const n = cspGuard.violations.length;
      const stable = n > 0 && n === last;
      last = n;
      return stable;
    }, { intervals: [300] }).toBe(true);
    expect(cspGuard.violations.join("\n")).toMatch(/img-src/);
    cspGuard.violations.length = 0; // violation provoquée : le test reste vert
  });

  test("cspGuard ignore le code injecté par l'outillage de test (axe, page.evaluate)", async ({ page, cspGuard }) => {
    await page.evaluate(() => document.body.setAttribute("style", "outline: 1px solid"));
    await page.waitForTimeout(300);
    expect(cspGuard.violations).toEqual([]);
  });

  test("consoleGuard relève console.error, sauf motif autorisé", async ({ page, consoleGuard }) => {
    consoleGuard.allow(/^Erreur autorisée/);
    await page.evaluate(() => {
      console.error("Erreur autorisée par le test");
      console.error("Erreur inattendue");
    });
    await expect.poll(() => consoleGuard.errors.length).toBe(1);
    expect(consoleGuard.errors[0]).toMatch(/^Erreur inattendue/);
    consoleGuard.errors.length = 0;
  });

  test("textGuard relève un texte technique ou anglais, hors « Détails techniques »", async ({ page, textGuard }) => {
    await page.evaluate(() => {
      const visible = document.createElement("p");
      visible.textContent = "Valeur : undefined";
      const button = document.createElement("button");
      button.setAttribute("aria-label", "Save");
      const details = document.createElement("details");
      details.dataset.technical = "";
      details.open = true;
      details.append(Object.assign(document.createElement("p"), { textContent: "TypeError: null (UUID 123e4567-e89b-12d3-a456-426614174000)" }));
      document.querySelector("main")!.append(visible, button, details);
    });
    await textGuard.check(page);
    await expect.poll(() => textGuard.findings.map((f) => f.rule).sort()).toEqual(["anglais « save »", "undefined"]);
    textGuard.findings.length = 0;
  });
});
