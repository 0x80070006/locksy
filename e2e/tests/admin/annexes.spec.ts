// Administration › pages annexes des réglages (cahier §3.4.6, §4.5, §4.10,
// fiche L12) : import en échec, extraits de déploiement sur les postes,
// affichage sur téléphone, filtre du journal par dates. L'historique, le
// retour à une version et l'import réussi enregistrent de vrais réglages :
// ils sont dans reglages-ecritures.spec.ts (exécutés à la suite).

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { expectToast, goHash } from "./outils.ts";

test.use({ textGuardMode: "strict" });

async function openPage(page: Page, hash: string, title: string) {
  await goHash(page, hash);
  await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
}

test.describe("Réglages › pages annexes", () => {
  test("import : fichier illisible puis essai à blanc en échec, messages français", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/500|Failed to load resource/);
    const page = await loggedIn("owner");
    await page.route((url) => url.pathname === "/api/admin/settings/import", (route) => route.fulfill({ status: 500, json: { error: "internal", message: "Erreur interne du serveur." } }));
    await openPage(page, "#/admin/reglages/transfert", "Importer / exporter");
    const input = page.locator("#reglages-import");
    await input.setInputFiles({ name: "notes.json", mimeType: "application/json", buffer: Buffer.from("pas du JSON") });
    await expect(page.getByText("Ce fichier n'est pas un fichier de réglages Locksy.")).toBeVisible();
    await input.setInputFiles({ name: "reglages.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify({ format: "locksy-settings-v1", values: {} })) });
    await expect(page.getByText(/Erreur interne|serveur/i).first()).toBeVisible();
  });

  test("déploiement sur les postes : extraits générés depuis les réglages, copie d'un bloc", async ({ loggedIn, browserName }) => {
    const page = await loggedIn("owner");
    await openPage(page, "#/admin/reglages/clients", "Réglages");
    await expect(page.getByRole("heading", { level: 2, name: "Déploiement sur les postes" })).toBeVisible();
    const reg = page.getByRole("region", { name: "Registre Windows (stratégie de groupe)" });
    await expect(reg).toContainText("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Locksy]");
    await expect(reg).toContainText("\"client.autolock_minutes\"=dword:");
    await expect(page.getByRole("region", { name: "Modèle d'administration" })).toContainText("<policyDefinitions");

    const id = "abcdefghijklmnopabcdefghijklmnop";
    await page.getByLabel("Identifiant de l'extension").fill(id);
    const chrome = page.getByRole("region", { name: "Google Chrome" });
    await expect(chrome).toContainText(`"${id};https://clients2.google.com/service/update2/crx"`);
    await expect(chrome).toContainText("\"3rdparty\"");

    // Réseau de test en HTTP (http://locksy:8743) : contexte non sécurisé, le
    // navigateur n'expose pas navigator.clipboard. Sans presse-papiers, la copie
    // échoue avec un message ; avec un presse-papiers (de test, en mémoire), elle réussit.
    const copy = chrome.locator("xpath=..").getByRole("button", { name: "Copier" });
    const secure = await page.evaluate(() => window.isSecureContext && !!navigator.clipboard);
    if (!secure) {
      await copy.click();
      await expectToast(page, /Copie impossible/);
      await page.evaluate(() => {
        let content = "";
        Object.defineProperty(navigator, "clipboard", {
          configurable: true,
          value: { writeText: async (v: string) => { content = String(v); }, readText: async () => content },
        });
      });
    } else {
      test.skip(browserName !== "chromium", "presse-papiers ouvert seulement dans le projet chromium");
    }
    await copy.click();
    await expectToast(page, "Extrait copié");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toContain(id);
  });

  test("téléphone : accueil, réglages et journal sans défilement horizontal", { tag: "@mobile" }, async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    for (const [hash, title] of [["#/admin", "Accueil"], ["#/admin/reglages/sessions", "Réglages"], ["#/admin/journal", "Journal"]]) {
      await openPage(page, hash, title);
      await expect(page.getByRole("navigation", { name: "Administration", exact: true })).toBeAttached();
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
    }
  });

  test("journal : période « dates » lue depuis l'adresse et transmise au serveur", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const asked: URLSearchParams[] = [];
    await page.route((url) => url.pathname === "/api/admin/audit", async (route) => {
      asked.push(new URL(route.request().url()).searchParams);
      await route.fulfill({ json: { entries: [], total: 0, next_cursor: null } });
    });
    await openPage(page, "#/admin/journal?periode=dates&du=2026-11-01&au=2026-11-10", "Journal");
    await expect(page.getByLabel("Du", { exact: true })).toHaveValue("2026-11-01");
    await expect(page.getByLabel("Au", { exact: true })).toHaveValue("2026-11-10");
    await expect.poll(() => asked.at(-1)?.get("from")).toBeTruthy();
    const from = Number(asked.at(-1)!.get("from"));
    const to = Number(asked.at(-1)!.get("to"));
    expect(to - from).toBeGreaterThan(9 * 86400);
    expect(to - from).toBeLessThan(10 * 86400 + 3600 * 2);
  });
});
