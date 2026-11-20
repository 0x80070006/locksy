// Configuration Playwright des tests de bout en bout de Locksy.
// À exécuter par tools/run.sh (image mcr.microsoft.com/playwright:v1.49.1-noble,
// réseau compose) : voir README.md.

import { defineConfig, devices } from "@playwright/test";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import type { E2EOptions } from "./fixtures/index.ts";

const key = process.env.E2E_KEY || "local";
const extPath = resolve(process.env.EXT_PATH || "../extension/dist/locksy-extension");
// 4 workers au plus ; 2 par défaut (Docker Desktop limité à 4 Go de mémoire).
const workers = Math.min(4, Math.max(1, Number(process.env.E2E_WORKERS) || 2));

// Fichiers exclus des projets navigateur génériques.
const notGeneric = [/tests\/(ui|extension|visual)\//, /\.api\.spec\.ts$/];

export default defineConfig<E2EOptions>({
  testDir: ".",
  testMatch: /.*\.spec\.ts$/,
  outputDir: `test-results/${key}`,
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  fullyParallel: true,
  workers,
  retries: 0, // un test instable est un bogue : aucune relance masquante
  forbidOnly: true,
  timeout: 90_000, // le KDF du navigateur prend environ 1 s par connexion
  expect: { timeout: 15_000 },
  reporter: [
    ["list"],
    ["html", { open: "never", outputFolder: `playwright-report/${key}` }],
  ],
  use: {
    baseURL: process.env.BASE_URL || "http://locksy:8743",
    locale: "fr-FR",
    timezoneId: "Europe/Paris",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    actionTimeout: 15_000,
  },
  // Galerie des composants (lot L3) : serveur statique, même CSP que Locksy.
  webServer: {
    command: "node tools/static.mjs --port 4173",
    url: "http://127.0.0.1:4173/js/app.js",
    reuseExistingServer: false,
    timeout: 20_000,
    stdout: "ignore",
  },
  projects: [
    {
      name: "chromium",
      testMatch: /tests\/.*\.spec\.ts$/,
      testIgnore: notGeneric,
      use: { ...devices["Desktop Chrome"], permissions: ["clipboard-read", "clipboard-write"] },
    },
    {
      name: "firefox",
      testMatch: /tests\/.*\.spec\.ts$/,
      testIgnore: notGeneric,
      use: { ...devices["Desktop Firefox"] },
    },
    {
      // Téléphone de 375 px : seules les spécifications marquées @mobile.
      name: "mobile",
      testMatch: /tests\/.*\.spec\.ts$/,
      testIgnore: notGeneric,
      grep: /@mobile/,
      use: { ...devices["Pixel 7"], viewport: { width: 375, height: 812 } },
    },
    {
      name: "ui-gallery",
      testMatch: /tests\/ui\/.*\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"], baseURL: "http://127.0.0.1:4173" },
    },
    {
      // Mêmes composants sous Firefox. Le presse-papiers asynchrone y est ouvert
      // par préférences (Firefox ne connaît pas la permission « clipboard-read »).
      name: "ui-gallery-firefox",
      testMatch: /tests\/ui\/.*\.spec\.ts$/,
      use: {
        ...devices["Desktop Firefox"],
        baseURL: "http://127.0.0.1:4173",
        launchOptions: { firefoxUserPrefs: { "dom.events.asyncClipboard.readText": true, "dom.events.testing.asyncClipboard": true } },
      },
    },
    {
      // Sans navigateur : fixture « request » (et apiAs) seulement.
      name: "api",
      testMatch: /\.api\.spec\.ts$/,
    },
    {
      name: "visual",
      testMatch: /tests\/visual\/.*\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"] },
    },
    {
      // Contexte persistant avec l'extension construite (fixture extensionContext) ;
      // les tests sont ignorés proprement si EXT_PATH n'existe pas.
      name: "extension",
      testMatch: /tests\/extension\/.*\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"], extensionPath: existsSync(extPath) ? extPath : "" },
    },
  ],
});
