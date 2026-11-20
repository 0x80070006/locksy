// Configuration Playwright des tests de sécurité (lot Q4), propre au dossier.
// Lancée par e2e/security/run.sh : « -c security/playwright.config.ts ».
//
// Les spécifications sont des *.spec.ts (jamais *.api.spec.ts : le projet
// « api » de la configuration générique les lancerait sans les services de la
// surcouche docker-compose.securite.yml). Les chemins relatifs se résolvant
// depuis ce dossier, toutes les sorties sont posées explicitement sous
// e2e/test-results et e2e/playwright-report (ignorés par git).

import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";
import { E2E_DIR, KEY } from "../fixtures/env.ts";
import type { E2EOptions } from "../fixtures/index.ts";

export default defineConfig<E2EOptions>({
  testDir: ".",
  testMatch: /\.spec\.ts$/,
  outputDir: resolve(E2E_DIR, "test-results", `${KEY}-securite`),
  globalSetup: resolve(E2E_DIR, "global-setup.ts"),
  globalTeardown: resolve(E2E_DIR, "global-teardown.ts"),
  fullyParallel: false,
  workers: Math.min(2, Math.max(1, Number(process.env.E2E_WORKERS) || 2)),
  retries: 0,
  forbidOnly: true,
  // Mesures de temps (énumération) et attente d'un blocage (installation).
  timeout: 300_000,
  expect: { timeout: 15_000 },
  reporter: [
    ["list"],
    ["json", { outputFile: resolve(E2E_DIR, "test-results", `${KEY}-securite`, "resultats.json") }],
    ["html", { open: "never", outputFolder: resolve(E2E_DIR, "playwright-report", `${KEY}-securite`) }],
  ],
  use: {
    baseURL: process.env.BASE_URL || "http://locksy:8743",
    locale: "fr-FR",
    timezoneId: "Europe/Paris",
    trace: "retain-on-failure",
    actionTimeout: 15_000,
  },
  projects: [
    {
      // Requêtes HTTP surtout ; le navigateur ne sert qu'à créer des comptes
      // par l'interface (dérivation de la clé dans la page).
      name: "securite-api",
      testMatch: /(entetes|entrees|enumeration|idor|limites|sessions)\.spec\.ts$/,
    },
    {
      name: "securite-chromium",
      testMatch: /(csp|installation|zero-knowledge)\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
