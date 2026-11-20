// Configuration Playwright des suites qui MODIFIENT l'organisation partagée
// (lot Q3b, contrat V1.3) : matrice des réglages (settings-matrix/*.isole.ts)
// et parcours d'administration A2 et A4 (ux/*.isole.ts). Elles se lancent
// SEULES, en Chromium, avec un seul worker :
//
//   bash e2e/tools/run.sh -p q3b-e2ex --fast-server -- -c tests/settings-matrix/isole.config.ts
//
// Les chemins sont résolus depuis E2E_DIR (fixtures/env.ts) : une
// configuration propre résout ses chemins relatifs par rapport à son propre
// dossier, et les sorties doivent rester dans des dossiers ignorés par git.

import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";
import { E2E_DIR, KEY } from "../../fixtures/env.ts";
import type { E2EOptions } from "../../fixtures/index.ts";

export default defineConfig<E2EOptions>({
  testDir: resolve(E2E_DIR, "tests"),
  testMatch: [/settings-matrix\/.*\.isole\.ts$/, /ux\/.*\.isole\.ts$/],
  outputDir: resolve(E2E_DIR, "test-results", `${KEY}-isole`),
  globalSetup: resolve(E2E_DIR, "global-setup.ts"),
  globalTeardown: resolve(E2E_DIR, "global-teardown.ts"),
  fullyParallel: false,
  workers: 1, // une seule écriture à la fois dans les réglages de l'organisation
  retries: 0,
  forbidOnly: true,
  timeout: 240_000, // une section entière : saisie, enregistrement, rechargement, retour au défaut
  expect: { timeout: 15_000 },
  reporter: [
    ["list"],
    ["html", { open: "never", outputFolder: resolve(E2E_DIR, "playwright-report", `${KEY}-isole`) }],
  ],
  use: {
    baseURL: process.env.BASE_URL || "http://locksy:8743",
    locale: "fr-FR",
    timezoneId: "Europe/Paris",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    actionTimeout: 15_000,
  },
  projects: [
    {
      name: "chromium-isole",
      use: { ...devices["Desktop Chrome"], permissions: ["clipboard-read", "clipboard-write"] },
    },
  ],
});
