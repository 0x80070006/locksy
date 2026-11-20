// Configuration Playwright du budget du front (lot Q6, cahier 00 §6.5,
// stratégie 05 §7). Les spécifications s'appellent *.perf.ts : le motif de la
// configuration générique (*.spec.ts) ne les voit pas. Un seul worker, pour
// que deux mesures ne se disputent jamais le processeur.
//
//   E2E_WORKERS=1 bash e2e/tools/run.sh -p q6-perf --fast-server -- -c tests/perf/perf.config.ts --project=perf-chromium
//
// Les chemins sont résolus depuis E2E_DIR (fixtures/env.ts) : une
// configuration propre résout ses chemins relatifs par rapport à son propre
// dossier, et les sorties doivent rester dans des dossiers ignorés par git.

import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";
import { E2E_DIR, KEY } from "../../fixtures/env.ts";
import type { E2EOptions } from "../../fixtures/index.ts";

const OUT = resolve(E2E_DIR, "test-results", `${KEY}-perf`);

export default defineConfig<E2EOptions>({
  testDir: resolve(E2E_DIR, "tests", "perf"),
  testMatch: /\.perf\.ts$/,
  outputDir: OUT,
  globalSetup: resolve(E2E_DIR, "global-setup.ts"),
  globalTeardown: resolve(E2E_DIR, "global-teardown.ts"),
  fullyParallel: false,
  workers: 1, // mesures de temps : jamais deux navigateurs en même temps
  retries: 0,
  forbidOnly: true,
  // Semis de 10 000 éléments et séries de déverrouillages (Argon2id réel).
  timeout: 600_000,
  expect: { timeout: 15_000 },
  reporter: [
    ["list"],
    ["json", { outputFile: resolve(OUT, "resultats.json") }],
    ["html", { open: "never", outputFolder: resolve(E2E_DIR, "playwright-report", `${KEY}-perf`) }],
  ],
  use: {
    baseURL: process.env.BASE_URL || "http://locksy:8743",
    locale: "fr-FR",
    timezoneId: "Europe/Paris",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    actionTimeout: 15_000,
    // Pas de relevé des textes pendant les mesures ; CSP et console restent surveillées.
    textGuardMode: "off",
  },
  projects: [
    { name: "perf-chromium", use: { ...devices["Desktop Chrome"] } },
    // Indicatif : les seuils propres à Firefox sont consignés, sans échec.
    { name: "perf-firefox", use: { ...devices["Desktop Firefox"] } },
  ],
});
