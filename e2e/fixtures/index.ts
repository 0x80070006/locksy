// Fixtures communes des tests de bout en bout de Locksy.
//
//   import { test, expect } from "../../fixtures/index.ts";
//
// Automatiques (tout test qui ouvre une page) : cspGuard, consoleGuard,
// textGuard, X-Forwarded-For unique par test.
// À la demande : org, loggedIn(role), apiAs(role), xff, clicks, extensionContext.
// Options : textGuardMode ("report" | "strict" | "off"), extensionPath.
// Voir README.md, section « Fixtures ».

import { test as base, expect, type APIRequestContext, type BrowserContext, type BrowserContextOptions, type Page } from "@playwright/test";
import { chromium } from "@playwright/test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BASE_URL } from "./env.ts";
import { Clicks } from "./clicks.ts";
import { Guards, type TextFinding, type TextGuardMode } from "./guards.ts";
import { ensureOrg, type Org, type Role } from "./org.ts";
import { loginUi, sessionToken } from "./ui.ts";

export { expect };
export type { Org, Role, TextFinding, TextGuardMode };

export interface E2EOptions {
  /** "report" (vague 1, défaut) : constats joints au rapport ; "strict" : échec ; "off". */
  textGuardMode: TextGuardMode;
  /** Dossier de l'extension construite ; vide = tests de l'extension ignorés. */
  extensionPath: string;
}

interface XffPool {
  next(): string;
}

interface E2EFixtures {
  /** Adresse X-Forwarded-For unique de ce test (10.<worker>.<n>.<n>). */
  xff: string;
  cspGuard: { readonly violations: string[] };
  consoleGuard: { allow(re: RegExp): void; readonly errors: string[] };
  textGuard: { readonly mode: TextGuardMode; readonly findings: TextFinding[]; check(page: Page): Promise<void> };
  /** Page connectée par l'interface sur BASE_URL avec le compte du rôle. */
  loggedIn: (role: Role) => Promise<Page>;
  /** Requêtes API authentifiées (Bearer de la page connectée) pour le rôle. */
  apiAs: (role: Role) => Promise<APIRequestContext>;
  clicks: Clicks;
  /** Contexte Chromium persistant avec l'extension chargée (projet « extension »). */
  extensionContext: BrowserContext;
  _guards: Guards;
  _newContext: (extra?: BrowserContextOptions) => Promise<BrowserContext>;
}

interface E2EWorkerFixtures {
  /** Organisation amorcée sur BASE_URL (comptes owner, admin, user). */
  org: Org;
  _xffPool: XffPool;
}

export const test = base.extend<E2EOptions & E2EFixtures, E2EWorkerFixtures>({
  textGuardMode: ["report", { option: true }],
  extensionPath: ["", { option: true }],

  _xffPool: [
    async ({}, use, workerInfo) => {
      // Plage 10.1.x.x à 10.200.x.x selon le worker ; 10.250+ est réservé à l'amorçage.
      const w = (workerInfo.workerIndex % 200) + 1;
      let n = 0;
      await use({
        next: () => {
          n++;
          return `10.${w}.${(n >> 8) & 255}.${n & 255}`;
        },
      });
    },
    { scope: "worker" },
  ],

  xff: async ({ _xffPool }, use) => {
    await use(_xffPool.next());
  },

  _guards: async ({}, use) => {
    await use(new Guards());
  },

  cspGuard: [
    async ({ _guards }, use) => {
      await use({ violations: _guards.csp });
      expect(_guards.csp, "Violations de la politique de sécurité du contenu (CSP)").toEqual([]);
    },
    { auto: true },
  ],

  consoleGuard: [
    async ({ _guards }, use) => {
      await use({ allow: (re: RegExp) => _guards.allow(re), errors: _guards.console });
      expect(_guards.console, "Erreurs dans la console du navigateur").toEqual([]);
    },
    { auto: true },
  ],

  textGuard: [
    async ({ _guards, textGuardMode }, use, testInfo) => {
      await use({
        mode: textGuardMode,
        findings: _guards.text,
        check: async (page: Page) => _guards.flush(page.context()),
      });
      if (textGuardMode === "off") return;
      const findings = await _guards.reportText(testInfo);
      if (textGuardMode === "strict") {
        expect(findings.map((f) => `${f.rule} : « ${f.text} » (${f.url})`), "Textes techniques ou anglais à l'écran").toEqual([]);
      }
    },
    { auto: true },
  ],

  // Contexte par défaut : surveillé par les gardes, X-Forwarded-For du test.
  context: async ({ context, _guards, xff }, use) => {
    await context.setExtraHTTPHeaders({ "X-Forwarded-For": xff });
    await _guards.watch(context);
    await use(context);
    await _guards.flush(context);
  },

  request: async ({ playwright, baseURL, xff }, use) => {
    const ctx = await playwright.request.newContext({ baseURL, extraHTTPHeaders: { "X-Forwarded-For": xff } });
    await use(ctx);
    await ctx.dispose();
  },

  // Contextes supplémentaires avec les options du projet, surveillés et fermés en fin de test.
  _newContext: async (
    { browser, _guards, _xffPool, locale, timezoneId, viewport, isMobile, hasTouch, deviceScaleFactor, userAgent, colorScheme, permissions },
    use,
  ) => {
    const opened: BrowserContext[] = [];
    await use(async (extra = {}) => {
      const ctx = await browser.newContext({
        locale, timezoneId, viewport, isMobile, hasTouch, deviceScaleFactor, userAgent, colorScheme, permissions,
        baseURL: BASE_URL,
        ...extra,
        extraHTTPHeaders: { "X-Forwarded-For": _xffPool.next(), ...(extra.extraHTTPHeaders || {}) },
      });
      await _guards.watch(ctx);
      opened.push(ctx);
      return ctx;
    });
    for (const ctx of opened) {
      await _guards.flush(ctx);
      await ctx.close();
    }
  },

  org: [
    async ({ browser }, use) => {
      await use(await ensureOrg(browser, { locale: "fr-FR", timezoneId: "Europe/Paris" }));
    },
    { scope: "worker", timeout: 240_000 },
  ],

  loggedIn: async ({ org, _newContext }, use) => {
    await use(async (role: Role) => {
      const page = await (await _newContext()).newPage();
      await loginUi(page, org.accounts[role]);
      return page;
    });
  },

  apiAs: async ({ loggedIn, playwright, _xffPool }, use) => {
    const cache = new Map<Role, APIRequestContext>();
    await use(async (role: Role) => {
      let api = cache.get(role);
      if (!api) {
        const token = await sessionToken(await loggedIn(role));
        api = await playwright.request.newContext({
          baseURL: BASE_URL,
          extraHTTPHeaders: { Authorization: `Bearer ${token}`, "X-Forwarded-For": _xffPool.next() },
        });
        cache.set(role, api);
      }
      return api;
    });
    for (const api of cache.values()) await api.dispose();
  },

  clicks: async ({}, use) => {
    await use(new Clicks());
  },

  extensionContext: async ({ extensionPath, _guards }, use, testInfo) => {
    testInfo.skip(!extensionPath, "Extension non construite : EXT_PATH absent (node extension/build.mjs).");
    const profile = mkdtempSync(join(tmpdir(), "locksy-ext-"));
    const ctx = await chromium.launchPersistentContext(profile, {
      channel: "chromium",
      locale: "fr-FR",
      timezoneId: "Europe/Paris",
      args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
    });
    await _guards.watch(ctx);
    try {
      await use(ctx);
      await _guards.flush(ctx);
    } finally {
      await ctx.close();
      rmSync(profile, { recursive: true, force: true });
    }
  },
});
