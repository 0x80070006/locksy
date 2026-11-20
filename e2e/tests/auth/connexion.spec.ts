// Écran de connexion (cahier §3.3.1, fiche L9) : méthode principale, autres
// méthodes repliées, méthode imposée, erreur générique, blocage avec le délai
// de Retry-After, code de vérification collé, code de secours, accessibilité.
//
// Les routes de la vague 2 absentes de l'image de test (/settings/public
// enrichi, double authentification du compte) sont simulées par page.route()
// selon les contrats C1.3 et A.5.

import type { Page, Route } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { seriousViolations } from "../../fixtures/axe.ts";
import { expectShell, KDF_TIMEOUT, loginUi } from "../../fixtures/ui.ts";
import { connecter, preparer } from "../shell/outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(preparer);

const LIBELLES = {
  email: "Adresse e-mail",
  password: /^Mot de passe maître$/,
  windowsUser: "Identifiant Windows",
  windowsPassword: "Mot de passe Windows",
  login: /^Se connecter$/,
  otherMethod: "Utiliser une autre méthode",
  ownerRescue: "Accès de secours des propriétaires",
  code: "Code de vérification",
  backupCode: "Code de secours",
  useBackup: "Utiliser un code de secours",
};

/** Réponse de /settings/public (A.5) avec la méthode de connexion voulue. */
async function publicSettings(page: Page, login: Record<string, unknown>) {
  await page.route("**/api/settings/public", async (route) => {
    const res = await route.fetch();
    const body = res.ok() ? await res.json() : {};
    await route.fulfill({ json: { ...body, login: { sso_label: "Microsoft", ldap_label: "Compte Windows", ...login } } });
  });
}

/** Simule la double authentification : première tentative 401 totp_required, puis le vrai serveur. */
async function requireTotp(page: Page) {
  const bodies: Record<string, unknown>[] = [];
  await page.route("**/api/auth/login", async (route: Route) => {
    const body = route.request().postDataJSON() as Record<string, unknown>;
    bodies.push(body);
    if (!body.totp) {
      await route.fulfill({ status: 401, json: { error: "totp_required", message: "Code requis." } });
      return;
    }
    await route.continue();
  });
  return bodies;
}

test.describe("Connexion", () => {
  test("par la méthode principale (mot de passe maître) : titre, coquille et focus", { tag: "@mobile" }, async ({ page, org }) => {
    await connecter(page, org.accounts.user);
    await expect(page).toHaveTitle("Mon coffre · Locksy");
    await expect(page.getByRole("button", { name: LIBELLES.login })).toHaveCount(0);
    // Après connexion, le focus est sur le titre de la vue, jamais sur <body>.
    expect(await page.evaluate(() => document.activeElement?.tagName)).not.toBe("BODY");
  });

  test("méthode principale Windows : le mot de passe maître est replié sous « Utiliser une autre méthode »", async ({ page }) => {
    await publicSettings(page, { primary_method: "ldap", methods: ["ldap", "password"], enforced: false });
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: "Connexion avec votre compte Windows" })).toBeVisible();
    await expect(page.getByLabel(LIBELLES.windowsUser)).toBeFocused();
    await expect(page.getByText("C'est le mot de passe de votre session Windows, pas votre mot de passe maître.")).toBeVisible();
    await expect(page.getByLabel(LIBELLES.email)).toBeHidden();
    const other = page.getByRole("button", { name: LIBELLES.otherMethod });
    await expect(other).toHaveAttribute("aria-expanded", "false");
    await other.click();
    await expect(other).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByLabel(LIBELLES.email)).toBeVisible();
    await expect(page.getByLabel(LIBELLES.password)).toBeVisible();
  });

  test("méthode imposée : aucune autre méthode, seulement l'accès de secours des propriétaires", async ({ page }) => {
    await publicSettings(page, { primary_method: "sso", methods: ["sso", "password"], enforced: true });
    await page.goto("/");
    await expect(page.getByRole("link", { name: "Continuer avec Microsoft" })).toBeVisible();
    await expect(page.getByRole("button", { name: LIBELLES.otherMethod })).toHaveCount(0);
    const rescue = page.getByRole("button", { name: LIBELLES.ownerRescue });
    await expect(rescue).toBeVisible();
    await expect(page.getByLabel(LIBELLES.email)).toBeHidden();
    await rescue.click();
    await expect(page.getByLabel(LIBELLES.email)).toBeVisible();
  });

  test("erreur générique sous le champ, identique pour une adresse inconnue", async ({ page, org, consoleGuard }) => {
    consoleGuard.allow(/status of 401/);
    await page.goto("/");
    for (const email of [org.accounts.user.email, `inconnu-${Date.now()}@e2e.test`]) {
      await page.getByLabel(LIBELLES.email).fill(email);
      await page.getByLabel(LIBELLES.password).fill("Ce-n-est-pas-le-bon-mot-de-passe");
      await page.getByRole("button", { name: LIBELLES.login }).click();
      const error = page.locator("#contenu").getByText("Adresse ou mot de passe incorrect.");
      await expect(error).toBeVisible({ timeout: KDF_TIMEOUT });
      await expect(page.getByLabel(LIBELLES.password)).toHaveAttribute("aria-invalid", "true");
      await expect(page.locator("#alert")).toHaveText("Adresse ou mot de passe incorrect.");
    }
  });

  test("blocage : délai venant de Retry-After, sans nombre d'essais restants", async ({ page, org, consoleGuard }) => {
    consoleGuard.allow(/status of 429/);
    await page.route("**/api/auth/login", (route) => route.fulfill({
      status: 429,
      headers: { "Retry-After": "900" },
      json: { error: "rate_limited", message: "Trop de tentatives.", retry_after: 900 },
    }));
    await page.goto("/");
    await page.getByLabel(LIBELLES.email).fill(org.accounts.user.email);
    await page.getByLabel(LIBELLES.password).fill("Peu-importe-le-mot-de-passe");
    await page.getByRole("button", { name: LIBELLES.login }).click();
    await expect(page.locator("#contenu").getByText("Trop d'essais. Réessayez dans 15 min.")).toBeVisible({ timeout: KDF_TIMEOUT });
    await expect(page.getByText(/essais? restants?/i)).toHaveCount(0);
  });

  test("code de vérification collé : envoyé tout seul au 6e chiffre", async ({ page, org, consoleGuard, browserName }) => {
    // Firefox ignore les données d'un événement « paste » synthétique (harnais, vague 1).
    test.skip(browserName === "firefox", "collage synthétique impossible sous Firefox : voir le test de saisie au clavier");
    consoleGuard.allow(/status of 401/);
    const bodies = await requireTotp(page);
    await page.goto("/");
    await page.getByLabel(LIBELLES.email).fill(org.accounts.user.email);
    await page.getByLabel(LIBELLES.password).fill(org.accounts.user.password);
    await page.getByRole("button", { name: LIBELLES.login }).click();
    const code = page.getByLabel(LIBELLES.code);
    await expect(code).toBeFocused({ timeout: KDF_TIMEOUT });
    await expect(page).toHaveTitle("Code de vérification · Locksy");
    // Collage « 273 647 » : espaces retirés, envoi automatique, sans clic sur « Valider ».
    await code.evaluate((el) => {
      const data = new DataTransfer();
      data.setData("text/plain", "273 647");
      el.dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }));
    });
    await expectShell(page);
    expect(bodies.at(-1)?.totp).toBe("273647");
  });

  test("code de vérification tapé avec une espace : envoyé au 6e chiffre, faux code signalé", async ({ page, org, consoleGuard }) => {
    consoleGuard.allow(/status of 401/);
    const bodies: Record<string, unknown>[] = [];
    await page.route("**/api/auth/login", async (route: Route) => {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      bodies.push(body);
      if (body.totp === "111111") {
        await route.fulfill({ status: 401, json: { error: "invalid_totp", message: "Code faux." } });
        return;
      }
      if (!body.totp) {
        await route.fulfill({ status: 401, json: { error: "totp_required", message: "Code requis." } });
        return;
      }
      await route.continue();
    });
    await page.goto("/");
    await page.getByLabel(LIBELLES.email).fill(org.accounts.user.email);
    await page.getByLabel(LIBELLES.password).fill(org.accounts.user.password);
    await page.getByRole("button", { name: LIBELLES.login }).click();
    const code = page.getByLabel(LIBELLES.code);
    await expect(code).toBeFocused({ timeout: KDF_TIMEOUT });
    await page.keyboard.type("111 111");
    await expect(code).toHaveAttribute("aria-invalid", "true");
    await expect(code).toBeFocused();
    await page.keyboard.type("273 647");
    await expectShell(page);
    expect(bodies.at(-1)?.totp).toBe("273647");
  });

  test("code de secours : même champ « totp » de la connexion", async ({ page, org, consoleGuard }) => {
    consoleGuard.allow(/status of 401/);
    const bodies = await requireTotp(page);
    await page.goto("/");
    await page.getByLabel(LIBELLES.email).fill(org.accounts.user.email);
    await page.getByLabel(LIBELLES.password).fill(org.accounts.user.password);
    await page.getByRole("button", { name: LIBELLES.login }).click();
    await page.getByRole("button", { name: LIBELLES.useBackup }).click({ timeout: KDF_TIMEOUT });
    await page.getByLabel(LIBELLES.backupCode).fill("ABCDE-FGHJK");
    await page.getByRole("button", { name: "Valider" }).click();
    await expectShell(page);
    expect(bodies.at(-1)?.totp).toBe("ABCDE-FGHJK");
  });

  test("compte désactivé : message et contact d'assistance", async ({ page, org, consoleGuard }) => {
    consoleGuard.allow(/status of 403/);
    await page.route("**/api/settings/public", async (route) => {
      const res = await route.fetch();
      const body = await res.json();
      await route.fulfill({ json: { ...body, branding: { ...body.branding, support_contact: "support@e2e.test" } } });
    });
    await page.route("**/api/auth/login", (route) => route.fulfill({ status: 403, json: { error: "account_disabled", message: "Compte désactivé." } }));
    await page.goto("/");
    await page.getByLabel(LIBELLES.email).fill(org.accounts.user.email);
    await page.getByLabel(LIBELLES.password).fill(org.accounts.user.password);
    await page.getByRole("button", { name: LIBELLES.login }).click();
    await expect(page.locator(".c-field__error").filter({ hasText: "Ce compte est désactivé." })).toContainText("Assistance : support@e2e.test", { timeout: KDF_TIMEOUT });
  });

  test("serveur occupé (503 + Retry-After) : nouvel essai poli, connexion sans erreur", async ({ page, org, consoleGuard }) => {
    consoleGuard.allow(/status of 503/);
    let calls = 0;
    await page.route("**/api/auth/prelogin", async (route) => {
      calls += 1;
      if (calls === 1) {
        await route.fulfill({ status: 503, headers: { "Retry-After": "1" }, json: { error: "server_busy", message: "Occupé.", retry_after: 1 } });
        return;
      }
      await route.continue();
    });
    await loginUi(page, org.accounts.user);
    expect(calls).toBe(2);
  });

  test("écran de connexion sans défaut d'accessibilité grave, pied légal présent", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: "Connexion" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Accessibilité" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Mot de passe maître oublié ?" })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    await page.getByRole("link", { name: "Accessibilité" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Déclaration d'accessibilité" })).toBeFocused();
  });
});

test.describe("Montée des paramètres de dérivation après connexion", () => {
  /** Paramètres actuels du compte (réponse de /auth/prelogin). */
  async function currentKdf(page: Page, email: string) {
    const res = await page.request.post("/api/auth/prelogin", { data: { email } });
    expect(res.ok()).toBe(true);
    return (await res.json()).kdf as { m_kib: number; t: number; p: number };
  }

  /** /settings/public annonce des paramètres plus forts (une passe de plus). */
  async function strongerKdf(page: Page, kdf: { m_kib: number; t: number }) {
    await page.route("**/api/settings/public", async (route) => {
      const res = await route.fetch();
      const body = await res.json();
      await route.fulfill({ json: { ...body, kdf: { memory_mib: kdf.m_kib / 1024, iterations: kdf.t + 1, parallelism: 1, upgrade_on_login: true } } });
    });
  }

  test("paramètres renforcés par l'organisation : POST /me/kdf avec la nouvelle clé enveloppée", async ({ page, org }) => {
    const kdf = await currentKdf(page, org.accounts.user.email);
    await strongerKdf(page, kdf);
    const bodies: Record<string, any>[] = [];
    await page.route("**/api/me/kdf", async (route) => {
      bodies.push(route.request().postDataJSON());
      await route.fulfill({ status: 204 });
    });
    await loginUi(page, org.accounts.user);
    expect(bodies).toHaveLength(1);
    const sent = bodies[0];
    expect(sent.kdf).toMatchObject({ alg: "argon2id", m_kib: kdf.m_kib, t: kdf.t + 1 });
    expect(sent.current_auth_key).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(sent.auth_key).not.toBe(sent.current_auth_key);
    expect(sent.wrapped_user_key).toMatch(/^v1\./);
  });

  test("serveur sans la route (404) : connexion normale, rien d'affiché", async ({ page, org, consoleGuard }) => {
    consoleGuard.allow(/status of 40[45]/);
    const kdf = await currentKdf(page, org.accounts.user.email);
    await strongerKdf(page, kdf);
    await loginUi(page, org.accounts.user);
    await expect(page).toHaveTitle("Mon coffre · Locksy");
    await expect(page.locator(".c-toasts")).not.toContainText("Erreur");
  });
});
