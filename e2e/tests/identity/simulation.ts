// Serveur d'identité simulé pour les tests de la connexion d'entreprise (L13).
//
// L'image de test (locksy-e2e-server:fast) ne contient pas les routes de la
// vague 2 (/admin/identity/status, /admin/sso/test-start, /admin/ldap/history,
// synchronisation à blanc…) : elles sont simulées par page.route() selon le
// contrat C1.2. Les routes historiques (/admin/sso, /admin/ldap, /admin/scim)
// le sont aussi, pour que les tests ne modifient pas l'organisation partagée.
//
// Chaque route peut être forcée en échec : `sim.fail("PUT /admin/sso", 500)`
// (réponse d'erreur) ou `sim.fail("DELETE /admin/scim/token", "reseau")`
// (connexion coupée).

import { expect, type Page, type Request, type Route } from "@playwright/test";
import { axe } from "../../fixtures/axe.ts";
import { L } from "../../fixtures/libelles.ts";
import { KDF_TIMEOUT } from "../../fixtures/ui.ts";

const now = () => Math.floor(Date.now() / 1000);

export interface IgnoredAccount {
  login: string;
  email: string | null;
  reason: string;
}

/** Comptes ignorés de la synchronisation à blanc simulée (raisons du contrat C1.2). */
export const IGNORED: IgnoredAccount[] = [
  { login: "jdurand", email: null, reason: "no_email" },
  { login: "stagiaire", email: "stagiaire@autre-domaine.fr", reason: "domain_not_allowed" },
  { login: "mpetit", email: "mpetit@entreprise.fr", reason: "disabled_in_directory" },
];

type Failure = number | "reseau";

export interface IdentitySim {
  /** Configuration SSO (forme de GET /admin/sso). */
  sso: Record<string, unknown>;
  /** Configuration de l'annuaire (forme de GET /admin/ldap). */
  ldap: Record<string, unknown>;
  scim: { token_set: boolean; token_created_at: number | null; token_expires_at: number | null; last_used_at: number | null };
  /** Tests réussis par l'administrateur (secondes Unix) ; null = jamais. */
  ssoOkByMe: number | null;
  ldapOkByMe: number | null;
  /** Requêtes reçues, dans l'ordre : « MÉTHODE /chemin?requête » et corps JSON. */
  calls: { key: string; body: unknown }[];
  /** Réponse 404 pour GET /admin/identity/status (serveur pas encore à jour). */
  statusMissing: boolean;
  /** Code d'échec d'un test SSO enregistré (sinon réussite) au prochain test-start. */
  nextSsoTest: { ok: boolean; error_code: string | null } | null;
  fail(route: string, how: Failure, error?: { code: string; message?: string }): void;
  heal(route: string): void;
  bodiesOf(route: string): unknown[];
}

const SSO_DEFAULT = {
  enabled: false, label: "", issuer: "", client_id: "", client_secret: "", has_secret: false,
  public_url: "https://locksy.entreprise.fr", enforce: false, auto_provision: false, allowed_domains: [],
  redirect_uri: "https://locksy.entreprise.fr/api/sso/callback", allowed_extension_ids: [], trust_unverified_email: false,
};

const LDAP_DEFAULT = {
  enabled: false, url: "", starttls: false, bind_dn: "", bind_password: "", has_password: false, base_dn: "",
  group_dn: "", login_attribute: "sAMAccountName", email_attribute: "mail", ca_pem: "", sync_minutes: 15,
  allow_login: false, enforce: false, label: "Compte Windows", last_sync: 0, last_result: "",
};

/**
 * Installe le serveur simulé sur la page. `init` règle l'état de départ
 * (configuration déjà faite, jeton SCIM présent…).
 */
export async function simulateIdentity(page: Page, init: Partial<Pick<IdentitySim, "sso" | "ldap" | "scim" | "ssoOkByMe" | "ldapOkByMe" | "statusMissing">> = {}): Promise<IdentitySim> {
  const failures = new Map<string, { how: Failure; error?: { code: string; message?: string } }>();
  const history: Record<string, unknown>[] = [];
  const sim: IdentitySim = {
    sso: { ...SSO_DEFAULT, ...(init.sso || {}) },
    ldap: { ...LDAP_DEFAULT, ...(init.ldap || {}) },
    scim: init.scim || { token_set: false, token_created_at: null, token_expires_at: null, last_used_at: null },
    ssoOkByMe: init.ssoOkByMe ?? null,
    ldapOkByMe: init.ldapOkByMe ?? null,
    statusMissing: init.statusMissing ?? false,
    nextSsoTest: null,
    calls: [],
    fail(route, how, error) { failures.set(route, { how, error }); },
    heal(route) { failures.delete(route); },
    bodiesOf(route) { return sim.calls.filter((c) => c.key.split("?")[0] === route).map((c) => c.body); },
  };
  let lastSsoTest: Record<string, unknown> | null = null;

  const status = () => ({
    sso: {
      configured: !!(sim.sso.issuer && sim.sso.client_id), enabled: !!sim.sso.enabled, enforce: !!sim.sso.enforce,
      last_test: lastSsoTest, last_ok_by_me_at: sim.ssoOkByMe, last_error: null,
    },
    ldap: {
      configured: !!(sim.ldap.url && sim.ldap.bind_dn && sim.ldap.base_dn), enabled: !!sim.ldap.enabled,
      allow_login: !!sim.ldap.allow_login, enforce: !!sim.ldap.enforce, last_test: null,
      last_ok_by_me_at: sim.ldapOkByMe, last_sync: history[0] || null,
    },
    scim: { ...sim.scim, base_url: "https://locksy.entreprise.fr/scim/v2" },
  });

  const json = (route: Route, body: unknown, statusCode = 200) => route.fulfill({ status: statusCode, json: body });
  const parse = (req: Request) => {
    try {
      return req.postDataJSON();
    } catch {
      return null;
    }
  };

  /** Table des routes simulées : « MÉTHODE /chemin » -> réponse. */
  const handlers: Record<string, (route: Route, body: any, url: URL) => Promise<void>> = {
    "GET /admin/identity/status": (r) => (sim.statusMissing
      ? json(r, { error: "not_found", message: "Introuvable." }, 404)
      : json(r, status())),
    "GET /admin/sso": (r) => json(r, { ...sim.sso, client_secret: "" }),
    "PUT /admin/sso": (r, b) => {
      const enforce = !!b.enforce;
      if (enforce && !sim.sso.enforce && !(sim.ssoOkByMe && now() - sim.ssoOkByMe < 86400)) {
        return json(r, { error: "test_required", message: "Test requis." }, 409);
      }
      sim.sso = { ...sim.sso, ...b, has_secret: !!(b.client_secret || sim.sso.has_secret), client_secret: "" };
      return json(r, { ...sim.sso });
    },
    "POST /admin/sso/test": (r) => json(r, { issuer: sim.sso.issuer, authorization_endpoint: "", token_endpoint: "", keys: 2 }),
    "POST /admin/sso/test-start": (r) => {
      // Le fournisseur « répond » aussitôt : le test est enregistré côté serveur.
      const outcome = sim.nextSsoTest || { ok: true, error_code: null };
      lastSsoTest = { at: now(), ok: outcome.ok, error_code: outcome.error_code, by_me: true };
      if (outcome.ok) sim.ssoOkByMe = now();
      return json(r, { url: "about:blank" });
    },
    "GET /admin/ldap": (r) => json(r, { ...sim.ldap, bind_password: "" }),
    "PUT /admin/ldap": (r, b) => {
      if (b.enforce && !sim.ldap.enforce && !(sim.ldapOkByMe && now() - sim.ldapOkByMe < 86400)) {
        return json(r, { error: "test_required", message: "Test requis." }, 409);
      }
      sim.ldap = { ...sim.ldap, ...b, has_password: !!(b.bind_password || sim.ldap.has_password), bind_password: "" };
      return json(r, { ...sim.ldap });
    },
    "POST /admin/ldap/test": (r) => json(r, { users: 45, sample: ["jdupont", "mmartin"] }),
    "POST /admin/ldap/test-login": (r) => {
      sim.ldapOkByMe = now();
      return json(r, { ok: true, error_code: null, email: "proprietaire@e2e.test" });
    },
    "POST /admin/ldap/sync": (r, _b, url) => {
      const dry = url.searchParams.get("dry_run") === "true";
      const report = { found: 42, created: dry ? 39 : 0, updated: 0, disabled: 0, enabled: 0, skipped: [] };
      history.unshift({
        id: history.length + 1, at: now(), dry_run: dry, ok: true, ...report, ignored: IGNORED,
        ignored_count: IGNORED.length, error_code: null, triggered_by: "moi",
      });
      return json(r, { ...report, dry_run: dry, ignored: IGNORED });
    },
    "GET /admin/ldap/history": (r) => json(r, history),
    "GET /admin/scim": (r) => json(r, {
      enabled: sim.scim.token_set, created_at: sim.scim.token_created_at, base_url: "https://locksy.entreprise.fr/scim/v2",
      expires_at: sim.scim.token_expires_at, last_used_at: sim.scim.last_used_at,
    }),
    "POST /admin/scim/token": (r) => {
      sim.scim = { token_set: true, token_created_at: now(), token_expires_at: null, last_used_at: null };
      return json(r, { token: "scim_jeton_affiche_une_fois_0123456789", base_url: "https://locksy.entreprise.fr/scim/v2", expires_at: null });
    },
    "DELETE /admin/scim/token": (r) => {
      sim.scim = { token_set: false, token_created_at: null, token_expires_at: null, last_used_at: null };
      return r.fulfill({ status: 204 });
    },
    "GET /admin/directory": (r) => json(r, []),
  };

  await page.route(
    (url) => /\/api\/admin\/(identity|sso|ldap|scim|directory)(\/|$|\?)/.test(url.pathname + url.search),
    async (route) => {
      const req = route.request();
      const url = new URL(req.url());
      const path = url.pathname.replace(/^\/api/, "");
      const key = `${req.method()} ${path}`;
      const body = parse(req);
      sim.calls.push({ key: `${key}${url.search}`, body });
      const failure = failures.get(key);
      if (failure) {
        if (failure.how === "reseau") return route.abort("connectionreset");
        const err = failure.error || { code: "internal", message: "Erreur interne." };
        return json(route, { error: err.code, message: err.message || "Erreur." }, failure.how);
      }
      const handler = handlers[key];
      if (!handler) return json(route, { error: "not_found", message: "Introuvable." }, 404);
      return handler(route, body || {}, url);
    },
  );
  return sim;
}

/**
 * Connexion par adresse et mot de passe maître, comme loginUi des fixtures,
 * mais l'arrivée est aussi reconnue au bouton « Menu » ou « Menu du compte » :
 * sous 600 px, la navigation principale est repliée dans le tiroir (inert), ce
 * que expectShell des fixtures ne sait pas encore attendre. Sert aux tests
 * @mobile (fixture `page`).
 */
export async function connexion(page: Page, a: { email: string; password: string }) {
  await page.goto("/");
  await page.getByLabel(L.email).fill(a.email);
  await page.getByLabel(L.masterPassword).fill(a.password);
  await page.getByRole("button", { name: L.login }).click();
  const arrivee = page.getByRole("navigation", { name: L.mainNav })
    .or(page.getByRole("button", { name: L.mobileMenu }))
    .or(page.getByRole("button", { name: L.accountMenu }));
  await expect(arrivee.first()).toBeVisible({ timeout: KDF_TIMEOUT });
}

/** Ouvre une page de la connexion d'entreprise sans recharger l'application (session conservée). */
export async function openIdentity(page: Page, section = "") {
  const hash = section ? `#/admin/connexion/${section}` : "#/admin/connexion";
  // La vue ouverte après la connexion (le coffre) doit avoir fini son rendu
  // (titre h1 présent) : changer d'adresse pendant ce premier rendu laisse
  // parfois la zone de contenu sur le squelette de chargement du routeur
  // (course signalée en handoff au lot L9).
  await expect(page.locator("main h1").first()).toBeAttached({ timeout: KDF_TIMEOUT });
  await page.evaluate((h) => { location.hash = h; }, hash);
}

/** Zone de contenu (les régions d'annonce et les toasts sont hors de <main>). */
export const vue = (page: Page) => page.getByRole("main");

/**
 * Violations d'accessibilité « serious » et « critical » de la zone de
 * contenu : la coquille (barre du haut, navigation) est testée par ses lots.
 */
export async function violationsDeLaVue(page: Page): Promise<string[]> {
  const { violations } = await axe(page).include("main").analyze();
  return violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => `${v.id} (${v.impact}) : ${v.nodes.slice(0, 6).map((n) => n.target.join(" ")).join(" | ")}`);
}

/** Message d'un toast (aussi présent dans la région d'annonce) : visible et annoncé. */
export const annonce = (page: Page, text: string) => page.getByText(text, { exact: true }).first();
