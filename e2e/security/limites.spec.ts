// Limites de débit (G10) : pour chaque plafond, N essais passent et le
// N+1-ième reçoit 429 « rate_limited » avec Retry-After, retry_after et un
// message en français. Les plafonds sont lus dans les sources (config.rs,
// sso.rs, auth.rs, registre des réglages), jamais recopiés de mémoire.
//
// Sur « locksy » (proxy de confiance), chaque test a sa propre adresse
// X-Forwarded-For : les compteurs ne se mélangent pas. Sur « locksy-direct »
// (sans proxy de confiance), X-Forwarded-For est ignoré : toutes les
// requêtes du lanceur partagent un compteur, que l'on prouve réglable (5).

import { test, expect, type APIRequestContext, type APIResponse } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { BASE_URL, E2E_DIR } from "../fixtures/env.ts";
import { installOwner, loginUi, logoutUi, testPassword } from "../fixtures/ui.ts";
import { adresse, b64, bloque, corpsInscription, DIRECT_SETUP_TOKEN, DIRECT_URL, inconnu, SANS_SURCOUCHE } from "./outils.ts";

// ------------------------------------------------------------ Plafonds lus dans les sources

const source = (f: string) => readFileSync(resolve(E2E_DIR, "../crates", f), "utf8");

function lu(fichier: string, motif: RegExp, quoi: string): number {
  const m = source(fichier).match(motif);
  if (!m) throw new Error(`Plafond « ${quoi} » introuvable dans crates/${fichier} : motif ${motif} à mettre à jour.`);
  return Number(m[1]);
}

const ip = (nom: string) => lu("locksy-server/src/config.rs", new RegExp(`"LOCKSY_RATELIMIT_${nom}_IP", (\\d+),`), `${nom} par adresse`);

const PLAFOND = {
  prelogin: ip("PRELOGIN"),
  loginIp: ip("LOGIN"),
  register: ip("REGISTER"),
  recoverIp: ip("RECOVER"),
  shareOpen: ip("SHARE_OPEN"),
  invite: ip("INVITE"),
  paire: lu("locksy-core/src/settings.rs", /s\("lockout\.pair_threshold",[^\n]*I\((\d+)\)\)/, "paire e-mail et adresse"),
  compte: lu("locksy-core/src/settings.rs", /s\("lockout\.account_threshold",[^\n]*I\((\d+)\)\)/, "adresse e-mail"),
  recoverCompte: lu("locksy-server/src/auth.rs", /format!\("recover:\{email\}"\);[\s\S]*?limiter\.attempt\(&key, (\d+)\)/, "récupération par compte"),
  ssoStart: lu("locksy-server/src/sso.rs", /"sso-start:\{\}", meta\.rate_key\(\)\), (\d+), 60\)/, "sso-start"),
  ssoRedeem: lu("locksy-server/src/sso.rs", /"sso-redeem:\{\}", meta\.rate_key\(\)\), (\d+), 60\)/, "sso-redeem"),
};

// ------------------------------------------------------------ Outils

type Essai = (xff: string, n: number) => Promise<APIResponse>;

/**
 * Joue `plafond` essais (aucun 429, aucun 5xx), puis vérifie que le suivant
 * est bloqué. `xff` : adresse fixe (plafond par adresse) ou neuve à chaque
 * essai (plafond par compte).
 */
async function nPuisBloque(essai: Essai, plafond: number, xff: () => string) {
  for (let n = 1; n <= plafond; n++) {
    const res = await essai(xff(), n);
    expect(res.status(), `essai ${n} sur ${plafond} : ${await res.text()}`).not.toBe(429);
    expect(res.status(), `essai ${n} : erreur serveur`).toBeLessThan(500);
  }
  await bloque(await essai(xff(), plafond + 1));
}

const fixe = () => {
  const a = adresse();
  return () => a;
};

const post = (api: APIRequestContext, url: string, data: unknown) => (xff: string) =>
  api.post(url, { data, headers: { "X-Forwarded-For": xff }, maxRedirects: 0 });

// ------------------------------------------------------------ Plafonds par adresse et par compte

test.describe("Limites de débit sur le serveur derrière proxy", () => {
  test.use({ baseURL: BASE_URL });

  test(`pré-connexion : ${PLAFOND.prelogin} par minute et par adresse`, async ({ request }) => {
    await nPuisBloque((xff) => post(request, "/api/auth/prelogin", { email: inconnu() })(xff), PLAFOND.prelogin, fixe());
  });

  test(`connexion : ${PLAFOND.paire} échecs par paire (e-mail, adresse)`, async ({ request }) => {
    const email = inconnu("paire");
    await nPuisBloque((xff) => post(request, "/api/auth/login", { email, auth_key: b64(32) })(xff), PLAFOND.paire, fixe());
  });

  test(`connexion : ${PLAFOND.compte} échecs par e-mail, toutes adresses confondues`, async ({ request }) => {
    const email = inconnu("compte");
    await nPuisBloque((xff) => post(request, "/api/auth/login", { email, auth_key: b64(32) })(xff), PLAFOND.compte, adresse);
  });

  test(`connexion : ${PLAFOND.loginIp} essais par adresse en 10 minutes, e-mails différents`, async ({ request }) => {
    await nPuisBloque((xff) => post(request, "/api/auth/login", { email: inconnu("ip"), auth_key: b64(32) })(xff), PLAFOND.loginIp, fixe());
  });

  test(`inscription : ${PLAFOND.register} par heure et par adresse`, async ({ request }) => {
    await nPuisBloque((xff) => post(request, "/api/auth/register", corpsInscription(inconnu("inscription")))(xff), PLAFOND.register, fixe());
  });

  test(`récupération : ${PLAFOND.recoverIp} par heure et par adresse`, async ({ request }) => {
    const essai: Essai = (xff) => post(request, "/api/auth/recover/start", { email: inconnu("recup"), recovery_auth: b64(32) })(xff);
    await nPuisBloque(essai, PLAFOND.recoverIp, fixe());
  });

  test(`récupération : ${PLAFOND.recoverCompte} échecs par compte, toutes adresses confondues`, async ({ request }) => {
    const email = inconnu("recup-compte");
    await nPuisBloque((xff) => post(request, "/api/auth/recover/start", { email, recovery_auth: b64(32) })(xff), PLAFOND.recoverCompte, adresse);
  });

  test(`ouverture de lien : ${PLAFOND.shareOpen} par minute et par adresse`, async ({ request }) => {
    const essai: Essai = (xff) => request.get(`/api/public/shares/${b64(32)}`, { headers: { "X-Forwarded-For": xff } });
    await nPuisBloque(essai, PLAFOND.shareOpen, fixe());
  });

  test(`lecture d'invitation : ${PLAFOND.invite} par minute et par adresse`, async ({ request }) => {
    const essai: Essai = (xff) => request.get(`/api/invites/${b64(32)}`, { headers: { "X-Forwarded-For": xff } });
    await nPuisBloque(essai, PLAFOND.invite, fixe());
  });

  test(`connexion d'entreprise : ${PLAFOND.ssoStart} démarrages par minute et par adresse`, async ({ request }) => {
    const essai: Essai = (xff) => request.get("/api/sso/start", { headers: { "X-Forwarded-For": xff }, maxRedirects: 0 });
    await nPuisBloque(essai, PLAFOND.ssoStart, fixe());
  });

  test(`connexion d'entreprise : ${PLAFOND.ssoRedeem} échanges de ticket par minute et par adresse`, async ({ request }) => {
    await nPuisBloque((xff) => post(request, "/api/sso/redeem", { ticket: b64(32) })(xff), PLAFOND.ssoRedeem, fixe());
  });

  test("IPv6 : le compteur porte sur le préfixe /64", async ({ request }) => {
    const prelogin = (xff: string) => post(request, "/api/auth/prelogin", { email: inconnu() })(xff);
    const moitie = PLAFOND.prelogin / 2;
    for (let n = 0; n < PLAFOND.prelogin; n++) {
      const res = await prelogin(n < moitie ? "2001:db8:1:2::1" : "2001:db8:1:2::ffff");
      expect(res.status(), `essai ${n + 1}`).toBe(200);
    }
    // Même /64, autre adresse : bloquée.
    await bloque(await prelogin("2001:db8:1:2::1"));
    await bloque(await prelogin("2001:db8:1:2:abcd::7"));
    // /64 voisin : compteur propre.
    expect((await prelogin("2001:db8:1:3::1")).status()).toBe(200);
  });
});

// ------------------------------------------------------------ Sans proxy de confiance

test.describe("Limites sans proxy de confiance (locksy-direct)", () => {
  test.describe.configure({ mode: "serial" });

  test("plafond réglé à 5, X-Forwarded-For ignoré, une réussite ne remet pas le compteur à zéro", async ({ browser, request }) => {
    test.skip(!DIRECT_URL, SANS_SURCOUCHE);
    const plafond = 5; // LOCKSY_RATELIMIT_LOGIN_IP de docker-compose.securite.yml (défaut : PLAFOND.loginIp).
    expect(plafond).toBeLessThan(PLAFOND.loginIp);
    const ctx = await browser.newContext({ baseURL: DIRECT_URL, locale: "fr-FR", timezoneId: "Europe/Paris" });
    try {
      const page = await ctx.newPage();
      const owner = { email: "proprietaire@direct.test", name: "Paule Directe", password: testPassword() };
      await installOwner(page, DIRECT_SETUP_TOKEN, owner);
      await logoutUi(page);
      // Chaque échec annonce une adresse différente : sans proxy de confiance,
      // le serveur ne la croit pas et compte tout sur l'adresse réelle.
      const echec = () =>
        request.post(`${DIRECT_URL}/api/auth/login`, {
          data: { email: inconnu("direct"), auth_key: b64(32) },
          headers: { "X-Forwarded-For": adresse() },
        });
      let essais = 0;
      for (; essais < 2; essais++) expect((await echec()).status()).toBe(401);
      // Réussite par l'interface (même adresse réelle, celle du lanceur).
      await loginUi(page, owner);
      essais++;
      for (; essais < plafond; essais++) expect((await echec()).status()).toBe(401);
      await bloque(await echec());
    } finally {
      await ctx.close();
    }
  });
});
