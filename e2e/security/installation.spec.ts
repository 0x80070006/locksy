// Installation (premier compte) sur un serveur vierge (locksy-vierge) :
// inscription refusée sans jeton ou avec un faux jeton ; 20 faux jetons
// bloquent l'installation, même avec le bon jeton, le temps du délai
// annoncé ; une fois le propriétaire créé par l'interface, le jeton ne sert
// plus. Une adresse X-Forwarded-For par essai : seul le blocage global des
// jetons d'installation joue, pas le plafond d'inscriptions par adresse.

import { test, expect } from "@playwright/test";
import { installOwner, testPassword } from "../fixtures/ui.ts";
import { adresse, bloque, corpsInscription, inconnu, refus, SANS_SURCOUCHE, VIERGE_SETUP_TOKEN, VIERGE_URL } from "./outils.ts";

/** Seuil global des essais de jeton d'installation (auth.rs, SETUP_ATTEMPT_KEY). */
const ESSAIS_AVANT_BLOCAGE = 20;

test.describe.configure({ mode: "serial" });

test.describe("Installation d'un serveur vierge", () => {
  test.skip(!VIERGE_URL, SANS_SURCOUCHE);

  const inscrire = (request: import("@playwright/test").APIRequestContext, extra: Record<string, unknown> = {}) =>
    request.post(`${VIERGE_URL}/api/auth/register`, {
      data: corpsInscription(inconnu("installation"), extra),
      headers: { "X-Forwarded-For": adresse() },
    });

  test("sans jeton : refusé", async ({ request }) => {
    const sante = await (await request.get(`${VIERGE_URL}/api/health`)).json();
    expect(sante.needs_setup, "le serveur doit être vierge").toBe(true);
    await refus(await inscrire(request), 403, "setup_token_required");
    await refus(await inscrire(request, { setup_token: "   " }), 403, "setup_token_required");
  });

  test(`faux jeton : refusé, et ${ESSAIS_AVANT_BLOCAGE} essais bloquent l'installation`, async ({ request }) => {
    for (let i = 1; i <= ESSAIS_AVANT_BLOCAGE; i++) {
      await refus(await inscrire(request, { setup_token: `faux-jeton-${i}-0123456789abcdef` }), 403, "invalid_setup_token");
    }
    // Bloqué pour tout le monde, même avec le bon jeton.
    const res = await inscrire(request, { setup_token: VIERGE_SETUP_TOKEN });
    await bloque(res);
    const attente = Number(res.headers()["retry-after"]);
    test.info().annotations.push({ type: "blocage", description: `installation bloquée ${attente} s après ${ESSAIS_AVANT_BLOCAGE} faux jetons` });
    expect((await (await request.get(`${VIERGE_URL}/api/health`)).json()).needs_setup).toBe(true);
    // Attente du délai annoncé, pour l'installation qui suit.
    await new Promise((r) => setTimeout(r, (attente + 1) * 1000));
  });

  test("le propriétaire s'installe par l'interface, puis le jeton ne sert plus", async ({ browser, request }) => {
    const ctx = await browser.newContext({ baseURL: VIERGE_URL, locale: "fr-FR", timezoneId: "Europe/Paris", extraHTTPHeaders: { "X-Forwarded-For": adresse() } });
    try {
      await installOwner(await ctx.newPage(), VIERGE_SETUP_TOKEN, { email: "proprietaire@vierge.test", name: "Paule Vierge", password: testPassword() });
    } finally {
      await ctx.close();
    }
    expect((await (await request.get(`${VIERGE_URL}/api/health`)).json()).needs_setup).toBe(false);
    // Jeton consommé, bon ou faux : l'inscription passe désormais par invitation.
    await refus(await inscrire(request, { setup_token: VIERGE_SETUP_TOKEN }), 403, "forbidden");
    await refus(await inscrire(request, { setup_token: "faux-jeton-apres-installation-0123" }), 403, "forbidden");
    await refus(await inscrire(request), 403, "forbidden");
  });
});
