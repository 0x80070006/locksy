// Coffre verrouillé (cahier §3.3.1, règle A12) : verrouillage manuel puis
// retour sur la page quittée, verrouillage automatique avec préavis de
// 60 secondes (horloge simulée), « Jamais » refusé quand l'organisation
// l'interdit, accessibilité de l'écran verrouillé.
//
// La politique de l'organisation (GET /settings/policy, A.4) est simulée par
// page.route() : l'image de test ne permet pas de la régler sans effet de bord.

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { seriousViolations } from "../../fixtures/axe.ts";
import { expectShell, KDF_TIMEOUT, loginUi } from "../../fixtures/ui.ts";
import { navPrincipale, preparer } from "../shell/outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(preparer);

const LIBELLES = {
  password: /^Mot de passe maître$/,
  unlock: /^Déverrouiller$/,
  lock: /^Verrouiller$/,
  stay: "Rester déverrouillé",
  logout: /^Se déconnecter$/,
};

/** Ajoute des entrées à la politique servie par le serveur. */
async function policy(page: Page, extra: Record<string, unknown>) {
  await page.route("**/api/settings/policy", async (route) => {
    const res = await route.fetch();
    const body = res.ok() ? await res.json() : { revision: 0, policy: {} };
    await route.fulfill({ json: { ...body, revision: (body.revision ?? 0) + 1000, policy: { ...(body.policy ?? {}), ...extra } } });
  });
}

async function unlock(page: Page, password: string) {
  await page.getByLabel(LIBELLES.password).fill(password);
  await page.getByRole("button", { name: LIBELLES.unlock }).click();
  await expectShell(page);
}

test("verrouillage manuel : session gardée, retour sur la page quittée après déverrouillage", async ({ page, org }) => {
  await loginUi(page, org.accounts.user);
  await navPrincipale(page).getByRole("link", { name: "Corbeille" }).click();
  await expect(page).toHaveTitle("Corbeille · Locksy");

  await page.getByRole("button", { name: LIBELLES.lock }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Verrouillé" })).toBeVisible();
  await expect(page).toHaveTitle("Verrouillé · Locksy");
  await expect(page).toHaveURL(/#\/verrouille$/);
  await expect(page.getByText("Votre coffre est verrouillé.", { exact: true })).toBeVisible();
  await expect(page.getByText(org.accounts.user.name)).toBeVisible();
  await expect(page.getByLabel(LIBELLES.password)).toBeFocused();
  // Coquille détruite : aucun nom de coffre ni compteur ne reste affiché.
  await expect(navPrincipale(page)).toHaveCount(0);
  expect(await page.evaluate(() => sessionStorage.getItem("locksy.session"))).toBeTruthy();
  expect(await seriousViolations(page)).toEqual([]);

  // Mauvais mot de passe : erreur sous le champ, aucune requête de connexion.
  await page.getByLabel(LIBELLES.password).fill("pas-le-bon-mot-de-passe");
  await page.getByRole("button", { name: LIBELLES.unlock }).click();
  await expect(page.locator("#contenu").getByText(/^Mot de passe maître incorrect./)).toBeVisible({ timeout: KDF_TIMEOUT });

  await unlock(page, org.accounts.user.password);
  await expect(page).toHaveTitle("Corbeille · Locksy");
  await expect(page).toHaveURL(/#\/corbeille$/);
});

test("verrouillage automatique : préavis de 60 s, « Rester déverrouillé », puis verrouillage", async ({ page, org }) => {
  await page.clock.install();
  await policy(page, { "client.autolock_minutes": { value: 2, mode: "enforced", min: 1, max: 1440 } });
  await loginUi(page, org.accounts.user);

  await page.clock.fastForward("01:01");
  const stay = page.getByRole("button", { name: LIBELLES.stay });
  await expect(stay).toBeVisible();
  await expect(page.locator("#alert")).toHaveText("Verrouillage dans 60 secondes");
  // Horloge simulée : le contrôle de stabilité d'un clic attend des images ; le clavier suffit.
  await stay.focus();
  await page.keyboard.press("Enter");
  await expect(stay).toHaveCount(0);

  // Le compte à rebours repart de zéro : rien à 1 min 30.
  await page.clock.fastForward("01:30");
  await expect(navPrincipale(page)).toBeVisible();

  await page.clock.fastForward("01:00");
  await expect(page.getByRole("heading", { level: 1, name: "Verrouillé" })).toBeVisible();
  await expect(page.getByText("Votre coffre est verrouillé (inactivité).")).toBeVisible();
  await unlock(page, org.accounts.user.password);
});

test("« Jamais » interdit par l'organisation : la préférence est ramenée et signalée", async ({ page, org }) => {
  await loginUi(page, org.accounts.user);
  // Préférence « Jamais » (0) chiffrée par la page, servie comme document du serveur.
  const cipher = await page.evaluate(async () => (await import("/js/vault.js")).encryptPrefs({ v: 1, lock: { minutes: 0 } }));
  await page.route("**/api/me/prefs", (route) => (route.request().method() === "GET"
    ? route.fulfill({ json: { revision: 9, cipher, updated_at: 1 } })
    : route.fallback()));
  // /sync annonce la même révision (serveurs qui publient prefs_revision).
  await page.route("**/api/sync*", async (route) => {
    const res = await route.fetch();
    await route.fulfill({ response: res, json: { ...(await res.json()), prefs_revision: 9 } });
  });
  await policy(page, {
    "client.autolock_minutes": { value: 10, mode: "default", min: 1, max: 30 },
    "client.autolock_allow_never": { value: false },
  });
  await page.getByRole("button", { name: LIBELLES.lock }).click();
  await unlock(page, org.accounts.user.password);
  await expect(page.locator(".c-toasts").getByText("Votre organisation limite le verrouillage à 30 min.")).toBeVisible();
  const effective = await page.evaluate(async () => (await import("/js/settings-client.js")).effective("client.autolock_minutes"));
  expect(effective).toMatchObject({ value: 30, max: 30 });
});

test("« Se déconnecter » depuis l'écran verrouillé : session fermée", async ({ page, org }) => {
  await loginUi(page, org.accounts.user);
  await page.getByRole("button", { name: LIBELLES.lock }).click();
  await page.getByRole("link", { name: LIBELLES.logout }).click();
  await expect(page.getByRole("button", { name: /^Se connecter$/ })).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem("locksy.session"))).toBeNull();
});
