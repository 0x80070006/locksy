// Paramètres › Mon compte (cahier §3.3.8, écarts #1 et #4) : nouvelle clé de
// récupération (échec puis réussite, fichier .txt, confirmation exigée) ;
// double authentification activée avec ses codes de secours montrés une
// seule fois, compteur, régénération confirmée par le mot de passe maître,
// fichier .txt. Les routes des codes de secours (C1.3) sont simulées : le
// serveur de l'image e2e ne les a pas encore.

import { readFile } from "node:fs/promises";
import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { KDF_TIMEOUT } from "../../fixtures/ui.ts";
import { secondsLeft, totp } from "../../fixtures/totp.ts";
import { aller, notification, nouveauCompte, tolerer } from "./outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(({ consoleGuard }) => tolerer(consoleGuard));

const CODES = Array.from({ length: 10 }, (_, i) => `ABCDE-${String(10_000 + i).slice(-5)}`.replace(/0/g, "Z"));
const NOUVEAUX = CODES.map((c) => c.replace("ABCDE", "QRSTV"));

/** Télécharge le fichier .txt de la fenêtre de secrets et renvoie son nom et son texte. */
async function telecharger(page: Page, fenetre: ReturnType<Page["getByRole"]>) {
  const [download] = await Promise.all([page.waitForEvent("download"), fenetre.getByRole("button", { name: "Télécharger (.txt)" }).click()]);
  return { nom: download.suggestedFilename(), texte: await readFile(await download.path(), "utf8") };
}

test("clé de récupération : échec signalé, puis nouvelle clé téléchargée en .txt", async ({ page, apiAs, consoleGuard }) => {
  test.setTimeout(150_000);
  consoleGuard.allow(/status of 500/);
  const compte = await nouveauCompte(page, await apiAs("owner"), "recuperation");
  let echec = true;
  await page.route("**/api/me/recovery", (route) => {
    if (!echec) return route.fallback();
    echec = false;
    return route.fulfill({ status: 500, json: { error: "internal", message: "Erreur interne." } });
  });
  await aller(page, "/parametres/compte");
  await page.getByRole("button", { name: "Générer une nouvelle clé" }).click();
  const saisie = page.getByRole("dialog", { name: "Générer une nouvelle clé de récupération" });
  await saisie.getByLabel(/^Mot de passe maître$/).fill(compte.password);
  await saisie.getByRole("button", { name: "Générer la clé" }).click();
  await expect(saisie.locator(".c-alert")).toBeVisible({ timeout: KDF_TIMEOUT });
  await saisie.getByRole("button", { name: "Générer la clé" }).click();

  const fenetre = page.getByRole("dialog", { name: "Votre nouvelle clé de récupération" });
  await expect(fenetre).toBeVisible({ timeout: KDF_TIMEOUT });
  const cle = ((await fenetre.locator("li").first().textContent()) ?? "").trim();
  expect(cle.length).toBeGreaterThan(20);
  const { nom, texte } = await telecharger(page, fenetre);
  expect(nom).toBe("locksy-cle-de-recuperation.txt");
  expect(texte).toContain(cle);
  expect(texte).toContain(compte.email);

  // « Terminé » exige la confirmation ; rien n'est gardé dans le navigateur.
  await fenetre.getByRole("button", { name: "Terminé" }).click();
  await expect(fenetre.getByText("Cochez la case pour confirmer que vous les avez conservés.")).toBeVisible();
  await fenetre.getByLabel("J'ai conservé ma clé de récupération").check();
  await fenetre.getByRole("button", { name: "Terminé" }).click();
  await expect(fenetre).toHaveCount(0);
  await expect(notification(page, "Nouvelle clé de récupération enregistrée.")).toBeVisible();
  const stocke = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
  expect(stocke).not.toContain(cle);
});

test("double authentification : codes de secours montrés une fois, compteur, régénération confirmée", async ({ page, apiAs, consoleGuard }) => {
  test.setTimeout(180_000);
  consoleGuard.allow(/status of (401|404|500)/);
  // Compte créé avant toute simulation : l'inscription ne passe par aucune interception.
  const compte = await nouveauCompte(page, await apiAs("owner"), "secours");
  // Activation réelle ; la réponse reçoit les codes de secours du contrat C1.3.
  await page.route("**/api/me/2fa/enable", async (route) => {
    const res = await route.fetch();
    if (!res.ok()) return route.fulfill({ response: res });
    return route.fulfill({ json: { ...(await res.json()), recovery_codes: CODES } });
  });
  let restants = 10;
  let echecs = 1;
  const enTetes: (string | undefined)[] = [];
  // POST /auth/reauth (C1.3) : la 2FA active exige le code pour « totp.recovery_codes ».
  await page.route("**/api/auth/reauth", (route) => {
    const body = route.request().postDataJSON();
    if (body.action !== "totp.recovery_codes") return route.fulfill({ status: 400, json: { error: "bad_request", message: "Action inconnue." } });
    if (!body.totp) return route.fulfill({ status: 401, json: { error: "totp_required", message: "Code requis." } });
    return route.fulfill({ json: { token: `rt1.${"a".repeat(43)}`, expires_in: 120, action: body.action } });
  });
  await page.route("**/api/me/2fa/recovery-codes", (route) => {
    if (route.request().method() === "GET") return route.fulfill({ json: { remaining: restants, total: 10, generated_at: Math.floor(Date.now() / 1000) } });
    enTetes.push(route.request().headers()["x-locksy-reauth"]);
    if (echecs-- > 0) return route.fulfill({ status: 500, json: { error: "internal", message: "Erreur interne." } });
    restants = 10;
    return route.fulfill({ json: { codes: NOUVEAUX, generated_at: Math.floor(Date.now() / 1000) } });
  });

  await aller(page, "/parametres/compte");
  await page.getByRole("button", { name: "Activer la double authentification" }).click();
  const activation = page.getByRole("dialog", { name: "Activer la double authentification" });
  await activation.getByText("Impossible de scanner ? Saisissez cette clé à la main").click();
  const secret = ((await activation.locator("details .u-mono").textContent()) ?? "").trim();
  if (secondsLeft() < 5) await page.waitForTimeout(6000);
  await activation.getByLabel("Code affiché par l'application").fill(totp(secret));
  await activation.getByRole("button", { name: "Activer", exact: true }).click();

  const codes = page.getByRole("dialog", { name: "Vos codes de secours" });
  await expect(codes).toBeVisible();
  for (const c of CODES) await expect(codes.getByText(c)).toBeVisible();
  const premier = await telecharger(page, codes);
  expect(premier.nom).toBe("locksy-codes-de-secours.txt");
  for (const c of CODES) expect(premier.texte).toContain(c);
  await codes.getByLabel("J'ai conservé mes codes de secours").check();
  await codes.getByRole("button", { name: "Terminé" }).click();
  await expect(codes).toHaveCount(0);
  await expect(page.getByText("10 codes restants sur 10.")).toBeVisible();
  // Les codes ne sont plus affichés nulle part.
  await expect(page.getByText(CODES[0])).toHaveCount(0);

  // Régénération : confirmation d'identité, échec signalé, puis nouveaux codes.
  restants = 2;
  await aller(page, "/parametres/appareils");
  await aller(page, "/parametres/compte");
  await expect(page.getByText("Il vous reste peu de codes de secours : générez-en de nouveaux.")).toBeVisible();
  for (let essai = 0; essai < 2; essai++) {
    await page.getByRole("button", { name: "Générer de nouveaux codes" }).click();
    const confirmation = page.getByRole("dialog", { name: "Générer de nouveaux codes de secours ?" });
    await confirmation.getByLabel(/^Mot de passe maître$/).fill(compte.password);
    await confirmation.getByRole("button", { name: "Confirmer" }).click();
    const code = page.getByRole("dialog", { name: "Code de vérification" });
    await expect(code).toBeVisible({ timeout: KDF_TIMEOUT });
    if (secondsLeft() < 5) await page.waitForTimeout(6000);
    await code.getByLabel("Code de vérification").pressSequentially(totp(secret));
    await expect(code).toHaveCount(0);
    if (essai === 0) await expect(notification(page, /Les codes n'ont pas été générés/)).toBeVisible();
  }
  const nouveaux = page.getByRole("dialog", { name: "Vos codes de secours" });
  await expect(nouveaux.getByText(NOUVEAUX[0])).toBeVisible();
  await nouveaux.getByLabel("J'ai conservé mes codes de secours").check();
  await nouveaux.getByRole("button", { name: "Terminé" }).click();
  await expect(page.getByText("10 codes restants sur 10.")).toBeVisible();
  expect(enTetes).toHaveLength(2);
  for (const h of enTetes) expect(h).toBe(`rt1.${"a".repeat(43)}`);
});
