// Préférences synchronisées (cahier §3.3.8, §4.9, fiche L11) : chaque
// préférence est relue après rechargement ET dans un second contexte de
// navigateur (même compte) ; une préférence hors des bornes de
// l'organisation est ramenée et signalée ; les options hors bornes restent
// visibles et désactivées, avec la mention de la politique ; un échec
// d'enregistrement est signalé et l'affichage revient à l'état réel.

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { loginUi } from "../../fixtures/ui.ts";
import { aller, deverrouiller, notification, nouveauCompte, politique, tolerer } from "./outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(({ consoleGuard }) => tolerer(consoleGuard));

/** Listes de choix : libellé -> valeur choisie. */
const CHOIX: Record<string, string> = {
  "Thème": "dark",
  "Contraste": "more",
  "Taille du texte": "125",
  "Densité": "compact",
  "Verrouiller Locksy après": "30",
  "Effacer le presse-papiers après": "60",
  "Style des mots de passe générés": "words",
  "Durée de validité par défaut": "240",
  "Nombre d'ouvertures par défaut": "3",
};
/** Interrupteurs : libellé -> état choisi (l'inverse du défaut). */
const INTERRUPTEURS: Record<string, boolean> = {
  "Verrouiller quand l'onglet est masqué": true,
  "Copier d'un clic sur la valeur": true,
  "Proposer d'enregistrer les comptes saisis": false,
  "Copier le code de vérification après « Remplir »": false,
  "Raccourcis à une touche": false,
};
const LONGUEUR = "Longueur des mots de passe générés";

/** Attend l'enregistrement chiffré (PUT /api/me/prefs) déclenché par `action`. */
async function enregistrer(page: Page, action: () => Promise<unknown>) {
  const put = page.waitForResponse((r) => r.url().includes("/api/me/prefs") && r.request().method() === "PUT");
  await action();
  expect((await put).ok()).toBe(true);
}

async function verifier(page: Page) {
  await aller(page, "/parametres/preferences");
  await expect(page.getByRole("heading", { name: "Apparence" })).toBeVisible();
  for (const [label, value] of Object.entries(CHOIX)) await expect(page.getByLabel(label, { exact: true })).toHaveValue(value);
  for (const [label, on] of Object.entries(INTERRUPTEURS)) {
    await expect(page.getByRole("switch", { name: label })).toHaveAttribute("aria-checked", String(on));
  }
  await expect(page.getByLabel(LONGUEUR)).toHaveValue("24");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
}

test("chaque préférence est relue après rechargement et sur un second navigateur", async ({ page, apiAs, browser }) => {
  test.setTimeout(240_000);
  const compte = await nouveauCompte(page, await apiAs("owner"), "preferences");
  await aller(page, "/parametres/preferences");
  await expect(page.getByRole("heading", { name: "Apparence" })).toBeVisible();
  // La case n'existe que si settings-client gère l'apparence locale (« prefs.sync ») ; cochée par défaut.
  const synchro = page.getByRole("checkbox", { name: "Synchroniser mes préférences sur mes appareils" });
  const geree = await page.evaluate(async () => (await import("/js/settings-client.js")).LOCAL_KEYS.includes("prefs.sync"));
  if (geree) await expect(synchro).toBeChecked();
  else await expect(synchro).toHaveCount(0);

  for (const [label, value] of Object.entries(CHOIX)) {
    await enregistrer(page, () => page.getByLabel(label, { exact: true }).selectOption(value));
  }
  for (const label of Object.keys(INTERRUPTEURS)) {
    await enregistrer(page, () => page.getByRole("switch", { name: label }).click());
  }
  await enregistrer(page, async () => {
    await page.getByLabel(LONGUEUR).fill("24");
    await page.getByLabel(LONGUEUR).press("Tab");
  });

  // Après rechargement (même navigateur).
  await page.reload();
  await deverrouiller(page, compte.password);
  await verifier(page);

  // Second navigateur : rien n'est partagé avec le premier, sauf le compte.
  const autre = await browser.newContext({ locale: "fr-FR", timezoneId: "Europe/Paris" });
  try {
    const p2 = await autre.newPage();
    await loginUi(p2, compte);
    await verifier(p2);
  } finally {
    await autre.close();
  }
});

test("préférence hors bornes : ramenée, signalée, options hors bornes désactivées", async ({ page, apiAs }) => {
  test.setTimeout(150_000);
  const compte = await nouveauCompte(page, await apiAs("owner"), "bornes");
  await page.evaluate(async () => {
    const S = await import("/js/settings-client.js");
    await S.savePrefs({ lock: { minutes: 240 } });
  });
  await politique(page, { "client.autolock_minutes": { value: 10, mode: "default", min: 1, max: 30 } });
  await page.reload();
  await deverrouiller(page, compte.password);
  await aller(page, "/parametres/preferences");

  await expect(page.getByText("Votre organisation limite ce réglage : la valeur a été ramenée à 30 minutes.")).toBeVisible();
  const delai = page.getByLabel("Verrouiller Locksy après", { exact: true });
  await expect(delai).toHaveValue("30");
  await expect(page.getByText("Limité à 30 minutes par votre organisation")).toBeVisible();
  await expect(delai.locator("option", { hasText: "1 heure" })).toBeDisabled();
  await expect(delai.locator("option", { hasText: "15 minutes" })).toBeEnabled();
});

test("échec d'enregistrement : message en français, valeur réelle rétablie", async ({ page, org, consoleGuard }) => {
  consoleGuard.allow(/status of 500/);
  await loginUi(page, org.accounts.user);
  await aller(page, "/parametres/preferences");
  const densite = page.getByLabel("Densité", { exact: true });
  const avant = await densite.inputValue();
  let panne: "500" | "reseau" = "500";
  await page.route("**/api/me/prefs", (route) => {
    if (route.request().method() !== "PUT") return route.fallback();
    if (panne === "reseau") return route.abort("internetdisconnected");
    return route.fulfill({ status: 500, json: { error: "internal", message: "Erreur interne." } });
  });
  const autre = avant === "compact" ? "comfortable" : "compact";
  await densite.selectOption(autre);
  await expect(notification(page, /La préférence n'a pas été enregistrée/)).toBeVisible();
  await expect(densite).toHaveValue(avant);

  // Réseau coupé : même message en français, valeur réelle rétablie.
  panne = "reseau";
  consoleGuard.allow(/net::ERR_INTERNET_DISCONNECTED|NetworkError|Failed to fetch/);
  await densite.selectOption(autre);
  await expect(notification(page, /La préférence n'a pas été enregistrée : Serveur injoignable/)).toBeVisible();
  await expect(densite).toHaveValue(avant);
});
