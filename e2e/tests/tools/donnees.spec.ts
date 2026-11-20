// Importer ou exporter (cahier §3.3.8, écarts #9, #10, #36) : import CSV
// avec un mot de passe « a;b » intact et un rapport d'erreurs ligne par
// ligne, envoi interrompu puis repris ; export refusé quand l'organisation
// l'a désactivé ; export chiffré confirmé par le mot de passe maître et
// tracé (POST /me/export, simulé selon C1.3) AVANT de produire le fichier.

import { readFile } from "node:fs/promises";
import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { KDF_TIMEOUT, loginUi } from "../../fixtures/ui.ts";
import { aller, creerElements, nouveauCompte, politique, tolerer } from "./outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(({ consoleGuard }) => tolerer(consoleGuard));

const CSV = [
  "name,url,username,password,notes",
  "Banque,https://banque.exemple,alice,a;b,",
  "Serveur NAS,,admin,x,y,z",
  "Wi-Fi,,,,",
  "\"Messagerie, bureau\",https://mail.exemple,bob,\"p,w;d\",\"ligne 1",
  "ligne 2\"",
].join("\r\n");

const motsDePasse = (page: Page) => page.evaluate(async () => {
  const V = await import("/js/vault.js");
  return [...V.state.items.values()].filter((i) => i.data && !i.deleted_at).map((i) => [i.data.name, i.data.password, i.data.notes]);
});

test("import CSV : « a;b » intact, rapport ligne par ligne, envoi interrompu puis repris", async ({ page, apiAs, consoleGuard }) => {
  test.setTimeout(150_000);
  consoleGuard.allow(/status of 500/);
  await nouveauCompte(page, await apiAs("owner"), "import");
  await aller(page, "/parametres/donnees");
  await page.getByLabel("Fichier à importer").setInputFiles({ name: "export.csv", mimeType: "text/csv", buffer: Buffer.from(`﻿${CSV}`) });
  await page.getByRole("button", { name: "Lire le fichier" }).click();

  await expect(page.getByText("2 éléments prêts à être importés.")).toBeVisible();
  await expect(page.getByText("Séparateur détecté : virgule.")).toBeVisible();
  await expect(page.getByText("2 lignes ne seront pas importées :")).toBeVisible();
  await expect(page.getByText(/^Ligne 3 : plus de valeurs que de colonnes/)).toBeVisible();
  await expect(page.getByText(/^Ligne 4 : ni nom, ni identifiant/)).toBeVisible();
  const apercu = page.getByRole("table", { name: "Éléments lus (2)" });
  await expect(apercu).toContainText("Messagerie, bureau");
  // Aucun mot de passe dans l'aperçu.
  await expect(apercu).not.toContainText("a;b");

  let echec = true;
  await page.route("**/api/items/batch", (route) => {
    if (!echec) return route.fallback();
    echec = false;
    return route.fulfill({ status: 500, json: { error: "internal", message: "Erreur interne." } });
  });
  await page.getByRole("button", { name: "Importer 2 éléments" }).click();
  await expect(page.getByText("Import interrompu : 0 éléments sur 2 ont été importés.")).toBeVisible();
  await page.getByRole("button", { name: "Reprendre l'import (2 restants)" }).click();
  await expect(page.getByText("2 éléments importés.").first()).toBeVisible();

  await expect.poll(() => motsDePasse(page)).toEqual(expect.arrayContaining([
    ["Banque", "a;b", ""],
    ["Messagerie, bureau", "p,w;d", "ligne 1\nligne 2"],
  ]));
});

test("export désactivé par l'organisation : section désactivée avec la raison", async ({ page, org }) => {
  await politique(page, { "export.enabled": { value: false } });
  await loginUi(page, org.accounts.user);
  await aller(page, "/parametres/donnees");
  await expect(page.getByText("Votre organisation a désactivé l'export des coffres.").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Exporter", exact: true })).toBeDisabled();
  await expect(page.getByLabel("Mot de passe d'export")).toHaveCount(0);
});

/** Remplit le formulaire d'export chiffré et confirme l'identité. */
async function exporter(page: Page, password: string) {
  await aller(page, "/parametres/donnees");
  await page.getByLabel("Mot de passe d'export", { exact: true }).fill("Export-de-test-2026!");
  await page.getByLabel("Confirmer le mot de passe d'export").fill("Export-de-test-2026!");
  await page.getByRole("button", { name: "Exporter", exact: true }).click();
  const confirmation = page.getByRole("dialog", { name: "Confirmer l'export" });
  await confirmation.getByLabel(/^Mot de passe maître$/).fill(password);
  await confirmation.getByRole("button", { name: "Confirmer" }).click();
  await expect(confirmation).toHaveCount(0, { timeout: KDF_TIMEOUT });
}

test("export chiffré : trace serveur avant le fichier ; refus du serveur ; panne", async ({ page, apiAs, consoleGuard }) => {
  test.setTimeout(150_000);
  consoleGuard.allow(/status of (403|500)/); // refus et panne simulés de POST /me/export
  // Compte créé avant toute simulation : l'inscription ne passe par aucune interception.
  const compte = await nouveauCompte(page, await apiAs("owner"), "export");
  // POST /auth/reauth (C1.3) : jeton d'usage unique pour « vault.export ».
  const jetons: string[] = [];
  await page.route("**/api/auth/reauth", (route) => {
    const { action } = route.request().postDataJSON();
    jetons.push(action);
    return route.fulfill({ json: { token: `rt1.${"e".repeat(43)}`, expires_in: 120, action } });
  });
  const traces: Record<string, unknown>[] = [];
  let reponse: { status: number; json?: object } = { status: 204 };
  const enTetes: (string | undefined)[] = [];
  await page.route("**/api/me/export", (route) => {
    enTetes.push(route.request().headers()["x-locksy-reauth"]);
    traces.push(route.request().postDataJSON());
    return reponse.status === 204 ? route.fulfill({ status: 204 }) : route.fulfill(reponse);
  });
  await creerElements(page, [{ name: "Serveur NAS", username: "exploitation", password: "Lune-Verte-Piano-77!" }]);

  // Réussite : la trace précède le fichier, qui se relit avec le mot de passe d'export.
  const telechargement = page.waitForEvent("download", { timeout: KDF_TIMEOUT });
  await exporter(page, compte.password);
  const fichier = await telechargement;
  expect(fichier.suggestedFilename()).toMatch(/^locksy-sauvegarde-\d{4}-\d{2}-\d{2}\.json$/);
  expect(traces[0]).toMatchObject({ scope: "all", format: "locksy", attachments: false });
  expect(enTetes[0]).toBe(`rt1.${"e".repeat(43)}`);
  const contenu = await readFile(await fichier.path(), "utf8");
  expect(contenu).not.toContain("Lune-Verte-Piano-77!");
  const relu = await page.evaluate(async (texte) => {
    const W = await import("/js/wasm.js");
    return JSON.parse(W.call("unprotect_export", { password: "Export-de-test-2026!", data: texte })).items.length;
  }, contenu);
  expect(relu).toBe(traces[0].items);

  // Panne du serveur : aucun fichier, message en français.
  reponse = { status: 500, json: { error: "internal", message: "Erreur interne." } };
  let fichiers = 0;
  page.on("download", () => { fichiers++; });
  await exporter(page, compte.password);
  await expect(page.getByText(/L'export n'a pas été fait/)).toBeVisible();

  // Refus (export désactivé entre-temps) : section désactivée avec la raison.
  reponse = { status: 403, json: { error: "export_disabled", message: "Export désactivé." } };
  await exporter(page, compte.password);
  await expect(page.getByRole("button", { name: "Exporter", exact: true })).toBeDisabled();
  expect(fichiers).toBe(0);
  expect(jetons).toEqual(["vault.export", "vault.export", "vault.export"]);
});
