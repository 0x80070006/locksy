// Synchronisation incrémentale (contrat C4.4, route /sync?since= du lot L7b,
// simulée : absente de l'image de test) et repli sur un serveur qui ne
// publie pas de position (R11) : la liste suit les éléments retirés.

import { test, expect } from "../../fixtures/index.ts";
import { aller, connexion, creerElement, liste, pressePapiers, tolererPrefs, unique } from "./outils.ts";

test.use({ textGuardMode: "strict" });

test.beforeEach(async ({ page, org, consoleGuard }) => {
  tolererPrefs(consoleGuard);
  await pressePapiers(page);
  await connexion(page, org.accounts.user);
});

test("/sync?since= : seul le changement est demandé, les éléments retirés disparaissent de la liste", async ({ page }) => {
  const nom = unique("Ancien compte");
  const garde = unique("Compte gardé");
  const id = await creerElement(page, { name: nom, password: "Retire-2026" });
  await creerElement(page, { name: garde, password: "Garde-2026" });
  const urls: string[] = [];
  await page.route("**/api/sync*", async (r) => {
    const url = new URL(r.request().url());
    urls.push(url.search);
    const since = url.searchParams.get("since");
    if (since === null) {
      const res = await r.fetch();
      const body = await res.json();
      return r.fulfill({ response: res, json: { ...body, seq: 41, full: true, removed: { items: [], collections: [] } } });
    }
    // Delta (C1.4) : rien de changé, sauf l'élément retiré.
    const res = await r.fetch({ url: url.origin + url.pathname });
    const body = await res.json();
    return r.fulfill({
      response: res,
      json: { profile: body.profile, collections: [], items: [], server_time: body.server_time, seq: 42, full: false, removed: { items: [id], collections: [] } },
    });
  });
  await page.evaluate(async () => (await import("/js/vault.js")).sync({ incremental: false }));
  await page.evaluate(async () => (await import("/js/vault.js")).sync());
  expect(urls).toEqual(["", "?since=41"]);
  await aller(page, "#/coffre/favoris");
  await aller(page, "#/coffre");
  await expect(liste(page).getByText(garde, { exact: true })).toBeVisible();
  await expect(liste(page).getByText(nom, { exact: true })).toHaveCount(0);
});

test("repli : serveur sans position (1.0), plus de since après sa première réponse", async ({ page }) => {
  // Serveur 1.0 simulé : la réponse du vrai serveur, sans seq, full ni removed.
  // La connexion a déjà gardé une position : la première demande peut la
  // porter ; une réponse sans position l'efface, les suivantes sont complètes.
  await page.route("**/api/sync*", async (route) => {
    const res = await route.fetch();
    const { seq: _seq, full: _full, removed: _removed, ...body } = await res.json();
    await route.fulfill({ json: body });
  });
  const urls: string[] = [];
  page.on("request", (r) => { if (r.url().includes("/api/sync")) urls.push(new URL(r.url()).search); });
  await page.evaluate(async () => {
    const V = await import("/js/vault.js");
    await V.sync();
    await V.sync();
    await V.sync();
  });
  expect(urls.length).toBeGreaterThanOrEqual(3);
  expect(urls.slice(-2)).toEqual(["", ""]);
});
