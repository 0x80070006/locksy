// Page publique d'un lien sécurisé (/s/<id>#<clé>, contrat C5) : preuve de
// possession avant toute lecture, affichage puis rejeu sans décompte dans
// le même onglet, états terminaux lisibles, « Lien introuvable » pour une
// preuve fausse, nom affiché seulement s'il est dans le contenu chiffré,
// habillage de l'organisation, repli sur la lecture historique.
//
// Les routes publiques (POST …/peek et …/open, GET historique) sont simulées
// selon C1.4 ; le contenu est chiffré par le vrai module de la page. La
// preuve exige l'opération share_proof : le module de l'image e2e (antérieur
// à la vague 2) ne l'a pas ; servirModuleCourant() sert celui des sources
// s'il a été compilé, sinon les tests de la preuve sont ignorés.

import { createHash } from "node:crypto";
import type { BrowserContext, Page, Route } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { preuveDisponible, servirModuleCourant } from "./outils.ts";

test.use({ textGuardMode: "strict" });

interface Lien {
  id: string;
  fragment: string;
  data: string;
}

const preuveDe = (fragment: string) => createHash("sha256").update(fragment, "utf8").digest("base64url");
const maintenant = () => Math.floor(Date.now() / 1000);

/** Chiffre `contenu` comme le fait la création d'un lien (clé dans le fragment). */
async function chiffrer(page: Page, id: string, contenu: object): Promise<Lien> {
  await page.goto("/s/preparation");
  await expect(page.getByRole("heading", { level: 1, name: "Lien incomplet" })).toBeVisible();
  const r = await page.evaluate(async (json) => {
    const W = await import("/js/wasm.js");
    const A = await import("/js/aad.js");
    await W.loadCrypto();
    const key = W.call("generate_key");
    const data = W.call("encrypt", { key, plaintext: json, aad: A.share() });
    const fragment = W.call("export_key", { key });
    W.call("drop_key", { key });
    return { data, fragment };
  }, JSON.stringify(contenu));
  return { id, ...r };
}

/**
 * Lien simulé avec preuve (serveur commun à plusieurs navigateurs) : nombre
 * d'ouvertures, rejeu par identifiant de consultation. brancher(contexte)
 * installe les routes dans un contexte de navigateur.
 */
function simulerLien(lien: Lien, maxViews: number) {
  const etat = { views: 0, nonces: new Set<string>(), ouvertures: 0 };
  const attendue = preuveDe(lien.fragment);
  const expires = maintenant() + 86_400;
  const fini = () => etat.views >= maxViews;
  const introuvable = { status: 404, json: { error: "not_found", message: "Lien introuvable." } };
  const termine = () => ({ status: 410, json: { error: "share_ended", message: "Fin.", reason: "exhausted", ended_at: maintenant() } });
  const brancher = async (ctx: BrowserContext) => {
    await ctx.route(`**/api/public/shares/${lien.id}/peek`, (route: Route) => {
      if (route.request().postDataJSON().proof !== attendue) return route.fulfill(introuvable);
      if (fini()) return route.fulfill(termine());
      return route.fulfill({ json: { state: "active", expires_at: expires, views_left: maxViews - etat.views } });
    });
    await ctx.route(`**/api/public/shares/${lien.id}/open`, (route: Route) => {
      const { proof, nonce } = route.request().postDataJSON();
      if (proof !== attendue) return route.fulfill(introuvable);
      const replayed = etat.nonces.has(nonce);
      if (!replayed && fini()) return route.fulfill(termine());
      if (!replayed) {
        etat.nonces.add(nonce);
        etat.views += 1;
      }
      etat.ouvertures += 1;
      return route.fulfill({ json: { data: lien.data, expires_at: expires, views_left: maxViews - etat.views, replayed } });
    });
  };
  return { etat, brancher };
}

test("preuve de possession : aperçu, affichage sans nom, rejeu sans décompte, lien épuisé lisible", async ({ page, browser, consoleGuard }) => {
  consoleGuard.allow(/status of 410/);
  test.skip(!(await servirModuleCourant(page)), "Module WebAssembly courant absent (e2e/.state/<clé>/locksy-courant.wasm).");
  await page.goto("/s/verification");
  test.skip(!(await preuveDisponible(page)), "Le module servi ne calcule pas la preuve (share_proof).");

  const lien = await chiffrer(page, "lien-preuve", { username: "alice", password: "Lune-Verte-Piano-77!", urls: ["https://nas.exemple/"] });
  const { etat, brancher } = simulerLien(lien, 2);
  await brancher(page.context());

  await page.goto(`/s/${lien.id}#${lien.fragment}`);
  await expect(page.getByRole("heading", { level: 1, name: "Quelqu'un vous a envoyé un secret" })).toBeVisible();
  await expect(page.getByText(/peut encore être ouvert 2 fois/)).toBeVisible();
  // La clé quitte aussitôt la barre d'adresse ; rien d'ouvert ni de décompté avant le clic.
  expect(new URL(page.url()).hash).toBe("");
  expect(etat.ouvertures).toBe(0);

  await page.getByRole("button", { name: "Afficher le secret" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Secret partagé" })).toBeVisible();
  await expect(page.getByText("alice")).toBeVisible();
  await expect(page.getByRole("link", { name: "https://nas.exemple/" })).toHaveAttribute("rel", "noopener noreferrer");
  await expect(page.getByText(/peut encore être ouvert 1 fois/)).toBeVisible();
  await expect(page).toHaveTitle("Secret partagé · Locksy");
  const stocke = await page.evaluate(() => JSON.stringify({ ...sessionStorage }) + JSON.stringify({ ...localStorage }));
  expect(stocke).not.toContain(lien.fragment);
  expect(stocke).not.toContain("Lune-Verte");

  // Même onglet : la même consultation n'est pas décomptée une deuxième fois.
  await page.goto("about:blank");
  await page.goto(`/s/${lien.id}#${lien.fragment}`);
  await page.getByRole("button", { name: "Afficher le secret" }).click();
  await expect(page.getByText("Déjà affiché dans cet onglet : cet affichage n'a pas été décompté.")).toBeVisible();
  expect(etat.views).toBe(1);

  // Autre navigateur : dernière ouverture, puis lien épuisé.
  const autre = await browser.newContext({ locale: "fr-FR", timezoneId: "Europe/Paris" });
  try {
    const p2 = await autre.newPage();
    await servirModuleCourant(p2);
    await brancher(autre);
    await p2.goto(`/s/${lien.id}#${lien.fragment}`);
    await p2.getByRole("button", { name: "Afficher le secret" }).click();
    await expect(p2.getByText(/C'était la dernière ouverture/)).toBeVisible();
    await p2.goto("about:blank");
    await p2.goto(`/s/${lien.id}#${lien.fragment}`);
    await expect(p2.getByRole("heading", { level: 1, name: "Ce lien n'est plus valide" })).toBeVisible();
    await expect(p2.getByText("Ce lien a déjà été ouvert le nombre de fois autorisé.")).toBeVisible();
  } finally {
    await autre.close();
  }
  expect(etat.views).toBe(2);
});

test("preuve fausse ou lien inconnu : « Lien introuvable »", async ({ page, consoleGuard }) => {
  consoleGuard.allow(/status of 404/);
  await servirModuleCourant(page);
  const lien = await chiffrer(page, "lien-inconnu", { password: "x" });
  await page.route("**/api/public/shares/lien-inconnu/peek", (route) => route.fulfill({ status: 404, json: { error: "not_found", message: "Lien introuvable." } }));
  await page.route("**/api/public/shares/lien-inconnu", (route) => route.fulfill({ status: 404, json: { error: "not_found", message: "Lien introuvable." } }));
  await page.goto(`/s/${lien.id}#${lien.fragment}`);
  await page.getByRole("button", { name: "Afficher le secret" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Lien introuvable" })).toBeVisible();
});

test("lien historique : nom inclus en titre (jamais dans l'onglet), habillage de l'organisation", async ({ page, consoleGuard }) => {
  // Le module courant calcule la preuve : l'aperçu répond 404 (lien sans
  // vérificateur), signalé en console, puis repli sur l'ouverture historique.
  consoleGuard.allow(/status of 404/);
  const lien = await chiffrer(page, "lien-historique", { name: "Serveur NAS", username: "exploitation", password: "Lune-Verte-Piano-77!", notes: "Baie 2\nPrise 14" });
  await page.route("**/api/settings/public", async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    await route.fulfill({
      json: {
        ...body,
        branding: { ...body.branding, org_name: "Mairie de Test", support_contact: "support@mairie.exemple" },
        legal: { ...body.legal, notice_url: "https://mairie.exemple/mentions" },
      },
    });
  });
  await page.route("**/api/public/shares/lien-historique/peek", (route) => route.fulfill({ status: 404, json: { error: "not_found", message: "Lien introuvable." } }));
  let lectures = 0;
  await page.route("**/api/public/shares/lien-historique", (route) => {
    lectures += 1;
    return route.fulfill({ json: { data: lien.data, expires_at: maintenant() + 3600, views_left: 0 } });
  });

  await page.goto(`/s/${lien.id}#${lien.fragment}`);
  await expect(page.getByText("Mairie de Test · Locksy")).toBeVisible();
  await expect(page.getByText("Besoin d'aide ? support@mairie.exemple")).toBeVisible();
  await expect(page.getByRole("link", { name: "Mentions légales" })).toHaveAttribute("href", "https://mairie.exemple/mentions");
  expect(lectures).toBe(0);
  await page.getByRole("button", { name: "Afficher le secret" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Serveur NAS" })).toBeVisible();
  await expect(page).toHaveTitle("Secret partagé · Locksy");
  await expect(page.getByText("Baie 2")).toBeVisible();
  await expect(page.getByText(/C'était la dernière ouverture/)).toBeVisible();
  await page.getByRole("button", { name: "Afficher le mot de passe" }).click();
  await expect(page.locator(".c-secret")).toHaveText("Lune-Verte-Piano-77!");
  expect(lectures).toBe(1);
});

test("lien incomplet : clé absente du lien", async ({ page }) => {
  await page.goto("/s/lien-sans-cle");
  await expect(page.getByRole("heading", { level: 1, name: "Lien incomplet" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Afficher le secret" })).toHaveCount(0);
});
