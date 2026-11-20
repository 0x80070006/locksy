// Premier affichage de l'écran de connexion (lot Q6, cahier 00 §6.5,
// stratégie 05 §7.2), mesures INDICATIVES : nombre de requêtes (≤ 25),
// octets de JavaScript reçus (≤ 120 Ko, 1 Ko = 1 024 o), délai jusqu'au champ
// « Adresse e-mail » utilisable (< 1,0 s en local ; < 2,0 s avec un réseau
// bridé à 20 Mbit/s et 40 ms d'aller-retour, Chromium seulement, par CDP).
// Chaque mesure part d'un contexte neuf (cache vide, aucune session).
// Les tailles des fichiers eux-mêmes sont contrôlées par
// bench/scripts/budget-assets.mjs.

import { test, expect } from "../../fixtures/index.ts";
import type { BrowserContext, Page, TestInfo } from "@playwright/test";
import { LIB, consigner, indicatif, nombre, noter, stats } from "./outils.ts";

const MESURES = 3;
const KO = 1024;

interface Chargement {
  requetes: number;
  octetsJs: number;
  /** Délai depuis le début de la navigation jusqu'au champ utilisable (ms). */
  champ: number;
}

/** Charge #/connexion dans un contexte neuf et relève requêtes, octets JS et délai. */
async function charger(ctx: BrowserContext, brider: boolean): Promise<Chargement> {
  const page: Page = await ctx.newPage();
  if (brider) {
    const cdp = await ctx.newCDPSession(page);
    await cdp.send("Network.enable");
    await cdp.send("Network.emulateNetworkConditions", { offline: false, latency: 40, downloadThroughput: 20_000_000 / 8, uploadThroughput: 20_000_000 / 8 });
  }
  // Instant où le champ « Adresse e-mail » existe, est actif et visible (ms depuis le début de la navigation).
  await page.addInitScript((etiquette: string) => {
    const w = window as unknown as { __locksyChampEmail?: number };
    const pret = () => {
      if (w.__locksyChampEmail !== undefined) return true;
      const label = [...document.querySelectorAll("label")].find((l) => (l.textContent || "").trim() === etiquette);
      const champ = label?.control as HTMLInputElement | null | undefined;
      if (!champ || champ.disabled || (typeof champ.checkVisibility === "function" && !champ.checkVisibility())) return false;
      w.__locksyChampEmail = performance.now();
      return true;
    };
    const demarrer = () => {
      if (pret()) return;
      const obs = new MutationObserver(() => { if (pret()) obs.disconnect(); });
      obs.observe(document.documentElement, { subtree: true, childList: true, attributes: true });
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", demarrer, { once: true });
    else demarrer();
  }, LIB.email());

  let requetes = 0;
  const corps: Promise<number>[] = [];
  page.on("request", () => { requetes++; });
  page.on("response", (r) => {
    if (/\.m?js(?:[?#]|$)/.test(new URL(r.url()).pathname)) corps.push(r.body().then((b) => b.length).catch(() => 0));
  });
  await page.goto("/#/connexion");
  await expect(page.getByLabel(LIB.email(), { exact: true })).toBeEditable();
  await page.waitForLoadState("networkidle");
  const champ = await page.evaluate(() => (window as unknown as { __locksyChampEmail?: number }).__locksyChampEmail ?? Number.NaN);
  const octetsJs = (await Promise.all(corps)).reduce((a, b) => a + b, 0);
  await page.close();
  return { requetes, octetsJs, champ };
}

async function serie(nouveau: () => Promise<BrowserContext>, brider: boolean, testInfo: TestInfo, titre: string) {
  const tours: Chargement[] = [];
  for (let i = 0; i < MESURES; i++) tours.push(await charger(await nouveau(), brider));
  const s = await consigner(testInfo, `${titre}, champ « ${LIB.email()} » utilisable`, stats(tours.map((t) => t.champ)));
  return { s, tours };
}

test.describe("Premier affichage de la connexion (indicatif)", () => {
  test("en local : ≤ 25 requêtes, ≤ 120 Ko de JS, champ utilisable < 1,0 s", async ({ _newContext }, testInfo) => {
    const { s, tours } = await serie(_newContext, false, testInfo, "Connexion, réseau local");
    const requetes = Math.max(...tours.map((t) => t.requetes));
    const octets = Math.max(...tours.map((t) => t.octetsJs));
    noter(testInfo, `Connexion : ${requetes} requêtes au premier affichage (budget indicatif ≤ 25, ${requetes <= 25 ? "conforme" : "dépassé (indicatif)"})`);
    noter(testInfo, `Connexion : ${nombre(Math.round(octets / KO))} Ko de JavaScript reçus (budget indicatif ≤ 120 Ko, ${octets <= 120 * KO ? "conforme" : "dépassé (indicatif)"} ; taille décompressée, le serveur envoie le JS en gzip)`);
    indicatif(testInfo, "Connexion en local, champ utilisable, médiane", s.mediane, 1_000);
    expect(tours.every((t) => Number.isFinite(t.champ)), "le champ « Adresse e-mail » a été repéré dans la page").toBe(true);
  });

  test("réseau bridé à 20 Mbit/s et 40 ms : champ utilisable < 2,0 s", async ({ _newContext, browserName }, testInfo) => {
    test.skip(browserName !== "chromium", "Bridage du réseau par CDP : Chromium seulement.");
    const { s, tours } = await serie(_newContext, true, testInfo, "Connexion, réseau bridé (20 Mbit/s, RTT 40 ms)");
    indicatif(testInfo, "Connexion avec réseau bridé, champ utilisable, médiane", s.mediane, 2_000);
    expect(tours.every((t) => Number.isFinite(t.champ)), "le champ « Adresse e-mail » a été repéré dans la page").toBe(true);
  });
});
