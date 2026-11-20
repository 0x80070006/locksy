// Déverrouillage du coffre (lot Q6, critère G27 ; cahier 00 §6.5,
// stratégie 05 §7.2) : du clic sur « Déverrouiller » à la première image où
// la liste « Éléments » est rendue et le compteur affiche « 1 000 éléments ».
// La mesure comprend tout le parcours réel : GET /me, dérivation Argon2id aux
// paramètres par défaut (wasm), /sync, déchiffrement, politique, préférences,
// charte, coquille et liste.
//
// Seuil BLOQUANT (seul de la vague) : Chromium, 1 000 éléments, p50 < 1,5 s et
// p95 < 2,5 s sur 10 mesures. Firefox (< 3,5 s) et 10 000 éléments (p95 < 5 s,
// aucune tâche > 5 s) sont indicatifs : consignés, sans échec.

import { test, expect } from "../../fixtures/index.ts";
import type { Page, TestInfo } from "@playwright/test";
import {
  LIB, armer, comptesPerf, connexionPerf, consigner, indicatif, ms, nombre, noter, reperes, resultat, stats,
  surveillerTachesLongues, tachesLongues, texteExact, type ComptePerf,
} from "./outils.ts";

interface Tour {
  total: number;
  /** Clic → locksy:sync:start (GET /me, dérivation de la clé, ouverture). */
  avantSync: number | null;
  /** locksy:sync:start → locksy:sync:decrypted (requête et déchiffrement). */
  sync: number | null;
  /** locksy:sync:decrypted → liste affichée (politique, préférences, rendu). */
  rendu: number | null;
  /** Tâches longues pendant le tour (ms), null si non mesurables. */
  taches: number[] | null;
}

/** Verrouille par le bouton de la coquille, puis déverrouille en chronométrant. */
async function unTour(page: Page, compte: ComptePerf): Promise<Tour> {
  await page.getByRole("button", { name: LIB.verrouiller(), exact: true }).click();
  const champ = page.getByLabel(LIB.motDePasse(), { exact: true });
  await expect(champ).toBeVisible();
  await expect(page).toHaveURL(/#\/verrouille/);
  await champ.fill(compte.password);
  await reperes(page); // efface les repères du tour précédent
  await armer(page, { coffre: { liste: LIB.liste(), compte: LIB.compte(compte.n) } });
  await page.getByRole("button", { name: LIB.deverrouiller(), exact: true }).click();
  const r = await resultat(page);
  const m = await reperes(page);
  const taches = await tachesLongues(page, r.clic);
  // Contrôle par Playwright de ce que la page a constaté elle-même.
  await expect(page.getByText(texteExact(LIB.compte(compte.n)))).toBeVisible();
  const debut = m["sync:start"];
  const dechiffre = m["sync:decrypted"];
  return {
    total: r.image - r.clic,
    avantSync: debut !== undefined ? debut - r.clic : null,
    sync: debut !== undefined && dechiffre !== undefined ? dechiffre - debut : null,
    rendu: dechiffre !== undefined ? r.image - dechiffre : null,
    taches,
  };
}

/** Série de `n` tours, consignée phase par phase. */
async function serie(page: Page, compte: ComptePerf, n: number, testInfo: TestInfo) {
  const tours: Tour[] = [];
  for (let i = 0; i < n; i++) tours.push(await unTour(page, compte));
  const titre = `Déverrouillage, ${nombre(compte.n)} éléments`;
  const total = await consigner(testInfo, titre, stats(tours.map((t) => t.total)));
  const phase = async (nom: string, cle: "avantSync" | "sync" | "rendu") => {
    const v = tours.map((t) => t[cle]).filter((x): x is number => x !== null);
    if (v.length) await consigner(testInfo, `${titre}, ${nom}`, stats(v));
    else noter(testInfo, `${titre}, ${nom} : repères locksy:sync:* absents (?perf=1 non pris en compte)`);
  };
  await phase("clic → sync:start (GET /me, dérivation Argon2id)", "avantSync");
  await phase("sync:start → sync:decrypted (/sync et déchiffrement)", "sync");
  await phase("sync:decrypted → liste affichée (politique, préférences, rendu)", "rendu");
  const taches = tours.map((t) => t.taches);
  if (taches.some((t) => t === null)) {
    noter(testInfo, `${titre} : tâches longues non mesurables dans ce navigateur (PerformanceObserver « longtask » absent)`);
  } else {
    const toutes = taches.flatMap((t) => t ?? []);
    noter(testInfo, `${titre} : tâche longue la plus longue ${ms(Math.max(0, ...toutes))} (${toutes.length} tâches > 50 ms sur ${n} tours)`);
  }
  return { total, taches };
}

test.describe("Déverrouillage du coffre (G27)", () => {
  test.beforeEach(async ({ page, consoleGuard }) => {
    // GET /api/me/prefs répond 404 tant que le compte n'a enregistré aucune préférence (annexe A.10).
    consoleGuard.allow(/status of 404/);
    await surveillerTachesLongues(page);
  });

  test("1 000 éléments : p50 < 1,5 s et p95 < 2,5 s sous Chromium (10 mesures)", async ({ page, apiAs, browser, browserName }, testInfo) => {
    const compte = (await comptesPerf(apiAs, browser))["1000"];
    await connexionPerf(page, compte);
    const { total } = await serie(page, compte, 10, testInfo);
    if (browserName === "chromium") {
      expect.soft(total.p50, `Déverrouillage de 1 000 éléments, p50 (valeurs : ${total.valeurs.map(ms).join(", ")})`).toBeLessThan(1_500);
      expect(total.p95, `Déverrouillage de 1 000 éléments, p95 (valeurs : ${total.valeurs.map(ms).join(", ")})`).toBeLessThan(2_500);
    } else {
      indicatif(testInfo, `Déverrouillage de 1 000 éléments sous ${browserName}, p95 (seuil indicatif)`, total.p95, 3_500);
    }
  });

  test("10 000 éléments : p95 < 5 s sans page qui ne répond plus (indicatif, 3 mesures)", async ({ page, apiAs, browser }, testInfo) => {
    const compte = (await comptesPerf(apiAs, browser))["10000"];
    noter(testInfo, "10 000 éléments : vault.js déchiffre par lots de 500, avec une image affichée entre deux lots, à partir de 2 000 éléments (BATCHED_FROM)");
    await connexionPerf(page, compte);
    const { total, taches } = await serie(page, compte, 3, testInfo);
    indicatif(testInfo, "Déverrouillage de 10 000 éléments, p95 (seuil indicatif)", total.p95, 5_000);
    const toutes = taches.flatMap((t) => t ?? []);
    if (!taches.some((t) => t === null)) indicatif(testInfo, "Déverrouillage de 10 000 éléments, tâche la plus longue (page qui ne répond plus au-delà)", Math.max(0, ...toutes), 5_000);
    const memoire = await page.evaluate(() => (performance as unknown as { memory?: { usedJSHeapSize: number } }).memory?.usedJSHeapSize ?? null);
    if (memoire !== null) noter(testInfo, `Mémoire JS après déverrouillage de 10 000 éléments : ${Math.round(memoire / 1_048_576)} Mo (budget indicatif < 150 Mo ; performance.memory, Chromium)`);
  });
});
