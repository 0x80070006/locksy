// Performance perçue du coffre (lot Q6, critère G40 ; cahier 00 §6.5) à
// 1 000 éléments : ouverture d'une fiche, frappe dans la recherche globale,
// coquille jamais redessinée. La frappe à 10 000 éléments est indicative.
//
// Ouverture d'une fiche : du clic sur la ligne à la première image où le
// titre h1 de la fiche est présent (MutationObserver, puis image suivante),
// médiane sur 10 lignes différentes, < 50 ms.
//
// Frappe (ADAPTATION) : le cahier demande « < 16 ms par image ». À 60 Hz,
// deux images sont espacées de 16,7 ms même au repos : l'intervalle brut ne
// peut pas passer sous 16 ms. Une image « tient dans son budget » quand elle
// arrive à l'heure : on mesure la période au repos P, puis les intervalles
// entre images pendant la frappe de 10 caractères (une recherche par
// caractère, le champ attendant 80 ms) ; le p95 des intervalles doit rester
// sous 1,5 × P (aucune image manquée au p95), et aucune tâche longue ne doit
// dépasser 200 ms (Chromium). À 10 000 éléments : p95 < 50 ms, indicatif.

import { test, expect } from "../../fixtures/index.ts";
import type { Page, TestInfo } from "@playwright/test";
import {
  LIB, armer, comptesPerf, connexionPerf, consigner, imagesPendant, indicatif, ms, noter, resultat, stats,
  surveillerTachesLongues, tachesLongues, texteExact,
} from "./outils.ts";

/** Ligne n° i (lien) de la liste « Éléments » et son titre affiché. */
async function ligne(page: Page, i: number) {
  const lien = page.getByRole("list", { name: LIB.liste(), exact: true }).getByRole("link").nth(i);
  await expect(lien).toBeVisible();
  const titre = await lien.evaluate((a) => (a.firstElementChild?.textContent || "").trim());
  expect(titre, `titre de la ligne ${i + 1}`).not.toBe("");
  return { lien, titre };
}

/** Frappe de `texte` dans la recherche globale, images relevées ; renvoie les statistiques. */
async function frappe(page: Page, texte: string, testInfo: TestInfo, titre: string) {
  const champ = page.getByRole("combobox", { name: LIB.recherche(), exact: true });
  await champ.click();
  await champ.fill("");
  const { periode, intervalles, debut } = await imagesPendant(page, async () => {
    // 120 ms entre deux touches : chaque caractère déclenche sa recherche (délai du champ : 80 ms).
    await champ.pressSequentially(texte, { delay: 120 });
    await expect(page.getByRole("list", { name: LIB.resultats(), exact: true })).toBeVisible();
    await page.waitForTimeout(300);
  });
  const s = await consigner(testInfo, titre, stats(intervalles), `période au repos ${periode.toFixed(1).replace(".", ",")} ms`);
  const taches = await tachesLongues(page, debut);
  if (taches === null) noter(testInfo, `${titre} : tâches longues non mesurables dans ce navigateur`);
  else noter(testInfo, `${titre} : ${taches.length} tâche(s) > 50 ms, la plus longue ${ms(Math.max(0, ...taches))}`);
  await champ.press("Escape");
  return { s, periode, taches };
}

test.describe("Performance perçue du coffre (G40)", () => {
  test.beforeEach(async ({ page, consoleGuard }) => {
    consoleGuard.allow(/status of 404/); // GET /api/me/prefs sans préférences enregistrées (annexe A.10)
    await surveillerTachesLongues(page);
  });

  test("1 000 éléments : ouverture d'une fiche < 50 ms (médiane sur 10)", async ({ page, apiAs, browser, browserName }, testInfo) => {
    const compte = (await comptesPerf(apiAs, browser))["1000"];
    await connexionPerf(page, compte);
    const dom: number[] = [];
    const image: number[] = [];
    // Lignes 2 à 11 : jamais la ligne déjà ouverte (un clic sur la fiche courante ne navigue pas).
    for (let i = 1; i <= 10; i++) {
      const { lien, titre } = await ligne(page, i);
      await armer(page, { titre });
      await lien.click();
      const r = await resultat(page);
      await expect(page.getByRole("heading", { level: 1, name: texteExact(titre) })).toBeVisible();
      dom.push(r.dom - r.clic);
      image.push(r.image - r.clic);
    }
    await consigner(testInfo, "Ouverture d'une fiche, 1 000 éléments, clic → titre dans le DOM", stats(dom));
    const s = await consigner(testInfo, "Ouverture d'une fiche, 1 000 éléments, clic → image affichant le titre", stats(image));
    if (browserName === "chromium") expect(s.mediane, `Ouverture d'une fiche (valeurs : ${image.map(ms).join(", ")})`).toBeLessThan(50);
    else indicatif(testInfo, `Ouverture d'une fiche sous ${browserName}, médiane (indicatif)`, s.mediane, 50);
  });

  test("1 000 éléments : frappe dans la recherche sans image manquée, aucune tâche > 200 ms", async ({ page, apiAs, browser, browserName }, testInfo) => {
    const compte = (await comptesPerf(apiAs, browser))["1000"];
    await connexionPerf(page, compte);
    const { s, periode, taches } = await frappe(page, "service 04", testInfo, "Frappe de 10 caractères, 1 000 éléments, intervalle entre images");
    const plafond = 1.5 * periode;
    if (browserName === "chromium") {
      expect.soft(s.p95, `p95 des intervalles entre images (période au repos ${periode.toFixed(1)} ms)`).toBeLessThan(plafond);
      expect(Math.max(0, ...(taches ?? [])), "tâche longue la plus longue pendant la frappe").toBeLessThanOrEqual(200);
    } else {
      indicatif(testInfo, `Frappe sous ${browserName}, p95 des intervalles (indicatif, 1,5 × période au repos)`, s.p95, plafond);
    }
  });

  test("la coquille n'est jamais redessinée : coffre → fiche → bilan → coffre", async ({ page, apiAs, browser }) => {
    const compte = (await comptesPerf(apiAs, browser))["1000"];
    await connexionPerf(page, compte);
    const nav = page.getByRole("navigation", { name: LIB.navigation(), exact: true });
    const entete = page.getByRole("banner");
    const navAvant = await nav.elementHandle();
    const enteteAvant = await entete.elementHandle();
    expect(navAvant && enteteAvant, "navigation principale et en-tête présents").toBeTruthy();

    const memes = async (etape: string) => {
      const [navApres, enteteApres] = [await nav.elementHandle(), await entete.elementHandle()];
      const verdict = await page.evaluate(([a, b, c, d]) => ({ connectes: !!a?.isConnected && !!c?.isConnected, nav: a === b, entete: c === d }),
        [navAvant, navApres, enteteAvant, enteteApres] as const);
      expect(verdict, `coquille après « ${etape} » : mêmes nœuds, toujours dans le document`).toEqual({ connectes: true, nav: true, entete: true });
    };

    const { lien, titre } = await ligne(page, 1);
    await lien.click();
    await expect(page.getByRole("heading", { level: 1, name: texteExact(titre) })).toBeVisible();
    await memes("fiche");

    await nav.getByRole("link", { name: LIB.bilan() }).click();
    await expect(page).toHaveURL(/#\/bilan/);
    await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
    await memes("bilan");

    await nav.getByRole("link", { name: LIB.tout() }).click();
    await expect(page).toHaveURL(/#\/coffre$/);
    await expect(page.getByText(texteExact(LIB.compte(compte.n)))).toBeVisible();
    await memes("coffre");
  });

  test("10 000 éléments : frappe dans la recherche, p95 < 50 ms par image (indicatif)", async ({ page, apiAs, browser }, testInfo) => {
    const compte = (await comptesPerf(apiAs, browser))["10000"];
    await connexionPerf(page, compte);
    const { s, taches } = await frappe(page, "service 04", testInfo, "Frappe de 10 caractères, 10 000 éléments, intervalle entre images");
    indicatif(testInfo, "Frappe à 10 000 éléments, p95 des intervalles entre images (indicatif)", s.p95, 50);
    if (taches !== null) indicatif(testInfo, "Frappe à 10 000 éléments, tâche la plus longue (indicatif)", Math.max(0, ...taches), 200);
  });
});
