// Accessibilité de tous les écrans (cahier §2.10, §3 et §6.4 « a11y »,
// critères G4 partie automatique et G3 en partie) : pour chaque écran,
// analyse axe (wcag2a, wcag2aa, wcag21a, wcag21aa, wcag22aa) à 1280 px puis
// 360 px, en clair, en sombre et en contraste renforcé : aucune violation
// « serious » ni « critical ». En plus : focus jamais sur <body>, un seul h1,
// seules régions live #status et #alert, aucun défilement horizontal à
// 320 px (zoom 400 %), cibles d'au moins 24 px à 360 px.
//
// Analyse faite sous Chromium (émulation CDP des préférences d'affichage) ;
// Firefox est couvert par les suites fonctionnelles. Le projet « mobile »
// rejoue les écrans marqués @mobile avec des cibles de 44 px (mode tactile).

import { test, expect } from "../../fixtures/index.ts";
import { controlerEcran, ecrans } from "./outils.ts";

test.use({ textGuardMode: "strict" });

// Défauts du produit constatés (V0.2) : un test annoté redevient rouge le jour
// où le défaut est corrigé, l'intégrateur retire alors l'annotation. Les
// défauts Q3b-H17 à Q3b-H20 (régions live en trop, cibles trop petites) sont
// corrigés : aucune annotation en cours.
const DEFAUTS: Record<string, string> = {};
// Téléphone (projet « mobile ») : cibles tactiles de 44 px (critère G3).
const DEFAUTS_MOBILE: Record<string, string> = {};

test.describe("Accessibilité de chaque écran (axe, structure, 320 px, cibles)", () => {
  for (const [nom, e] of Object.entries(ecrans())) {
    const options = e.mobile ? { tag: "@mobile" } : {};
    test(nom, options, async ({ page, org, browser, loggedIn, apiAs, browserName, isMobile, consoleGuard }) => {
      test.skip(browserName !== "chromium", "Analyse axe faite sous Chromium (CDP) ; Firefox est couvert par les suites fonctionnelles");
      test.setTimeout(150_000);
      const defaut = DEFAUTS[nom] || (isMobile ? DEFAUTS_MOBILE[nom] : undefined);
      if (defaut) test.fail(true, defaut);
      // GET /api/me/prefs répond 404 tant qu'aucune préférence n'existe.
      consoleGuard.allow(/status of 404/);
      const ecran = await e.preparer({ page, org, browser, loggedIn, apiAs });
      // Téléphone (projet « mobile ») : 360 px seulement, cibles tactiles de 44 px.
      const problemes = await controlerEcran(ecran, isMobile ? { cible: 44, largeurs: [360] } : { cible: 24 });
      expect(problemes, `Accessibilité de l'écran « ${nom} »`).toEqual([]);
    });
  }
});
