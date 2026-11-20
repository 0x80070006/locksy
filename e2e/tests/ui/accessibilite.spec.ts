// Galerie des composants : aucune violation « serious » ou « critical » d'axe
// (WCAG 2.0, 2.1 et 2.2, niveaux A et AA) en clair, en sombre et en contraste
// renforcé, à 360 et 1280 px ; puis avec une fenêtre, un menu et un panneau ouverts.

import { test, expect } from "../../fixtures/index.ts";
import { seriousViolations } from "../../fixtures/axe.ts";
import { openGallery } from "./galerie.ts";

const THEMES = [
  { name: "clair", query: "theme=light" },
  { name: "sombre", query: "theme=dark" },
  { name: "contraste renforcé", query: "theme=light&contrast=more" },
  { name: "sombre et contraste renforcé", query: "theme=dark&contrast=more" },
];

// La galerie montre tous les textes des composants : aucun terme technique ni anglais.
test.use({ textGuardMode: "strict" });

test.describe("Accessibilité de la galerie (axe)", () => {
  for (const width of [360, 1280]) {
    for (const theme of THEMES) {
      test(`${theme.name}, ${width} px`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        await openGallery(page, undefined, theme.query);
        expect(await seriousViolations(page)).toEqual([]);
      });
    }
  }

  test("fenêtre, menu et panneau ouverts", async ({ page }) => {
    await openGallery(page, undefined, "theme=dark");
    await page.getByRole("button", { name: "Plus d'actions", exact: true }).click();
    await expect(page.getByRole("menu")).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    await page.keyboard.press("Escape");

    await page.getByRole("button", { name: "Ouvrir une fenêtre" }).click();
    await expect(page.getByRole("dialog", { name: "Nouveau coffre" })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    await page.keyboard.press("Escape");

    await page.getByRole("button", { name: "Ouvrir le panneau" }).click();
    await expect(page.getByRole("dialog", { name: "Modifier l'élément" })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
  });
});
