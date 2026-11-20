// Raccourcis (règle A6) : une touche simple n'agit pas dans un champ de
// saisie, ni quand les touches simples sont désactivées ; « ? » ouvre l'aide.

import { test, expect } from "../../fixtures/index.ts";
import { openGallery, sortie } from "./galerie.ts";

test.describe("hotkeys", () => {
  test.beforeEach(async ({ page }) => {
    await openGallery(page, "raccourcis");
  });

  test("« N » hors champ agit, dans un champ ne fait rien", async ({ page }) => {
    await page.locator("h1").click();
    await page.keyboard.press("n");
    await expect(sortie(page, "raccourcis")).toHaveText("Nouvel élément demandé (1)");
    const field = page.getByLabel("Champ de test des raccourcis");
    await field.click();
    await page.keyboard.press("n");
    await page.keyboard.press("?");
    await expect(field).toHaveValue("n?");
    await expect(sortie(page, "raccourcis")).toHaveText("Nouvel élément demandé (1)");
    await expect(page.getByRole("dialog")).toHaveCount(0);
  });

  test("touches simples désactivées : rien ne se passe", async ({ page }) => {
    const toggle = page.getByRole("switch", { name: "Raccourcis à une touche" });
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-checked", "false");
    await page.keyboard.press("n");
    await page.keyboard.press("?");
    expect(await page.evaluate(() => (window as any).gallery.hotkeysCount())).toBe(0);
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await toggle.click();
    await page.keyboard.press("?");
    await expect(page.getByRole("dialog", { name: "Raccourcis clavier" })).toBeVisible();
    // Fenêtre ouverte : les raccourcis du coffre ne passent plus.
    await page.keyboard.press("n");
    expect(await page.evaluate(() => (window as any).gallery.hotkeysCount())).toBe(0);
  });
});
