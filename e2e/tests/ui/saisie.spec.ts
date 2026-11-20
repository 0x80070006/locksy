// Saisie : code de vérification (collage normalisé), durées bornées (options
// hors bornes désactivées avec la raison), listes de valeurs, champs reliés.

import { test, expect } from "../../fixtures/index.ts";
import { openGallery, sortie } from "./galerie.ts";

test.describe("otpInput()", () => {
  test.beforeEach(async ({ page }) => {
    await openGallery(page, "code");
  });

  test("un seul champ numérique, code à usage unique", async ({ page }) => {
    const input = page.getByLabel("Code de vérification", { exact: true });
    await expect(input).toHaveAttribute("inputmode", "numeric");
    await expect(input).toHaveAttribute("autocomplete", "one-time-code");
    expect(await page.locator("[data-component=code] input").count()).toBe(1);
  });

  test("collage « 273 647 » -> onComplete(\"273647\")", async ({ page, browserName }) => {
    const input = page.getByLabel("Code de vérification", { exact: true });
    await input.focus();
    if (browserName === "firefox") {
      // Firefox ignore les données d'un « paste » synthétique : vrai collage
      // depuis le presse-papiers (ouvert par préférences, playwright.config.ts).
      await page.evaluate(() => navigator.clipboard.writeText("273 647"));
      await input.press("Control+V");
    } else {
      await input.evaluate((el) => {
        const data = new DataTransfer();
        data.setData("text", "273 647");
        el.dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }));
      });
    }
    await expect(input).toHaveValue("273647");
    await expect(sortie(page, "code")).toHaveText("Code reçu : 273647");
  });

  test("frappe avec espaces et tirets : chiffres seulement, envoi au 6e", async ({ page }) => {
    const input = page.getByLabel("Code de vérification", { exact: true });
    await input.pressSequentially("12 3-4");
    await expect(input).toHaveValue("1234");
    await expect(sortie(page, "code")).toHaveText("");
    await input.pressSequentially("56");
    await expect(sortie(page, "code")).toHaveText("Code reçu : 123456");
  });
});

test.describe("durationSelect()", () => {
  test.beforeEach(async ({ page }) => {
    await openGallery(page, "duree");
  });

  test("options hors bornes présentes, désactivées, raison reliée", async ({ page }) => {
    const select = page.getByLabel("Verrouiller Locksy après");
    await expect(select.locator("option[value='60']")).toBeDisabled();
    await expect(select.locator("option[value='240']")).toBeDisabled();
    await expect(select.locator("option[value='30']")).toBeEnabled();
    await expect(select.locator("option[value='60']")).toHaveText("1 heure (non autorisé)");
    const ids = (await select.getAttribute("aria-describedby"))!.split(" ");
    const texts = await Promise.all(ids.map((id) => page.locator(`[id="${id}"]`).textContent()));
    expect(texts.join(" ")).toContain("Limité à 30 min par votre organisation");
    await expect(select).toHaveAccessibleDescription(/Limité à 30 min par votre organisation/);
  });

  test("« Autre… » ouvre un champ borné", async ({ page }) => {
    const select = page.getByLabel("Verrouiller Locksy après");
    await select.selectOption("autre");
    const custom = page.getByLabel("Durée personnalisée (en minutes)");
    await expect(custom).toBeFocused();
    await custom.fill("45");
    await custom.press("Tab");
    await expect(custom).toHaveAttribute("aria-invalid", "true");
    await expect(page.locator("#alert")).toHaveText("Limité à 30 min par votre organisation");
    await custom.fill("20");
    await custom.press("Tab");
    await expect(custom).not.toHaveAttribute("aria-invalid", "true");
    await expect(sortie(page, "duree")).toHaveText("Durée choisie : 20 min");
  });

  test("« Jamais » proposé quand il est permis", async ({ page }) => {
    const select = page.getByLabel("Effacer le presse-papiers après");
    await expect(select.locator("option[value='0']")).toHaveText("Jamais");
    await expect(select.locator("option[value='60']")).toHaveText("1 minute");
  });
});

test.describe("chipsInput()", () => {
  test("ajout, refus avec l'erreur à côté, retrait", async ({ page }) => {
    await openGallery(page, "liste-saisie");
    const input = page.getByLabel("Domaines autorisés");
    await input.fill("partenaire.fr");
    await input.press("Enter");
    await expect(sortie(page, "liste-saisie")).toHaveText("3 domaines");
    await input.fill("pas un domaine");
    await input.press("Enter");
    await expect(input).toHaveAttribute("aria-invalid", "true");
    await expect(input).toHaveAccessibleDescription(/n'est pas un nom de domaine/);
    await input.fill("");
    await page.getByRole("button", { name: "Retirer exemple.fr" }).click();
    await expect(sortie(page, "liste-saisie")).toHaveText("2 domaines");
    await expect(input).toBeFocused();
  });
});
