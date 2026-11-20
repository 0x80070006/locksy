// Fenêtres, panneau et confirmations (règle A4) : focus initial, piège du
// focus, Échap limité à la fenêtre du dessus, retour du focus, Entrée,
// garde « Quitter sans enregistrer ? ».

import { test, expect } from "../../fixtures/index.ts";
import { activeInfo, openGallery, sortie } from "./galerie.ts";

const inDialog = (page: import("@playwright/test").Page) => page.evaluate(() => !!document.activeElement?.closest("dialog"));

test.describe("dialog()", () => {
  test.beforeEach(async ({ page }) => {
    await openGallery(page, "fenetre");
  });

  test("focus initial, piège du focus et retour au déclencheur", async ({ page }) => {
    const opener = page.getByRole("button", { name: "Ouvrir une fenêtre" });
    await opener.click();
    const dlg = page.getByRole("dialog", { name: "Nouveau coffre" });
    await expect(dlg).toBeVisible();
    await expect(dlg.getByLabel("Nom du coffre")).toBeFocused();
    for (let i = 0; i < 8; i++) {
      await page.keyboard.press("Tab");
      expect(await inDialog(page), `Tab n° ${i + 1} : ${await activeInfo(page)}`).toBe(true);
    }
    for (let i = 0; i < 8; i++) {
      await page.keyboard.press("Shift+Tab");
      expect(await inDialog(page), `Maj+Tab n° ${i + 1} : ${await activeInfo(page)}`).toBe(true);
    }
    await page.keyboard.press("Escape");
    await expect(dlg).toHaveCount(0);
    await expect(opener).toBeFocused();
  });

  test("Échap ne ferme que la fenêtre du dessus", async ({ page }) => {
    await page.getByRole("button", { name: "Ouvrir une fenêtre" }).click();
    const first = page.getByRole("dialog", { name: "Nouveau coffre" });
    const nestedOpener = first.getByRole("button", { name: "Ouvrir une seconde fenêtre" });
    await nestedOpener.click();
    const second = page.getByRole("dialog", { name: "Seconde fenêtre" });
    await expect(second).toBeVisible();
    await expect(second.getByRole("button", { name: "Fermer" })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(second).toHaveCount(0);
    await expect(first).toBeVisible();
    await expect(nestedOpener).toBeFocused();
  });

  test("Entrée dans un champ valide l'action principale", async ({ page }) => {
    await page.getByRole("button", { name: "Ouvrir une fenêtre" }).click();
    await page.getByLabel("Nom du coffre").fill("Comptabilité");
    await page.keyboard.press("Enter");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(sortie(page, "fenetre")).toHaveText("Créé : Comptabilité");
    await expect(page.getByRole("button", { name: "Ouvrir une fenêtre" })).toBeFocused();
  });

  test("garde de saisie : Rester garde la saisie, Abandonner ferme", async ({ page }) => {
    const opener = page.getByRole("button", { name: "Ouvrir une fenêtre" });
    await opener.click();
    const dlg = page.getByRole("dialog", { name: "Nouveau coffre" });
    await page.getByLabel("Nom du coffre").fill("Comptabilité");
    await page.keyboard.press("Escape");
    const guard = page.getByRole("dialog", { name: "Quitter sans enregistrer ?" });
    await expect(guard).toBeVisible();
    await expect(guard.getByRole("button", { name: "Rester" })).toBeFocused();
    await expect(guard.getByRole("button", { name: "Enregistrer" })).toBeVisible();
    await guard.getByRole("button", { name: "Rester" }).click();
    await expect(guard).toHaveCount(0);
    await expect(dlg).toBeVisible();
    await expect(page.getByLabel("Nom du coffre")).toHaveValue("Comptabilité");
    await expect(page.getByLabel("Nom du coffre")).toBeFocused();

    // « Annuler » passe aussi par la garde.
    await dlg.getByRole("button", { name: "Annuler" }).click();
    await expect(guard).toBeVisible();
    await guard.getByRole("button", { name: "Abandonner" }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(sortie(page, "fenetre")).toHaveText("Fenêtre fermée");
    await expect(opener).toBeFocused();
  });

  test("garde de saisie : Enregistrer exécute l'action principale", async ({ page }) => {
    const opener = page.getByRole("button", { name: "Ouvrir une fenêtre" });
    await opener.click();
    await page.getByLabel("Nom du coffre").fill("Direction");
    await page.keyboard.press("Escape");
    await page.getByRole("dialog", { name: "Quitter sans enregistrer ?" }).getByRole("button", { name: "Enregistrer" }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(sortie(page, "fenetre")).toHaveText("Créé : Direction");
    await expect(opener).toBeFocused();
  });

  test("aide des raccourcis générée depuis le registre", async ({ page }) => {
    await page.getByRole("button", { name: "Afficher les raccourcis" }).click();
    const help = page.getByRole("dialog", { name: "Raccourcis clavier" });
    await expect(help).toBeVisible();
    await expect(help.getByText("Rechercher dans tout le coffre")).toBeVisible();
    await expect(help.getByText("Nouvel élément")).toBeVisible();
    await help.getByRole("button", { name: "Fermer" }).click();
    await expect(help).toHaveCount(0);
  });
});

test.describe("panel()", () => {
  test("focus, piège, Échap et garde", async ({ page }) => {
    await openGallery(page, "panneau");
    const opener = page.getByRole("button", { name: "Ouvrir le panneau" });
    await opener.click();
    const panel = page.getByRole("dialog", { name: "Modifier l'élément" });
    await expect(panel.getByLabel("Titre")).toBeFocused();
    for (let i = 0; i < 6; i++) {
      await page.keyboard.press("Tab");
      expect(await panel.evaluate((p) => p.contains(document.activeElement)), `Tab n° ${i + 1}`).toBe(true);
    }
    await page.keyboard.press("Escape");
    await expect(panel).toHaveCount(0);
    await expect(opener).toBeFocused();

    await opener.click();
    await panel.getByLabel("Titre").fill("Messagerie");
    await page.keyboard.press("Escape");
    const guard = page.getByRole("dialog", { name: "Quitter sans enregistrer ?" });
    await guard.getByRole("button", { name: "Enregistrer" }).click();
    await expect(panel).toHaveCount(0);
    await expect(sortie(page, "panneau")).toHaveText("Panneau enregistré : Messagerie");
    await expect(opener).toBeFocused();
  });
});

test.describe("confirm()", () => {
  test.beforeEach(async ({ page }) => {
    await openGallery(page, "confirmation");
  });

  test("niveau 1 : le focus va sur Annuler, la fenêtre nomme l'objet", async ({ page }) => {
    await page.getByRole("button", { name: "Niveau 1" }).click();
    const dlg = page.getByRole("dialog", { name: "Mettre à la corbeille ?" });
    await expect(dlg.getByText("Gmail")).toBeVisible();
    await expect(dlg.getByRole("button", { name: "Annuler" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(sortie(page, "confirmation")).toHaveText("Annulé");
    await page.getByRole("button", { name: "Niveau 1" }).click();
    await page.getByRole("button", { name: "Mettre à la corbeille" }).click();
    await expect(sortie(page, "confirmation")).toHaveText("Confirmé");
  });

  test("niveau 2 : résumé chiffré de l'impact", async ({ page }) => {
    await page.getByRole("button", { name: "Niveau 2" }).click();
    const dlg = page.getByRole("dialog", { name: "Révoquer tous les liens ?" });
    await expect(dlg.getByText("12 liens sécurisés ne fonctionneront plus.")).toBeVisible();
    await dlg.getByRole("button", { name: "Révoquer" }).click();
    await expect(sortie(page, "confirmation")).toHaveText("Confirmé");
  });

  test("niveau 3 : nom de l'objet et mot de passe maître", async ({ page }) => {
    await page.getByRole("button", { name: "Niveau 3" }).click();
    const dlg = page.getByRole("dialog", { name: "Supprimer définitivement le coffre ?" });
    await dlg.getByLabel("Saisissez « Équipe IT » pour confirmer").fill("Equipe");
    await dlg.getByLabel("Mot de passe maître").fill("démo");
    await dlg.getByRole("button", { name: "Supprimer définitivement" }).click();
    await expect(dlg.getByText("Le nom saisi ne correspond pas à « Équipe IT ».")).toBeVisible();
    await dlg.getByLabel("Saisissez « Équipe IT » pour confirmer").fill("equipe it");
    await dlg.getByLabel("Mot de passe maître").fill("faux");
    await dlg.getByRole("button", { name: "Supprimer définitivement" }).click();
    await expect(dlg.getByLabel("Mot de passe maître")).toHaveAttribute("aria-invalid", "true");
    await dlg.getByLabel("Mot de passe maître").fill("démo");
    await dlg.getByRole("button", { name: "Supprimer définitivement" }).click();
    await expect(sortie(page, "confirmation")).toHaveText("Confirmé avec preuve");
  });

  test("niveau 0 : action immédiate et « Annuler » pendant 8 s", async ({ page }) => {
    await page.getByRole("button", { name: "Niveau 0" }).click();
    await expect(sortie(page, "confirmation")).toHaveText("Confirmé");
    await expect(page.locator("#status")).toHaveText("Élément mis à la corbeille.");
    await page.locator(".c-toast").getByRole("button", { name: "Annuler" }).click();
    await expect(sortie(page, "confirmation")).toHaveText("Action annulée par l'utilisateur");
    await expect(page.locator("#status")).toHaveText("Action annulée");
  });
});
