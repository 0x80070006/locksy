// Administration › Réglages (cahier §3.4.6, §4.8, fiche L12) : écran généré
// depuis /admin/settings/schema (route réelle de l'image), recherche par
// synonyme, badge « Modifié », « Rétablir », saisie conservée entre les
// sections, chaque réglage du registre modifiable, profils, conflit 409
// simulé, échecs d'écriture, repli sur les 5 réglages historiques quand
// /schema manque (R11).
//
// Aucun test de ce fichier n'enregistre de vrai réglage : ceux qui le font
// sont dans reglages-ecritures.spec.ts (exécutés à la suite).

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { goHash, L, missing } from "./outils.ts";

test.use({ textGuardMode: "strict" });

const AUTOLOCK = "Verrouillage automatique des applications";
const MAX_HOURS = "Durée maximale d'une session";
const IDLE = "Déconnexion après inactivité";

async function openSettings(page: Page, section = "sessions") {
  await goHash(page, `#/admin/reglages/${section}`);
  await expect(page.getByRole("heading", { level: 1, name: "Réglages" })).toBeVisible();
}

test.describe("Réglages", () => {
  test("la recherche « verrou » trouve le verrouillage automatique (synonyme)", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    await openSettings(page, "login");
    await page.getByLabel(L.settingsSearch).fill("verrou");
    await expect(page.getByLabel(AUTOLOCK, { exact: true })).toBeVisible();
    await expect(page.getByText(/réglages? trouvés?/)).toBeVisible();
    // La clé technique n'est affichée que dans « Détails techniques ».
    await expect(page.getByText("client.autolock_minutes", { exact: true })).toBeHidden();
  });

  test("badge « Modifié », « Rétablir » et saisie conservée en changeant de section", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    await openSettings(page);
    const idle = page.getByLabel(IDLE, { exact: true });
    await idle.selectOption("30");
    const setting = page.locator(".c-setting", { has: idle });
    await expect(setting.getByText("Modifié")).toBeVisible();
    await expect(page.getByText("1 modification non enregistrée")).toBeVisible();

    // Changer de section ne perd rien.
    await page.getByRole("navigation", { name: "Sections des réglages" }).getByRole("link", { name: /^Mots de passe/ }).click();
    await expect(page.getByRole("heading", { level: 2, name: "Mots de passe" })).toBeVisible();
    await expect(page.getByText("1 modification non enregistrée")).toBeVisible();
    await page.getByRole("navigation", { name: "Sections des réglages" }).getByRole("link", { name: /^Sessions/ }).click();
    await expect(page.getByLabel(IDLE, { exact: true })).toHaveValue("30");

    await page.locator(".c-setting", { has: page.getByLabel(IDLE, { exact: true }) }).getByRole("button", { name: /^Rétablir/ }).click();
    await expect(page.getByText("1 modification non enregistrée")).toBeHidden();
  });

  test("conflit 409 : « Voir ses changements » puis « Recharger en gardant les miens »", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/409|Failed to load resource/);
    const page = await loggedIn("owner");
    await page.route("**/api/admin/settings", async (route) => {
      if (route.request().method() !== "PATCH") return route.fallback();
      return route.fulfill({ status: 409, json: { error: "settings_conflict", message: "Conflit.", current_revision: 99, by: "Hugo Martin", at: Math.floor(Date.now() / 1000) - 120 } });
    });
    await openSettings(page);
    await page.getByLabel(IDLE, { exact: true }).selectOption("30");
    await page.getByRole("button", { name: L.saveSettings }).click();
    await page.getByRole("dialog", { name: "Enregistrer 1 modification" }).getByRole("button", { name: L.save }).click();
    const conflict = page.getByRole("dialog", { name: "Réglages modifiés entre-temps" });
    await expect(conflict.getByText("Hugo Martin a modifié ces réglages")).toBeVisible();
    await conflict.getByRole("button", { name: "Voir ses changements" }).click();
    await expect(page.getByRole("dialog", { name: "Changements enregistrés entre-temps" })).toBeVisible();
    await page.getByRole("dialog", { name: "Changements enregistrés entre-temps" }).getByRole("button", { name: "Recharger en gardant les miens" }).click();
    // La saisie est conservée et revalidée sur la nouvelle version.
    await expect(page.getByRole("dialog", { name: "Enregistrer 1 modification" })).toBeVisible();
    await page.getByRole("dialog", { name: "Enregistrer 1 modification" }).getByRole("button", { name: "Revenir" }).click();
    await expect(page.getByLabel(IDLE, { exact: true })).toHaveValue("30");
  });

  test("échec d'enregistrement (500 puis réseau coupé) : message français, saisie intacte", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/500|Failed to load resource|ERR_FAILED/);
    const page = await loggedIn("owner");
    let mode: "500" | "reseau" = "500";
    await page.route("**/api/admin/settings", async (route) => {
      if (route.request().method() !== "PATCH") return route.fallback();
      if (mode === "reseau") return route.abort("failed");
      return route.fulfill({ status: 500, json: { error: "internal", message: "Erreur interne du serveur." } });
    });
    await openSettings(page);
    await page.getByLabel(IDLE, { exact: true }).selectOption("30");
    await page.getByRole("button", { name: L.saveSettings }).click();
    const recap = page.getByRole("dialog", { name: "Enregistrer 1 modification" });
    await recap.getByRole("button", { name: L.save }).click();
    await expect(recap.getByText(/Erreur|serveur/i).first()).toBeVisible();
    mode = "reseau";
    await recap.getByRole("button", { name: L.save }).click();
    await expect(recap.getByText(/Serveur injoignable/)).toBeVisible();
    await recap.getByRole("button", { name: "Revenir" }).click();
    await expect(page.getByLabel(IDLE, { exact: true })).toHaveValue("30");
    await expect(page.getByText("1 modification non enregistrée")).toBeVisible();
  });

  test("chaque réglage du registre a sa commande modifiable, dans sa section", async ({ loggedIn, apiAs }) => {
    const api = await apiAs("owner");
    const schema = await (await api.get("/api/admin/settings/schema")).json();
    const values = (await (await api.get("/api/admin/settings")).json()).values || {};
    const page = await loggedIn("owner");
    const sections: string[] = schema.sections.filter((s: string) => schema.settings.some((d: { section: string }) => d.section === s));
    let seen = 0;
    for (const section of sections) {
      await openSettings(page, section);
      const defs = schema.settings.filter((d: { section: string }) => d.section === section);
      // Section affichée (réglages avancés compris, même repliés) avant de la parcourir.
      await expect(page.locator(`.c-setting[data-key="${defs[0].key}"]`)).toBeAttached();
      const advanced = page.locator("details.c-card:not([open]) > summary");
      if (await advanced.count()) await advanced.first().click();
      for (const def of defs) {
        const setting = page.locator(`.c-setting[data-key="${def.key}"]`);
        await expect(setting, `réglage ${def.key} absent de la section ${section}`).toBeVisible();
        if (values[def.key]?.source === "host_locked") continue;
        const controls = setting.locator("input:not([type=hidden]), select, textarea, button");
        await expect(controls.first(), `réglage ${def.key} non modifiable`).toBeEnabled();
        seen++;
      }
    }
    expect(seen).toBeGreaterThan(90);
  });

  test("profil de sécurité : refus expliqué sous le réglage, puis récapitulatif avant toute écriture", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sent: { profile?: string; dry_run?: boolean }[] = [];
    // « Renforcé » : essai à blanc simulé (contrat A.3) ; « Strict » : vrai serveur,
    // qui refuse la double authentification pour tous tant que la propriétaire
    // ne l'a pas activée pour elle-même.
    await page.route("**/api/admin/settings/profile", async (route) => {
      const body = route.request().postDataJSON();
      sent.push(body);
      if (body.profile !== "reinforced") return route.fallback();
      return route.fulfill({ json: {
        ok: true, requires_reauth: false, requires_owner: true, impact: [], warnings: [], errors: {},
        diff: [
          { key: "session.idle_minutes", old: 60, new: 30, lowered: false },
          { key: "session.max_hours", old: 12, new: 8, lowered: false },
        ],
      } });
    });
    await openSettings(page, "login");
    const profiles = page.getByRole("group", { name: "Profil de sécurité" });

    await profiles.getByText("Strict", { exact: true }).click();
    await expect(page.locator(".c-setting[data-key=\"twofa.required\"]").getByText("Activez d'abord votre propre double authentification.")).toBeVisible();
    await expect(profiles.getByRole("radio", { name: "Strict" })).not.toBeChecked();

    await profiles.getByText("Renforcé", { exact: true }).click();
    const recap = page.getByRole("dialog", { name: "Profil Renforcé : 2 réglages vont changer" });
    await expect(recap.getByRole("button", { name: "Appliquer le profil Renforcé" })).toBeEnabled();
    await recap.getByRole("button", { name: "Revenir" }).click();
    await expect(recap).toBeHidden();
    await expect(profiles.getByRole("radio", { name: "Renforcé" })).not.toBeChecked();
    expect(sent.map((b) => [b.profile, b.dry_run])).toEqual([["strict", true], ["reinforced", true]]);
  });

  test("repli R11 : sans /admin/settings/schema, les réglages historiques restent modifiables", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/404/);
    const page = await loggedIn("owner");
    await missing(page, "GET", "/admin/settings/schema");
    await openSettings(page, "sessions");
    await expect(page.getByText("Ce serveur ne propose encore que les réglages essentiels.", { exact: false })).toBeVisible();
    await expect(page.getByLabel(IDLE, { exact: true })).toBeVisible();
    await expect(page.getByLabel(MAX_HOURS, { exact: true })).toBeVisible();
    await expect(page.getByLabel(AUTOLOCK, { exact: true })).toHaveCount(0);
  });
});
