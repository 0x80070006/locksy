// Administration › Journal (cahier §3.4.8, fiche L12) : une phrase par
// événement sans code brut (textGuard strict), gravité en badge et en texte,
// filtres dans l'adresse, panneau de détail avec « Détails techniques »,
// événement inconnu, export CSV avec les mêmes filtres et son échec.

import { test, expect } from "../../fixtures/index.ts";
import { goHash, now } from "./outils.ts";

test.use({ textGuardMode: "strict" });

const ENTRIES = [
  { id: 12, at: now() - 120, user_id: null, email: "hugo.martin@exemple.fr", action: "login.failed", target: "", ip: "10.0.0.8", user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0", details: "", severity: "warning" },
  { id: 11, at: now() - 600, user_id: null, email: "camille.durand@exemple.fr", action: "settings.lowered", target: "r43", ip: "10.0.0.9", user_agent: "", details: "session.max_hours", severity: "critical" },
  { id: 10, at: now() - 900, user_id: null, email: "camille.durand@exemple.fr", action: "inconnu.futur", target: "", ip: "10.0.0.9", user_agent: "", details: "", severity: "info" },
];

test.describe("Journal", () => {
  test("phrases lisibles, gravité en texte, filtres dans l'adresse, détail technique replié", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const seen: URLSearchParams[] = [];
    await page.route((url) => url.pathname === "/api/admin/audit", async (route) => {
      const q = new URL(route.request().url()).searchParams;
      seen.push(q);
      const level = q.get("severity");
      const entries = level ? ENTRIES.filter((e) => e.severity === level) : ENTRIES;
      await route.fulfill({ json: { entries, total: entries.length, next_cursor: null } });
    });
    await goHash(page, "#/admin/journal");
    await expect(page.getByRole("heading", { level: 1, name: "Journal" })).toBeVisible();
    const table = page.getByRole("table", { name: "Événements du journal" });
    await expect(table.getByText("hugo.martin@exemple.fr : connexion refusée, mot de passe incorrect (Chrome sur Windows)")).toBeVisible();
    await expect(table.getByText("Critique")).toBeVisible();
    await expect(table.getByText("camille.durand@exemple.fr : événement technique")).toBeVisible();

    await page.getByRole("button", { name: /^Gravité/ }).click();
    await page.getByRole("menuitemradio", { name: "Attention" }).click();
    await expect(page).toHaveURL(/gravite=warning/);
    await expect.poll(() => seen.at(-1)?.get("severity")).toBe("warning");
    await expect(table.getByText("Critique")).toHaveCount(0);

    await table.getByRole("button", { name: /connexion refusée/ }).click();
    const panel = page.getByRole("dialog", { name: "connexion refusée, mot de passe incorrect" });
    await expect(panel.getByText("Attention")).toBeVisible();
    await expect(panel.getByText("login.failed")).toBeHidden();
    await panel.getByText("Détails techniques").click();
    await expect(panel.getByText("login.failed")).toBeVisible();
    await expect(panel.getByText("10.0.0.8")).toBeVisible();
    await panel.getByRole("button", { name: "Voir les événements de cette personne" }).click();
    await expect(page).toHaveURL(/personne=hugo\.martin%40exemple\.fr|personne=hugo.martin@exemple.fr/);
  });

  test("journal réel de l'organisation : aucun code brut à l'écran", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    await goHash(page, "#/admin/journal");
    await expect(page.getByText(/connexion réussie/).first()).toBeVisible();
  });

  test("export CSV avec les filtres, puis échec affiché en français", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/500|Failed to load resource/);
    const page = await loggedIn("owner");
    let fail = false;
    const asked: string[] = [];
    await page.route((url) => url.pathname === "/api/admin/audit.csv", async (route) => {
      asked.push(route.request().url());
      if (fail) return route.fulfill({ status: 500, json: { error: "internal", message: "Erreur interne du serveur." } });
      return route.fulfill({ body: "﻿date_locale;date_utc\r\n", headers: { "content-type": "text/csv" } });
    });
    await goHash(page, "#/admin/journal?gravite=critical&periode=7j");
    await page.getByRole("button", { name: "Exporter (CSV)" }).click();
    await expect(page.locator(".c-toast").filter({ hasText: "Journal exporté." })).toBeVisible();
    expect(new URL(asked[0]).searchParams.get("severity")).toBe("critical");
    expect(new URL(asked[0]).searchParams.get("from")).toBeTruthy();
    fail = true;
    await page.getByRole("button", { name: "Exporter (CSV)" }).click();
    await expect(page.locator(".c-toast").filter({ hasText: /Erreur|serveur/i }).first()).toBeVisible();
  });
});
