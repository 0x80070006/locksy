// Assistant « Départ de l'entreprise » (cahier §3.4.5, parcours A3, fiche
// L12) : 4 étapes, repreneur proposé parmi les membres, simulation affichée
// avant toute écriture (dry_run), confirmation par mot de passe maître,
// rapport CSV ; échec du départ réel ; repli sans offboard-plan.
// Routes simulées selon le contrat C1.1.

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { goHash, L, missing, now, simulate, type SimServer } from "./outils.ts";

test.use({ textGuardMode: "strict" });

const PLAN = {
  user: { id: "u-hugo", name: "Hugo Martin", email: "hugo.martin@exemple.fr", role: "user", status: "active" },
  sessions: 2,
  collections: [
    { id: "c1", personal: false, items_count: 340, sole_manager: true, shared: true, members: [{ user_id: "u-lea", name: "Léa Petit", email: "lea.petit@exemple.fr", role: "editor" }] },
    { id: "c2", personal: false, items_count: 12, sole_manager: true, shared: true, members: [{ user_id: "u-camille", name: "Camille Durand", email: "camille.durand@exemple.fr", role: "reader" }] },
    { id: "c3", personal: false, items_count: 4, sole_manager: true, shared: false, members: [] },
  ],
  delete_after_days: 30,
};

const REPORT = { disabled: true, sessions_closed: 2, transferred: 2, orphaned: [{ collection_id: "c3", items_count: 4 }], rotation_suggested: 2, shares_revoked: 1, deprovision_at: now() + 30 * 86400 };

async function wizardPage(page: Page): Promise<SimServer> {
  const sim = await simulate(page);
  await sim.on("GET", "/admin/users/u-hugo/offboard-plan", () => PLAN);
  await sim.on("POST", "/admin/users/u-hugo/offboard", () => ({ report: REPORT, report_csv: "/api/admin/users/u-hugo/access-report.csv" }));
  await sim.on("POST", "/auth/reauth", (_r, body) => ({ token: "rt1.depart", expires_in: 120, action: (body as { action: string }).action }));
  await goHash(page, "#/admin/personnes/u-hugo/depart");
  await expect(page.getByRole("heading", { level: 1, name: "Départ de Hugo Martin" })).toBeVisible();
  return sim;
}

test.describe("Départ de l'entreprise", () => {
  test("4 étapes, simulation sans écriture puis départ confirmé en 6 gestes au plus", async ({ loggedIn, org, clicks }) => {
    const page = await loggedIn("owner");
    const sim = await wizardPage(page);
    const next = () => page.getByRole("button", { name: "Continuer" });
    const n = await clicks.measure(async () => {
      await expect(page.getByRole("checkbox", { name: /Désactiver le compte/ })).toBeChecked();
      await clicks.click(next());
      await expect(page.getByLabel("Repreneur").first()).toHaveValue("u-lea");
      await expect(page.getByText(/1 coffre n'a pas d'autre membre/)).toBeVisible();
      await clicks.click(next());
      await expect(page.getByRole("checkbox", { name: /Conseiller de changer ces mots de passe/ })).toBeChecked();
      await clicks.click(next());
      await expect(page.getByText("Voici ce qui sera fait. Rien n'est encore modifié.")).toBeVisible();
      await expect(page.getByText("2 coffres repris par un membre.")).toBeVisible();
      await clicks.click(page.getByRole("button", { name: "Confirmer le départ" }));
      const dlg = page.getByRole("dialog", { name: "Confirmer le départ de Hugo Martin" });
      await dlg.getByLabel(L.masterPassword).fill(org.accounts.owner.password);
      await clicks.click(dlg.getByRole("button", { name: "Confirmer le départ" }));
      await expect(page.getByRole("button", { name: "Télécharger le rapport (CSV)" })).toBeVisible({ timeout: 60_000 });
    });
    expect(n).toBeLessThanOrEqual(6);
    const calls = sim.called("POST", "/admin/users/u-hugo/offboard");
    expect(calls[0].query.get("dry_run")).toBe("true");
    const real = calls.at(-1)!;
    expect(real.query.get("dry_run")).toBe("false");
    expect(real.headers["x-locksy-reauth"]).toBe("rt1.depart");
    expect(real.body).toMatchObject({ disable: true, revoke_sessions: true, suggest_rotation: true, delete_after_days: 30,
      transfers: [{ collection_id: "c1", new_manager_id: "u-lea" }, { collection_id: "c2", new_manager_id: "u-camille" }] });
    expect((sim.called("POST", "/auth/reauth")[0].body as { action: string }).action).toBe("admin.offboard");
  });

  test("échec du départ : message français, rien n'est annoncé comme fait", async ({ loggedIn, org, consoleGuard }) => {
    consoleGuard.allow(/500|Failed to load resource/);
    const page = await loggedIn("owner");
    const sim = await wizardPage(page);
    for (let i = 0; i < 3; i++) await page.getByRole("button", { name: "Continuer" }).click();
    await expect(page.getByText("Voici ce qui sera fait.", { exact: false })).toBeVisible();
    sim.fail("POST", "/admin/users/u-hugo/offboard", 500);
    await page.getByRole("button", { name: "Confirmer le départ" }).click();
    const dlg = page.getByRole("dialog", { name: "Confirmer le départ de Hugo Martin" });
    await dlg.getByLabel(L.masterPassword).fill(org.accounts.owner.password);
    await dlg.getByRole("button", { name: "Confirmer le départ" }).click();
    await expect(page.locator(".c-toast").filter({ hasText: /Erreur|serveur/i }).first()).toBeVisible({ timeout: 60_000 });
    await expect(page.getByRole("button", { name: "Télécharger le rapport (CSV)" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Confirmer le départ" })).toBeVisible();
  });

  test("repli : serveur sans plan de départ, l'assistant coupe quand même l'accès", async ({ loggedIn, org, consoleGuard }) => {
    consoleGuard.allow(/404/);
    const page = await loggedIn("owner");
    await missing(page, "GET", /^\/admin\/users\/[^/]+\/offboard-plan$/);
    const users = await page.evaluate(async () => (await fetch("/api/admin/users", { headers: { authorization: `Bearer ${sessionStorage.getItem("locksy.session")}` } })).json());
    const alice = (users as { id: string; email: string }[]).find((u) => u.email === org.accounts.user.email)!;
    const sim = await simulate(page);
    await sim.on("POST", `/admin/users/${alice.id}/revoke-sessions`, () => ({}));
    await sim.on("PUT", `/admin/users/${alice.id}`, () => ({}));
    await goHash(page, `#/admin/personnes/${alice.id}/depart`);
    await expect(page.getByRole("heading", { level: 1, name: `Départ de ${org.accounts.user.name}` })).toBeVisible();
    await page.getByRole("button", { name: "Continuer" }).click();
    await expect(page.getByText("Ce serveur ne détaille pas encore les coffres", { exact: false })).toBeVisible();
  });
});
