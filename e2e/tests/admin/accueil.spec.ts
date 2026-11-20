// Administration › Accueil (cahier §3.4.2, fiche L12) : mise en service
// déduite de l'état réel, chaque alerte « À traiter » ouvre la liste filtrée
// ou le réglage en contexte (parcours A2 en 3 gestes, impact affiché), taux
// de double authentification sur les comptes actifs avec numérateur et
// dénominateur. /admin/stats enrichi (contrat C1.1) est simulé.

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { goHash, L, now, simulate, type SimServer } from "./outils.ts";

test.use({ textGuardMode: "strict" });

const stats = () => ({
  users: 50, active_users: 42, users_with_2fa: 37, collections: 12, shared_collections: 8, items: 900, active_shares: 7, failed_logins_24h: 2,
  active_with_2fa: 37, admins_without_2fa: 1, owners: 1, inactive_users: 4, pending_invites: 3, expired_invites: 3, active_share_links: 7,
  last_ldap_sync: { at: now() - 720, ok: true, found: 42 }, scim_last_used_at: null, last_backup_at: now() - 3 * 3600, pending_deprovision: 0,
  setup: { second_owner: false, twofa_self: true, login_method_chosen: true, profile_chosen: true, invites_sent: false, extension_seen: false, siem_configured: false },
});

async function home(page: Page): Promise<SimServer> {
  const sim = await simulate(page);
  await sim.on("GET", "/admin/stats", () => stats());
  await goHash(page, "#/admin");
  await expect(page.getByRole("heading", { level: 1, name: "Accueil" })).toBeVisible();
  return sim;
}

test.describe("Accueil de l'administration", () => {
  test("mise en service, chiffres et état du service", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    await home(page);
    await expect(page.getByRole("heading", { name: "Mise en service · 3 étapes sur 6" })).toBeVisible();
    await expect(page.getByText("Prochaine étape : Nommer un deuxième propriétaire.")).toBeVisible();
    await expect(page.getByText("avec double authentification (37 sur 42)")).toBeVisible();
    await expect(page.getByText(/Active Directory : synchronisé il y a 12 min \(42 comptes\)/)).toBeVisible();
    await expect(page.getByText("Vous gérez les accès, pas les secrets", { exact: false })).toBeVisible();
    // Aucune recherche du coffre dans l'administration.
    await expect(page.getByRole("main").getByRole("search", { name: "Rechercher dans tout le coffre" })).toHaveCount(0);
  });

  test("chaque alerte ouvre la liste filtrée", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sim = await home(page);
    await sim.on("GET", "/admin/people", () => ({ total: 0, page: 1, per_page: 25, rows: [] }));
    const todo = page.getByRole("region", { name: "À traiter" });
    const cases: [RegExp, RegExp][] = [
      [/administrateur n'a pas activé/, /#\/admin\/personnes\?role=admin&2fa=non&etat=actif/],
      [/invitations ont expiré/, /#\/admin\/personnes\?etat=invitation_expiree/],
      [/Un seul propriétaire/, /#\/admin\/personnes\?role=admin/],
      [/ne se sont pas connectées depuis 90 jours/, /#\/admin\/personnes\?etat=inactif/],
    ];
    for (const [text, url] of cases) {
      const alert = todo.locator(".c-alert", { hasText: text });
      await alert.getByRole("link").first().click();
      await expect(page).toHaveURL(url);
      await expect(page.getByRole("heading", { level: 1, name: /^Personnes/ })).toBeVisible();
      expect(sim.called("GET", "/admin/people").length).toBeGreaterThan(0);
      await goHash(page, "#/admin");
      await expect(page.getByRole("heading", { level: 1, name: "Accueil" })).toBeVisible();
    }
  });

  test("parcours A2 : imposer la double authentification en 3 gestes, impact affiché", async ({ loggedIn, clicks }) => {
    const page = await loggedIn("owner");
    const sim = await home(page);
    await sim.on("POST", "/admin/settings/validate", () => ({
      ok: true, diff: [{ key: "twofa.required", old: false, new: true, lowered: false }], requires_reauth: false, requires_owner: true,
      impact: [{ key: "twofa.required", affected_users: 5, affected_admins: 1, link: "#/admin/personnes?2fa=non&etat=actif" }], warnings: [], errors: {},
    }));
    await sim.on("PATCH", "/admin/settings", () => ({ status: 200, json: { revision: 43, changed: ["twofa.required"] }, headers: { etag: "\"r43\"" } }));
    const n = await clicks.measure(async () => {
      await clicks.click(page.getByRole("button", { name: "Imposer la double authentification…" }));
      const panel = page.getByRole("dialog", { name: "Imposer la double authentification…" });
      await clicks.click(panel.getByRole("switch", { name: "Double authentification obligatoire pour tous" }));
      await expect(panel.getByText("5 personnes devront activer la double authentification à leur prochaine connexion.")).toBeVisible();
      await clicks.click(panel.getByRole("button", { name: L.save }));
      await expect(panel).toBeHidden();
    });
    expect(n).toBeLessThanOrEqual(3);
    expect(sim.called("PATCH", "/admin/settings")[0].body).toMatchObject({ changes: { "twofa.required": true } });
    expect(sim.called("PATCH", "/admin/settings")[0].headers["if-match"]).toMatch(/^"r\d+"$/);
  });

  test("réglage en contexte en échec : message dans le panneau, saisie conservée", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/500|Failed to load resource/);
    const page = await loggedIn("owner");
    const sim = await home(page);
    await sim.on("POST", "/admin/settings/validate", () => ({ ok: true, diff: [], requires_reauth: false, requires_owner: false, impact: [], warnings: [], errors: {} }));
    await sim.on("PATCH", "/admin/settings", () => ({}));
    sim.fail("PATCH", "/admin/settings", 500);
    await page.locator(".c-alert", { hasText: /ne se sont pas connectées/ }).getByRole("button", { name: "Modifier le seuil" }).click();
    const panel = page.getByRole("dialog", { name: "Modifier le seuil" });
    await panel.getByLabel("Signaler les comptes inactifs après", { exact: true }).selectOption("180");
    await panel.getByRole("button", { name: L.save }).click();
    await expect(panel.getByText(/Erreur|serveur/i).first()).toBeVisible();
    await expect(panel.getByLabel("Signaler les comptes inactifs après", { exact: true })).toHaveValue("180");
  });

  test("repli : statistiques historiques seulement, l'accueil reste lisible", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await sim.on("GET", "/admin/stats", () => ({ users: 3, active_users: 3, users_with_2fa: 1, collections: 1, shared_collections: 0, items: 0, active_shares: 0, failed_logins_24h: 0 }));
    await goHash(page, "#/admin");
    await expect(page.getByText("avec double authentification (1 sur 3)")).toBeVisible();
    await expect(page.getByRole("heading", { name: /Mise en service/ })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Activité récente" })).toBeVisible();
  });
});
