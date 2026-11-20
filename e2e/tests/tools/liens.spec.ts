// Liens envoyés (#/liens, cahier §3.3.5) : nom local (coffre ou préférences
// chiffrées, jamais le serveur), « Élément supprimé », états terminaux et
// motifs lisibles, révocation avec échec puis réussite ; repli sur la liste
// des liens actifs quand GET /shares?all=1 manque.
//
// GET /shares?all=1 et DELETE /shares/:id sont simulés selon le contrat C1.4.

import { test, expect } from "../../fixtures/index.ts";
import { loginUi } from "../../fixtures/ui.ts";
import { aller, creerElements, notification, nouveauCompte, tolerer } from "./outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(({ consoleGuard }) => tolerer(consoleGuard));

const maintenant = () => Math.floor(Date.now() / 1000);
/** GET /api/shares?all=1 (tous les liens) et GET /api/shares (actifs seulement). */
const tousLesLiens = (url: URL) => url.pathname === "/api/shares" && url.searchParams.get("all") === "1";
const liensActifs = (url: URL) => url.pathname === "/api/shares" && !url.searchParams.has("all");

test("noms locaux, états terminaux lisibles, révocation (échec puis réussite)", async ({ page, apiAs, consoleGuard }) => {
  test.setTimeout(150_000);
  consoleGuard.allow(/status of 500/);
  await nouveauCompte(page, await apiAs("owner"), "liens");
  const [itemId] = await creerElements(page, [{ name: "Serveur NAS", username: "exploitation", password: "Lune-Verte-Piano-77!" }]);
  // Nom gardé à la création d'un lien vers un élément supprimé depuis.
  await page.evaluate(async () => {
    const S = await import("/js/settings-client.js");
    await S.savePrefs({ links: { "lien-ancien": { item_id: "element-disparu", label: "Ancien routeur" } } });
  });

  const t0 = maintenant();
  let revoque = false;
  const liens = () => [
    { id: "lien-actif", created_at: t0 - 60, expires_at: t0 + 86_400, max_views: 3, views: 1, state: revoque ? "revoked" : "active", ended_at: revoque ? t0 : null, ended_reason: revoque ? "revoked" : null, item_id: itemId, has_verifier: true },
    { id: "lien-ancien", created_at: t0 - 7200, expires_at: t0 + 3600, max_views: 1, views: 1, state: "exhausted", ended_at: t0 - 3600, ended_reason: "exhausted", item_id: null, has_verifier: true },
    { id: "lien-admin", created_at: t0 - 7200, expires_at: t0 + 3600, max_views: 5, views: 0, state: "revoked", ended_at: t0 - 1800, ended_reason: "revoked_admin", item_id: null, has_verifier: false },
  ];
  await page.route(tousLesLiens, (route) => route.fulfill({ json: liens() }));
  let echecs = 1;
  const suppressions: string[] = [];
  await page.route("**/api/shares/lien-actif", async (route) => {
    suppressions.push(route.request().method());
    if (echecs-- > 0) return route.fulfill({ status: 500, json: { error: "internal", message: "Erreur interne." } });
    revoque = true;
    return route.fulfill({ status: 204 });
  });

  await aller(page, "/liens");
  await expect(page.getByRole("heading", { level: 1, name: "Liens envoyés" })).toBeVisible();
  const actifs = page.getByRole("table", { name: "Lien actif (1)" });
  await expect(actifs.getByRole("row").filter({ hasText: "Serveur NAS" })).toContainText("1 sur 3");
  const termines = page.getByRole("table", { name: "Liens terminés (2)" });
  await expect(termines.getByRole("row").filter({ hasText: "Ancien routeur" })).toContainText("Nombre d'ouvertures atteint");
  await expect(termines.getByRole("row").filter({ hasText: "Élément supprimé" })).toContainText("Révoqué par un administrateur");

  const revoquer = page.getByRole("button", { name: "Révoquer le lien vers Serveur NAS" });
  await revoquer.click();
  await page.getByRole("dialog", { name: "Révoquer ce lien ?" }).getByRole("button", { name: "Révoquer" }).click();
  await expect(notification(page, /Le lien n'a pas été révoqué/)).toBeVisible();
  await expect(revoquer).toBeVisible();

  await revoquer.click();
  await page.getByRole("dialog", { name: "Révoquer ce lien ?" }).getByRole("button", { name: "Révoquer" }).click();
  await expect(notification(page, "Lien révoqué.")).toBeVisible();
  await expect(page.getByText("Aucun lien actif.")).toBeVisible();
  await expect(page.getByRole("table", { name: "Liens terminés (3)" }).getByRole("row").filter({ hasText: "Serveur NAS" })).toContainText("Révoqué par vous");
  expect(suppressions).toEqual(["DELETE", "DELETE"]);
});

test("serveur sans GET /shares?all=1 : liste des liens actifs (repli)", async ({ page, org, consoleGuard }) => {
  consoleGuard.allow(/status of 404/);
  const t0 = maintenant();
  await page.route(tousLesLiens, (route) => route.fulfill({ status: 404, json: { error: "not_found", message: "Ressource introuvable." } }));
  await page.route(liensActifs, (route) => route.fulfill({
    json: [{ id: "lien-historique", created_at: t0 - 60, expires_at: t0 + 3600, max_views: 2, views: 0 }],
  }));
  await loginUi(page, org.accounts.user);
  await aller(page, "/liens");
  const actifs = page.getByRole("table", { name: "Lien actif (1)" });
  await expect(actifs.getByRole("row").filter({ hasText: "Élément supprimé" })).toContainText("0 sur 2");
  await expect(page.getByRole("table", { name: /terminés/ })).toHaveCount(0);
});
