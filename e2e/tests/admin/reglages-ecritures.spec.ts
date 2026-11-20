// Administration › Réglages : les tests qui ENREGISTRENT de vrais réglages
// (récapitulatif et « Annuler », parcours A4, historique et retour à une
// version, import). L'organisation de test est partagée par toute la suite
// et un retour à une version remet TOUS les réglages à leur état d'alors :
// ces tests tournent donc les uns après les autres (mode « serial »), et ce
// sont les seuls de tests/admin à écrire des réglages réels.

import type { APIRequestContext, Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { expectToast, goHash, L } from "./outils.ts";

test.use({ textGuardMode: "strict" });

const AUTOLOCK = "Verrouillage automatique des applications";
const MAX_HOURS = "Durée maximale d'une session";
const ORG_NAME = "Nom de l'organisation";

/** Révision courante (ETag « "r42" ») des réglages. */
async function currentEtag(api: APIRequestContext): Promise<string> {
  const res = await api.get("/api/admin/settings");
  expect(res.ok()).toBeTruthy();
  return res.headers()["etag"];
}

/** Enregistre des réglages sans abaissement (aucune confirmation d'identité). */
async function patch(api: APIRequestContext, changes: Record<string, unknown>, reason?: string): Promise<number> {
  const res = await api.patch("/api/admin/settings", { data: { changes, reason }, headers: { "If-Match": await currentEtag(api) } });
  expect(res.status()).toBe(200);
  return (await res.json()).revision;
}

/** Remet au défaut les clés touchées par un test (révision courante en If-Match). */
async function resetKeys(api: APIRequestContext, keys: string[]) {
  const res = await api.post("/api/admin/settings/reset", { data: { keys }, headers: { "If-Match": await currentEtag(api) } });
  expect([200, 428]).toContain(res.status());
}

async function orgName(api: APIRequestContext): Promise<string> {
  const res = await api.get("/api/admin/settings");
  return (await res.json()).values["branding.org_name"].value;
}

async function openPage(page: Page, hash: string, title: string) {
  await goHash(page, hash);
  await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
}

async function openSettings(page: Page, section = "sessions") {
  await openPage(page, `#/admin/reglages/${section}`, "Réglages");
}

test.describe("Réglages › enregistrements réels", () => {
  test.describe.configure({ mode: "serial" });

  test("récapitulatif : abaissement signalé, mot de passe maître exigé, puis « Révision N · Annuler »", async ({ loggedIn, apiAs, org }) => {
    const page = await loggedIn("owner");
    await openSettings(page);
    await page.getByLabel(MAX_HOURS, { exact: true }).selectOption("24");
    await page.getByRole("button", { name: L.saveSettings }).click();
    const recap = page.getByRole("dialog", { name: "Enregistrer 1 modification" });
    await expect(recap.getByText("Sécurité abaissée", { exact: true })).toBeVisible();
    await recap.getByLabel("Motif").fill("audit de sécurité");
    await recap.getByRole("button", { name: L.save }).click();
    const reauth = page.getByRole("dialog", { name: "Confirmer l'abaissement de la sécurité" });
    await reauth.getByLabel(L.masterPassword).fill(org.accounts.owner.password);
    await reauth.getByRole("button", { name: "Confirmer" }).click();
    await expectToast(page, /Réglages enregistrés \(révision \d+\)/);
    await expect(page.getByLabel(MAX_HOURS, { exact: true })).toHaveValue("24");

    // « Annuler » dans le message : l'ancienne valeur revient (nouvelle révision).
    const api = await apiAs("owner");
    const maxHours = async () => (await (await api.get("/api/admin/settings")).json()).values["session.max_hours"].value;
    expect(await maxHours()).toBe(24);
    await page.locator(".c-toast").filter({ hasText: /Réglages enregistrés/ }).getByRole("button", { name: "Annuler" }).click();
    await expect.poll(maxHours).toBe(12);
    await expect(page.getByLabel(MAX_HOURS, { exact: true })).toHaveValue("12");
    await resetKeys(api, ["session.max_hours"]);
  });

  test("parcours A4 : changer le verrouillage des postes en 4 gestes", async ({ loggedIn, clicks, apiAs }) => {
    const page = await loggedIn("owner");
    await goHash(page, "#/admin");
    await expect(page.getByRole("navigation", { name: L.adminNav })).toBeVisible();
    const n = await clicks.measure(async () => {
      await clicks.click(page.getByRole("navigation", { name: L.adminNav }).getByRole("link", { name: "Réglages" }));
      await page.getByLabel(L.settingsSearch).fill("verrou");
      const select = page.getByLabel(AUTOLOCK, { exact: true });
      clicks.count++;
      await select.selectOption("5");
      await clicks.click(page.getByRole("button", { name: L.saveSettings }));
      await clicks.click(page.getByRole("dialog", { name: "Enregistrer 1 modification" }).getByRole("button", { name: L.save }));
      await expectToast(page, /Réglages enregistrés/);
    });
    expect(n).toBeLessThanOrEqual(4);
    await resetKeys(await apiAs("owner"), ["client.autolock_minutes"]);
  });

  test("historique : révision lisible avec motif, puis retour à la version précédente", async ({ loggedIn, apiAs }) => {
    const api = await apiAs("owner");
    const page = await loggedIn("owner");
    // L'organisation est partagée par les tests qui tournent en parallèle :
    // d'autres révisions peuvent s'intercaler, les numéros sont donc relevés.
    const prev = await patch(api, { "branding.org_name": "Version précédente" });
    const revision = await patch(api, { "branding.org_name": "Essai historique" }, "essai de l'historique");
    await openPage(page, "#/admin/reglages/historique", "Historique");

    const ours = page.getByRole("region", { name: `Révision ${revision}`, exact: true });
    await expect(ours.getByText("Motif : essai de l'historique")).toBeVisible();
    await expect(ours.getByText(ORG_NAME)).toBeVisible();
    // La révision la plus récente est la version en vigueur : pas de retour possible.
    const newest = page.getByRole("region", { name: /^Révision \d+$/ }).first();
    await expect(newest.getByRole("button", { name: "Revenir à cette version" })).toHaveCount(0);

    const previous = page.getByRole("region", { name: `Révision ${prev}`, exact: true });
    await previous.getByRole("button", { name: "Revenir à cette version" }).click();
    const dlg = page.getByRole("dialog", { name: `Revenir à la révision ${prev} ?` });
    await expect(dlg.getByText(`Tous les réglages reviennent à leur valeur de la révision ${prev}.`)).toBeVisible();
    await dlg.getByRole("button", { name: "Revenir à cette version" }).click();
    await expectToast(page, /Réglages restaurés \(révision \d+\)\./);
    await expect(page.getByRole("region", { name: /^Révision \d+$/ }).first().getByText("retour à une version antérieure")).toBeVisible();
    expect(await orgName(api)).toBe("Version précédente");
    await resetKeys(api, ["branding.org_name"]);
  });

  test("historique : retour en échec (500 puis réseau coupé), message français et réglages intacts", async ({ loggedIn, apiAs, consoleGuard }) => {
    consoleGuard.allow(/500|Failed to load resource|ERR_FAILED/);
    const api = await apiAs("owner");
    const page = await loggedIn("owner");
    await patch(api, { "branding.org_name": "Version précédente" });
    const revision = await patch(api, { "branding.org_name": "Essai échec" });
    let mode: "500" | "reseau" = "500";
    await page.route((url) => url.pathname.startsWith("/api/admin/settings/revert/"), (route) => (mode === "reseau"
      ? route.abort("failed")
      : route.fulfill({ status: 500, json: { error: "internal", message: "Erreur interne du serveur." } })));
    await openPage(page, "#/admin/reglages/historique", "Historique");
    const previous = page.getByRole("region", { name: `Révision ${revision - 1}`, exact: true });
    for (const expected of [/Erreur interne|serveur/i, /Serveur injoignable/]) {
      await previous.getByRole("button", { name: "Revenir à cette version" }).click();
      await page.getByRole("dialog", { name: `Revenir à la révision ${revision - 1} ?` }).getByRole("button", { name: "Revenir à cette version" }).click();
      await expect(page.locator(".c-toast").filter({ hasText: expected }).first()).toBeVisible();
      mode = "reseau";
    }
    expect(await orgName(api)).toBe("Essai échec");
    await resetKeys(api, ["branding.org_name"]);
  });

  test("export sans secret, puis import en deux temps : essai à blanc avec cases, application en une révision", async ({ loggedIn, apiAs }) => {
    const api = await apiAs("owner");
    const page = await loggedIn("owner");
    await openPage(page, "#/admin/reglages/transfert", "Importer / exporter");

    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Exporter les réglages" }).click();
    const file = await download;
    expect(file.suggestedFilename()).toMatch(/^locksy-reglages-\d{4}-\d{2}-\d{2}\.json$/);

    // Fichier d'une autre instance : un nom d'organisation différent.
    const doc = await (await api.get("/api/admin/settings/export")).json();
    // Valeurs sous leur forme enregistrée ({ value, mode?, min?, max? }).
    doc.values["branding.org_name"] = { value: "Organisation importée" };
    delete doc.sha256;
    await page.locator("#reglages-import").setInputFiles({ name: "reglages.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(doc)) });
    const boxes = page.getByRole("group", { name: /réglage diffère : cochez ceux à appliquer/ });
    await expect(boxes.getByRole("checkbox", { name: ORG_NAME })).toBeChecked();
    expect(await orgName(api)).toBe("");

    await page.getByRole("button", { name: "Vérifier et importer" }).click();
    const recap = page.getByRole("dialog", { name: "Importer 1 réglage" });
    await recap.getByRole("button", { name: "Importer", exact: true }).click();
    await expectToast(page, /Réglages importés \(révision \d+\)/);
    expect(await orgName(api)).toBe("Organisation importée");
    await resetKeys(api, ["branding.org_name"]);
  });
});
