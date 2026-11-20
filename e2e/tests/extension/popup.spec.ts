// Extension (lot L14, cahier §3.5.1 et §5.4 L14, écarts #37 et #38) :
// remplissage p95 < 300 ms, code copié puis effacé après le délai,
// enregistrement avec les vraies valeurs saisies, extension.http_fill = block,
// verrouillage réel (alarme simulée), axe, ouverture → liste filtrée < 400 ms,
// injection du code de vérification (totp_fill), échecs d'écriture, extension
// refusée par l'organisation et repli 404.
//
// Projet « extension » : EXT_PATH vers la variante des tests
// (node extension/build.mjs --test → extension/dist/locksy-extension-test) ;
// sans EXT_PATH, les tests sont ignorés proprement par la fixture.

import type { BrowserContext, Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { seriousViolations } from "../../fixtures/axe.ts";
import { findForbidden } from "../../fixtures/guards.ts";
import { totp } from "../../fixtures/totp.ts";
import type { Account } from "../../fixtures/ui.ts";
import { organisation } from "./amorcage.ts";
import {
  L, KDF_TIMEOUT, loginPage, uniqueSite, serveSite, extension, configureServer, tabIdOf, openPopup, unlock, createItem,
  clipboardText, percentile, localCopy,
} from "./outils.ts";

const SECRET = "JBSWY3DPEHPK3PXP";

// Extension copiée hors du montage /work avant le lancement du contexte (fixture extensionContext).
test.use({ extensionPath: localCopy() });
// Le premier test amorce aussi l'organisation (trois comptes, voir amorcage.ts).
test.describe.configure({ timeout: 240_000 });

// Réponses attendues, pas des pannes : /extension/allowed absente d'un serveur
// qui ne la connaît pas (repli testé plus bas), /me/prefs en 404 tant que la
// personne n'a enregistré aucune préférence, icône des sites de test simulés
// (le navigateur la demande hors de context.route()). Le garde ne compare que
// le texte du message, sans l'adresse : seuls ces deux libellés sont admis.
test.beforeEach(({ consoleGuard }) => {
  consoleGuard.allow(/^Failed to load resource: (the server responded with a status of 404 \(Not Found\)|net::ERR_NAME_NOT_RESOLVED)$/);
});

interface Setup {
  ctx: BrowserContext;
  control: Page;
  id: string;
  origin: string;
  site: Page;
  popup: Page;
  csp: string[];
  account: Account;
}

/** Site de test ouvert dans un onglet, popup visant cet onglet, compte « user » déverrouillé. */
async function setup(ctx: BrowserContext, xff: string, { scheme = "https", code = false, login = true } = {}): Promise<Setup> {
  await ctx.setExtraHTTPHeaders({ "X-Forwarded-For": xff });
  const { id, control } = await extension(ctx);
  const account = (await organisation(ctx, id)).accounts.user;
  await configureServer(control);
  const origin = uniqueSite(scheme as "https" | "http");
  await serveSite(ctx, origin, loginPage({ code }));
  const site = await ctx.newPage();
  await site.goto(`${origin}/connexion`);
  const { popup, csp } = await openPopup(ctx, id, await tabIdOf(control, site));
  if (login) await unlock(popup, account);
  return { ctx, control, id, origin, site, popup, csp, account };
}

const hostOf = (origin: string) => new URL(origin).hostname;

/**
 * Étapes de l'ouverture du popup (ms depuis le début de la navigation) :
 * repères locksy:popup:* et locksy:sync:* (popup.html?perf=1) et requêtes
 * au serveur (fin de réponse). Pièce jointe du test de durée.
 */
function openingSteps(page: Page): Promise<Record<string, number>> {
  return page.evaluate(() => {
    const out: Record<string, number> = {};
    for (const e of performance.getEntries()) {
      if (e.entryType === "mark" && e.name.startsWith("locksy:")) out[e.name.slice(7)] = Math.round(e.startTime);
      else if (e.entryType === "resource") {
        const path = new URL(e.name).pathname;
        // Les fichiers de l'extension (chrome-extension://) n'ont pas de mesure de ressource.
        if (path.startsWith("/api/")) out[path.slice(1)] = Math.round((e as PerformanceResourceTiming).responseEnd);
      }
    }
    const nav = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined;
    if (nav) out.domContentLoaded = Math.round(nav.domContentLoadedEventEnd);
    return out;
  });
}

test.describe("Extension : fenêtre de remplissage", () => {
  test.use({ textGuardMode: "strict" });

  // Durée mesurée DANS le navigateur, du début du chargement du popup à la
  // première image qui affiche la liste (repère « painted ») : le délai propre
  // à Playwright (création de la page, attente des sélecteurs) n'en fait pas
  // partie. La durée vue par Playwright est jointe pour information.
  test("ouverture → liste filtrée sur le site en moins de 400 ms", async ({ extensionContext, xff }, testInfo) => {
    test.fail(true, "Défaut produit, handoff V3I-H1 : ouverture du popup en 540 à 720 ms (médiane), pour 400 ms ; le chargement des modules partagés (ui/index.js, catalogue fr.js de 233 Ko) en prend environ 500");
    const s = await setup(extensionContext, xff);
    const name = `Intranet ${hostOf(s.origin)}`;
    await createItem(s.popup, { name, url: s.origin });
    const tabId = await tabIdOf(s.control, s.site);
    const times: number[] = [];
    const wall: number[] = [];
    const steps: Record<string, number>[] = [];
    for (let i = 0; i < 7; i++) {
      const page = await extensionContext.newPage();
      const t0 = Date.now();
      await page.goto(`chrome-extension://${s.id}/popup.html?tab=${tabId}&perf=1`);
      await expect(page.getByRole("button", { name: L.fill(name) })).toBeVisible();
      wall.push(Date.now() - t0);
      await expect.poll(() => openingSteps(page).then((x) => x["popup:painted"] ?? 0)).toBeGreaterThan(0);
      const st = await openingSteps(page);
      steps.push(st);
      times.push(st["popup:painted"]);
      await page.close();
    }
    await testInfo.attach("ouverture-ms.json", { body: JSON.stringify({ times, wall, steps }, null, 1), contentType: "application/json" });
    expect(percentile(times, 0.5), `mesures : ${times.join(", ")} ms (Playwright : ${wall.join(", ")} ms)`).toBeLessThan(400);
    // La liste « Pour ce site » ne montre que les comptes du site ouvert.
    await expect(s.popup.getByRole("list", { name: L.forSite }).getByRole("listitem")).toHaveCount(1);
    expect(s.csp).toEqual([]);
  });

  // Durée mesurée dans le navigateur, du clic dans le popup (horloge absolue
  // performance.timeOrigin + now) à l'événement « input » du champ du mot de
  // passe dans la page : la latence propre à Playwright n'en fait pas partie.
  test("remplissage : identifiant et mot de passe, p95 < 300 ms", async ({ extensionContext, xff }, testInfo) => {
    const s = await setup(extensionContext, xff);
    const name = `Messagerie ${hostOf(s.origin)}`;
    await createItem(s.popup, { name, url: s.origin, username: "camille.durand", password: "Rempli-Par-Locksy-7" });
    // Premier remplissage par un vrai clic (contrôle fonctionnel), puis
    // mesures : le popup se ferme après chaque remplissage (comme dans le
    // navigateur) et il est rouvert à chaque mesure.
    await s.popup.getByRole("button", { name: L.fill(name) }).click();
    await expect(s.site.locator("#mdp")).toHaveValue("Rempli-Par-Locksy-7");
    await expect(s.site.locator("#identifiant")).toHaveValue("camille.durand");
    const tabId = await tabIdOf(s.control, s.site);
    const times: number[] = [];
    for (let i = 0; i < 20; i++) {
      await s.site.evaluate(() => {
        const w = window as unknown as { filledAt?: number };
        delete w.filledAt;
        for (const id of ["identifiant", "mdp"]) (document.getElementById(id) as HTMLInputElement).value = "";
        document.getElementById("mdp")!.addEventListener("input", () => { w.filledAt = performance.timeOrigin + performance.now(); }, { once: true });
      });
      const popup = await extensionContext.newPage();
      await popup.goto(`chrome-extension://${s.id}/popup.html?tab=${tabId}`);
      const fill = popup.getByRole("button", { name: L.fill(name) });
      await expect(fill).toBeVisible({ timeout: KDF_TIMEOUT });
      const closed = popup.waitForEvent("close");
      const clickedAt = await fill.evaluate((b: HTMLElement) => {
        const at = performance.timeOrigin + performance.now();
        b.click();
        return at;
      });
      const filledAt = await s.site.waitForFunction(() => (window as unknown as { filledAt?: number }).filledAt, null, { polling: 5 });
      times.push(Math.round((await filledAt.jsonValue() as number) - clickedAt));
      await closed;
    }
    await testInfo.attach("remplissage-ms.json", { body: JSON.stringify(times), contentType: "application/json" });
    await expect(s.site.locator("#mdp")).toHaveValue("Rempli-Par-Locksy-7");
    expect(percentile(times, 0.95), `mesures : ${times.join(", ")} ms`).toBeLessThan(300);
  });

  test("enregistre les valeurs saisies dans la page, jamais un mot de passe généré", async ({ extensionContext, xff }) => {
    const s = await setup(extensionContext, xff);
    // Rien de saisi : le popup propose explicitement de créer un mot de passe.
    await s.popup.getByRole("button", { name: L.save }).click();
    await expect(s.popup.getByText("Aucun mot de passe saisi sur cette page")).toBeVisible();
    await expect(s.popup.getByRole("button", { name: L.createPassword })).toBeVisible();
    await s.popup.getByRole("button", { name: "Retour" }).click();

    await s.site.locator("#identifiant").fill("camille.durand@exemple.fr");
    await s.site.locator("#mdp").fill("Ma-Vraie-Valeur-42");
    await s.popup.getByRole("button", { name: L.save }).click();
    await expect(s.popup.getByText("repris de la page")).toBeVisible();
    await expect(s.popup.getByLabel("Identifiant")).toHaveValue("camille.durand@exemple.fr");
    await expect(s.popup.getByLabel("Mot de passe", { exact: true })).toHaveValue("Ma-Vraie-Valeur-42");
    await s.popup.getByRole("button", { name: "Enregistrer", exact: true }).click();
    await expect(s.popup.getByRole("heading", { name: L.forSite })).toBeVisible();
    const name = hostOf(s.origin);
    await expect(s.popup.getByRole("button", { name: L.fill(name) })).toBeVisible();
    const stored = await s.popup.evaluate(async (n) => {
      const V = await import("./lib/vault.js");
      const it = [...V.state.items.values()].find((i) => i.data?.name === n);
      return { username: it?.data.username, password: it?.data.password, urls: it?.data.urls };
    }, name);
    expect(stored).toEqual({ username: "camille.durand@exemple.fr", password: "Ma-Vraie-Valeur-42", urls: [s.origin] });
  });

  test("échec de l'enregistrement : message en français, saisie intacte", async ({ extensionContext, xff, consoleGuard }) => {
    consoleGuard.allow(/Failed to load resource|net::ERR_FAILED/);
    const s = await setup(extensionContext, xff);
    await s.site.locator("#identifiant").fill("camille");
    await s.site.locator("#mdp").fill("Valeur-Intacte-9");
    await s.popup.getByRole("button", { name: L.save }).click();
    await s.popup.route("**/api/items", (route) => route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ error: "internal", message: "panne" }) }));
    await s.popup.getByRole("button", { name: "Enregistrer", exact: true }).click();
    const alert = s.popup.locator("#alert");
    await expect(alert).toBeVisible();
    await expect(alert).not.toHaveText(/panne|internal|500/);
    await expect(s.popup.getByLabel("Mot de passe", { exact: true })).toHaveValue("Valeur-Intacte-9");
    await s.popup.unroute("**/api/items");
    await s.popup.route("**/api/items", (route) => route.abort("failed"));
    await s.popup.getByRole("button", { name: "Enregistrer", exact: true }).click();
    await expect(alert).toContainText("Serveur injoignable");
    await expect(s.popup.getByLabel("Identifiant")).toHaveValue("camille");
  });

  test("code de vérification : copié après le remplissage puis effacé après le délai", async ({ extensionContext, xff }) => {
    const s = await setup(extensionContext, xff);
    const name = `Banque ${hostOf(s.origin)}`;
    await createItem(s.popup, { name, url: s.origin, totp: SECRET });
    // Délai d'effacement réduit à 10 s dans les préférences (synchronisées).
    await s.popup.getByRole("button", { name: L.prefs }).click();
    await s.popup.getByLabel(L.clipboardAfter).selectOption("10");
    await expect(s.popup.locator("#status")).toHaveText("Préférence enregistrée.");
    await s.popup.getByRole("button", { name: "Retour" }).click();

    await s.popup.bringToFront();
    await s.popup.getByRole("button", { name: L.fillCode(name) }).click();
    // Message visible (notification) et annoncé (#status).
    await expect(s.popup.getByText("Code copié, collez-le à l'étape suivante").first()).toBeVisible();
    await expect(s.site.locator("#mdp")).toHaveValue("Mdp-Essai-2024-x");
    const copied = await clipboardText(s.popup);
    const now = Date.now() / 1000;
    expect([totp(SECRET, { time: now }), totp(SECRET, { time: now - 30 })]).toContain(copied);
    // Popup fermé : le service worker efface le presse-papiers.
    await s.popup.close();
    const reader = await extensionContext.newPage();
    await reader.goto(`chrome-extension://${s.id}/popup.html?tab=${await tabIdOf(s.control, s.site)}`);
    await expect.poll(async () => (await clipboardText(reader)).trim(), { timeout: 20_000, intervals: [1000] }).toBe("");
  });

  test("injection du code de vérification dans la page quand l'élément le permet (#37)", async ({ extensionContext, xff }) => {
    const s = await setup(extensionContext, xff, { code: true });
    const name = `Portail ${hostOf(s.origin)}`;
    await createItem(s.popup, { name, url: s.origin, totp: SECRET, totpFill: true });
    // totp_fill : le bouton remplit le code au lieu de le copier.
    await s.popup.getByRole("button", { name: L.fill(name), exact: true }).click();
    await expect(s.site.locator("#mdp")).toHaveValue("Mdp-Essai-2024-x");
    const now = Date.now() / 1000;
    const code = await s.site.locator("#code").inputValue();
    expect([totp(SECRET, { time: now }), totp(SECRET, { time: now - 30 })]).toContain(code);
  });

  test("page http : remplissage bloqué par la politique (extension.http_fill = block)", async ({ extensionContext, xff }) => {
    const s = await setup(extensionContext, xff, { scheme: "http" });
    const name = `Ancien ${hostOf(s.origin)}`;
    await createItem(s.popup, { name, url: s.origin });
    await expect(s.popup.getByText("votre organisation interdit d'y remplir un mot de passe")).toBeVisible();
    const fill = s.popup.getByRole("button", { name: L.fill(name) });
    await expect(fill).toHaveAttribute("aria-disabled", "true");
    await fill.click({ force: true });
    await expect(s.site.locator("#mdp")).toHaveValue("");
  });

  test("page http : avertissement seulement si l'organisation choisit « warn »", async ({ extensionContext, xff }) => {
    const s = await setup(extensionContext, xff, { scheme: "http", login: false });
    await s.ctx.route("**/api/settings/policy", (route) => route.fulfill({
      status: 200, contentType: "application/json",
      body: JSON.stringify({ revision: 1, policy: { "extension.http_fill": { value: "warn" } } }),
    }));
    await unlock(s.popup, s.account);
    const name = `Ancien ${hostOf(s.origin)}`;
    await createItem(s.popup, { name, url: s.origin });
    await expect(s.popup.getByText("circule en clair sur le réseau")).toBeVisible();
    await s.popup.getByRole("button", { name: L.fill(name) }).click();
    await expect(s.site.locator("#mdp")).toHaveValue("Mdp-Essai-2024-x");
  });

  test("verrouillage réel à l'échéance (alarme simulée), popup ouvert ou fermé", async ({ extensionContext, xff }) => {
    const s = await setup(extensionContext, xff);
    const alarm = await s.control.evaluate(() => chrome.alarms.get("locksy-autolock"));
    expect(alarm?.scheduledTime).toBeGreaterThan(Date.now());
    await expect(s.popup.getByText(/Verrouillage dans \d+ min/)).toBeVisible();
    // Échéance avancée à maintenant : le service worker efface la session.
    await s.control.evaluate(() => chrome.alarms.create("locksy-autolock", { when: Date.now() + 500 }));
    await expect.poll(() => s.control.evaluate(async () => (await chrome.storage.session.get("vault")).vault ?? null), { timeout: 10_000 }).toBeNull();
    await expect(s.popup.getByLabel(L.master, { exact: true })).toBeVisible();
    await expect(s.popup.locator("#app").getByText("Coffre verrouillé.")).toBeVisible();
    // Réouverture : le mot de passe maître est redemandé.
    const again = await extensionContext.newPage();
    await again.goto(`chrome-extension://${s.id}/popup.html?tab=${await tabIdOf(s.control, s.site)}`);
    await expect(again.getByLabel(L.master, { exact: true })).toBeVisible();
  });

  test("accessibilité (axe) et textes du popup : connexion puis écran principal", async ({ extensionContext, xff }) => {
    const s = await setup(extensionContext, xff, { login: false });
    await expect(s.popup.getByRole("heading", { level: 1, name: "Locksy" })).toBeVisible();
    expect(await seriousViolations(s.popup)).toEqual([]);
    await unlock(s.popup, s.account);
    const name = `Accessible ${hostOf(s.origin)}`;
    await createItem(s.popup, { name, url: s.origin, totp: SECRET });
    await expect(s.popup.getByRole("heading", { level: 1, name: "Locksy" })).toBeVisible();
    await expect(s.popup.getByRole("list", { name: L.forSite })).toBeVisible();
    await expect(s.popup.getByRole("button", { name: L.lock })).toBeVisible();
    await expect(s.popup.getByRole("button", { name: L.open })).toBeVisible();
    expect(await seriousViolations(s.popup)).toEqual([]);
    const text = await s.popup.locator("body").innerText();
    expect(text.split("\n").flatMap(findForbidden)).toEqual([]);
    expect(s.csp).toEqual([]);
  });

  test("extension refusée par l'organisation, et repli quand le serveur ne connaît pas la vérification", async ({ extensionContext, xff }) => {
    const s = await setup(extensionContext, xff, { login: false });
    // Serveur sans la route (404) : comportement d'avant, l'écran de connexion s'affiche.
    await expect(s.popup.getByLabel(L.master, { exact: true })).toBeVisible();
    await s.ctx.route(/\/api\/extension\/allowed\?/, (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ allowed: false }) }));
    await s.popup.reload();
    await expect(s.popup.getByText("Extension non autorisée")).toBeVisible();
    await expect(s.popup.getByText(s.id)).toBeVisible();
    await expect(s.popup.getByLabel(L.master, { exact: true })).toHaveCount(0);
  });
});

test.describe("Extension : connexion", () => {
  test("le mot de passe maître déverrouille et le verrouillage manuel revient à la connexion", async ({ extensionContext, xff }) => {
    const s = await setup(extensionContext, xff);
    await s.popup.getByRole("button", { name: L.lock }).click();
    await expect(s.popup.getByLabel(L.master, { exact: true })).toBeVisible({ timeout: KDF_TIMEOUT });
    expect(await s.control.evaluate(async () => (await chrome.storage.session.get("vault")).vault ?? null)).toBeNull();
  });
});

declare const chrome: any;
