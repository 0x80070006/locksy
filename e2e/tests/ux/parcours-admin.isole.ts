// Parcours chiffrés de l'administration qui MODIFIENT l'organisation
// (cahier §3.6, critère G6) : A2 « imposer la double authentification »
// (3 clics depuis l'Accueil, impact affiché) et A4 « changer le délai de
// verrouillage des postes » (4 clics). Suite isolée : isole.config.ts.
//
// Le serveur refuse d'imposer la double authentification à un propriétaire
// qui ne l'a pas lui-même (garde-fou §4.6.4) : A2 est fait par un SECOND
// propriétaire créé ici, qui active sa double authentification par
// l'interface. La 2FA du propriétaire partagé n'est jamais touchée. Les
// réglages reviennent à leur défaut par l'API en fin de test, même en échec.

import type { Locator } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { totp, secondsLeft } from "../../fixtures/totp.ts";
import { registerInvite, testPassword } from "../../fixtures/ui.ts";
import { KDF_TIMEOUT, fenetre, goHash, retablirReglages, titre } from "./outils.ts";

test.use({ textGuardMode: "strict" });

const TOLERANCE = 1;

/** Code TOTP qui ne change pas pendant la saisie. */
async function codeStable(secret: string): Promise<string> {
  if (secondsLeft() < 4) await new Promise((r) => setTimeout(r, (secondsLeft() + 1) * 1000));
  return totp(secret);
}

async function mesurer(gestes: string[], cible: Locator, nom: string, clicks: { click(l: Locator): Promise<void> }) {
  gestes.push(`clic « ${nom} »`);
  await clicks.click(cible);
}

test.describe("Parcours chiffrés de l'administration (§3.6)", () => {
  test("A2 : imposer la double authentification en 3 clics depuis l'Accueil, impact affiché", async ({ page, loggedIn, apiAs, org, clicks }) => {
    test.setTimeout(240_000);
    // Second propriétaire : invité administrateur, élevé propriétaire (confirmation d'identité).
    const owner = await loggedIn("owner");
    const email = `proprietaire-a2-${Date.now()}@e2e.test`;
    const inv = await (await apiAs("owner")).post("/api/admin/invites", { data: { email, role: "admin" } });
    expect(inv.ok(), await inv.text()).toBe(true);
    const password = testPassword();
    await registerInvite(page, (await inv.json()).token, { name: "Inès Responsable", password });
    await expect(page.locator("#contenu h1").first()).toBeVisible({ timeout: KDF_TIMEOUT });
    const promu = await owner.evaluate(async ({ mail, pwd }) => {
      const V = await import("/js/vault.js");
      const A = await import("/js/api.js");
      const users = await A.api("GET", "/admin/users");
      const u = users.find((x: { email: string }) => x.email === mail);
      const reauth = await A.exchangeReauth("admin.role", await V.authProof(pwd));
      await A.api("PUT", `/admin/users/${u.id}`, { role: "owner" }, { reauth });
      return u.id as string;
    }, { mail: email, pwd: org.accounts.owner.password });
    expect(promu).toBeTruthy();

    // Il active sa double authentification par l'interface.
    await page.reload();
    await page.getByLabel("Mot de passe maître", { exact: true }).fill(password);
    await page.getByRole("button", { name: /^(Déverrouiller|Se connecter)$/ }).click();
    await expect(page.locator("#contenu h1").first()).toBeVisible({ timeout: KDF_TIMEOUT });
    await goHash(page, "#/parametres/compte");
    await page.getByRole("button", { name: "Activer la double authentification" }).click();
    const activation = fenetre(page, "Activer la double authentification");
    await activation.getByText("Impossible de scanner ? Saisissez cette clé à la main").click();
    const secret = (await activation.locator("p.u-mono").innerText()).replace(/\s+/g, "");
    await activation.getByLabel("Code affiché par l'application").fill(await codeStable(secret));
    await activation.getByRole("button", { name: "Activer", exact: true }).click();
    const codes = fenetre(page, "Vos codes de secours");
    await expect(codes).toBeVisible();
    await codes.getByLabel("J'ai conservé mes codes de secours").check();
    await codes.getByRole("button", { name: "Terminé" }).click();

    try {
      await goHash(page, "#/admin");
      await expect(titre(page, "Accueil")).toBeVisible();
      const gestes: string[] = [];
      await mesurer(gestes, page.getByRole("button", { name: "Imposer la double authentification…" }), "Imposer la double authentification…", clicks);
      const panneau = page.getByRole("dialog", { name: "Imposer la double authentification…" });
      await mesurer(gestes, panneau.getByRole("switch", { name: "Double authentification obligatoire pour tous" }), "Double authentification obligatoire pour tous", clicks);
      // Impact affiché avant l'enregistrement.
      await expect(panneau.getByText(/personnes? devr(a|ont) activer la double authentification/)).toBeVisible();
      await mesurer(gestes, panneau.getByRole("button", { name: "Enregistrer", exact: true }), "Enregistrer", clicks);
      const confirmation = page.getByRole("dialog", { name: /Confirme/ });
      if (await confirmation.isVisible().catch(() => false)) {
        await confirmation.getByLabel("Mot de passe maître", { exact: true }).fill(password);
        const champCode = confirmation.getByLabel(/Code/);
        if (await champCode.count()) await champCode.fill(await codeStable(secret));
        await mesurer(gestes, confirmation.getByRole("button", { name: "Confirmer", exact: true }), "Confirmer", clicks);
      }
      await expect(panneau).toBeHidden();
      const v = (await (await apiAs("owner")).get("/api/admin/settings")).json();
      expect((await v).values["twofa.required"].value, "Double authentification imposée").toBe(true);
      expect(gestes.length, `A2 : ${gestes.length} gestes pour une cible de 3 (± ${TOLERANCE}) : ${gestes.join(", ")}`).toBeLessThanOrEqual(3 + TOLERANCE);
    } finally {
      expect.soft(await retablirReglages(page, ["twofa.required"], password, () => codeStable(secret)), "Retour au défaut de twofa.required").toBe("ok");
    }
  });

  test("A4 : changer le délai de verrouillage des postes en 4 clics", async ({ loggedIn, org, clicks }) => {
    const page = await loggedIn("owner");
    await goHash(page, "#/admin");
    await expect(titre(page, "Accueil")).toBeVisible();
    const gestes: string[] = [];
    try {
      await mesurer(gestes, page.getByRole("navigation", { name: "Administration" }).getByRole("link", { name: /^Réglages/ }), "Réglages", clicks);
      // Recherche : saisie non comptée.
      await page.getByLabel("Chercher un réglage").fill("verrou");
      const delai = page.getByLabel("Verrouillage automatique des applications", { exact: true });
      gestes.push("choix « 5 minutes »");
      clicks.count++;
      await delai.selectOption("5");
      await mesurer(gestes, page.getByRole("button", { name: "Vérifier et enregistrer", exact: true }), "Vérifier et enregistrer", clicks);
      await mesurer(gestes, page.getByRole("dialog", { name: /^Enregistrer 1 modification$/ }).getByRole("button", { name: "Enregistrer", exact: true }), "Enregistrer", clicks);
      const abaissement = page.getByRole("dialog", { name: "Confirmer l'abaissement de la sécurité" });
      await expect(page.locator(".c-toast").filter({ hasText: /Réglages enregistrés/ }).first().or(abaissement)).toBeVisible();
      expect(await abaissement.isVisible(), "Raccourcir le délai n'abaisse pas la sécurité : aucune confirmation").toBe(false);
      expect(gestes.length, `A4 : ${gestes.length} gestes pour une cible de 4 (± ${TOLERANCE}) : ${gestes.join(", ")}`).toBeLessThanOrEqual(4 + TOLERANCE);
    } finally {
      expect.soft(await retablirReglages(page, ["client.autolock_minutes"], org.accounts.owner.password), "Retour au défaut").toBe("ok");
    }
  });
});

