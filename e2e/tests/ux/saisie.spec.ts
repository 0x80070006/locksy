// Zéro perte de saisie (cahier §6.4 « ux/saisie », critère G35, §3.1 règle 1).
//
// Pour chaque formulaire (éditeur, partage, compte, réglages de
// l'administration, assistants SSO et Active Directory, invitation) : une
// saisie, puis l'un des gestes qui pourraient la perdre :
//   - Échap ;
//   - un clic hors de la fenêtre ou du panneau ;
//   - un changement d'adresse (fragment) et un clic dans la navigation ;
//   - la fermeture de l'onglet.
// Attendu : la garde « Quitter sans enregistrer ? » (Rester / Abandonner /
// Enregistrer) quand le formulaire allait disparaître ; « Rester » rend la
// saisie à l'identique. Un geste qui ne ferme rien laisse la saisie en place.
// La fermeture de l'onglet passe par la demande du navigateur (beforeunload).
//
// Préférences : enregistrées à chaque changement, rien ne se perd ; la valeur
// est relue après un changement d'adresse puis après rechargement.

import type { Locator, Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { simulateIdentity } from "../identity/simulation.ts";
import { KDF_TIMEOUT, connexion, creerElement, fenetre, goHash, nouveauCompte, titre, tolererPannes, unique } from "./outils.ts";

test.use({ textGuardMode: "strict" });

const GARDE = "Quitter sans enregistrer ?";

interface Ouvert {
  page: Page;
  /** Ce qui porte la saisie (champ, ou ligne ajoutée). */
  champ: Locator;
  /** Valeur saisie (champ de formulaire) ; absente si `champ` est une ligne. */
  valeur?: string;
  /** Adresse d'un autre écran, et lien de navigation qui y mène. */
  ailleurs: string;
  lien: (page: Page) => Locator;
}

interface Formulaire {
  ouvrir: (fx: Fx) => Promise<Ouvert>;
  /** Gestes connus pour perdre la saisie : défaut produit (handoff). */
  defauts?: Partial<Record<Geste, string>>;
}

interface Fx {
  page: Page;
  org: { accounts: Record<"owner" | "admin" | "user", { email: string; password: string; name: string; id: string }> };
  loggedIn: (role: "owner" | "admin" | "user") => Promise<Page>;
}

type Geste = "Échap" | "clic hors du formulaire" | "changement d'adresse" | "clic dans la navigation" | "fermeture de l'onglet";
const GESTES: Geste[] = ["Échap", "clic hors du formulaire", "changement d'adresse", "clic dans la navigation", "fermeture de l'onglet"];

const navUtilisateur = (page: Page) => page.getByRole("navigation", { name: "Navigation principale" }).getByRole("link", { name: /^Corbeille/ });
const navAdmin = (page: Page) => page.getByRole("navigation", { name: "Administration" }).getByRole("link", { name: /^Journal/ });

const FORMULAIRES: Record<string, Formulaire> = {
  "éditeur d'élément": {
    ouvrir: async ({ page, org }) => {
      await connexion(page, org.accounts.user);
      await page.getByRole("button", { name: "Nouveau", exact: true }).first().click();
      const champ = page.getByLabel("Nom", { exact: true });
      await expect(champ).toBeFocused();
      await champ.fill("Brouillon à garder");
      return { page, champ, valeur: "Brouillon à garder", ailleurs: "#/corbeille", lien: navUtilisateur };
    },
  },

  "partage avec des collègues": {
    ouvrir: async ({ page, org }) => {
      await connexion(page, org.accounts.user);
      const nom = unique("Partage en cours");
      const id = await creerElement(page, { name: nom, password: "Saisie-Partage-2026" });
      await goHash(page, `#/element/${id}`);
      await page.getByRole("button", { name: "Partager", exact: true }).first().click();
      const dlg = fenetre(page, /^Partager/);
      await dlg.getByLabel("Avec qui ?").fill("Adam");
      await dlg.getByRole("button", { name: `Ajouter ${org.accounts.admin.name}` }).click();
      const champ = dlg.getByText(org.accounts.admin.name).first();
      await expect(champ).toBeVisible();
      return { page, champ, ailleurs: "#/corbeille", lien: navUtilisateur };
    },
  },

  "compte (nom affiché)": {
    ouvrir: async ({ page, org }) => {
      await connexion(page, org.accounts.user);
      await goHash(page, "#/parametres/compte");
      const champ = page.getByLabel("Votre nom");
      await expect(champ).toHaveValue(org.accounts.user.name);
      await champ.fill("Alice Martin-Durand");
      return { page, champ, valeur: "Alice Martin-Durand", ailleurs: "#/corbeille", lien: navUtilisateur };
    },
  },

  "réglages de l'organisation": {
    ouvrir: async ({ loggedIn }) => {
      const page = await loggedIn("owner");
      await goHash(page, "#/admin/reglages/sessions");
      await expect(titre(page, "Réglages")).toBeVisible();
      const champ = page.getByLabel("Déconnexion après inactivité", { exact: true });
      await champ.selectOption("30");
      return { page, champ, valeur: "30", ailleurs: "#/admin/journal", lien: navAdmin };
    },
  },

  "assistant SSO": {
    ouvrir: async ({ loggedIn }) => {
      const page = await loggedIn("owner");
      await simulateIdentity(page);
      await expect(page.locator("main h1").first()).toBeAttached({ timeout: KDF_TIMEOUT });
      await goHash(page, "#/admin/connexion/sso");
      await page.getByRole("radio", { name: /Okta/ }).check({ force: true });
      await page.getByRole("button", { name: "Continuer", exact: true }).click();
      const champ = page.getByLabel("Adresse de l'émetteur");
      await champ.fill("https://entreprise.okta.com");
      return { page, champ, valeur: "https://entreprise.okta.com", ailleurs: "#/admin/journal", lien: navAdmin };
    },
  },

  "assistant Active Directory": {
    ouvrir: async ({ loggedIn }) => {
      const page = await loggedIn("owner");
      await simulateIdentity(page);
      await expect(page.locator("main h1").first()).toBeAttached({ timeout: KDF_TIMEOUT });
      await goHash(page, "#/admin/connexion/ad");
      const champ = page.getByLabel("Adresse du contrôleur de domaine");
      await champ.fill("ldaps://dc1.entreprise.local:636");
      return { page, champ, valeur: "ldaps://dc1.entreprise.local:636", ailleurs: "#/admin/journal", lien: navAdmin };
    },
  },

  "invitation de personnes": {
    ouvrir: async ({ loggedIn }) => {
      const page = await loggedIn("owner");
      await goHash(page, "#/admin/personnes");
      await expect(titre(page, "Personnes")).toBeVisible();
      await page.getByRole("button", { name: "Inviter des personnes" }).first().click();
      const champ = fenetre(page, "Inviter des personnes").getByLabel("Adresses e-mail");
      await champ.fill("lea.petit@exemple.fr, hugo.martin@exemple.fr");
      return { page, champ, valeur: "lea.petit@exemple.fr, hugo.martin@exemple.fr", ailleurs: "#/admin/journal", lien: navAdmin };
    },
  },
};

/** La saisie est toujours là, à l'identique. */
async function intacte(o: Ouvert) {
  await expect(o.champ, "Saisie toujours affichée").toBeVisible();
  if (o.valeur !== undefined) await expect(o.champ, "Saisie à l'identique").toHaveValue(o.valeur);
}

/** Si la garde s'affiche, « Rester » ; sinon le formulaire ne doit pas avoir disparu. */
async function resterSiGarde(page: Page) {
  const garde = page.getByRole("dialog", { name: GARDE });
  await garde.waitFor({ state: "visible", timeout: 2_000 }).catch(() => undefined);
  if (await garde.isVisible()) {
    await expect(garde.getByRole("button", { name: "Rester", exact: true })).toBeVisible();
    await expect(garde.getByRole("button", { name: "Abandonner", exact: true })).toBeVisible();
    await garde.getByRole("button", { name: "Rester", exact: true }).click();
    await expect(garde).toBeHidden();
  }
}

async function jouer(geste: Geste, o: Ouvert) {
  const { page } = o;
  const adresse = page.url();
  switch (geste) {
    case "Échap":
      await o.champ.focus().catch(() => undefined);
      await page.keyboard.press("Escape");
      await resterSiGarde(page);
      await intacte(o);
      return;
    case "clic hors du formulaire":
      // Coin haut gauche : fond d'une fenêtre modale, ou zone neutre de la page.
      await page.mouse.click(3, 3);
      await resterSiGarde(page);
      await intacte(o);
      return;
    case "changement d'adresse":
    case "clic dans la navigation": {
      if (geste === "changement d'adresse") await goHash(page, o.ailleurs);
      else {
        const lien = o.lien(page);
        // Lien masqué par une fenêtre modale : la page derrière ne change pas.
        if (await lien.isVisible()) await lien.click({ timeout: 3_000 }).catch(() => undefined);
      }
      const garde = page.getByRole("dialog", { name: GARDE });
      await expect(garde.or(o.champ).first()).toBeVisible();
      await resterSiGarde(page);
      await intacte(o);
      expect(page.url(), "Adresse inchangée après « Rester »").toBe(adresse);
      return;
    }
    case "fermeture de l'onglet": {
      const demande = new Promise<string>((resolve) => {
        page.once("dialog", (d) => { resolve(d.type()); void d.dismiss(); });
        setTimeout(() => resolve("aucune"), 5_000);
      });
      await page.close({ runBeforeUnload: true });
      expect(await demande, "Le navigateur demande confirmation avant de fermer l'onglet").toBe("beforeunload");
    }
  }
}

test.describe("Zéro perte de saisie : la garde « Quitter sans enregistrer ? »", () => {
  for (const [nom, f] of Object.entries(FORMULAIRES)) {
    for (const geste of GESTES) {
      test(`${nom} : ${geste}`, async ({ page, org, loggedIn, consoleGuard }) => {
        // GET /api/me/prefs répond 404 tant qu'aucune préférence n'existe.
        tolererPannes(consoleGuard);
        const defaut = f.defauts?.[geste];
        if (defaut) test.fail(true, defaut);
        const o = await f.ouvrir({ page, org, loggedIn });
        await jouer(geste, o);
      });
    }
  }

  test("préférences : enregistrées à chaque changement, relues après navigation et rechargement", async ({ page, apiAs }) => {
    test.setTimeout(150_000);
    const compte = await nouveauCompte(page, await apiAs("owner"), "preferences-saisie");
    await goHash(page, "#/parametres/preferences");
    const densite = page.getByLabel("Densité", { exact: true });
    const autre = (await densite.inputValue()) === "compact" ? "comfortable" : "compact";
    await densite.selectOption(autre);
    // Changement d'adresse : aucune garde, la valeur est déjà enregistrée.
    await goHash(page, "#/corbeille");
    await expect(page.getByRole("dialog", { name: GARDE })).toHaveCount(0);
    await expect(titre(page, "Corbeille")).toBeVisible();
    await goHash(page, "#/parametres/preferences");
    await expect(densite).toHaveValue(autre);
    // Rechargement : relue depuis le serveur après le déverrouillage.
    await page.reload();
    await page.getByLabel("Mot de passe maître", { exact: true }).fill(compte.password);
    await page.getByRole("button", { name: /^(Déverrouiller|Se connecter)$/ }).click();
    await expect(page.locator("#contenu h1").first()).toBeVisible({ timeout: KDF_TIMEOUT });
    await goHash(page, "#/parametres/preferences");
    await expect(page.getByLabel("Densité", { exact: true })).toHaveValue(autre);
  });
});
