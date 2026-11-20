// Zéro action muette (cahier §6.4 « ux/echecs », critère G36, contrat V2.3).
//
// 1. Garde-fou : la liste des écritures du client web est GÉNÉRÉE depuis
//    web/js (expression de V1.8, plus les requêtes publiques de share.js) et
//    comparée au tableau ECRITURES (ecritures.ts) : égalité stricte.
// 2. Les références à d'autres suites sont vérifiées (titre exact et panne
//    simulée dans le fichier).
// 3. Chaque écriture « ici » a un scénario, joué deux fois : réponse 500,
//    puis requête coupée. Attendus : un message en français visible, l'objet
//    intact (relu par l'API ou à l'écran), aucun état optimiste resté
//    affiché.
//
// Les comptes, éléments et coffres sont créés par chaque test (noms
// uniques) : rien d'organisationnel n'est modifié.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import type { APIRequestContext, Browser, Page } from "@playwright/test";
import { test, expect, type Org } from "../../fixtures/index.ts";
import { BASE_URL, E2E_DIR } from "../../fixtures/env.ts";
import { totp } from "../../fixtures/totp.ts";
import { loginUi } from "../../fixtures/ui.ts";
import { simulateIdentity, type IdentitySim } from "../identity/simulation.ts";
import { ECRITURES } from "./ecritures.ts";
import {
  KDF_TIMEOUT, connexion, coffres, creerCoffre, creerElement, etatElement, fenetre, goHash, invitation,
  nouveauCompte, panne, pressePapiers, testPassword, titre, tolererPannes, unique, type Compte, type Panne,
} from "./outils.ts";

test.use({ textGuardMode: "strict" });

const DEPOT = resolve(E2E_DIR, "..");

// ------------------------------------------------------------------ Liste générée (V1.8)

function fichiersJs(dir: string, out: string[] = []): string[] {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) fichiersJs(p, out);
    else if (p.endsWith(".js")) out.push(p);
  }
  return out;
}

/** Normalisation : `${…}` → « :p », requête retirée, préfixe /api absent. */
const normaliser = (methode: string, chemin: string) =>
  `${methode} ${chemin.replace(/\$\{[^}]*\}/g, ":p").split("?")[0].replace(/^\/api(?=\/)/, "")}`;

/** Écritures du client web : api()/apiFull() de web/js, et requêtes publiques de share.js. */
function ecrituresDuWeb(): Map<string, string[]> {
  const web = join(DEPOT, "web", "js");
  const trouvees = new Map<string, string[]>();
  const noter = (cle: string, ou: string) => trouvees.set(cle, [...(trouvees.get(cle) || []), ou]);
  for (const fichier of fichiersJs(web)) {
    const src = readFileSync(fichier, "utf8");
    const rel = fichier.slice(web.length + 1).split("\\").join("/");
    const ligne = (i: number) => src.slice(0, i).split("\n").length;
    for (const m of src.matchAll(/\b(api|apiFull)\(\s*"(POST|PUT|PATCH|DELETE)"\s*,\s*([`"'])([\s\S]*?)\3/g)) {
      noter(normaliser(m[2], m[4]), `${rel}:${ligne(m.index!)}`);
    }
    // (ADAPTATION) La page publique d'un lien (share.js) n'utilise pas api() :
    // ses écritures passent par request("POST", …), un fetch sans session.
    if (rel === "share.js") {
      for (const m of src.matchAll(/\brequest\(\s*"(POST|PUT|PATCH|DELETE)"\s*,\s*([`"'])([\s\S]*?)\2/g)) {
        noter(normaliser(m[1], m[3].replace(/\$\{encodeURIComponent\([^)]*\)\}/g, ":p")), `${rel}:${ligne(m.index!)}`);
      }
    }
  }
  return trouvees;
}

test.describe("Écritures du web : garde-fou", () => {
  test("chaque écriture du client web a une entrée dans ecritures.ts, et aucune entrée n'est périmée", () => {
    const web = ecrituresDuWeb();
    expect(web.size, "Aucune écriture trouvée : expression à revoir").toBeGreaterThan(20);
    const sansEntree = [...web.keys()].filter((k) => !(k in ECRITURES)).map((k) => `${k} (${web.get(k)!.join(", ")})`).sort();
    const perimees = Object.keys(ECRITURES).filter((k) => !web.has(k)).sort();
    expect(sansEntree, "Écritures sans test d'échec").toEqual([]);
    expect(perimees, "Entrées sans écriture correspondante dans web/js").toEqual([]);
  });

  test("chaque référence existe : titre exact et panne simulée dans le fichier", () => {
    const problemes: string[] = [];
    for (const [cle, e] of Object.entries(ECRITURES)) {
      if ("spec" in e) {
        const f = join(E2E_DIR, e.spec);
        if (!existsSync(f)) { problemes.push(`${cle} : fichier absent ${e.spec}`); continue; }
        const src = readFileSync(f, "utf8");
        if (!src.includes(`"${e.titre}"`)) problemes.push(`${cle} : titre absent de ${e.spec} : « ${e.titre} »`);
        // (ADAPTATION) l'utilitaire des suites admin et identité s'appelle sim.fail(…).
        if (!/route\.abort\(|status: 500|\.fail\(/.test(src)) problemes.push(`${cle} : aucune panne simulée dans ${e.spec}`);
      }
      if ("exempte" in e && e.exempte.trim().length < 20) problemes.push(`${cle} : raison d'exemption trop courte`);
      if ("ici" in e && !SCENARIOS[cle]) problemes.push(`${cle} : aucun scénario dans echecs.spec.ts`);
    }
    expect(problemes, "Références d'échec invalides").toEqual([]);
  });
});

// ------------------------------------------------------------------ Scénarios

interface Ctx {
  page: Page;
  org: Org;
  browser: Browser;
  loggedIn: (role: "owner" | "admin" | "user") => Promise<Page>;
  apiAs: (role: "owner" | "admin" | "user") => Promise<APIRequestContext>;
}

interface Scenario {
  methode: string;
  /** Chemin sans /api (expression). */
  chemin: RegExp;
  /** Prépare l'écran ; renvoie la page où agir et l'état à relire. */
  preparer: (c: Ctx) => Promise<{ page: Page; etat?: Record<string, unknown> }>;
  /** Geste de la personne qui déclenche l'écriture. */
  agir: (page: Page, etat: Record<string, unknown>, c: Ctx) => Promise<void>;
  /** L'objet est intact (API ou écran) ; aucun état optimiste affiché. */
  verifier: (page: Page, etat: Record<string, unknown>, c: Ctx) => Promise<void>;
  /** Message attendu propre à l'écran (sinon : repli d'api.js et catalogue errors.*). */
  message?: Record<Panne, RegExp>;
  /** Défaut produit connu (test annoté test.fail, handoff). */
  defaut?: string;
  /** Simulation de routes avant d'agir (serveur d'identité simulé…). */
  simuler?: (page: Page) => Promise<IdentitySim | void>;
}

/** Message d'échec en français visible : toast, alerte, erreur de champ ou de fenêtre. */
async function messageVisible(page: Page, comment: Panne, propre?: Record<Panne, RegExp>) {
  const attendu = propre
    ? propre[comment]
    : comment === 500 ? /Le serveur a rencontré un problème|Erreur interne du serveur/ : /Serveur injoignable/;
  const zone = propre
    ? page.getByText(attendu)
    : page.locator(".c-toast, .c-alert, .c-field__error, [role=alert]:not(#alert), .c-dialog [role=alert]").filter({ hasText: attendu });
  try {
    await expect(zone.first()).toBeVisible({ timeout: 20_000 });
  } catch {
    // Relevé de ce qui est affiché à la place, pour le rapport.
    const affiche = await page.locator(".c-toast, dialog[open], #contenu").evaluateAll((els) => els
      .map((e) => (e as HTMLElement).innerText.replace(/\s+/g, " ").trim().slice(0, 1500))
      .filter(Boolean)).catch(() => [] as string[]);
    const quoi = comment === 500 ? "500" : "réseau coupé";
    throw new Error(`Aucun message d'échec (${quoi}) correspondant à ${attendu}. Affiché : ${affiche.join(" ¦ ")}`);
  }
}

/** Ouvre « Gérer le coffre » depuis la page du coffre. */
async function gererCoffre(page: Page, id: string) {
  await goHash(page, `#/coffre/c/${id}`);
  await page.getByRole("button", { name: /^(Gérer le coffre|Voir les membres)$/ }).first().click();
  const dlg = fenetre(page, /^Gérer le coffre/);
  await expect(dlg).toBeVisible();
  return dlg;
}

async function actionDuCoffre(page: Page, id: string, action: string) {
  const dlg = await gererCoffre(page, id);
  await dlg.getByRole("button", { name: "Plus d'actions", exact: true }).click();
  await page.getByRole("menuitem", { name: action, exact: true }).click();
  return dlg;
}

/** Membres d'un coffre (identifiant, rôle) relus par l'API de la page. */
const membres = (page: Page, id: string) => page.evaluate(async (cid) => {
  const { api } = await import("/js/api.js");
  return (await api("GET", `/collections/${encodeURIComponent(cid)}/members`)) as { user_id: string; role: string }[];
}, id);

/** Profil du compte connecté (GET /api/me). */
const moi = (page: Page) => page.evaluate(async () => (await import("/js/api.js")).api("GET", "/me"));

/** Compte neuf connecté dans la page par défaut. */
async function compteNeuf(c: Ctx, prefixe: string): Promise<Compte> {
  return nouveauCompte(c.page, await c.apiAs("owner"), prefixe);
}

/** Fiche d'une personne dans l'administration (propriétaire). */
async function fiche(c: Ctx, cible: Compte): Promise<Page> {
  const admin = await c.loggedIn("owner");
  await goHash(admin, `#/admin/personnes/${cible.id}`);
  // Le bouton existe dans la ligne de la liste et dans la fiche ouverte : celui de la fiche.
  await expect(admin.getByRole("button", { name: `Plus d'actions pour ${cible.name}` }).last()).toBeVisible();
  return admin;
}

async function menuFiche(page: Page, cible: Compte, action: string) {
  await page.getByRole("button", { name: `Plus d'actions pour ${cible.name}` }).last().click();
  await page.getByRole("menuitem", { name: action }).click();
}

/** Utilisateur de l'organisation (relu par l'API du propriétaire). */
async function utilisateur(c: Ctx, id: string) {
  const users = await (await (await c.apiAs("owner")).get("/api/admin/users")).json();
  return users.find((u: { id: string }) => u.id === id) as Record<string, unknown> | undefined;
}

/** Inscription par un lien d'invitation, en gardant la clé de récupération affichée. */
async function inscrireAvecCle(page: Page, token: string, password: string): Promise<string> {
  await page.goto(`/#/inscription/${encodeURIComponent(token)}`);
  await page.getByLabel(/^(Nom affiché|Votre nom)$/).fill("Camille Durand");
  await page.getByLabel("Mot de passe maître", { exact: true }).fill(password);
  await page.getByLabel(/^Confirme[rz] le mot de passe maître$/).fill(password);
  await page.getByRole("button", { name: "Créer mon coffre", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Votre clé de récupération" })).toBeVisible({ timeout: KDF_TIMEOUT });
  const cle = (await page.locator("p.u-mono").innerText()).trim();
  await page.getByLabel(/J'ai (?:mis cette clé en lieu sûr|conservé ma clé de récupération)/).check();
  await page.getByRole("button", { name: "Continuer", exact: true }).click();
  await expect(page.locator("#contenu h1").first()).toBeVisible({ timeout: KDF_TIMEOUT });
  return cle;
}

/** Remplace la réponse de GET /api/settings/public (méthode de connexion Windows). */
async function connexionWindows(page: Page) {
  await page.route("**/api/settings/public", async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    await route.fulfill({ json: { ...body, login: { ...(body.login || {}), primary_method: "ldap", methods: ["ldap", "password"], ldap_label: "Compte Windows" } } });
  });
}

/** Lien sécurisé réel vers un élément (adresse complète avec la clé dans le fragment). */
async function lienSecurise(page: Page): Promise<string> {
  const id = await creerElement(page, { name: unique("Lien en panne"), password: "Clair-Lune-2026" });
  return page.evaluate(async (itemId) => {
    const V = await import("/js/vault.js");
    const it = V.state.items.get(itemId);
    const res = await V.createShareLink({ name: "", password: it.data.password }, 60, 3, { itemId });
    return String(res.url || res.link || res);
  }, id);
}

/** Page publique d'un lien : textes propres (tools.share.server_error, tools.share.offline). */
const PAGE_LIEN: Record<Panne, RegExp> = { 500: /Le serveur n'a pas pu répondre/, reseau: /Serveur injoignable/ };

const SCENARIOS: Record<string, Scenario> = {
  // ---------------------------------------------------------------- Accès
  "POST /auth/login": {
    methode: "POST", chemin: /^\/auth\/login$/,
    preparer: async ({ page }) => {
      await page.goto("/");
      return { page };
    },
    agir: async (page, _e, { org }) => {
      await page.getByLabel("Adresse e-mail").fill(org.accounts.user.email);
      await page.getByLabel("Mot de passe maître", { exact: true }).fill(org.accounts.user.password);
      await page.getByRole("button", { name: "Se connecter", exact: true }).click();
    },
    verifier: async (page) => {
      // Toujours sur l'écran de connexion, saisie conservée, aucune session.
      await expect(page.getByRole("button", { name: "Se connecter", exact: true })).toBeVisible();
      await expect(page.getByLabel("Adresse e-mail")).not.toHaveValue("");
      expect(await page.evaluate(() => sessionStorage.getItem("locksy.session"))).toBeNull();
    },
  },

  "POST /auth/register": {
    methode: "POST", chemin: /^\/auth\/register$/,
    preparer: async (c) => {
      const inv = await invitation(await c.apiAs("owner"), "inscription-panne");
      await c.page.goto(`/#/inscription/${encodeURIComponent(inv.token)}`);
      return { page: c.page, etat: { email: inv.email } };
    },
    agir: async (page) => {
      const pwd = testPassword();
      await page.getByLabel(/^(Nom affiché|Votre nom)$/).fill("Camille Durand");
      await page.getByLabel("Mot de passe maître", { exact: true }).fill(pwd);
      await page.getByLabel(/^Confirme[rz] le mot de passe maître$/).fill(pwd);
      await page.getByRole("button", { name: "Créer mon coffre", exact: true }).click();
    },
    verifier: async (page, etat, c) => {
      await expect(page.getByRole("button", { name: "Créer mon coffre", exact: true })).toBeVisible();
      const users = await (await (await c.apiAs("owner")).get("/api/admin/users")).json();
      expect(users.some((u: { email: string }) => u.email === etat.email), "Aucun compte créé").toBe(false);
    },
  },

  "POST /auth/recover/start": {
    methode: "POST", chemin: /^\/auth\/recover\/start$/,
    preparer: async (c) => {
      const inv = await invitation(await c.apiAs("owner"), "recuperation-panne");
      const password = testPassword();
      const cle = await inscrireAvecCle(c.page, inv.token, password);
      // Session oubliée (autre appareil) : rechargement sur l'écran de récupération.
      await c.page.evaluate(() => sessionStorage.clear());
      await c.page.goto("/#/connexion");
      await c.page.reload();
      await expect(c.page.getByRole("button", { name: "Se connecter", exact: true })).toBeVisible();
      await c.page.evaluate(() => { location.hash = "#/recuperation"; });
      await expect(titre(c.page, "Récupérer mon compte")).toBeVisible();
      return { page: c.page, etat: { email: inv.email, cle, password } };
    },
    agir: async (page, etat) => {
      const neuf = testPassword();
      await page.getByLabel("Adresse e-mail").fill(String(etat.email));
      await page.getByLabel("Clé de récupération").fill(String(etat.cle));
      await page.getByLabel("Nouveau mot de passe maître", { exact: true }).fill(neuf);
      await page.getByLabel("Confirmer le nouveau mot de passe maître").fill(neuf);
      await page.getByRole("button", { name: "Définir le nouveau mot de passe" }).click();
    },
    verifier: async (page, etat) => {
      await expect(titre(page, "Récupérer mon compte")).toBeVisible();
      // L'ancien mot de passe maître ouvre toujours le coffre.
      await page.unrouteAll({ behavior: "ignoreErrors" });
      await loginUi(page, { email: String(etat.email), password: String(etat.password) });
    },
  },

  "POST /auth/recover/finish": {
    methode: "POST", chemin: /^\/auth\/recover\/finish$/,
    preparer: async (c) => SCENARIOS["POST /auth/recover/start"].preparer(c),
    agir: async (page, etat, c) => SCENARIOS["POST /auth/recover/start"].agir(page, etat, c),
    verifier: async (page, etat, c) => SCENARIOS["POST /auth/recover/start"].verifier(page, etat, c),
  },

  "POST /auth/reauth": {
    methode: "POST", chemin: /^\/auth\/reauth$/,
    // Abaisser un réglage demande une confirmation d'identité : jeton rt1 (C4.1).
    preparer: async (c) => {
      const admin = await c.loggedIn("owner");
      await goHash(admin, "#/admin/reglages/sessions");
      await expect(titre(admin, "Réglages")).toBeVisible();
      return { page: admin };
    },
    agir: async (page, _e, { org }) => {
      await page.getByLabel("Durée maximale d'une session", { exact: true }).selectOption("24");
      await page.getByRole("button", { name: "Vérifier et enregistrer", exact: true }).click();
      await page.getByRole("dialog", { name: "Enregistrer 1 modification" }).getByRole("button", { name: "Enregistrer", exact: true }).click();
      const dlg = fenetre(page, "Confirmer l'abaissement de la sécurité");
      await dlg.getByLabel("Mot de passe maître", { exact: true }).fill(org.accounts.owner.password);
      await dlg.getByRole("button", { name: "Confirmer", exact: true }).click();
    },
    verifier: async (page, _e, c) => {
      await expect(fenetre(page, "Confirmer l'abaissement de la sécurité")).toBeVisible();
      const v = (await (await (await c.apiAs("owner")).get("/api/admin/settings")).json()).values["session.max_hours"];
      expect(v.value, "Durée maximale inchangée").toBe(12);
    },
  },

  "POST /ldap/login": {
    methode: "POST", chemin: /^\/ldap\/login$/,
    preparer: async ({ page }) => {
      await connexionWindows(page);
      await page.goto("/");
      await expect(page.getByLabel("Identifiant Windows")).toBeVisible();
      return { page };
    },
    agir: async (page) => {
      await page.getByLabel("Identifiant Windows").fill("cdurand");
      await page.getByLabel("Mot de passe Windows").fill("mot-de-passe-windows");
      await page.getByRole("button", { name: "Continuer", exact: true }).click();
    },
    verifier: async (page) => {
      await expect(page.getByLabel("Identifiant Windows")).toHaveValue("cdurand");
      expect(await page.evaluate(() => sessionStorage.getItem("locksy.session"))).toBeNull();
    },
  },

  "POST /sso/redeem": {
    methode: "POST", chemin: /^\/sso\/redeem$/,
    preparer: async ({ page }) => {
      await page.goto("/");
      await expect(page.getByRole("button", { name: "Se connecter", exact: true })).toBeVisible();
      return { page };
    },
    agir: async (page) => {
      await page.goto("/#/sso?ticket=ticket-d-essai-0123456789");
    },
    verifier: async (page) => {
      await expect(page.getByRole("link", { name: /Retour à la connexion|Revenir à la connexion/ })).toBeVisible();
      expect(await page.evaluate(() => sessionStorage.getItem("locksy.session"))).toBeNull();
    },
  },

  // ---------------------------------------------------------------- Coffre
  "PUT /items/:p": {
    methode: "PUT", chemin: /^\/items\/[^/]+$/,
    preparer: async ({ page, org }) => {
      await connexion(page, org.accounts.user);
      const nom = unique("Facturation");
      const id = await creerElement(page, { name: nom, password: "Panne-Modif-2026" });
      await goHash(page, `#/element/${id}/modifier`);
      await expect(page.getByLabel("Nom", { exact: true })).toHaveValue(nom);
      return { page, etat: { id, nom } };
    },
    agir: async (page, etat) => {
      await page.getByLabel("Nom", { exact: true }).fill(`${etat.nom} modifié`);
      await page.getByRole("button", { name: "Enregistrer", exact: true }).click();
    },
    verifier: async (page, etat) => {
      // Saisie intacte dans l'éditeur, élément inchangé sur le serveur.
      await expect(page.getByLabel("Nom", { exact: true })).toHaveValue(`${etat.nom} modifié`);
      expect((await etatElement(page, String(etat.id)))?.name).toBe(etat.nom);
    },
  },

  "PUT /items/:p/attachments/:p": {
    methode: "PUT", chemin: /^\/items\/[^/]+\/attachments\/[^/]+$/,
    preparer: async ({ page, org }) => {
      await connexion(page, org.accounts.user);
      const id = await creerElement(page, { name: unique("Contrat signé"), password: "Piece-Jointe-2026" });
      await goHash(page, `#/element/${id}`);
      await page.getByText(/^Pièces? jointes? \(0\)$/).click();
      return { page, etat: { id } };
    },
    agir: async (page) => {
      const choix = page.waitForEvent("filechooser");
      await page.getByRole("button", { name: "Ajouter une pièce jointe" }).click();
      await (await choix).setFiles({ name: "contrat.txt", mimeType: "text/plain", buffer: Buffer.from("contrat de test") });
    },
    verifier: async (page, etat) => {
      await expect(page.getByText(/^« contrat\.txt » ajouté$/)).toHaveCount(0);
      expect((await etatElement(page, String(etat.id)))?.attachments).toBe(0);
    },
  },

  "DELETE /attachments/:p": {
    methode: "DELETE", chemin: /^\/attachments\/[^/]+$/,
    preparer: async (c) => {
      const s = await SCENARIOS["PUT /items/:p/attachments/:p"].preparer(c);
      await SCENARIOS["PUT /items/:p/attachments/:p"].agir(s.page, s.etat!, c);
      await expect(s.page.getByText("« contrat.txt » ajouté")).toBeVisible();
      return s;
    },
    agir: async (page) => {
      await page.getByRole("button", { name: "Supprimer contrat.txt" }).click();
      await fenetre(page, "Supprimer la pièce jointe ?").getByRole("button", { name: "Supprimer définitivement" }).click();
    },
    verifier: async (page, etat) => {
      // L'élément garde sa pièce jointe tant que le fichier n'est pas supprimé.
      expect((await etatElement(page, String(etat.id)))?.attachments).toBe(1);
    },
  },

  "POST /collections": {
    methode: "POST", chemin: /^\/collections$/,
    preparer: async ({ page, org }) => {
      await connexion(page, org.accounts.user);
      return { page, etat: { nom: unique("Équipe compta") } };
    },
    agir: async (page, etat) => {
      await page.getByRole("button", { name: "Nouveau coffre" }).first().click();
      const dlg = fenetre(page, "Nouveau coffre");
      await dlg.getByLabel("Nom du coffre").fill(String(etat.nom));
      await dlg.getByRole("button", { name: "Créer", exact: true }).click();
    },
    verifier: async (page, etat) => {
      await expect(fenetre(page, "Nouveau coffre").getByLabel("Nom du coffre")).toHaveValue(String(etat.nom));
      expect((await coffres(page)).map((c) => c.name)).not.toContain(etat.nom);
    },
  },

  "PUT /collections/:p": {
    methode: "PUT", chemin: /^\/collections\/[^/]+$/,
    preparer: async ({ page, org }) => {
      await connexion(page, org.accounts.user);
      const nom = unique("Équipe achats");
      return { page, etat: { nom, id: await creerCoffre(page, nom) } };
    },
    agir: async (page, etat) => {
      await actionDuCoffre(page, String(etat.id), "Renommer");
      const dlg = fenetre(page, "Renommer le coffre");
      await dlg.getByLabel("Nouveau nom").fill(`${etat.nom} renommé`);
      await dlg.getByRole("button", { name: "Renommer", exact: true }).click();
    },
    verifier: async (page, etat) => {
      await expect(fenetre(page, "Renommer le coffre").getByLabel("Nouveau nom")).toHaveValue(`${etat.nom} renommé`);
      expect((await coffres(page)).find((c) => c.id === etat.id)?.name).toBe(etat.nom);
    },
  },

  "DELETE /collections/:p": {
    methode: "DELETE", chemin: /^\/collections\/[^/]+$/,
    preparer: async (c) => SCENARIOS["PUT /collections/:p"].preparer(c),
    agir: async (page, etat, { org }) => {
      await actionDuCoffre(page, String(etat.id), "Supprimer le coffre");
      const dlg = fenetre(page, "Supprimer ce coffre ?");
      await dlg.getByLabel(`Saisissez « ${etat.nom} » pour confirmer`).fill(String(etat.nom));
      await dlg.getByLabel("Mot de passe maître", { exact: true }).fill(org.accounts.user.password);
      await dlg.getByRole("button", { name: "Supprimer le coffre" }).click();
    },
    verifier: async (page, etat) => {
      expect((await coffres(page)).some((c) => c.id === etat.id), "Le coffre existe toujours").toBe(true);
    },
  },

  "PUT /collections/:p/members/:p": {
    methode: "PUT", chemin: /^\/collections\/[^/]+\/members\/[^/]+$/,
    preparer: async ({ page, org }) => {
      await connexion(page, org.accounts.user);
      const nom = unique("Équipe support");
      const id = await creerCoffre(page, nom, [org.accounts.admin.email]);
      const dlg = await gererCoffre(page, id);
      const droits = dlg.getByLabel(`Droits de ${org.accounts.admin.name}`);
      return { page, etat: { id, avant: await droits.inputValue() } };
    },
    agir: async (page, etat, { org }) => {
      const droits = fenetre(page, /^Gérer le coffre/).getByLabel(`Droits de ${org.accounts.admin.name}`);
      const autre = (await droits.locator("option").evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value))).find((v) => v !== etat.avant)!;
      await droits.selectOption(autre);
    },
    verifier: async (page, etat, { org }) => {
      // Le sélecteur revient au rôle réel ; le serveur n'a rien changé.
      await expect(fenetre(page, /^Gérer le coffre/).getByLabel(`Droits de ${org.accounts.admin.name}`)).toHaveValue(String(etat.avant));
      const m = (await membres(page, String(etat.id))).find((x) => x.user_id === org.accounts.admin.id);
      expect(m?.role).toBe(etat.avant);
    },
  },

  "DELETE /collections/:p/members/:p": {
    methode: "DELETE", chemin: /^\/collections\/[^/]+\/members\/[^/]+$/,
    preparer: async ({ page, org, loggedIn }) => {
      // Adam crée un coffre et y ajoute Alice ; Alice veut le quitter.
      const adam = await loggedIn("admin");
      const nom = unique("Équipe partagée");
      const id = await creerCoffre(adam, nom, [org.accounts.user.email]);
      await connexion(page, org.accounts.user);
      return { page, etat: { id, nom } };
    },
    agir: async (page, etat) => {
      const dlg = await gererCoffre(page, String(etat.id));
      await dlg.getByRole("button", { name: "Quitter le coffre" }).click();
      await fenetre(page, "Quitter ce coffre ?").getByRole("button", { name: "Quitter", exact: true }).click();
    },
    verifier: async (page, etat) => {
      expect((await coffres(page)).some((c) => c.id === etat.id), "Toujours membre du coffre").toBe(true);
    },
  },

  "POST /collections/:p/rotate": {
    methode: "POST", chemin: /^\/collections\/[^/]+\/rotate$/,
    preparer: async ({ page, org }) => {
      await connexion(page, org.accounts.user);
      const nom = unique("Équipe réseau");
      const id = await creerCoffre(page, nom);
      const item = await creerElement(page, { name: unique("Routeur"), password: "Rotation-2026" }, id);
      return { page, etat: { id, nom, item } };
    },
    agir: async (page, etat) => {
      await actionDuCoffre(page, String(etat.id), "Renouveler la clé");
      await fenetre(page, "Renouveler la clé du coffre ?").getByRole("button", { name: "Renouveler la clé" }).click();
    },
    verifier: async (page, etat) => {
      // Contenu toujours lisible avec l'ancienne clé.
      expect((await etatElement(page, String(etat.item)))?.password).toBe("Rotation-2026");
      expect((await coffres(page)).find((c) => c.id === etat.id)?.name).toBe(etat.nom);
    },
  },

  "POST /public/shares/:p/peek": {
    methode: "POST", chemin: /^\/public\/shares\/[^/]+\/peek$/,
    message: PAGE_LIEN,
    preparer: async ({ page, org, browser }) => {
      await connexion(page, org.accounts.user);
      const url = await lienSecurise(page);
      const ctx = await browser.newContext({ baseURL: BASE_URL, extraHTTPHeaders: { "X-Forwarded-For": "10.248.0.9" } });
      const visiteur = await ctx.newPage();
      return { page: visiteur, etat: { url } };
    },
    agir: async (page, etat) => {
      await page.goto(String(etat.url));
    },
    verifier: async (page) => {
      // Rien n'est révélé, aucune consultation décomptée.
      await expect(page.getByText("Clair-Lune-2026")).toHaveCount(0);
    },
  },

  "POST /public/shares/:p/open": {
    methode: "POST", chemin: /^\/public\/shares\/[^/]+\/open$/,
    message: PAGE_LIEN,
    preparer: async (c) => SCENARIOS["POST /public/shares/:p/peek"].preparer(c),
    agir: async (page, etat) => {
      await page.goto(String(etat.url));
      await page.getByRole("button", { name: /^(Afficher|Révéler|Voir)/ }).first().click();
    },
    verifier: async (page) => {
      await expect(page.getByText("Clair-Lune-2026")).toHaveCount(0);
    },
  },

  // ---------------------------------------------------------------- Compte
  "PUT /me": {
    methode: "PUT", chemin: /^\/me$/,
    preparer: async (c) => {
      const compte = await compteNeuf(c, "nom-panne");
      await goHash(c.page, "#/parametres/compte");
      await expect(c.page.getByLabel("Votre nom")).toHaveValue(compte.name);
      return { page: c.page, etat: { compte } };
    },
    agir: async (page) => {
      await page.getByLabel("Votre nom").fill("Camille Martin");
      await page.getByRole("button", { name: "Enregistrer le nom" }).click();
    },
    verifier: async (page, etat) => {
      await expect(page.getByLabel("Votre nom")).toHaveValue("Camille Martin");
      expect((await moi(page)).name).toBe((etat.compte as Compte).name);
    },
  },

  "POST /me/password": {
    methode: "POST", chemin: /^\/me\/password$/,
    preparer: async (c) => {
      const compte = await compteNeuf(c, "motdepasse-panne");
      await goHash(c.page, "#/parametres/compte");
      return { page: c.page, etat: { compte } };
    },
    agir: async (page, etat) => {
      const neuf = testPassword();
      await page.getByRole("button", { name: "Changer le mot de passe maître" }).click();
      const dlg = fenetre(page, "Changer le mot de passe maître");
      await dlg.getByLabel("Mot de passe maître actuel").fill((etat.compte as Compte).password);
      await dlg.getByLabel("Nouveau mot de passe maître", { exact: true }).fill(neuf);
      await dlg.getByLabel("Confirmer le nouveau mot de passe maître").fill(neuf);
      await dlg.getByRole("button", { name: "Changer le mot de passe" }).click();
    },
    verifier: async (page, etat) => {
      await expect(fenetre(page, "Changer le mot de passe maître")).toBeVisible();
      // L'ancien mot de passe ouvre toujours le coffre.
      await page.unrouteAll({ behavior: "ignoreErrors" });
      await page.evaluate(() => sessionStorage.clear());
      await loginUi(page, etat.compte as Compte);
    },
  },

  "POST /me/2fa/setup": {
    methode: "POST", chemin: /^\/me\/2fa\/setup$/,
    preparer: async (c) => {
      await compteNeuf(c, "2fa-panne");
      await goHash(c.page, "#/parametres/compte");
      return { page: c.page };
    },
    agir: async (page) => {
      await page.getByRole("button", { name: "Activer la double authentification" }).click();
    },
    verifier: async (page) => {
      expect((await moi(page)).totp_enabled ?? (await moi(page)).twofa ?? false).toBeFalsy();
      await expect(page.getByRole("button", { name: "Activer la double authentification" })).toBeVisible();
    },
  },

  "POST /me/2fa/enable": {
    methode: "POST", chemin: /^\/me\/2fa\/enable$/,
    preparer: async (c) => {
      const compte = await compteNeuf(c, "2fa-activation-panne");
      await goHash(c.page, "#/parametres/compte");
      await c.page.getByRole("button", { name: "Activer la double authentification" }).click();
      const dlg = fenetre(c.page, "Activer la double authentification");
      await dlg.getByText("Impossible de scanner ? Saisissez cette clé à la main").click();
      const secret = (await dlg.locator(".u-mono").first().innerText()).replace(/\s+/g, "");
      return { page: c.page, etat: { secret, compte } };
    },
    agir: async (page, etat) => {
      const dlg = fenetre(page, "Activer la double authentification");
      await dlg.getByLabel("Code affiché par l'application").fill(totp(String(etat.secret)));
      await dlg.getByRole("button", { name: "Activer", exact: true }).click();
    },
    verifier: async (page) => {
      await expect(fenetre(page, "Activer la double authentification")).toBeVisible();
      await expect(page.getByText("Double authentification activée.")).toHaveCount(0);
    },
  },

  "POST /me/2fa/disable": {
    methode: "POST", chemin: /^\/me\/2fa\/disable$/,
    preparer: async (c) => {
      const s = await SCENARIOS["POST /me/2fa/enable"].preparer(c);
      await SCENARIOS["POST /me/2fa/enable"].agir(s.page, s.etat!, c);
      await expect(s.page.getByText("Double authentification activée.").first()).toBeVisible();
      // Fenêtre des codes de secours : conservés, puis fermée.
      const codes = fenetre(s.page, "Vos codes de secours");
      await expect(codes).toBeVisible();
      await codes.getByLabel("J'ai conservé mes codes de secours").check();
      await codes.getByRole("button", { name: "Terminé" }).click();
      await expect(codes).toBeHidden();
      return s;
    },
    agir: async (page, etat) => {
      await page.getByRole("button", { name: "Désactiver la double authentification" }).click();
      const dlg = fenetre(page, /Désactiver la double authentification/);
      // Confirmation d'identité : mot de passe maître, puis code de vérification.
      await dlg.getByLabel("Mot de passe maître", { exact: true }).fill((etat.compte as Compte).password);
      await dlg.getByRole("button", { name: "Confirmer", exact: true }).click();
      const fenetreCode = fenetre(page, "Code de vérification");
      await expect(fenetreCode).toBeVisible({ timeout: KDF_TIMEOUT });
      await fenetreCode.getByRole("textbox").first().fill(totp(String(etat.secret), { time: Date.now() / 1000 + 30 }));
      // Le sixième chiffre envoie le code ; sinon « Valider ».
      const valider = fenetreCode.getByRole("button", { name: "Valider", exact: true });
      if (await valider.isVisible().catch(() => false)) await valider.click().catch(() => undefined);
    },
    verifier: async (page) => {
      await expect(page.getByRole("button", { name: "Désactiver la double authentification" })).toBeVisible();
    },
  },

  "DELETE /me/sessions/:p": {
    methode: "DELETE", chemin: /^\/me\/sessions\/[^/]+$/,
    preparer: async (c) => {
      const compte = await compteNeuf(c, "sessions-panne");
      // Seconde session du même compte, sur un autre « appareil ».
      const ctx = await c.browser.newContext({ baseURL: BASE_URL, extraHTTPHeaders: { "X-Forwarded-For": "10.248.1.7" } });
      await loginUi(await ctx.newPage(), compte);
      await goHash(c.page, "#/parametres/appareils");
      await expect(c.page.getByRole("table")).toBeVisible();
      const n = await c.page.getByRole("button", { name: /^Fermer la session / }).count();
      return { page: c.page, etat: { n } };
    },
    agir: async (page) => {
      await page.getByRole("button", { name: /^Fermer la session / }).first().click();
      const dlg = page.getByRole("dialog");
      if (await dlg.count()) await dlg.getByRole("button", { name: /^Fermer/ }).last().click();
    },
    verifier: async (page, etat) => {
      const sessions = await page.evaluate(async () => (await import("/js/api.js")).api("GET", "/me/sessions"));
      expect(sessions.length, "Aucune session fermée").toBe(Number(etat.n) + 1);
    },
  },

  // ---------------------------------------------------------------- Administration
  "POST /admin/invites": {
    methode: "POST", chemin: /^\/admin\/invites$/,
    preparer: async (c) => {
      const admin = await c.loggedIn("owner");
      // Serveur sans envoi groupé (repli R11) : une invitation à la fois.
      await admin.route((u) => u.pathname === "/api/admin/invites/batch", (r) => r.fulfill({ status: 404, body: "" }));
      await goHash(admin, "#/admin/personnes");
      await expect(titre(admin, "Personnes")).toBeVisible();
      return { page: admin, etat: { email: `repli-${Date.now()}@e2e.test` } };
    },
    agir: async (page, etat) => {
      await page.getByRole("button", { name: "Inviter des personnes" }).first().click();
      const dlg = fenetre(page, "Inviter des personnes");
      await dlg.getByRole("textbox").first().fill(String(etat.email));
      await dlg.getByRole("button", { name: /^Inviter/ }).last().click();
    },
    verifier: async (page, etat, c) => {
      const invites = await (await (await c.apiAs("owner")).get("/api/admin/invites")).json();
      expect(JSON.stringify(invites)).not.toContain(String(etat.email));
    },
  },

  "POST /admin/invites/:p/resend": {
    methode: "POST", chemin: /^\/admin\/invites\/[^/]+\/resend$/,
    preparer: async (c) => {
      const inv = await invitation(await c.apiAs("owner"), "renvoi-panne");
      const admin = await c.loggedIn("owner");
      await goHash(admin, `#/admin/personnes?q=${encodeURIComponent(inv.email)}`);
      await expect(admin.getByText(inv.email).first()).toBeVisible();
      return { page: admin, etat: { email: inv.email } };
    },
    agir: async (page, etat) => {
      await page.getByRole("button", { name: new RegExp(`^Plus d'actions pour ${String(etat.email).replace(/[.+]/g, "\\$&")}`) }).click();
      await page.getByRole("menuitem", { name: "Renvoyer l'invitation" }).click();
    },
    verifier: async (page) => {
      await expect(fenetre(page, "Nouveau lien d'invitation")).toHaveCount(0);
    },
  },

  "DELETE /admin/invites/:p": {
    methode: "DELETE", chemin: /^\/admin\/invites\/[^/]+$/,
    preparer: async (c) => SCENARIOS["POST /admin/invites/:p/resend"].preparer(c),
    agir: async (page, etat) => {
      await page.getByRole("button", { name: new RegExp(`^Plus d'actions pour ${String(etat.email).replace(/[.+]/g, "\\$&")}`) }).click();
      await page.getByRole("menuitem", { name: "Révoquer l'invitation" }).click();
      await fenetre(page, "Révoquer l'invitation ?").getByRole("button", { name: "Révoquer l'invitation" }).click();
    },
    verifier: async (page, etat, c) => {
      const invites = await (await (await c.apiAs("owner")).get("/api/admin/invites")).json();
      expect(JSON.stringify(invites)).toContain(String(etat.email));
    },
  },

  "PATCH /admin/users/:p": {
    methode: "PATCH", chemin: /^\/admin\/users\/[^/]+$/,
    preparer: async (c) => {
      const cible = await compteNeuf(c, "fiche-panne");
      return { page: await fiche(c, cible), etat: { cible } };
    },
    agir: async (page, etat) => {
      const cible = etat.cible as Compte;
      await menuFiche(page, cible, "Modifier");
      const dlg = fenetre(page, `Modifier ${cible.name}`);
      await dlg.getByLabel("Nom", { exact: true }).fill("Camille Bernard");
      await dlg.getByRole("button", { name: "Enregistrer", exact: true }).click();
    },
    verifier: async (page, etat, c) => {
      const cible = etat.cible as Compte;
      await expect(fenetre(page, `Modifier ${cible.name}`).getByLabel("Nom", { exact: true })).toHaveValue("Camille Bernard");
      expect((await utilisateur(c, cible.id!))?.name).toBe(cible.name);
    },
  },

  "DELETE /admin/users/:p": {
    methode: "DELETE", chemin: /^\/admin\/users\/[^/]+$/,
    preparer: async (c) => SCENARIOS["PATCH /admin/users/:p"].preparer(c),
    agir: async (page, etat, { org }) => {
      const cible = etat.cible as Compte;
      await menuFiche(page, cible, "Supprimer");
      const dlg = fenetre(page, `Supprimer le compte de ${cible.name} ?`);
      await dlg.getByLabel(`Saisissez « ${cible.name} » pour confirmer`).fill(cible.name);
      await dlg.getByLabel("Mot de passe maître", { exact: true }).fill(org.accounts.owner.password);
      await dlg.getByRole("button", { name: "Supprimer", exact: true }).click();
    },
    verifier: async (_page, etat, c) => {
      expect(await utilisateur(c, (etat.cible as Compte).id!), "Le compte existe toujours").toBeTruthy();
    },
  },

  "POST /admin/users/:p/revoke-sessions": {
    methode: "POST", chemin: /^\/admin\/users\/[^/]+\/revoke-sessions$/,
    // Action rapide de la ligne, dans la liste filtrée (menu ⋯).
    preparer: async (c) => {
      const cible = await compteNeuf(c, "deconnexion-panne");
      const admin = await c.loggedIn("owner");
      await goHash(admin, `#/admin/personnes?q=${encodeURIComponent(cible.email)}`);
      await expect(admin.getByText(cible.email).first()).toBeVisible();
      return { page: admin, etat: { cible } };
    },
    agir: async (page, etat) => {
      await page.getByRole("button", { name: `Plus d'actions pour ${(etat.cible as Compte).name}` }).first().click();
      await page.getByRole("menuitem", { name: "Déconnecter partout" }).click();
    },
    verifier: async (_page, _etat, c) => {
      // La session de la personne (page par défaut) reste ouverte.
      expect((await moi(c.page)).email).toBeTruthy();
    },
  },

  "DELETE /admin/users/:p/sessions/:p": {
    methode: "DELETE", chemin: /^\/admin\/users\/[^/]+\/sessions\/[^/]+$/,
    preparer: async (c) => SCENARIOS["PATCH /admin/users/:p"].preparer(c),
    agir: async (page) => {
      await page.getByRole("tab", { name: /^Sessions/ }).click();
      await page.getByRole("button", { name: /^Fermer la session / }).first().click();
    },
    verifier: async (_page, _etat, c) => {
      expect((await moi(c.page)).email).toBeTruthy();
    },
  },

  "POST /admin/users/:p/reset-2fa": {
    methode: "POST", chemin: /^\/admin\/users\/[^/]+\/reset-2fa$/,
    // Rapport de l'action de masse : la ligne ignorée et sa raison.
    message: { 500: /le serveur a refusé l'action/, reseau: /le serveur a refusé l'action/ },
    preparer: async (c) => {
      const cible = await compteNeuf(c, "reinit-2fa-panne");
      const admin = await c.loggedIn("owner");
      // Serveur sans action de masse (repli R11) : une réinitialisation par compte.
      await admin.route((u) => u.pathname === "/api/admin/users/bulk", (r) => r.fulfill({ status: 404, body: "" }));
      await goHash(admin, `#/admin/personnes?q=${encodeURIComponent(cible.email)}`);
      await expect(admin.getByText(cible.email).first()).toBeVisible();
      return { page: admin, etat: { cible } };
    },
    agir: async (page, etat) => {
      const cible = etat.cible as Compte;
      await page.getByRole("checkbox", { name: new RegExp(cible.name) }).first().check();
      await page.getByRole("button", { name: /Réinitialiser la double authentification/ }).first().click();
      const dlg = page.getByRole("dialog");
      await dlg.getByRole("button", { name: /Réinitialiser|Confirmer/ }).last().click();
    },
    verifier: async (_page, etat, c) => {
      expect(await utilisateur(c, (etat.cible as Compte).id!)).toBeTruthy();
    },
  },

  "POST /admin/settings/validate": {
    methode: "POST", chemin: /^\/admin\/settings\/validate$/,
    preparer: async (c) => {
      const admin = await c.loggedIn("owner");
      await goHash(admin, "#/admin/reglages/sessions");
      await expect(titre(admin, "Réglages")).toBeVisible();
      return { page: admin };
    },
    agir: async (page) => {
      await page.getByLabel("Déconnexion après inactivité", { exact: true }).selectOption("30");
      await page.getByRole("button", { name: "Vérifier et enregistrer", exact: true }).click();
    },
    verifier: async (page, _e, c) => {
      await expect(page.getByLabel("Déconnexion après inactivité", { exact: true })).toHaveValue("30");
      await expect(page.getByText("1 modification non enregistrée")).toBeVisible();
      const v = (await (await (await c.apiAs("owner")).get("/api/admin/settings")).json()).values["session.idle_minutes"];
      expect(v.value).toBe(60);
    },
  },

  "POST /admin/settings/profile": {
    methode: "POST", chemin: /^\/admin\/settings\/profile$/,
    preparer: async (c) => SCENARIOS["POST /admin/settings/validate"].preparer(c),
    agir: async (page) => {
      await page.getByRole("group", { name: "Profil de sécurité" }).getByText("Strict", { exact: true }).click();
    },
    verifier: async (page, _e, c) => {
      await expect(page.getByRole("dialog", { name: /^Profil Strict/ })).toHaveCount(0);
      const v = (await (await (await c.apiAs("owner")).get("/api/admin/settings")).json()).values["session.idle_minutes"];
      expect(v.value).toBe(60);
    },
  },

  "PUT /admin/settings": {
    methode: "PUT", chemin: /^\/admin\/settings$/,
    preparer: async (c) => {
      const admin = await c.loggedIn("owner");
      // Serveur sans registre (repli R11) : les 5 réglages historiques.
      await admin.route((u) => u.pathname === "/api/admin/settings/schema", (r) => r.fulfill({ status: 404, body: "" }));
      await goHash(admin, "#/admin/reglages/sessions");
      await expect(titre(admin, "Réglages")).toBeVisible();
      return { page: admin };
    },
    agir: async (page) => {
      await page.getByLabel("Déconnexion après inactivité", { exact: true }).selectOption("30");
      await page.getByRole("button", { name: "Vérifier et enregistrer", exact: true }).click();
      const recap = page.getByRole("dialog", { name: /^Enregistrer/ });
      if (await recap.isVisible().catch(() => false)) await recap.getByRole("button", { name: "Enregistrer", exact: true }).click();
    },
    verifier: async (page, _e, c) => {
      await expect(page.getByLabel("Déconnexion après inactivité", { exact: true })).toHaveValue("30");
      const v = (await (await (await c.apiAs("owner")).get("/api/admin/settings")).json()).values["session.idle_minutes"];
      expect(v.value).toBe(60);
    },
  },

  "POST /admin/mail/queue/:p/retry": {
    methode: "POST", chemin: /^\/admin\/mail\/queue\/[^/]+\/retry$/,
    preparer: async (c) => {
      const admin = await c.loggedIn("owner");
      const t0 = Math.floor(Date.now() / 1000);
      // File d'envoi : une invitation en échec (seule la lecture est simulée).
      await admin.route((u) => u.pathname === "/api/admin/mail/queue", (r) => r.fulfill({
        json: [{ id: "e-1", kind: "invite", to_email: "lea.petit@exemple.fr", status: "failed", attempts: 3, last_error_code: "smtp_connect", updated_at: t0 - 600, created_at: t0 - 3600 }],
      }));
      await goHash(admin, "#/admin/reglages/systeme");
      await expect(admin.getByRole("button", { name: "Renvoyer l'e-mail à lea.petit@exemple.fr" })).toBeVisible();
      return { page: admin };
    },
    agir: async (page) => {
      await page.getByRole("button", { name: "Renvoyer l'e-mail à lea.petit@exemple.fr" }).click();
    },
    verifier: async (page) => {
      await expect(page.getByRole("button", { name: "Renvoyer l'e-mail à lea.petit@exemple.fr" })).toBeVisible();
    },
  },

  // ---------------------------------------------------------------- Connexion d'entreprise (serveur simulé)
  "POST /admin/ldap/test": {
    methode: "POST", chemin: /^\/admin\/ldap\/test$/,
    simuler: (page) => simulateIdentity(page),
    preparer: async (c) => {
      const admin = await c.loggedIn("owner");
      return { page: admin };
    },
    agir: async (page) => {
      await expect(page.locator("main h1").first()).toBeAttached({ timeout: KDF_TIMEOUT });
      await goHash(page, "#/admin/connexion/ad");
      await page.getByLabel("Adresse du contrôleur de domaine").fill("ldaps://dc1.entreprise.local:636");
      await page.getByLabel("Compte de service (lecture seule)").fill("svc_locksy@entreprise.local");
      await page.getByLabel("Mot de passe du compte de service").fill("mot-de-passe-du-service");
      await page.getByLabel("Racine de recherche").fill("DC=entreprise,DC=local");
      await page.getByRole("button", { name: "Continuer", exact: true }).click();
    },
    verifier: async (page) => {
      await expect(page.getByLabel("Adresse du contrôleur de domaine")).toHaveValue("ldaps://dc1.entreprise.local:636");
      await expect(page.getByRole("heading", { level: 2, name: /Qui peut se connecter$/ })).toHaveCount(0);
    },
  },

  "PUT /admin/ldap": {
    methode: "PUT", chemin: /^\/admin\/ldap$/,
    simuler: (page) => simulateIdentity(page),
    preparer: async (c) => SCENARIOS["POST /admin/ldap/test"].preparer(c),
    agir: async (page, e, c) => SCENARIOS["POST /admin/ldap/test"].agir(page, e, c),
    verifier: async (page, e, c) => SCENARIOS["POST /admin/ldap/test"].verifier(page, e, c),
  },

  "POST /admin/ldap/test-login": {
    methode: "POST", chemin: /^\/admin\/ldap\/test-login$/,
    simuler: (page) => simulateIdentity(page),
    preparer: async (c) => {
      const admin = await c.loggedIn("owner");
      return { page: admin };
    },
    agir: async (page, e, c) => {
      // Étape 1 réussie (la panne ne vise que le test de connexion), puis étape 3.
      await SCENARIOS["POST /admin/ldap/test"].agir(page, e, c);
      await expect(page.getByRole("heading", { level: 2, name: /Qui peut se connecter$/ })).toBeVisible();
      await page.getByRole("button", { name: "Continuer", exact: true }).click();
      await page.getByLabel("Identifiant Windows").fill("proprietaire");
      await page.getByLabel("Mot de passe Windows").fill("mot-de-passe-windows");
      await page.getByRole("button", { name: "Tester avec mon compte" }).click();
    },
    verifier: async (page) => {
      await expect(page.getByText("Test réussi : votre compte Windows est bien reconnu.")).toHaveCount(0);
      await expect(page.getByLabel("Identifiant Windows")).toHaveValue("proprietaire");
    },
  },
};

// ------------------------------------------------------------------ Tests

const PANNES: Panne[] = [500, "reseau"];

test.describe("Écritures du web : panne simulée, message français, objet intact", () => {
  for (const [cle, s] of Object.entries(SCENARIOS)) {
    for (const comment of PANNES) {
      const nom = comment === 500 ? "réponse 500" : "réseau coupé";
      test(`${cle} : ${nom}`, async ({ page, org, browser, loggedIn, apiAs, consoleGuard }) => {
        test.setTimeout(150_000);
        if (s.defaut) test.fail(true, s.defaut);
        tolererPannes(consoleGuard);
        await pressePapiers(page);
        const c: Ctx = { page, org, browser, loggedIn, apiAs };
        const prep = await s.preparer(c);
        const etat = prep.etat || {};
        const sim = s.simuler ? await s.simuler(prep.page) : undefined;
        // La panne vise exactement l'écriture testée.
        let intercepte: Awaited<ReturnType<typeof panne>> | null = null;
        if (sim) sim.fail(cle, comment);
        else intercepte = await panne(prep.page, s.methode, s.chemin, comment);
        await s.agir(prep.page, etat, c);
        await messageVisible(prep.page, comment, s.message);
        if (intercepte) expect(intercepte.vues.length, `Requête ${cle} interceptée`).toBeGreaterThan(0);
        await intercepte?.lever();
        if (sim) sim.heal(cle);
        await s.verifier(prep.page, etat, c);
      });
    }
  }
});
