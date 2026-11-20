// Outils communs des tests du coffre (lot L10) : libellés de l'annexe C,
// préparation (bruits tolérés), création d'éléments et de coffres par le
// module de chiffrement de la page (même instance que l'application), et
// création par l'éditeur neuf (le createItem de fixtures/ui.ts vise l'ancien
// éditeur modal).

import { expect, type Locator, type Page } from "@playwright/test";
import { expectShell } from "../../fixtures/ui.ts";

/**
 * Connexion par adresse et mot de passe maître, comme loginUi de fixtures/ui.ts ;
 * l'arrivée est reconnue par expectShell (navigation, ou bouton « Menu » sous
 * 900 px), que le coffre soit vide (accueil) ou non.
 */
export async function connexion(page: Page, a: { email: string; password: string }) {
  await page.goto("/");
  await page.getByLabel("Adresse e-mail").fill(a.email);
  await page.getByLabel("Mot de passe maître", { exact: true }).fill(a.password);
  await page.getByRole("button", { name: "Se connecter", exact: true }).click();
  await expectShell(page);
}

/** Garde de console du harnais (fixture `consoleGuard`). */
interface ConsoleGuard {
  allow(re: RegExp): void;
}

/** Libellés contractuels (annexe C) utilisés par ces tests. */
export const LIB = {
  nouveau: { name: "Nouveau", exact: true },
  enregistrer: { name: "Enregistrer", exact: true },
  annuler: { name: "Annuler", exact: true },
  nom: { exact: true } as const,
  liste: "Éléments",
  recherche: "Rechercher dans tout le coffre",
  sauve: /Élément enregistré/,
  quitter: "Quitter sans enregistrer ?",
  partager: { name: "Partager", exact: true },
};

/**
 * Bruits tolérés : GET /api/me/prefs répond 404 tant qu'aucun document de
 * préférences n'existe (annexe A.10) ; le navigateur le signale en console.
 */
export function tolererPrefs(consoleGuard: ConsoleGuard) {
  consoleGuard.allow(/status of 404/);
}

/** Pannes volontaires (réponse 500, requête coupée) : signalées en console par le navigateur. */
export function tolererPannes(consoleGuard: ConsoleGuard) {
  consoleGuard.allow(/status of 50\d|status of 409|Failed to load resource|NetworkError|ERR_FAILED/);
}

/**
 * Presse-papiers de test. Le réseau d'essai sert Locksy en HTTP sur un nom
 * d'hôte (http://locksy:8743) : ce n'est pas un contexte sécurisé, le
 * navigateur n'y expose pas navigator.clipboard (en production, HTTPS l'expose).
 * On le remplace, avant le chargement, par un presse-papiers en mémoire que
 * le test relit avec `lirePressePapiers`.
 */
export async function pressePapiers(page: Page) {
  await page.addInitScript(() => {
    if (window.isSecureContext && navigator.clipboard) return;
    let contenu = "";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async (v: string) => { contenu = String(v); },
        readText: async () => contenu,
      },
    });
  });
}

/** Contenu du presse-papiers (réel ou de test). */
export const lirePressePapiers = (page: Page) => page.evaluate(() => navigator.clipboard.readText());

/** Message passager (toast) contenant le texte. */
export const toast = (page: Page, texte: string | RegExp): Locator => page.locator(".c-toast").filter({ hasText: texte });

/** Va à une adresse de l'application sans recharger la page (changement de fragment). */
export async function aller(page: Page, hash: string) {
  await page.evaluate((h) => { location.hash = h; }, hash);
}

/** Liste des éléments. */
export const liste = (page: Page): Locator => page.getByRole("list", { name: LIB.liste });

/** Données d'un élément (forme de vault.emptyItem). */
export type Donnees = Record<string, unknown> & { name: string };

/**
 * Crée un élément par vault.js (sans l'éditeur), synchronise, puis renvoie
 * son identifiant. `collectionId` : coffre visé (défaut : coffre personnel).
 */
export async function creerElement(page: Page, data: Donnees, collectionId?: string): Promise<string> {
  return page.evaluate(async ({ d, cid }) => {
    const V = await import("/js/vault.js");
    // Juste après un déverrouillage, la première synchronisation peut être en cours.
    if (!V.state.collections.size) await V.sync();
    const target = cid || [...V.state.collections.values()].find((c) => c.personal)?.id;
    if (!target) throw new Error("Coffre personnel introuvable.");
    const id = await V.createItem(target, { ...V.emptyItem(String(d.kind || "login")), ...d });
    await V.sync();
    return id;
  }, { d: data, cid: collectionId });
}

/**
 * Crée un coffre partagé dont `emails` sont membres (rôle editor), par
 * vault.js ; renvoie son identifiant.
 */
export async function creerCoffre(page: Page, nom: string, emails: string[]): Promise<string> {
  return page.evaluate(async ({ n, mails }) => {
    const V = await import("/js/vault.js");
    const { api } = await import("/js/api.js");
    const id = await V.createCollection(n);
    await V.sync();
    const dir = await api("GET", "/directory");
    for (const mail of mails) {
      const u = dir.find((x: { email: string }) => x.email === mail);
      if (!u) throw new Error(`Personne absente de l'annuaire : ${mail}`);
      await V.addMember(id, u, "editor");
    }
    await V.sync();
    return id;
  }, { n: nom, mails: emails });
}

/** Coffre d'un élément, après une nouvelle synchronisation. */
export async function coffreDe(page: Page, itemId: string): Promise<{ collectionId: string | null; personal: boolean | null; deleted: boolean }> {
  return page.evaluate(async (id) => {
    const V = await import("/js/vault.js");
    await V.sync();
    const it = V.state.items.get(id);
    const c = it ? V.state.collections.get(it.collection_id) : null;
    return { collectionId: it?.collection_id ?? null, personal: c ? !!c.personal : null, deleted: !!it?.deleted_at };
  }, itemId);
}

/** Noms des coffres visibles, après une nouvelle synchronisation. */
export async function nomsDesCoffres(page: Page): Promise<string[]> {
  return page.evaluate(async () => {
    const V = await import("/js/vault.js");
    await V.sync();
    return [...V.state.collections.values()].map((c) => String(c.name));
  });
}

/** Nom unique pour un test (le serveur d'essai est partagé par toute l'exécution). */
export function unique(base: string): string {
  return `${base} ${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`;
}

/** Ouvre l'éditeur de création par « Nouveau », choisit le type et vérifie le focus sur « Nom ». */
export async function ouvrirCreation(page: Page, type?: string) {
  await page.getByRole("button", LIB.nouveau).click();
  const nom = page.getByLabel("Nom", LIB.nom);
  await expect(nom).toBeFocused();
  if (type) {
    // Cartes de choix : on clique la carte visible, comme une personne.
    await page.getByRole("group", { name: "Que voulez-vous enregistrer ?" }).getByText(type, { exact: true }).click();
    await expect(page.getByRole("radio", { name: type, exact: true })).toBeChecked();
    await expect(nom).toHaveValue("");
  }
  return nom;
}

/** Enregistre l'éditeur ouvert et attend la fiche de l'élément. */
export async function enregistrer(page: Page, nom: string) {
  await page.getByRole("button", LIB.enregistrer).click();
  await expect(page.getByText(LIB.sauve).first()).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: nom })).toBeVisible();
}
