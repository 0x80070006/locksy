// Outils des suites d'accessibilité (lot Q3b, cahier §2.10 et §6.4 « a11y ») :
// modes d'affichage émulés (clair, sombre, contraste renforcé), largeurs, et
// contrôle complet d'un écran : axe (WCAG 2.0 à 2.2, A et AA), focus jamais
// sur <body>, un seul h1, une seule paire de régions live, refusion à 320 px
// (zoom 400 %) et taille des cibles. Aucun import d'un autre lot de la vague 3.

import type { APIRequestContext, Browser, CDPSession, Page } from "@playwright/test";
import { seriousViolations, WCAG_TAGS } from "../../fixtures/axe.ts";
import { test, expect, type Org } from "../../fixtures/index.ts";
import { FRESH_URL } from "../../fixtures/env.ts";
import { health } from "../../fixtures/org.ts";

export interface Mode {
  nom: string;
  sombre: boolean;
  contraste: boolean;
}

/** Les trois modes du cahier (§2.2) : l'application suit « Système » par défaut. */
export function modes(): Mode[] {
  return [
    { nom: "clair", sombre: false, contraste: false },
    { nom: "sombre", sombre: true, contraste: false },
    { nom: "contraste renforcé", sombre: false, contraste: true },
  ];
}

/** Largeurs analysées : bureau, puis téléphone étroit (critère G3 en partie). */
export const LARGEURS = [1280, 360] as const;

/**
 * Émule les préférences du système par CDP : Playwright 1.49 n'émule pas
 * prefers-contrast, et les deux préférences doivent être posées ensemble.
 */
export async function appliquerMode(page: Page, cdp: CDPSession, mode: Mode) {
  await cdp.send("Emulation.setEmulatedMedia", {
    features: [
      { name: "prefers-color-scheme", value: mode.sombre ? "dark" : "light" },
      { name: "prefers-contrast", value: mode.contraste ? "more" : "no-preference" },
    ],
  });
  // Laisse le navigateur recalculer les styles avant l'analyse.
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

/** Contrôles structurels d'un écran (indépendants du mode). */
export async function structure(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const pb: string[] = [];
    const visible = (el: Element) => {
      const s = getComputedStyle(el);
      const r = el.getBoundingClientRect();
      return s.visibility !== "hidden" && s.display !== "none" && r.width > 0 && r.height > 0 && !el.closest("[hidden], [inert]");
    };
    if (document.activeElement === document.body || !document.activeElement) pb.push("focus sur <body> après le rendu (A3)");
    // Un écran rendu inerte par une fenêtre modale garde son h1 (la fenêtre a son propre titre).
    const affiche = (el: Element) => { const r = el.getBoundingClientRect(); return !el.closest("[hidden]") && getComputedStyle(el).display !== "none" && r.width > 0 && r.height > 0; };
    const h1 = [...document.querySelectorAll("h1")].filter(affiche);
    if (h1.length !== 1) pb.push(`${h1.length} titres h1 visibles au lieu d'un seul (A8)`);
    const status = document.querySelectorAll("#status[role=status]").length;
    const alert = document.querySelectorAll("#alert[role=alert]").length;
    if (status !== 1 || alert !== 1) pb.push("régions #status (role=status) et #alert (role=alert) absentes (A1)");
    const autres = [...document.querySelectorAll("[aria-live]:not([aria-live=off]), [role=status], [role=alert], [role=log]")]
      .filter((el) => el.id !== "status" && el.id !== "alert" && visible(el))
      .map((el) => `<${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${el.className ? `.${String(el.className).split(/\s+/).join(".")}` : ""} ${el.getAttribute("role") ? `role=${el.getAttribute("role")}` : `aria-live=${el.getAttribute("aria-live")}`}>`);
    if (autres.length) pb.push(`régions live en plus de #status et #alert (A1) : ${[...new Set(autres)].slice(0, 5).join(", ")}`);
    return pb;
  });
}

/** Défilement horizontal de la page (refusion, A14). */
export const debordement = (page: Page) =>
  page.evaluate(() => {
    const d = document.documentElement;
    return d.scrollWidth > d.clientWidth ? `défilement horizontal : ${d.scrollWidth} px pour ${d.clientWidth} px` : null;
  });

/**
 * Cibles interactives plus petites que `min` px (A15, WCAG 2.5.8). Exceptions
 * de la norme : liens dans le texte, contrôles natifs masqués dont le libellé
 * est la cible (cases, boutons radio, fichiers), éléments hors écran.
 */
export async function ciblesTropPetites(page: Page, min: number): Promise<string[]> {
  return page.evaluate((taille) => {
    const sel = "a[href], button, input, select, textarea, summary, [role=button], [role=switch], [role=tab], [role=menuitem], [role=option], [role=checkbox], [role=radio], [tabindex]:not([tabindex='-1'])";
    const out: string[] = [];
    for (const el of document.querySelectorAll<HTMLElement>(sel)) {
      if (el.closest("[hidden], [inert], .u-sr-only, details:not([open]) > :not(summary)")) continue;
      if (el instanceof HTMLInputElement && ["radio", "checkbox", "file", "hidden"].includes(el.type)) continue;
      const s = getComputedStyle(el);
      if (s.visibility === "hidden" || s.display === "none" || Number(s.opacity) === 0) continue;
      const r = el.getBoundingClientRect();
      // Hors de la page (lien d'évitement masqué tant qu'il n'a pas le focus).
      if (!r.width || !r.height || r.right < 0 || r.left > innerWidth || r.bottom <= 0) continue;
      // Lien dans une phrase : exception « en ligne » de la norme.
      if (el.tagName === "A" && s.display === "inline" && el.parentElement && /^(P|LI|SPAN|SMALL|DD|TD)$/.test(el.parentElement.tagName)) continue;
      if (r.width + 0.5 < taille || r.height + 0.5 < taille) {
        const nom = (el.getAttribute("aria-label") || el.textContent || el.getAttribute("name") || el.tagName).trim().replace(/\s+/g, " ").slice(0, 40);
        out.push(`${el.tagName.toLowerCase()} « ${nom} » ${Math.round(r.width)}×${Math.round(r.height)}`);
      }
    }
    return [...new Set(out)];
  }, min);
}

/**
 * Contrôle complet de l'écran affiché : pour chaque largeur et chaque mode,
 * axe (serious et critical) ; puis la structure, la refusion à 320 px et la
 * taille des cibles à 360 px (`cible` px : 24, ou 44 en mode tactile).
 * Rend l'écran à 1280 px à la fin. Renvoie la liste lisible des problèmes.
 */
export async function controlerEcran(page: Page, { cible = 24, largeurs = LARGEURS }: { cible?: number; largeurs?: readonly number[] } = {}): Promise<string[]> {
  const pb: string[] = [];
  const cdp = await page.context().newCDPSession(page);
  const initial = page.viewportSize() || { width: 1280, height: 800 };
  try {
    // Le focus est posé sur le titre juste après le rendu : on lui laisse un instant.
    await page.waitForFunction(() => document.activeElement && document.activeElement !== document.body, undefined, { timeout: 2_000 }).catch(() => undefined);
    for (const p of await structure(page)) pb.push(p);
    for (const largeur of largeurs) {
      await page.setViewportSize({ width: largeur, height: largeur > 600 ? 800 : 740 });
      for (const mode of modes()) {
        await appliquerMode(page, cdp, mode);
        for (const v of await seriousViolations(page, WCAG_TAGS)) pb.push(`${largeur} px, ${mode.nom} : ${v}`);
      }
      if (largeur === 360) {
        const petites = await ciblesTropPetites(page, cible);
        if (petites.length) pb.push(`360 px : cibles de moins de ${cible} px : ${petites.slice(0, 8).join(" ; ")}${petites.length > 8 ? ` (+${petites.length - 8})` : ""}`);
      }
    }
    await page.setViewportSize({ width: 320, height: 640 });
    const deborde = await debordement(page);
    if (deborde) pb.push(`320 px (zoom 400 %) : ${deborde}`);
    for (const p of await structure(page)) if (!pb.includes(p)) pb.push(`après les changements de largeur : ${p}`);
  } finally {
    await cdp.send("Emulation.setEmulatedMedia", { features: [] }).catch(() => undefined);
    await page.setViewportSize(initial);
    await cdp.detach().catch(() => undefined);
  }
  return pb;
}

// ------------------------------------------------------------------ Écrans du §3

/** Fixtures utiles à la préparation d'un écran. */
interface Fx {
  page: Page;
  org: Org;
  browser: Browser;
  loggedIn: (role: "owner" | "admin" | "user") => Promise<Page>;
  apiAs: (role: "owner" | "admin" | "user") => Promise<APIRequestContext>;
}

/** Écran prêt à analyser : la page, et ce qui prouve que le rendu est fini. */
type Preparation = (fx: Fx) => Promise<Page>;

const titre = (page: Page, nom: string | RegExp) => page.getByRole("heading", { level: 1, name: nom });

/** Va à une route sans recharger (le coffre reste ouvert), après le premier rendu. */
async function aller(page: Page, hash: string) {
  await expect(page.locator("#contenu h1").first()).toBeAttached({ timeout: 60_000 });
  await page.evaluate((h) => { location.hash = h; }, hash);
}

/** Écran de l'application pour un rôle : route, puis titre attendu. */
const ecranApp = (role: "owner" | "admin" | "user", hash: string, h1: string | RegExp): Preparation => async ({ loggedIn }) => {
  const page = await loggedIn(role);
  await aller(page, hash);
  await expect(titre(page, h1)).toBeVisible();
  return page;
};

/** Élément créé dans le coffre personnel par le module de la page. */
async function element(page: Page, nom: string): Promise<string> {
  return page.evaluate(async (n) => {
    const V = await import("/js/vault.js");
    if (!V.state.collections.size) await V.sync();
    const perso = [...V.state.collections.values()].find((c: { personal?: boolean }) => c.personal);
    const id = await V.createItem(perso!.id, { ...V.emptyItem("login"), name: n, username: "a.martin", password: "Clair-Lune-Accessible-2026", urls: ["https://intranet.exemple.fr"], password_changed_at: V.now() });
    await V.sync();
    return id;
  }, nom);
}

const unique = (base: string) => `${base} ${Math.random().toString(36).slice(2, 7)}`;

/** Coffre partagé (avec Adam) créé par Alice ; renvoie son identifiant. */
async function coffre(page: Page, nom: string, email: string): Promise<string> {
  return page.evaluate(async ({ n, mail }) => {
    const V = await import("/js/vault.js");
    const { api } = await import("/js/api.js");
    const id = await V.createCollection(n);
    await V.sync();
    const u = (await api("GET", "/directory")).find((x: { email: string }) => x.email === mail);
    if (u) await V.addMember(id, u, "editor");
    await V.sync();
    return id;
  }, { n: nom, mail: email });
}

const SECTIONS_REGLAGES = ["login", "sessions", "passwords", "sharing", "clients", "retention", "branding", "mail", "advanced", "identity"];

/** Tous les écrans du §3 (V1.4 : 10 sections de réglages). */
export function ecrans(): Record<string, { preparer: Preparation; mobile?: boolean }> {
  const out: Record<string, { preparer: Preparation; mobile?: boolean }> = {
    // ---------------------------------------------------------------- Accès
    "connexion": {
      mobile: true,
      preparer: async ({ page }) => {
        await page.goto("/#/connexion");
        await expect(page.getByRole("button", { name: "Se connecter", exact: true })).toBeVisible();
        return page;
      },
    },
    "récupération du compte": {
      preparer: async ({ page }) => {
        await page.goto("/#/recuperation");
        await expect(titre(page, "Récupérer mon compte")).toBeVisible();
        return page;
      },
    },
    "inscription par invitation": {
      mobile: true,
      preparer: async ({ page, apiAs }) => {
        const res = await (await apiAs("owner")).post("/api/admin/invites", { data: { email: `a11y-${Date.now()}@e2e.test`, role: "user" } });
        const { token } = await res.json();
        await page.goto(`/#/inscription/${encodeURIComponent(token)}`);
        await expect(page.getByRole("button", { name: "Créer mon coffre", exact: true })).toBeVisible();
        return page;
      },
    },
    "coffre verrouillé": {
      preparer: async ({ loggedIn }) => {
        const page = await loggedIn("user");
        await expect(page.locator("#contenu h1").first()).toBeVisible();
        await page.getByRole("button", { name: "Verrouiller", exact: true }).first().click();
        await expect(page.getByRole("button", { name: "Déverrouiller", exact: true })).toBeVisible();
        return page;
      },
    },
    "installation": {
      preparer: async ({ page }) => {
        const h = await health(FRESH_URL);
        test.skip(!h?.needs_setup, "Serveur neuf déjà installé (ou injoignable) : l'écran d'installation n'est plus affiché.");
        await page.goto(`${FRESH_URL}/#/installation`);
        await expect(page.getByLabel("Jeton d'installation")).toBeVisible();
        return page;
      },
    },

    // ---------------------------------------------------------------- Pages publiques
    "aide et raccourcis": {
      preparer: async ({ page }) => {
        await page.goto("/#/aide");
        await expect(titre(page, "Aide et raccourcis")).toBeVisible();
        return page;
      },
    },
    "déclaration d'accessibilité": {
      preparer: async ({ page }) => {
        await page.goto("/#/accessibilite");
        await expect(titre(page, "Déclaration d'accessibilité")).toBeVisible();
        return page;
      },
    },
    "mentions légales": {
      preparer: async ({ page }) => {
        await page.goto("/#/mentions");
        await expect(titre(page, "Mentions légales")).toBeVisible();
        return page;
      },
    },
    "page d'un lien sécurisé": {
      mobile: true,
      preparer: async ({ page, loggedIn }) => {
        const alice = await loggedIn("user");
        await expect(alice.locator("#contenu h1").first()).toBeVisible();
        const id = await element(alice, unique("Wifi invités"));
        const url = await alice.evaluate(async (itemId) => {
          const V = await import("/js/vault.js");
          const it = V.state.items.get(itemId);
          const r = await V.createShareLink({ name: "", password: it.data.password }, 60, 3, { itemId });
          return String(r.url || r.link || r);
        }, id);
        await page.goto(url);
        await expect(page.locator("h1").first()).toBeVisible();
        return page;
      },
    },

    // ---------------------------------------------------------------- Coffre
    "coffre (tout)": {
      mobile: true,
      preparer: async ({ loggedIn }) => {
        const page = await loggedIn("user");
        await expect(page.locator("#contenu h1").first()).toBeVisible();
        await element(page, unique("Messagerie"));
        await aller(page, "#/corbeille");
        await aller(page, "#/coffre");
        await expect(titre(page, "Tout")).toBeVisible();
        return page;
      },
    },
    "favoris (vide)": { preparer: ecranApp("user", "#/coffre/favoris", "Favoris") },
    "un coffre partagé": {
      preparer: async ({ loggedIn, org }) => {
        const page = await loggedIn("user");
        await expect(page.locator("#contenu h1").first()).toBeVisible();
        const id = await coffre(page, unique("Équipe accessibilité"), org.accounts.admin.email);
        await aller(page, `#/coffre/c/${id}`);
        await expect(page.getByRole("button", { name: /^(Gérer le coffre|Voir les membres)$/ }).first()).toBeVisible();
        return page;
      },
    },
    "fiche d'un élément": {
      mobile: true,
      preparer: async ({ loggedIn }) => {
        const page = await loggedIn("user");
        await expect(page.locator("#contenu h1").first()).toBeVisible();
        const nom = unique("Portail RH");
        const id = await element(page, nom);
        await aller(page, `#/element/${id}`);
        await expect(titre(page, nom)).toBeVisible();
        return page;
      },
    },
    "modification d'un élément": {
      preparer: async ({ loggedIn }) => {
        const page = await loggedIn("user");
        await expect(page.locator("#contenu h1").first()).toBeVisible();
        const id = await element(page, unique("Banque"));
        await aller(page, `#/element/${id}/modifier`);
        await expect(page.getByLabel("Nom", { exact: true })).toBeVisible();
        return page;
      },
    },
    "nouvel élément": {
      preparer: async ({ loggedIn }) => {
        const page = await loggedIn("user");
        await aller(page, "#/nouveau");
        await expect(page.getByLabel("Nom", { exact: true })).toBeVisible();
        return page;
      },
    },
    "corbeille": { preparer: ecranApp("user", "#/corbeille", "Corbeille") },

    // ---------------------------------------------------------------- Outils
    "bilan de sécurité": {
      mobile: true,
      // Au moins un élément : le bilan affiche alors ses catégories repliables.
      preparer: async (fx) => {
        const page = await fx.loggedIn("user");
        await expect(page.locator("#contenu h1").first()).toBeVisible();
        await element(page, unique("Ancien webmail"));
        await aller(page, "#/bilan");
        await expect(titre(page, "Bilan de sécurité")).toBeVisible();
        return page;
      },
    },
    "liens envoyés": { preparer: ecranApp("user", "#/liens", "Liens envoyés") },
    "générateur (page)": { mobile: true, preparer: ecranApp("user", "#/generateur", "Générateur") },

    // ---------------------------------------------------------------- Paramètres
    "paramètres : compte": { mobile: true, preparer: ecranApp("user", "#/parametres/compte", "Paramètres") },
    "paramètres : préférences": { preparer: ecranApp("user", "#/parametres/preferences", "Paramètres") },
    "paramètres : appareils": { preparer: ecranApp("user", "#/parametres/appareils", "Paramètres") },
    "paramètres : données": { preparer: ecranApp("user", "#/parametres/donnees", "Paramètres") },
    "paramètres : activité": { preparer: ecranApp("user", "#/parametres/activite", "Paramètres") },

    // ---------------------------------------------------------------- Fenêtres
    "fenêtre « Partager »": {
      preparer: async ({ loggedIn }) => {
        const page = await loggedIn("user");
        await expect(page.locator("#contenu h1").first()).toBeVisible();
        const nom = unique("Compte fournisseur");
        await aller(page, `#/element/${await element(page, nom)}`);
        await page.getByRole("button", { name: "Partager", exact: true }).first().click();
        await expect(page.getByRole("dialog", { name: /^Partager/ })).toBeVisible();
        return page;
      },
    },
    "fenêtre « Générer un mot de passe »": {
      preparer: async ({ loggedIn }) => {
        const page = await loggedIn("user");
        await expect(page.locator("#contenu h1").first()).toBeVisible();
        await page.getByRole("button", { name: "Générer", exact: true }).first().click();
        await expect(page.getByRole("dialog", { name: /Générer un mot de passe/ }).or(page.getByRole("complementary", { name: /Générer/ })).first()).toBeVisible();
        return page;
      },
    },
    "fenêtre « Quitter sans enregistrer ? »": {
      preparer: async ({ loggedIn }) => {
        const page = await loggedIn("user");
        await aller(page, "#/nouveau");
        await page.getByLabel("Nom", { exact: true }).fill("Brouillon");
        await page.getByLabel("Nom", { exact: true }).press("Escape");
        await expect(page.getByRole("dialog", { name: "Quitter sans enregistrer ?" })).toBeVisible();
        return page;
      },
    },
    "fenêtre « Supprimer définitivement ? »": {
      preparer: async ({ loggedIn }) => {
        const page = await loggedIn("user");
        await expect(page.locator("#contenu h1").first()).toBeVisible();
        const id = await element(page, unique("Ancien routeur"));
        await page.evaluate(async (itemId) => {
          const { api } = await import("/js/api.js");
          const V = await import("/js/vault.js");
          await api("DELETE", `/items/${itemId}`);
          await V.sync();
        }, id);
        await aller(page, "#/corbeille");
        await aller(page, `#/element/${id}`);
        await page.getByRole("button", { name: "Supprimer définitivement", exact: true }).click();
        await expect(page.getByRole("dialog", { name: "Supprimer définitivement ?" })).toBeVisible();
        return page;
      },
    },

    // ---------------------------------------------------------------- Administration
    "administration : accueil": { mobile: true, preparer: ecranApp("owner", "#/admin", "Accueil") },
    "administration : personnes": { mobile: true, preparer: ecranApp("owner", "#/admin/personnes", "Personnes") },
    "administration : fiche d'une personne": {
      preparer: async (fx) => ecranApp("owner", `#/admin/personnes/${fx.org.accounts.user.id}`, "Personnes")(fx),
    },
    "administration : départ de l'entreprise": {
      preparer: async (fx) => ecranApp("owner", `#/admin/personnes/${fx.org.accounts.user.id}/depart`, /Départ/)(fx),
    },
    "administration : historique des réglages": { preparer: ecranApp("owner", "#/admin/reglages/historique", /Historique/) },
    "administration : import et export des réglages": { preparer: ecranApp("owner", "#/admin/reglages/transfert", /Importer/) },
    "administration : système": { preparer: ecranApp("owner", "#/admin/reglages/systeme", /Système/) },
    "administration : journal": { preparer: ecranApp("owner", "#/admin/journal", "Journal") },
    "administration : connexion d'entreprise": { preparer: ecranApp("owner", "#/admin/connexion", "Connexion d'entreprise") },
    "administration : SSO": { preparer: ecranApp("owner", "#/admin/connexion/sso", /Connexion d'entreprise|SSO|Microsoft/) },
    "administration : Active Directory": { preparer: ecranApp("owner", "#/admin/connexion/ad", /Connexion d'entreprise|Windows/) },
    "administration : création automatique des comptes": { preparer: ecranApp("owner", "#/admin/connexion/scim", /Connexion d'entreprise|automatique/) },
    "fenêtre « Inviter des personnes »": {
      preparer: async (fx) => {
        const page = await ecranApp("owner", "#/admin/personnes", "Personnes")(fx);
        await page.getByRole("button", { name: "Inviter des personnes" }).first().click();
        await expect(page.getByRole("dialog", { name: "Inviter des personnes" })).toBeVisible();
        return page;
      },
    },
    "fenêtre « Changer le rôle »": {
      preparer: async (fx) => {
        // Menu ⋯ de la ligne, dans la liste filtrée.
        const page = await ecranApp("owner", `#/admin/personnes?q=${encodeURIComponent(fx.org.accounts.user.email)}`, "Personnes")(fx);
        await page.getByRole("button", { name: `Plus d'actions pour ${fx.org.accounts.user.name}` }).first().click();
        await page.getByRole("menuitem", { name: /^Changer le rôle/ }).click();
        await expect(page.getByRole("dialog", { name: /^Changer le rôle/ })).toBeVisible();
        return page;
      },
    },
    "administration refusée à un utilisateur": {
      preparer: async ({ loggedIn }) => {
        const page = await loggedIn("user");
        await aller(page, "#/admin");
        await expect(page.getByText("Cette page est réservée aux administrateurs.")).toBeVisible();
        return page;
      },
    },
  };
  for (const s of SECTIONS_REGLAGES) {
    out[`administration : réglages « ${s} »`] = { mobile: s === "sessions", preparer: ecranApp("owner", `#/admin/reglages/${s}`, "Réglages") };
  }
  return out;
}
