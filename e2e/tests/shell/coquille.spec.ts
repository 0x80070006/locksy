// Coquille de l'application (cahier §3.1, §3.2, règles A3, A7, A8, R5 ;
// fiche L9) : lien d'évitement, focus sur le h1 après chaque navigation,
// titre de l'onglet jamais égal au nom d'un élément ou d'un coffre, coquille
// jamais reconstruite (même nœud <nav> après une synchronisation), bandeau
// hors ligne, pastille du bilan de sécurité, recherche globale (Ctrl K),
// menu du compte, commutateur d'administration, page réservée, page
// introuvable, anciennes adresses, tiroir de navigation sur téléphone (@mobile).

import { test, expect } from "../../fixtures/index.ts";
import { seriousViolations } from "../../fixtures/axe.ts";
import { loginUi } from "../../fixtures/ui.ts";
import { connecter, creerElement, elementActif, navPrincipale, preparer, reseau } from "./outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(preparer);

test.describe("Coquille (bureau)", () => {
  test.skip(({ isMobile }) => isMobile, "parcours au clavier et à la souris sur grand écran");

  test("lien d'évitement en premier, puis le contenu", async ({ page, org }) => {
    await loginUi(page, org.accounts.user);
    const first = await page.evaluate(() => document.querySelector("a[href], button, input, select, textarea, [tabindex]:not([tabindex='-1'])")?.textContent?.trim());
    expect(first).toBe("Aller au contenu");
    const skip = page.getByRole("link", { name: "Aller au contenu" });
    await skip.focus();
    await expect(skip).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(page.locator("main#contenu")).toBeFocused();
    expect(await page.locator("#contenu[aria-live], #app[aria-live]").count()).toBe(0);
  });

  test("focus sur le h1 et titre de l'onglet après chaque navigation", async ({ page, org }) => {
    await loginUi(page, org.accounts.user);
    const nav = navPrincipale(page);
    for (const [link, title] of [["Favoris", "Favoris"], ["Corbeille", "Corbeille"], ["Bilan de sécurité", "Bilan de sécurité"], ["Tout", "Mon coffre"]]) {
      await nav.getByRole("link", { name: new RegExp(`^${link}`) }).click();
      await expect(page).toHaveTitle(`${title} · Locksy`);
      await expect(nav.getByRole("link", { name: new RegExp(`^${link}`) })).toHaveAttribute("aria-current", "page");
      await expect.poll(async () => (await elementActif(page)).tag).toBe("H1");
    }
    await page.getByRole("button", { name: "Menu du compte" }).click();
    await page.getByRole("menuitem", { name: "Aide et raccourcis" }).click();
    await expect(page).toHaveTitle("Aide et raccourcis · Locksy");
    await expect(page.getByRole("heading", { level: 1, name: "Aide et raccourcis" })).toBeFocused();
  });

  test("titre de l'onglet jamais égal au nom d'un élément ou d'un coffre", async ({ page, org }) => {
    await loginUi(page, org.accounts.user);
    const name = `Serveur NAS confidentiel ${Date.now()}`;
    const { id, collectionId } = await creerElement(page, name);
    const titles: string[] = [];
    for (const path of [`/#/element/${id}`, `/#/element/${id}/modifier`, `/#/coffre/c/${collectionId}`, "/#/coffre"]) {
      await page.goto(path);
      await expect(page.getByRole("navigation", { name: "Navigation principale" })).toBeVisible();
      titles.push(await page.title());
    }
    expect(titles).toEqual(["Élément · Locksy", "Modification · Locksy", "Coffre · Locksy", "Mon coffre · Locksy"]);
    for (const title of titles) expect(title).not.toContain(name);
    for (const title of titles) expect(title).not.toContain("Coffre personnel");
    expect(page.url()).not.toContain(encodeURIComponent(name));
  });

  test("coquille jamais reconstruite : même <nav> après synchronisation, compteurs à jour", async ({ page, org }) => {
    await loginUi(page, org.accounts.user);
    const nav = navPrincipale(page);
    await page.evaluate(() => {
      (window as unknown as { __nav: Element | null }).__nav = document.querySelector("nav[aria-label='Navigation principale']");
    });
    const before = Number((await nav.getByRole("link", { name: /^Tout/ }).locator("[data-count]").textContent()) || "0");
    await creerElement(page, `Élément de synchronisation ${Date.now()}`);

    // Coupure du réseau : bandeau ; retour du réseau : synchronisation.
    await reseau(page, false);
    await expect(page.getByText("Hors ligne : les données affichées sont celles du dernier déverrouillage.")).toBeVisible();
    await reseau(page, true);
    await expect(page.getByText("Hors ligne : les données affichées sont celles du dernier déverrouillage.")).toHaveCount(0);
    // Le compte suit le coffre synchronisé (d'autres tests en parallèle peuvent
    // ajouter des éléments au même compte : au moins le nôtre en plus).
    await expect.poll(async () => {
      const shown = Number((await nav.getByRole("link", { name: /^Tout/ }).locator("[data-count]").textContent()) || "0");
      const live = await page.evaluate(async () => [...(await import("/js/vault.js")).state.items.values()].filter((i) => !i.deleted_at).length);
      return shown === live && shown >= before + 1;
    }).toBe(true);

    // Navigation entre vues : la coquille reste la même aussi.
    await nav.getByRole("link", { name: /^Corbeille/ }).click();
    await expect(page).toHaveTitle("Corbeille · Locksy");
    const same = await page.evaluate(() => (window as unknown as { __nav: Element | null }).__nav === document.querySelector("nav[aria-label='Navigation principale']"));
    expect(same).toBe(true);
  });

  test("pastille du bilan de sécurité : un mot de passe faible est compté « à corriger »", async ({ page, org }) => {
    await loginUi(page, org.accounts.user);
    await creerElement(page, `Imprimante du couloir ${Date.now()}`, "azerty");
    await reseau(page, false);
    await reseau(page, true);
    const bilan = navPrincipale(page).getByRole("link", { name: /^Bilan de sécurité/ });
    await expect(bilan).toContainText(/\d+ à corriger/);
  });

  test("recherche globale : Ctrl K, résultats, ouverture de la fiche", async ({ page, org }) => {
    await loginUi(page, org.accounts.user);
    const name = `Routeur Wifi ${Date.now()}`;
    await creerElement(page, name);
    // Le fournisseur de recherche lit le coffre déchiffré : synchronisation par le retour du réseau.
    await reseau(page, false);
    await reseau(page, true);
    await expect.poll(() => page.evaluate(async (n) => [...(await import("/js/vault.js")).state.items.values()].some((i) => i.data?.name === n), name)).toBe(true);
    await page.locator("main#contenu").focus();
    await page.keyboard.press("Control+k");
    const search = page.getByRole("searchbox", { name: "Rechercher dans tout le coffre" })
      .or(page.getByRole("combobox", { name: "Rechercher dans tout le coffre" }))
      .or(page.getByRole("textbox", { name: "Rechercher dans tout le coffre" }));
    await expect(search.first()).toBeFocused();
    // Sans saisie : le groupe « Actions ».
    await expect(page.getByRole("region", { name: "Actions" })).toBeVisible();
    // Nom complet en minuscules : d'autres tests en parallèle créent aussi des « Routeur Wifi … ».
    await search.first().fill(name.toLowerCase());
    const result = page.getByRole("link", { name: new RegExp(name) });
    await expect(result).toBeVisible();
    await search.first().press("ArrowDown");
    await expect(result).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/#\/element\//);
    await expect(page).not.toHaveTitle(new RegExp(name));
  });

  test("menu du compte d'un utilisateur : pas d'administration ; route réservée expliquée", async ({ page, org }) => {
    await loginUi(page, org.accounts.user);
    await page.getByRole("button", { name: "Menu du compte" }).click();
    for (const item of ["Paramètres", "Liens envoyés", "Aide et raccourcis", "Se déconnecter"]) {
      await expect(page.getByRole("menuitem", { name: item })).toBeVisible();
    }
    await expect(page.getByRole("menuitem", { name: "Administration" })).toHaveCount(0);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("navigation", { name: "Mon coffre ou administration" })).toHaveCount(0);

    await page.goto("/#/admin/personnes");
    await expect(page.getByRole("heading", { level: 1, name: "Cette page est réservée aux administrateurs." })).toBeFocused();
    await page.getByRole("link", { name: "Retour au coffre" }).click();
    await expect(page).toHaveTitle("Mon coffre · Locksy");
  });

  test("administrateur : commutateur « Mon coffre | Administration » et entrée du menu", async ({ page, org }) => {
    await loginUi(page, org.accounts.admin);
    const switcher = page.getByRole("navigation", { name: "Mon coffre ou administration" });
    await expect(switcher.getByRole("link", { name: "Mon coffre" })).toHaveAttribute("aria-current", "page");
    await page.getByRole("button", { name: "Menu du compte" }).click();
    await page.getByRole("menuitem", { name: "Administration" }).click();
    await expect(page).toHaveURL(/#\/admin/);
    await expect(switcher.getByRole("link", { name: "Administration" })).toHaveAttribute("aria-current", "page");
  });

  test("page introuvable et anciennes adresses", async ({ page, org }) => {
    await loginUi(page, org.accounts.user);
    await page.goto("/#/nulle-part");
    await expect(page.getByRole("heading", { level: 1, name: "Page introuvable" })).toBeFocused();
    await expect(page).toHaveTitle("Page introuvable · Locksy");
    for (const [old, now] of [["/#/vault", /#\/coffre$/], ["/#/health", /#\/bilan$/], ["/#/shares", /#\/liens$/], ["/#/settings", /#\/parametres\/compte$/], ["/#/generator", /#\/generateur$/]] as const) {
      await page.goto(old);
      await expect(page).toHaveURL(now);
    }
  });

  test("coquille sans défaut d'accessibilité grave", async ({ page, org }) => {
    await loginUi(page, org.accounts.user);
    await expect(page.getByRole("banner")).toBeVisible();
    await expect(page.getByRole("main")).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
  });
});

test.describe("Tiroir de navigation (téléphone)", () => {
  test.use({ viewport: { width: 375, height: 812 } });

  test("fermé : masqué et non tabulable ; « Menu » l'ouvre, Échap le referme", { tag: "@mobile" }, async ({ page, org }) => {
    await connecter(page, org.accounts.user);
    const menu = page.getByRole("button", { name: "Menu", exact: true });
    await expect(menu).toHaveAttribute("aria-expanded", "false");
    const sidebar = page.locator("aside.l-sidebar");
    await expect(sidebar).toBeHidden();
    expect(await sidebar.evaluate((el) => (el as HTMLElement).inert)).toBe(true);

    // Tout le parcours au clavier évite la barre latérale fermée.
    for (let i = 0; i < 25; i++) {
      await page.keyboard.press("Tab");
      const inSidebar = await page.evaluate(() => !!document.activeElement?.closest("aside"));
      expect(inSidebar).toBe(false);
    }

    await menu.click();
    await expect(menu).toHaveAttribute("aria-expanded", "true");
    await expect(navPrincipale(page).getByRole("link", { name: /^Tout/ })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(sidebar).toBeHidden();
    await expect(menu).toBeFocused();

    // Un lien du tiroir ferme le tiroir et mène à la vue.
    await menu.click();
    await navPrincipale(page).getByRole("link", { name: /^Corbeille/ }).click();
    await expect(page).toHaveTitle("Corbeille · Locksy");
    await expect(sidebar).toBeHidden();
    await expect(menu).toHaveAttribute("aria-expanded", "false");
  });
});
