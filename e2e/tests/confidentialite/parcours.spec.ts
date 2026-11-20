// Confidentialité locale (cahier §6.4 « confidentialite », critère G39,
// contrat V2.1 partie navigateur) : après un parcours complet, aucun nom
// d'élément ou de coffre, mot de passe, note ni brouillon dans le titre de
// l'onglet, l'adresse, localStorage, sessionStorage, IndexedDB, ni dans les
// régions annoncées #status et #alert ; seules les clés de stockage admises.
//
// Admis : sessionStorage « locksy.session » et « locksy.share.nonce.* » ;
// localStorage « locksy.local », « locksy.kdfpins », « locksy.keypins ».
// L'identifiant (UUID) d'un élément est admis dans l'adresse, son nom jamais.
// La base (locksy.db) est couverte par le lot Q4 (security/zero-knowledge).

import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { addPasswordItem, expectShell, KDF_TIMEOUT, logoutUi, registerInvite, testPassword } from "../../fixtures/ui.ts";

test.use({ textGuardMode: "strict" });

const SESSION_ADMISES = [/^locksy\.session$/, /^locksy\.share\.nonce\./];
const LOCAL_ADMISES = [/^locksy\.local$/, /^locksy\.kdfpins$/, /^locksy\.keypins$/];

const alea = () => Math.random().toString(36).slice(2, 8);

interface Releve {
  etape: string;
  titre: string;
  adresse: string;
}

interface Stockage {
  local: Record<string, string>;
  session: Record<string, string>;
  bases: string[];
  status: string;
  alert: string;
}

/** Titre de l'onglet et adresse, à chaque étape. */
async function relever(page: Page, etape: string, releves: Releve[]) {
  releves.push({ etape, titre: await page.title(), adresse: page.url() });
}

async function stockage(page: Page): Promise<Stockage> {
  return page.evaluate(async () => {
    const lire = (s: Storage) => Object.fromEntries(Array.from({ length: s.length }, (_, i) => s.key(i)!).map((k) => [k, s.getItem(k) || ""]));
    const bases = typeof indexedDB.databases === "function" ? (await indexedDB.databases()).map((d) => String(d.name)) : [];
    return {
      local: lire(localStorage),
      session: lire(sessionStorage),
      bases,
      status: document.getElementById("status")?.textContent || "",
      alert: document.getElementById("alert")?.textContent || "",
    };
  });
}

/** Problèmes de confidentialité : secrets retrouvés, clés de stockage non admises, base IndexedDB. */
function fuites(secrets: string[], releves: Releve[], s: Stockage[]): string[] {
  const pb: string[] = [];
  const cherche = (ou: string, texte: string) => {
    for (const secret of secrets) if (texte.includes(secret)) pb.push(`« ${secret} » trouvé dans ${ou}`);
  };
  for (const r of releves) {
    cherche(`le titre de l'onglet (${r.etape})`, r.titre);
    cherche(`l'adresse (${r.etape})`, decodeURIComponent(r.adresse));
  }
  for (const [i, st] of s.entries()) {
    const quand = i === 0 ? "avant la déconnexion" : "après la déconnexion";
    for (const [k, v] of Object.entries(st.local)) {
      if (!LOCAL_ADMISES.some((re) => re.test(k))) pb.push(`clé localStorage non admise « ${k} » (${quand})`);
      cherche(`localStorage « ${k} » (${quand})`, `${k}=${v}`);
    }
    for (const [k, v] of Object.entries(st.session)) {
      if (!SESSION_ADMISES.some((re) => re.test(k))) pb.push(`clé sessionStorage non admise « ${k} » (${quand})`);
      cherche(`sessionStorage « ${k} » (${quand})`, `${k}=${v}`);
    }
    if (st.bases.length) pb.push(`bases IndexedDB présentes (${quand}) : ${st.bases.join(", ")}`);
    cherche(`#status (${quand})`, st.status);
    cherche(`#alert (${quand})`, st.alert);
  }
  return pb;
}

/** Compte utilisateur neuf, inscrit par l'interface dans la page. */
async function compteNeuf(page: Page, owner: import("@playwright/test").APIRequestContext) {
  const email = `confidentialite-${Date.now()}-${alea()}@e2e.test`;
  const res = await owner.post("/api/admin/invites", { data: { email, role: "user" } });
  expect(res.ok(), await res.text()).toBe(true);
  const password = testPassword();
  await registerInvite(page, (await res.json()).token, { name: "Camille Durand", password });
  await expect(page.locator("#contenu h1").first()).toBeVisible({ timeout: KDF_TIMEOUT });
  return { email, password };
}

/** Presse-papiers en mémoire (HTTP sur un nom d'hôte : pas de navigator.clipboard). */
async function pressePapiers(page: Page) {
  await page.addInitScript(() => {
    if (window.isSecureContext && navigator.clipboard) return;
    let contenu = "";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async (v: string) => { contenu = String(v); }, readText: async () => contenu },
    });
  });
}

const aller = (page: Page, hash: string) => page.evaluate((h) => { location.hash = h; }, hash);

async function deverrouiller(page: Page, password: string) {
  await page.getByLabel("Mot de passe maître", { exact: true }).fill(password);
  await page.getByRole("button", { name: /^(Déverrouiller|Se connecter)$/ }).click();
  await expectShell(page);
}

test.describe("Confidentialité locale : aucun nom ni secret hors du coffre chiffré", () => {
  test("parcours complet : titre, adresse, stockage, IndexedDB, #status et #alert", async ({ page, apiAs, org }) => {
    test.setTimeout(240_000);
    await pressePapiers(page);
    const compte = await compteNeuf(page, await apiAs("owner"));
    const releves: Releve[] = [];
    const id = alea();
    const nom1 = `Confidentiel-${id}-banque`;
    const nom2 = `Confidentiel-${id}-paie`;
    const mdp1 = `Secret-Banque-${id}-7!`;
    const mdp2 = `Secret-Paie-${id}-9?`;
    const nomNote = `Confidentiel-${id}-note`;
    const texteNote = `Code du coffre-fort physique ${id}`;
    const nomCoffre = `Confidentiel-${id}-coffre`;
    const brouillon = `Brouillon-${id}-jamais-enregistre`;
    const secrets = [nom1, nom2, mdp1, mdp2, nomNote, texteNote, nomCoffre, brouillon];

    // Deux éléments par l'éditeur, une note et un coffre partagé par le module de la page.
    await addPasswordItem(page, { name: nom1, username: "c.durand", password: mdp1 });
    await relever(page, "création du premier élément", releves);
    await addPasswordItem(page, { name: nom2, username: "c.durand", password: mdp2 });
    await relever(page, "création du second élément", releves);
    const ids = await page.evaluate(async ({ note, texte, coffre, admin }) => {
      const V = await import("/js/vault.js");
      const { api } = await import("/js/api.js");
      const perso = [...V.state.collections.values()].find((c: { personal?: boolean }) => c.personal)!;
      const noteId = await V.createItem(perso.id, { ...V.emptyItem("note"), name: note, notes: texte });
      const cid = await V.createCollection(coffre);
      await V.sync();
      const u = (await api("GET", "/directory")).find((x: { email: string }) => x.email === admin);
      if (u) await V.addMember(cid, u, "editor");
      await V.sync();
      const first = [...V.state.items.values()].find((i: { data?: { name?: string } }) => i.data?.name?.endsWith("-banque"))!;
      return { noteId, cid, first: first.id as string };
    }, { note: nomNote, texte: texteNote, coffre: nomCoffre, admin: org.accounts.admin.email });

    // Ouvrir la note, le coffre, puis le premier élément.
    await aller(page, `#/element/${ids.noteId}`);
    await expect(page.getByRole("heading", { level: 1, name: nomNote })).toBeVisible();
    await relever(page, "fiche de la note", releves);
    await aller(page, `#/coffre/c/${ids.cid}`);
    await expect(page.getByRole("button", { name: /^(Gérer le coffre|Voir les membres)$/ }).first()).toBeVisible();
    await relever(page, "coffre partagé", releves);
    await aller(page, `#/element/${ids.first}`);
    await expect(page.getByRole("heading", { level: 1, name: nom1 })).toBeVisible();
    await relever(page, "fiche de l'élément", releves);

    // Copier le mot de passe : « Mot de passe copié », jamais le secret.
    await page.getByRole("button", { name: "Copier le mot de passe", exact: true }).first().click();
    await expect(page.locator("#status")).toContainText("Mot de passe copié");
    expect(await page.locator("#status").textContent()).not.toContain(mdp1);

    // Modifier sans enregistrer : brouillon abandonné.
    await aller(page, `#/element/${ids.first}/modifier`);
    await page.getByLabel("Nom", { exact: true }).fill(brouillon);
    await relever(page, "modification en cours", releves);
    await aller(page, "#/coffre");
    await page.getByRole("dialog", { name: "Quitter sans enregistrer ?" }).getByRole("button", { name: "Abandonner", exact: true }).click();
    await relever(page, "brouillon abandonné", releves);

    // Générer : l'annonce dit la longueur et la robustesse, jamais le mot de passe.
    await page.getByRole("button", { name: "Générer", exact: true }).first().click();
    const panneau = page.getByRole("dialog", { name: "Générer un mot de passe" }).or(page.getByRole("complementary", { name: "Générer un mot de passe" })).first();
    await expect(panneau).toBeVisible();
    // « Un autre » : nouveau tirage, annoncé après un court délai.
    await panneau.getByRole("button", { name: "Un autre", exact: true }).click();
    await expect(page.locator("#status")).toContainText(/Nouveau mot de passe|Nouvelle phrase de passe/, { timeout: 5_000 });
    const genere = await panneau.locator("input, output, .u-mono").first().evaluate((el) => (el as HTMLInputElement).value || el.textContent || "");
    if (genere.trim().length >= 8) {
      secrets.push(genere.trim());
      expect(await page.locator("#status").textContent(), "Annonce du générateur sans le secret").not.toContain(genere.trim());
    }
    await relever(page, "générateur", releves);
    await page.keyboard.press("Escape");

    // Lien sécurisé vers le second élément.
    await aller(page, "#/coffre");
    await page.getByRole("list", { name: "Éléments" }).getByText(nom2, { exact: true }).click();
    await expect(page.getByRole("heading", { level: 1, name: nom2 })).toBeVisible();
    await page.getByRole("button", { name: "Partager", exact: true }).first().click();
    const partage = page.getByRole("dialog", { name: /^Partager/ });
    await partage.getByRole("tab", { name: "Par lien sécurisé" }).click();
    await partage.getByRole("button", { name: "Créer et copier le lien" }).click();
    await expect(partage.getByLabel("Lien sécurisé", { exact: true })).toBeVisible();
    await relever(page, "lien sécurisé créé", releves);
    await page.keyboard.press("Escape");

    // Recherche globale.
    await page.keyboard.press("Control+k");
    await page.keyboard.type(`Confidentiel-${id}`);
    await expect(page.getByText(nom1, { exact: true }).first()).toBeVisible();
    await relever(page, "recherche", releves);
    await page.keyboard.press("Escape");

    // Verrouiller, déverrouiller.
    await page.getByRole("button", { name: "Verrouiller", exact: true }).first().click();
    await expect(page.getByRole("button", { name: "Déverrouiller", exact: true })).toBeVisible();
    await relever(page, "verrouillé", releves);
    await deverrouiller(page, compte.password);
    await relever(page, "déverrouillé", releves);

    // Aucun brouillon retrouvé après rechargement.
    await page.reload();
    await deverrouiller(page, compte.password);
    await aller(page, `#/element/${ids.first}/modifier`);
    await expect(page.getByLabel("Nom", { exact: true })).toHaveValue(nom1);
    await aller(page, "#/coffre");
    await expect(page.getByText(brouillon)).toHaveCount(0);

    const avant = await stockage(page);
    await logoutUi(page);
    await relever(page, "déconnecté", releves);
    const apres = await stockage(page);
    expect(apres.session["locksy.session"], "Jeton de session effacé à la déconnexion").toBeUndefined();

    expect(fuites(secrets, releves, [avant, apres]), "Fuites de données locales").toEqual([]);
  });

  test("téléphone : fiche ouverte et copie, sans nom dans le titre, l'adresse ni le stockage", { tag: "@mobile" }, async ({ page, apiAs }) => {
    test.setTimeout(180_000);
    await pressePapiers(page);
    await compteNeuf(page, await apiAs("owner"));
    const id = alea();
    const nom = `Confidentiel-${id}-mobile`;
    const mdp = `Secret-Mobile-${id}-3#`;
    const releves: Releve[] = [];
    const itemId = await page.evaluate(async ({ n, p }) => {
      const V = await import("/js/vault.js");
      const perso = [...V.state.collections.values()].find((c: { personal?: boolean }) => c.personal)!;
      const i = await V.createItem(perso.id, { ...V.emptyItem("login"), name: n, username: "mobile", password: p, password_changed_at: V.now() });
      await V.sync();
      return i;
    }, { n: nom, p: mdp });
    await aller(page, `#/element/${itemId}`);
    await expect(page.getByRole("heading", { level: 1, name: nom })).toBeVisible();
    await relever(page, "fiche sur téléphone", releves);
    await page.getByRole("button", { name: "Copier le mot de passe", exact: true }).first().click();
    await expect(page.locator("#status")).toContainText("Mot de passe copié");
    const s = await stockage(page);
    expect(fuites([nom, mdp], releves, [s]), "Fuites de données locales").toEqual([]);
  });
});
