// Matrice du paramétrage, partie interface (critère G2, cahier §6.4) :
// section par section, CHAQUE réglage « modifiable » de matrice.ts est changé
// dans Réglages (#/admin/reglages/<section>) vers une valeur valide
// différente du défaut, calculée depuis son type ; puis « Vérifier et
// enregistrer », « Enregistrer » (mot de passe maître si demandé),
// rechargement, contrôle de la valeur à l'écran ET dans GET
// /api/admin/settings, vérification de l'application (effets.ts), et enfin
// retour au défaut par l'API, même en cas d'échec.
//
// Les clés à garde-fou (`ui: { refus }`) sont essayées une à une : le refus
// s'affiche en français à côté du champ et rien n'est enregistré.
//
// Suite isolée (isole.config.ts) : elle modifie l'organisation partagée.

import type { APIRequestContext, Locator, Page } from "@playwright/test";
import { test, expect } from "../../fixtures/index.ts";
import { KDF_TIMEOUT, expectShell } from "../../fixtures/ui.ts";
import { EFFETS, normale } from "./effets.ts";
import { MATRICE } from "./matrice.ts";

test.use({ textGuardMode: "strict" });

// ------------------------------------------------------------------ Schéma

interface Kind {
  type: string;
  min?: number;
  max?: number;
  unit?: string;
  values?: string[];
  multiline?: boolean;
  max_len?: number;
}

interface Def {
  key: string;
  kind: Kind;
  default: unknown;
  section: string;
  order: number;
  advanced: boolean;
  owner_only: boolean;
  client: boolean;
  public: boolean;
  modes: boolean;
  host_locked: boolean;
  presets: number[];
}

const DUREES = new Set(["seconds", "minutes", "hours", "days"]);

/** Valeur par défaut nue (le défaut d'une clé à modes est { value, mode, max }). */
function defautDe(def: Def): unknown {
  const d = def.default as { value?: unknown } | null;
  return d && typeof d === "object" && !Array.isArray(d) && "value" in d ? d.value : d;
}

/** Image PNG de 1 × 1 pixel (logo de l'organisation). */
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
  "base64",
);
const IMAGE = "image:logo.png";
const SECRET = "Secret-Essai-2026";

/**
 * Valeurs choisies à la main : règles croisées (§4.6), environnement de test
 * (adresses du lanceur 10.x, 172.16-31.x et 192.168.x), comptes partagés à
 * ne pas bloquer, textes et adresses plausibles.
 */
const CHOISIES: Record<string, unknown> = {
  "twofa.required_roles": ["admin"],
  "twofa.grace_days": 14,
  "access.allowed_email_domains": ["e2e.test"],
  "access.ip_allowlist": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "access.ip_rescue": ["10.0.0.0/8"],
  "session.max_per_user": 50,
  "client.autolock_minutes": 15,
  "attachment.max_file_mib": 5,
  // Au moins la durée par défaut d'un lien (règle croisée share_expiry).
  "share.max_expiry_minutes": 10_080,
  "generator.symbols": "!@#$%",
  "master_password.banned_words": ["exemple"],
  "extension.excluded_sites": ["exemple.fr"],
  "extension.allowed_ids": ["abcdefghijklmnopabcdefghijklmnop"],
  "branding.org_name": "Organisation d'essai",
  "branding.logo": IMAGE,
  "branding.accent_color": "#326fa5",
  "branding.login_message": "Bienvenue sur le coffre d'essai.",
  "branding.support_contact": "assistance@exemple.fr",
  "branding.totp_issuer": "Coffre d'essai",
  "legal.notice_url": "https://exemple.fr/mentions-legales",
  "legal.privacy_url": "https://exemple.fr/confidentialite",
  "legal.accessibility_url": "https://exemple.fr/accessibilite",
  "legal.login_banner": "Accès réservé aux comptes d'essai.",
  "legal.charter_text": "Charte d'essai : les secrets restent dans le coffre.",
  "legal.dpo_contact": "dpo@exemple.fr",
  "i18n.timezone": "Europe/Brussels",
  "mail.smtp.host": "smtp.exemple.fr",
  "mail.smtp.security": "tls",
  "mail.smtp.username": "coffre",
  "mail.smtp.password": SECRET,
  "mail.from": "coffre@exemple.fr",
  "mail.reply_to": "assistance@exemple.fr",
  "mail.notify.admin_digest": "off",
  "instance.public_url": "https://coffre.exemple.fr",
  "audit.syslog.url": "udp://siem.exemple.fr:514",
};

/** Valeur cible : valide, différente du défaut, calculée depuis le type. */
function cible(def: Def): unknown {
  if (def.key in CHOISIES) return CHOISIES[def.key];
  const d = defautDe(def);
  const k = def.kind;
  switch (k.type) {
    case "bool":
      return !d;
    case "int": {
      const min = Number(k.min);
      const max = Number(k.max);
      const presets = (def.presets || []).filter((p) => p !== d && p >= min && p <= max && (p !== 0 || min === 0));
      if (presets.length) return presets[0];
      return Number(d) + 1 <= max ? Number(d) + 1 : Number(d) - 1;
    }
    case "enum":
      return (k.values || []).find((v) => v !== d);
    case "roles":
      return ["admin"];
    case "domains":
      return ["exemple.fr"];
    case "cidrs":
      return ["10.0.0.0/8"];
    case "emails":
      return ["essai@exemple.fr"];
    case "words":
      return ["exemple"];
    case "url":
      return `https://exemple.fr/${def.key.replace(/\W+/g, "-")}`;
    case "email":
      return "essai@exemple.fr";
    case "color":
      return "#326fa5";
    case "image":
      return IMAGE;
    case "secret":
      return SECRET;
    default:
      return k.multiline ? `Texte d'essai pour ${def.key}.` : "Valeur d'essai";
  }
}

// ------------------------------------------------------------------ Commandes de l'écran

const reglage = (page: Page, key: string): Locator => page.locator(`.c-setting[data-key="${key}"]`);

/** Champ de texte du réglage (ni nombre, ni sélecteur de couleur). */
const champTexte = (box: Locator) =>
  box.locator("textarea, input:not([type=number]):not([type=color]):not([type=radio]):not([type=checkbox]):not([type=file]):not([type=password]):not(.c-chips__input)").first();

/** Change la valeur d'un réglage comme une personne : clic, choix, saisie. */
async function ecrire(page: Page, def: Def, v: unknown) {
  const box = reglage(page, def.key);
  await box.scrollIntoViewIfNeeded();
  const k = def.kind;
  switch (k.type) {
    case "bool": {
      const sw = box.getByRole("switch").first();
      if ((await sw.getAttribute("aria-checked")) !== String(v)) await sw.click();
      await expect(sw).toHaveAttribute("aria-checked", String(v));
      return;
    }
    case "int": {
      if (DUREES.has(String(k.unit))) await box.locator("select").first().selectOption(String(v));
      else {
        const input = box.locator("input[type=number]").first();
        await input.fill(String(v));
        await input.press("Tab");
      }
      return;
    }
    case "enum": {
      // Choix segmenté : le bouton radio est masqué, on clique son libellé.
      const radio = box.locator(`input[type=radio][value="${String(v)}"]`).first();
      if (await radio.count()) {
        await box.locator(`label:has(> input[type=radio][value="${String(v)}"])`).first().click();
        await expect(radio).toBeChecked();
      } else await box.locator("select").first().selectOption(String(v));
      return;
    }
    case "roles":
      for (const role of ["user", "admin", "owner"]) {
        const caseRole = box.locator(`input[type=checkbox][value="${role}"]`);
        // Case masquée par la mise en forme en cartes : on clique son libellé.
        if ((await caseRole.isChecked()) !== (v as string[]).includes(role)) await box.locator(`label:has(> input[type=checkbox][value="${role}"])`).click();
        await expect(caseRole).toBeChecked({ checked: (v as string[]).includes(role) });
      }
      return;
    case "domains":
    case "cidrs":
    case "emails":
    case "words": {
      const input = box.locator(".c-chips__input");
      for (const item of v as string[]) {
        await input.fill(item);
        await input.press("Enter");
        await expect(box.locator(".c-chips > li > span", { hasText: item })).toBeVisible();
      }
      return;
    }
    case "secret": {
      await box.getByRole("button", { name: /^(Définir|Remplacer)$/ }).click();
      const input = box.locator("input[type=password]");
      await input.fill(String(v));
      await input.press("Tab");
      return;
    }
    case "image":
      await box.locator("input[type=file]").setInputFiles({ name: "logo.png", mimeType: "image/png", buffer: PNG });
      await expect(box.locator("img").first()).toBeVisible();
      return;
    default: {
      const input = champTexte(box);
      await input.fill(String(v));
      await input.press("Tab");
    }
  }
}

/** Valeur affichée par l'écran (après rechargement), sous une forme comparable à la cible. */
async function lire(page: Page, def: Def): Promise<unknown> {
  const box = reglage(page, def.key);
  const k = def.kind;
  switch (k.type) {
    case "bool":
      return (await box.getByRole("switch").first().getAttribute("aria-checked")) === "true";
    case "int":
      return Number(DUREES.has(String(k.unit))
        ? await box.locator("select").first().inputValue()
        : await box.locator("input[type=number]").first().inputValue());
    case "enum": {
      const radio = box.locator("input[type=radio]:checked").first();
      return (await box.locator(`input[type=radio][value="${(k.values || [])[0]}"]`).count())
        ? radio.getAttribute("value")
        : box.locator("select").first().inputValue();
    }
    case "roles":
      return box.locator("input[type=checkbox]:checked").evaluateAll((els) => els.map((e) => (e as HTMLInputElement).value));
    case "domains":
    case "cidrs":
    case "emails":
    case "words":
      return (await box.locator(".c-chips > li > span").allTextContents()).map((s) => s.trim());
    case "secret":
      return (await box.getByText("Défini", { exact: true }).isVisible()) ? SECRET : "";
    case "image":
      return (await box.locator("img").first().isVisible()) ? IMAGE : "";
    default:
      return champTexte(box).inputValue();
  }
}

/** Valeur enregistrée côté serveur, sous la même forme comparable. */
function valeurServeur(def: Def, entry: Record<string, unknown> | undefined): unknown {
  if (!entry) return undefined;
  if (def.kind.type === "secret") return entry.has_secret ? SECRET : "";
  if (def.kind.type === "image") {
    const v = entry.value as unknown;
    const present = typeof v === "string" ? v.length > 0 : !!(v && typeof v === "object" && (v as { has_image?: boolean }).has_image);
    return present ? IMAGE : "";
  }
  return entry.value;
}

/** Ouvre la section et déplie ses réglages avancés. */
async function ouvrirSection(page: Page, section: string) {
  await page.evaluate((h) => { location.hash = h; }, `#/admin/reglages/${section}`);
  await expect(page.getByRole("heading", { level: 1, name: "Réglages" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 2 }).first()).toBeVisible();
  const avances = page.locator("#contenu details.c-card").filter({ has: page.locator(":scope > summary", { hasText: /^Réglages? avancés? \(/ }) });
  if ((await avances.count()) && !(await avances.evaluate((d) => (d as HTMLDetailsElement).open))) {
    await avances.locator(":scope > summary").click();
  }
}

/** « Vérifier et enregistrer », récapitulatif, mot de passe maître si demandé. */
async function enregistrer(page: Page, motDePasse: string) {
  await page.getByRole("button", { name: "Vérifier et enregistrer", exact: true }).click();
  const recap = page.getByRole("dialog", { name: /^Enregistrer \d+ modifications?$/ });
  const refus = page.locator(".c-toast").filter({ hasText: /réglages? à corriger/ }).first();
  await expect(recap.or(refus).first()).toBeVisible();
  if (await refus.isVisible()) {
    // Valeur cible refusée par la validation : le message dit laquelle et pourquoi.
    const erreurs = await page.locator(".c-setting").evaluateAll((els) => els
      .map((el) => ({ cle: el.getAttribute("data-key"), texte: el.querySelector(":scope > .c-field__error:not([hidden])")?.textContent?.trim() }))
      .filter((x) => x.texte)
      .map((x) => `${x.cle} : ${x.texte}`));
    expect(erreurs, "Valeurs cibles refusées par la validation").toEqual([]);
  }
  await recap.getByRole("button", { name: "Enregistrer", exact: true }).click();
  const confirmation = page.getByRole("dialog", { name: "Confirmer l'abaissement de la sécurité" });
  const enregistre = page.locator(".c-toast").filter({ hasText: /Réglages enregistrés \(révision \d+\)/ }).first();
  await expect(confirmation.or(enregistre).first()).toBeVisible({ timeout: KDF_TIMEOUT });
  if (await confirmation.isVisible()) {
    await confirmation.getByLabel("Mot de passe maître", { exact: true }).fill(motDePasse);
    await confirmation.getByRole("button", { name: "Confirmer", exact: true }).click();
  }
  await expect(enregistre).toBeVisible({ timeout: KDF_TIMEOUT });
}

/** Recharge la page et déverrouille (charte acceptée si une nouvelle version est demandée). */
async function recharger(page: Page, motDePasse: string) {
  await page.reload();
  const champ = page.getByLabel("Mot de passe maître", { exact: true });
  await expect(champ).toBeVisible({ timeout: KDF_TIMEOUT });
  await champ.fill(motDePasse);
  await page.getByRole("button", { name: /^(Déverrouiller|Se connecter)$/ }).click();
  const charte = page.getByRole("button", { name: "J'accepte la charte", exact: true });
  const coquille = page.getByRole("navigation", { name: /^Navigation(?: principale)?$/ });
  await expect(charte.or(coquille).first()).toBeVisible({ timeout: KDF_TIMEOUT });
  if (await charte.isVisible()) await charte.click();
  await expectShell(page);
}

/**
 * Remet des clés au défaut DEPUIS la page connectée : le jeton de
 * réauthentification est lié à la session qui l'a demandé (C4.1), il ne vaut
 * donc que pour les requêtes de cette page. Renvoie « ok » ou la raison.
 */
async function retablir(page: Page, cles: string[], motDePasse: string): Promise<string> {
  if (!cles.length) return "ok";
  return page.evaluate(async ({ keys, pwd }) => {
    const V = await import("/js/vault.js");
    const A = await import("/js/api.js");
    const reauth = await A.exchangeReauth("settings", await V.authProof(pwd));
    let dernier = "";
    for (let essai = 0; essai < 3; essai++) {
      const cur = await A.apiFull("GET", "/admin/settings");
      try {
        await A.apiFull("POST", "/admin/settings/reset", { keys }, { ifMatch: cur.etag, reauth });
        return "ok";
      } catch (e) {
        const err = e as { status?: number; code?: string; message?: string };
        dernier = `${err.status} ${err.code} : ${err.message}`;
        if (err.status !== 409) break;
      }
    }
    return dernier;
  }, { keys: cles, pwd: motDePasse });
}

async function schema(api: APIRequestContext): Promise<{ sections: string[]; settings: Def[] }> {
  const res = await api.get("/api/admin/settings/schema");
  expect(res.ok(), `GET /api/admin/settings/schema : ${res.status()}`).toBe(true);
  return res.json();
}

// ------------------------------------------------------------------ Parcours d'un groupe de réglages

interface Fixtures {
  page: Page;
  loggedIn: (role: "owner" | "admin" | "user") => Promise<Page>;
  apiAs: (role: "owner" | "admin" | "user") => Promise<APIRequestContext>;
  org: { accounts: Record<"owner" | "admin" | "user", { email: string; password: string }> };
  consoleGuard: { allow(re: RegExp): void };
}

/**
 * Pour les réglages retenus par `filtre` : présence de chaque commande, puis,
 * section par section, saisie de la valeur cible, enregistrement,
 * rechargement, contrôle à l'écran et dans l'API, vérifications « ici »,
 * et retour au défaut (toujours, même après un échec).
 */
async function parcourir({ page, loggedIn, apiAs, org, consoleGuard }: Fixtures, filtre: (d: Def) => boolean, nom: string) {
  // GET /api/me/prefs répond 404 tant qu'aucune préférence n'existe.
  consoleGuard.allow(/status of 404/);
  const owner = org.accounts.owner;
  const api = await apiAs("owner");
  const defs = (await schema(api)).settings.filter(filtre).sort((a, b) => a.order - b.order);
  expect(defs.length, `Aucun réglage pour ${nom}`).toBeGreaterThan(0);
  for (const d of defs.filter((x) => x.host_locked)) test.info().annotations.push({ type: "fixé par l'hébergeur", description: d.key });

  const admin = await loggedIn("owner");
  const sections = [...new Set(defs.map((d) => d.section))];
  for (const section of sections) {
    await ouvrirSection(admin, section);
    for (const d of defs.filter((x) => x.section === section)) await expect(reglage(admin, d.key), `Commande du réglage ${d.key}`).toHaveCount(1);
  }
  const modifiables = defs.filter((d) => MATRICE[d.key]?.ui === "modifiable" && !d.host_locked);
  if (!modifiables.length) return;

  const cibles = new Map(modifiables.map((d) => [d.key, cible(d)]));
  const verifs = modifiables.filter((d) => MATRICE[d.key].preuves.some((p) => "e2e" in p && p.e2e === "ici"));
  // Session de l'utilisateur ouverte AVANT l'enregistrement : une nouvelle
  // version de la charte (legal.charter_version) bloquerait une connexion après.
  const user = verifs.length ? await apiAs("user") : null;
  const pageUser = verifs.length ? await loggedIn("user") : null;
  const ecrites: string[] = [];
  try {
    for (const section of sections) {
      const ici = modifiables.filter((d) => d.section === section);
      if (!ici.length) continue;
      await ouvrirSection(admin, section);
      for (const d of ici) {
        await ecrire(admin, d, cibles.get(d.key));
        ecrites.push(d.key);
      }
    }
    await expect(admin.getByText(/^\d+ modifications? non enregistrées?$/)).toBeVisible();
    await enregistrer(admin, owner.password);

    // Conservée : à l'écran après rechargement, et dans l'API.
    await recharger(admin, owner.password);
    const ecarts: string[] = [];
    const valeurs = (await (await api.get("/api/admin/settings")).json()).values;
    for (const section of sections) {
      const ici = modifiables.filter((d) => d.section === section);
      if (!ici.length) continue;
      await ouvrirSection(admin, section);
      for (const d of ici) {
        const attendu = normale(cibles.get(d.key));
        const ecran = normale(await lire(admin, d));
        const serveur = normale(valeurServeur(d, valeurs[d.key]));
        if (JSON.stringify(ecran) !== JSON.stringify(attendu) && String(ecran) !== String(attendu)) ecarts.push(`${d.key} à l'écran : ${JSON.stringify(ecran)} au lieu de ${JSON.stringify(attendu)}`);
        if (JSON.stringify(serveur) !== JSON.stringify(attendu)) ecarts.push(`${d.key} dans l'API : ${JSON.stringify(serveur)} au lieu de ${JSON.stringify(attendu)}`);
      }
    }
    expect(ecarts, "Réglages non conservés après rechargement").toEqual([]);

    // Appliquée : preuves « ici » de la matrice.
    if (user && pageUser) {
      // La page de l'utilisateur relit la politique (nouvelle révision).
      await pageUser.evaluate(async () => (await import("/js/settings-client.js")).loadPolicy());
      for (const d of verifs) {
        const verif = EFFETS[d.key];
        expect(verif, `Vérification « ici » absente pour ${d.key}`).toBeTruthy();
        await verif({ cle: d.key, cible: cibles.get(d.key), owner: api, user, page: pageUser, anonyme: page.request, accueil: page });
      }
    }
  } finally {
    // Retour au défaut même après un échec ; il ne masque pas l'erreur d'origine.
    const page2 = admin.isClosed() ? await loggedIn("owner") : admin;
    const retour = await retablir(page2, ecrites, owner.password).catch((e) => String(e));
    expect.soft(retour, `Retour au défaut (${nom})`).toBe("ok");
  }
  const apres = (await (await api.get("/api/admin/settings")).json()).values;
  const restes = ecrites.filter((k) => apres[k]?.source && apres[k].source !== "default");
  expect(restes, "Réglages restés modifiés après le retour au défaut").toEqual([]);
}

// ------------------------------------------------------------------ Tests

/** Sections du registre (V1.4 : 10 sections, « identity » comprise ; jamais codé en dur dans les assertions). */
const SECTIONS = ["login", "sessions", "passwords", "sharing", "clients", "retention", "branding", "mail", "advanced", "identity"];

test.describe("Matrice du paramétrage : chaque réglage modifiable, conservé, appliqué", () => {
  test("les sections parcourues ici sont celles du registre", async ({ apiAs }) => {
    const s = await schema(await apiAs("owner"));
    expect([...s.sections].sort(), "Sections de GET /admin/settings/schema").toEqual([...SECTIONS].sort());
  });

  for (const section of SECTIONS) {
    test(`section « ${section} » : saisie, enregistrement, rechargement, application`, async ({ page, loggedIn, apiAs, org, consoleGuard }) => {
      // Les réglages à modes (Libres / Par défaut / Imposé) ont leur propre test.
      await parcourir({ page, loggedIn, apiAs, org, consoleGuard }, (d) => d.section === section && !d.modes, `section ${section}`);
    });
  }

  test("réglages à modes (Libres / Par défaut / Imposé) : saisie, enregistrement, rechargement, application", async ({ page, loggedIn, apiAs, org, consoleGuard }) => {
    await parcourir({ page, loggedIn, apiAs, org, consoleGuard }, (d) => d.modes, "réglages à modes");
  });

  for (const [cle, entree] of Object.entries(MATRICE).filter(([, e]) => e.ui !== "modifiable")) {
    const code = (entree.ui as { refus: string }).refus;
    test(`garde-fou « ${cle} » : refus « ${code} » affiché en français à côté du réglage`, async ({ loggedIn, apiAs }) => {
      const api = await apiAs("owner");
      const def = (await schema(api)).settings.find((d) => d.key === cle);
      expect(def, `Clé ${cle} absente du schéma`).toBeTruthy();
      const valeur = def!.kind.type === "bool" ? true : (def!.kind.values || []).find((v) => v !== defautDe(def!) && v !== "password");
      // Le serveur refuse avec le code attendu…
      const res = await api.post("/api/admin/settings/validate", { data: { changes: { [cle]: valeur } } });
      expect(res.ok(), await res.text()).toBe(true);
      const validation = await res.json();
      expect(validation.ok, "Validation refusée").toBe(false);
      expect(validation.errors?.[cle]?.code, `Code du refus de ${cle}`).toBe(code);
      // … et l'écran l'explique à côté du champ, sans rien enregistrer.
      const page = await loggedIn("owner");
      const avant = (await api.get("/api/admin/settings")).headers()["etag"];
      await ouvrirSection(page, def!.section);
      await ecrire(page, def!, valeur);
      await page.getByRole("button", { name: "Vérifier et enregistrer", exact: true }).click();
      const erreur = reglage(page, cle).locator(":scope > .c-field__error");
      await expect(erreur).toBeVisible();
      await expect(erreur).not.toHaveText(/^\s*$/);
      await expect(page.locator(".c-toast").filter({ hasText: /réglages? à corriger/ }).first()).toBeVisible();
      await page.getByRole("button", { name: "Tout annuler", exact: true }).click();
      expect((await api.get("/api/admin/settings")).headers()["etag"], "Aucune révision écrite").toBe(avant);
    });
  }

  test("liste blanche sans l'adresse de l'auteur : refus expliqué, rien n'est enregistré", async ({ loggedIn, apiAs }) => {
    const api = await apiAs("owner");
    const res = await api.post("/api/admin/settings/validate", { data: { changes: { "access.ip_allowlist": ["203.0.113.0/24"] } } });
    const validation = await res.json();
    expect(validation.errors?.["access.ip_allowlist"]?.code).toBe("missing_own_ip");
    const page = await loggedIn("owner");
    const def = (await schema(api)).settings.find((d) => d.key === "access.ip_allowlist")!;
    await ouvrirSection(page, "login");
    await ecrire(page, def, ["203.0.113.0/24"]);
    await page.getByRole("button", { name: "Vérifier et enregistrer", exact: true }).click();
    await expect(reglage(page, "access.ip_allowlist").locator(":scope > .c-field__error")).toContainText(/doit faire partie de la liste/);
    await page.getByRole("button", { name: "Tout annuler", exact: true }).click();
  });

  test("administrateur : les réglages réservés aux propriétaires sont en lecture seule, avec la raison", async ({ loggedIn, apiAs }) => {
    const defs = (await schema(await apiAs("owner"))).settings.filter((d) => d.owner_only);
    expect(defs.length).toBeGreaterThan(0);
    const page = await loggedIn("admin");
    for (const section of [...new Set(defs.map((d) => d.section))]) {
      await ouvrirSection(page, section);
      for (const d of defs.filter((x) => x.section === section)) {
        const box = reglage(page, d.key);
        await expect(box.getByText("Seuls les propriétaires peuvent modifier ce réglage."), d.key).toBeVisible();
        await expect(box.locator("input, select, textarea, [role=switch]"), `${d.key} : aucune commande`).toHaveCount(0);
      }
    }
  });

  test("couleur de l'organisation appliquée à l'interface (écran de connexion)", async ({ page, loggedIn, apiAs, org }) => {
    const api = await apiAs("owner");
    const owner = await loggedIn("owner");
    const etag = (await api.get("/api/admin/settings")).headers()["etag"];
    const res = await api.patch("/api/admin/settings", { data: { changes: { "branding.accent_color": "#326fa5" } }, headers: { "If-Match": etag } });
    expect(res.status(), await res.text()).toBe(200);
    try {
      await page.goto("/");
      const bouton = page.getByRole("button", { name: "Se connecter", exact: true });
      await expect(bouton).toBeVisible();
      await expect(bouton).toHaveCSS("background-color", "rgb(50, 111, 165)");
    } finally {
      expect.soft(await retablir(owner, ["branding.accent_color"], org.accounts.owner.password)).toBe("ok");
    }
  });
});
