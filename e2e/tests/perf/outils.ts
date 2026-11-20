// Outils des mesures du front (lot Q6) : libellés lus dans le catalogue
// généré, comptes semés de 1 000 et 10 000 éléments (une fois par exécution),
// statistiques (médiane, p50, p95 au rang le plus proche), repères posés
// dans la page et annotations « mesure » des rapports.
//
// Propre au lot : aucun import d'un autre lot de la vague 3.

import { expect, type APIRequestContext, type Browser, type Page, type TestInfo } from "@playwright/test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { BASE_URL, E2E_DIR, statePath } from "../../fixtures/env.ts";
import { once } from "../../fixtures/lock.ts";
import { ORG_FILE } from "../../fixtures/org.ts";
import { registerInvite, testPassword } from "../../fixtures/ui.ts";

// ---------------------------------------------------------------- Libellés

type Texte = string | { one: string; other: string };
let catalogue: Record<string, Texte> | null = null;

/** Nombre à la française (espace fine insécable U+202F), comme fmtNumber de l'application. */
export const nombre = (n: number) => new Intl.NumberFormat("fr-FR").format(n);

/**
 * Texte de l'interface lu dans design/i18n/fr.gen.json : `{param}` remplacés,
 * pluriel « one » si n = 1, sinon « other » (n formaté à la française).
 */
export function libelle(cle: string, params: Record<string, string | number> = {}): string {
  catalogue ??= JSON.parse(readFileSync(resolve(E2E_DIR, "../design/i18n/fr.gen.json"), "utf8")) as Record<string, Texte>;
  const v = catalogue[cle];
  if (v === undefined) throw new Error(`Clé absente du catalogue fr.gen.json : ${cle}`);
  const n = typeof params.n === "number" ? params.n : undefined;
  const modele = typeof v === "string" ? v : n === 1 ? v.one : v.other;
  return modele.replace(/\{(\w+)\}/g, (m, k: string) => {
    if (!(k in params)) return m;
    const p = params[k];
    return typeof p === "number" ? nombre(p) : p;
  });
}

/** Comparaison insensible aux espaces (U+202F, insécables, multiples). */
export const espaces = (s: string) => s.replace(/\s+/gu, " ").trim();

/** Expression qui reconnaît un texte exact, espaces quelconques. */
export function texteExact(s: string): RegExp {
  const echappe = espaces(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/ /g, "\\s+");
  return new RegExp(`^\\s*${echappe}\\s*$`, "u");
}

// ---------------------------------------------------------------- Comptes semés

export interface ComptePerf {
  email: string;
  password: string;
  name: string;
  n: number;
}

interface FichierComptes {
  /** Empreinte de org.json : un serveur recréé invalide les comptes. */
  org: string;
  comptes: Record<string, ComptePerf>;
}

const FICHIER = "perf-comptes.json";
/** Tailles semées une fois par exécution. */
export const TAILLES = [1_000, 10_000] as const;

const empreinteOrg = () => {
  const f = statePath(ORG_FILE);
  return existsSync(f) ? createHash("sha256").update(readFileSync(f)).digest("hex") : "";
};

/** Nom de l'élément n° i (unique, avec accents, tri alphabétique = ordre de semis). */
export const nomElement = (i: number) => `Service ${String(i).padStart(5, "0")} ${["Comptabilité", "Réseau", "Messagerie", "Paie", "Dépôt"][i % 5]}`;

/**
 * Sème `n` éléments dans le coffre personnel par le VRAI client de la page
 * (vault.importItems par lots de 500, chiffrement dans le navigateur), puis
 * synchronise. Un élément sur dix porte une note, un sur vingt est une note
 * sécurisée.
 */
async function semer(page: Page, n: number) {
  await page.evaluate(async ({ n }) => {
    const V = await import("/js/vault.js");
    if (!V.state.collections.size) await V.sync();
    const perso = [...V.state.collections.values()].find((c) => c.personal);
    if (!perso) throw new Error("Coffre personnel introuvable.");
    const themes = ["Comptabilité", "Réseau", "Messagerie", "Paie", "Dépôt"];
    const alea = (len: number) => {
      const a = new Uint8Array(len);
      crypto.getRandomValues(a);
      return Array.from(a, (b) => "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_!".charAt(b % 60)).join("");
    };
    const liste = [];
    for (let i = 0; i < n; i++) {
      const num = String(i).padStart(5, "0");
      const kind = i % 20 === 19 ? "note" : "login";
      const d = V.emptyItem(kind);
      d.name = `Service ${num} ${themes[i % 5]}`;
      if (kind === "login") {
        d.username = `utilisateur.${num}@exemple.fr`;
        d.password = alea(20);
        d.urls = [`https://service-${num}.exemple.fr/connexion`];
      }
      d.tags = [themes[i % 5].toLowerCase()];
      if (i % 10 === 0 || kind === "note") d.notes = `Consigne d'accès n° ${num} : ${alea(180)}`;
      liste.push(d);
    }
    await V.importItems(perso.id, liste);
    await V.sync();
    const vivants = [...V.state.items.values()].filter((it) => !it.deleted_at).length;
    if (vivants !== n) throw new Error(`Semis incomplet : ${vivants} éléments au lieu de ${n}.`);
  }, { n });
}

/**
 * Comptes de 1 000 et 10 000 éléments, créés UNE fois par exécution
 * (e2e/.state/<cle>/perf-comptes.json, verrou `once`) : invitation par
 * l'administrateur, inscription par l'interface (KDF par défaut = paramètres
 * réels), semis par le client.
 */
export async function comptesPerf(apiAs: (role: "admin") => Promise<APIRequestContext>, browser: Browser): Promise<Record<string, ComptePerf>> {
  const fichier = statePath(FICHIER);
  const org = empreinteOrg();
  // Échec de semis laissé par une exécution précédente (plus ancien que org.json) : oublié.
  const echec = `${fichier}.echec`;
  const orgFichier = statePath(ORG_FILE);
  if (existsSync(echec) && existsSync(orgFichier) && statSync(echec).mtimeMs < statSync(orgFichier).mtimeMs) rmSync(echec);
  if (existsSync(fichier)) {
    try {
      if ((JSON.parse(readFileSync(fichier, "utf8")) as FichierComptes).org !== org) rmSync(fichier);
    } catch {
      rmSync(fichier, { force: true });
    }
  }
  const { value } = await once<FichierComptes>(fichier, async () => {
    const admin = await apiAs("admin");
    const comptes: Record<string, ComptePerf> = {};
    for (const [k, n] of TAILLES.entries()) {
      const email = `perf-${n}-${Date.now()}@e2e.test`;
      const res = await admin.post("/api/admin/invites", { data: { email, role: "user" } });
      if (!res.ok()) throw new Error(`Invitation de ${email} refusée : ${res.status()} ${await res.text()}`);
      const { token } = await res.json();
      const compte = { email, password: testPassword(), name: `Mesure ${nombre(n)} éléments`, n };
      // Adresse propre au semis (plage 10.249.x.x, hors de celles des tests et de l'amorçage).
      const ctx = await browser.newContext({ baseURL: BASE_URL, locale: "fr-FR", timezoneId: "Europe/Paris", extraHTTPHeaders: { "X-Forwarded-For": `10.249.0.${k + 1}` } });
      try {
        const page = await ctx.newPage();
        // Adresse imposée par l'invitation : seuls le nom et le mot de passe sont saisis.
        await registerInvite(page, token, { name: compte.name, password: compte.password });
        await semer(page, n);
      } finally {
        await ctx.close();
      }
      comptes[String(n)] = compte;
    }
    return { org, comptes };
  }, { timeoutMs: 900_000, staleMs: 900_000 });
  return value.comptes;
}

// ---------------------------------------------------------------- Statistiques

export interface Stats {
  n: number;
  mediane: number;
  p50: number;
  p95: number;
  min: number;
  max: number;
  valeurs: number[];
}

/** Percentile au rang le plus proche (rang = ⌈p/100 × n⌉). */
export function percentile(tri: number[], p: number): number {
  if (!tri.length) return Number.NaN;
  return tri[Math.min(tri.length, Math.max(1, Math.ceil((p / 100) * tri.length))) - 1];
}

export function stats(valeurs: number[]): Stats {
  const tri = [...valeurs].sort((a, b) => a - b);
  const m = tri.length >> 1;
  const mediane = tri.length % 2 ? tri[m] : (tri[m - 1] + tri[m]) / 2;
  return { n: tri.length, mediane, p50: percentile(tri, 50), p95: percentile(tri, 95), min: tri[0], max: tri[tri.length - 1], valeurs };
}

export const ms = (v: number) => `${nombre(Math.round(v))} ms`;

/**
 * Consigne une série : annotation « mesure » du rapport, ligne « [mesure] »
 * dans la sortie (lue par le rapport du lot) et pièce jointe JSON.
 */
export async function consigner(testInfo: TestInfo, titre: string, s: Stats, extra = ""): Promise<Stats> {
  const description = `${titre} : médiane ${ms(s.mediane)}, p50 ${ms(s.p50)}, p95 ${ms(s.p95)}, max ${ms(s.max)} (n = ${s.n})${extra ? ` ; ${extra}` : ""}`;
  testInfo.annotations.push({ type: "mesure", description });
  console.log(`[mesure] ${testInfo.project.name} · ${description}`);
  await testInfo.attach(`${titre}.json`, { body: JSON.stringify(s, null, 2), contentType: "application/json" });
  return s;
}

/** Consigne un fait mesuré isolé (sans série). */
export function noter(testInfo: TestInfo, texte: string) {
  testInfo.annotations.push({ type: "mesure", description: texte });
  console.log(`[mesure] ${testInfo.project.name} · ${texte}`);
}

/**
 * Seuil indicatif : consigné avec son verdict, jamais d'échec. Les seuils
 * bloquants passent par expect() dans la spécification.
 */
export function indicatif(testInfo: TestInfo, libelleSeuil: string, valeur: number, seuil: number) {
  const ok = valeur < seuil;
  noter(testInfo, `${libelleSeuil} : ${ms(valeur)} pour < ${ms(seuil)}, ${ok ? "conforme" : "dépassé (indicatif)"}`);
  return ok;
}

// ---------------------------------------------------------------- Repères dans la page

/**
 * À appeler avant le premier chargement : relève les tâches longues
 * (PerformanceObserver « longtask », Chromium seulement) dans
 * window.__locksyTachesLongues.
 */
export async function surveillerTachesLongues(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as { __locksyTachesLongues: { debut: number; duree: number }[]; __locksyTachesLonguesOk: boolean };
    w.__locksyTachesLongues = [];
    w.__locksyTachesLonguesOk = false;
    if (typeof PerformanceObserver === "undefined" || !PerformanceObserver.supportedEntryTypes?.includes("longtask")) return;
    new PerformanceObserver((liste) => {
      for (const e of liste.getEntries()) w.__locksyTachesLongues.push({ debut: e.startTime, duree: e.duration });
    }).observe({ type: "longtask", buffered: true });
    w.__locksyTachesLonguesOk = true;
  });
}

/** Tâches longues relevées depuis `depuis` (ms de la page) ; null si le navigateur ne les expose pas. */
export async function tachesLongues(page: Page, depuis = 0): Promise<number[] | null> {
  return page.evaluate((depuis) => {
    const w = window as unknown as { __locksyTachesLongues?: { debut: number; duree: number }[]; __locksyTachesLonguesOk?: boolean };
    if (!w.__locksyTachesLonguesOk) return null;
    return (w.__locksyTachesLongues || []).filter((t) => t.debut >= depuis).map((t) => t.duree);
  }, depuis);
}

/** Libellés utilisés par les mesures (catalogue généré, annexe C). */
export const LIB = {
  email: () => libelle("auth.field.email"),
  connexion: () => libelle("auth.action.login"),
  motDePasse: () => libelle("common.glossary.master_password"),
  deverrouiller: () => libelle("auth.action.unlock"),
  verrouiller: () => libelle("common.action.lock"),
  liste: () => libelle("vault.list.label"),
  compte: (n: number) => libelle("vault.list.count", { n }),
  navigation: () => libelle("shell.nav.label"),
  recherche: () => libelle("shell.search.label"),
  resultats: () => libelle("shell.search.results"),
  bilan: () => libelle("shell.nav.health"),
  tout: () => libelle("shell.nav.all"),
};

/**
 * Connexion avec les repères de performance (/?perf=1 : vault.js pose
 * locksy:sync:start, sync:fetched et sync:decrypted), jusqu'au compteur
 * « <n> éléments » de la liste.
 */
export async function connexionPerf(page: Page, compte: ComptePerf) {
  await page.goto("/?perf=1#/connexion");
  await page.getByLabel(LIB.email(), { exact: true }).fill(compte.email);
  await page.getByLabel(LIB.motDePasse(), { exact: true }).fill(compte.password);
  await page.getByRole("button", { name: LIB.connexion(), exact: true }).click();
  await expect(page.getByText(texteExact(LIB.compte(compte.n)))).toBeVisible({ timeout: 180_000 });
  await expect(page.getByRole("list", { name: LIB.liste(), exact: true })).toBeVisible();
}

/**
 * Arme, dans la page, la mesure « du prochain clic à la première image où
 * la condition est vraie » (vérifiée à chaque image par requestAnimationFrame).
 * Condition « coffre » : la liste « Éléments » a au moins une ligne et le
 * compteur affiche `compte`. Condition « titre » : un h1 vaut `titre`
 * (détecté par MutationObserver, puis image suivante).
 */
export async function armer(page: Page, cond: { coffre?: { liste: string; compte: string }; titre?: string }) {
  await page.evaluate((cond) => {
    const norm = (s: string | null | undefined) => (s || "").replace(/\s+/gu, " ").trim();
    const w = window as unknown as { __locksyMesure?: Promise<{ clic: number; dom: number; image: number }> };
    let clic = -1;
    document.addEventListener("click", () => { if (clic < 0) clic = performance.now(); }, { capture: true, once: true });
    const vrai = () => {
      if (cond.titre !== undefined) return [...document.querySelectorAll("h1")].some((h) => norm(h.textContent) === cond.titre);
      const c = cond.coffre!;
      const liste = [...document.querySelectorAll("ul[aria-label]")].find((u) => u.getAttribute("aria-label") === c.liste);
      if (!liste || !liste.querySelector("li:not([data-spacer])")) return false;
      const compte = norm(c.compte);
      return [...document.querySelectorAll("p")].some((p) => norm(p.textContent) === compte);
    };
    w.__locksyMesure = new Promise((ok, ko) => {
      const limite = setTimeout(() => ko(new Error("Condition de fin jamais atteinte en 120 s.")), 120_000);
      const fin = (dom: number) => requestAnimationFrame(() => {
        clearTimeout(limite);
        ok({ clic, dom, image: performance.now() });
      });
      if (cond.titre !== undefined) {
        const obs = new MutationObserver(() => {
          if (clic >= 0 && vrai()) {
            obs.disconnect();
            fin(performance.now());
          }
        });
        obs.observe(document.body, { subtree: true, childList: true, characterData: true });
      } else {
        const image = () => {
          if (clic >= 0 && vrai()) fin(performance.now());
          else requestAnimationFrame(image);
        };
        requestAnimationFrame(image);
      }
    });
  }, { coffre: cond.coffre, titre: cond.titre === undefined ? undefined : cond.titre.replace(/\s+/gu, " ").trim() });
}

/** Résultat de la mesure armée : instants (ms de la page) du clic, du DOM prêt et de l'image suivante. */
export async function resultat(page: Page): Promise<{ clic: number; dom: number; image: number }> {
  return page.evaluate(() => (window as unknown as { __locksyMesure: Promise<{ clic: number; dom: number; image: number }> }).__locksyMesure);
}

/** Repères locksy:* de vault.js (startTime du dernier de chaque nom), puis effacement. */
export async function reperes(page: Page): Promise<Record<string, number>> {
  return page.evaluate(() => {
    const out: Record<string, number> = {};
    for (const e of performance.getEntriesByType("mark")) if (e.name.startsWith("locksy:")) out[e.name.slice(7)] = e.startTime;
    performance.clearMarks();
    performance.clearMeasures();
    return out;
  });
}

/**
 * Intervalles entre images (requestAnimationFrame) pendant `action`. Renvoie
 * aussi la période au repos, mesurée juste avant sur 40 images.
 */
export async function imagesPendant(page: Page, action: () => Promise<void>): Promise<{ periode: number; intervalles: number[]; debut: number }> {
  // Chaque enregistrement a son numéro : la boucle d'un enregistrement arrêté
  // s'éteint d'elle-même et n'écrit jamais dans le suivant.
  const enregistrer = () => page.evaluate(() => {
    const w = window as unknown as { __locksyImages: number[]; __locksyImagesTour: number };
    const tour = (w.__locksyImagesTour || 0) + 1;
    const images: number[] = [];
    w.__locksyImagesTour = tour;
    w.__locksyImages = images;
    const boucle = (t: number) => {
      if (w.__locksyImagesTour !== tour) return;
      images.push(t);
      requestAnimationFrame(boucle);
    };
    requestAnimationFrame(boucle);
    return performance.now();
  });
  const arreter = () => page.evaluate(() => {
    const w = window as unknown as { __locksyImages: number[]; __locksyImagesTour: number };
    w.__locksyImagesTour++;
    const t = w.__locksyImages;
    return t.slice(1).map((v, i) => v - t[i]);
  });
  await enregistrer();
  await page.waitForTimeout(700);
  const repos = await arreter();
  const periode = stats(repos.slice(-40)).mediane;
  const debut = await enregistrer();
  await action();
  const intervalles = await arreter();
  return { periode, intervalles, debut };
}
