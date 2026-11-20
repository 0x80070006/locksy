// Gardes automatiques de chaque test navigateur :
// - cspGuard     : aucune violation de la CSP (événement securitypolicyviolation
//                  et messages « Refused to » / « Content-Security-Policy »),
//                  hors code injecté par l'outillage de test (voir plus bas) ;
// - consoleGuard : aucune console.error ni exception non rattrapée, sauf
//                  motifs autorisés par consoleGuard.allow(regex) ;
// - textGuard    : aucun texte technique ni anglais à l'écran, hors volet
//                  « Détails techniques » ([data-technical]).
// Chaque contexte (page par défaut, pages de loggedIn) est surveillé par
// `watch` et relevé une dernière fois par `flush` avant sa fermeture.

import type { BrowserContext, ConsoleMessage, Page, TestInfo } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { BASE_URL, FRESH_URL } from "./env.ts";

/** Origines de Locksy : les pages tierces (Dex, mailpit) ne sont pas jugées sur leurs textes ni leur CSP. */
const LOCKSY_ORIGINS = new Set([BASE_URL, FRESH_URL, "http://127.0.0.1:4173"].map((u) => new URL(u).origin));
const ours = (url: string) => {
  try {
    return LOCKSY_ORIGINS.has(new URL(url).origin);
  } catch {
    return false;
  }
};

export type TextGuardMode = "report" | "strict" | "off";

export interface TextFinding {
  rule: string;
  text: string;
  url: string;
}

interface Rule {
  name: string;
  re: RegExp;
}

const here = (f: string) => fileURLToPath(new URL(f, import.meta.url));
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function loadRules(): Rule[] {
  const lines = (file: string) =>
    readFileSync(here(file), "utf8").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  const technical = lines("termes-interdits.txt").map((l) => {
    const [name, source] = l.split("\t");
    if (!source) throw new Error(`termes-interdits.txt : ligne sans tabulation : ${l}`);
    return { name, re: new RegExp(source, "iu") };
  });
  const english = lines("anglicismes.txt").map((w) => ({
    name: `anglais « ${w} »`,
    re: new RegExp(`(?<![\\p{L}\\p{N}_@.-])${escape(w).replace(/ /g, "\\s+")}(?![\\p{L}\\p{N}_@-])`, "iu"),
  }));
  return [...technical, ...english];
}

let rules: Rule[] | null = null;

/** Termes interdits trouvés dans un texte affiché (adresses e-mail et URL retirées). */
export function findForbidden(text: string): string[] {
  rules ??= loadRules();
  const cleaned = text
    .replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, " ")
    .replace(/\b(?:https?|ldaps?|otpauth):\/\/\S+/gi, " ");
  return rules.filter((r) => r.re.test(cleaned)).map((r) => r.name);
}

/**
 * Script injecté dans chaque page : relève les violations CSP et, à chaque
 * changement du DOM (regroupé), les textes visibles et les attributs lus par
 * les lecteurs d'écran, hors [data-technical]. Il n'utilise ni eval ni style
 * en ligne : il fonctionne sous la CSP de Locksy.
 */
function pageProbe() {
  const w = window as unknown as Record<string, unknown>;
  if (w.__locksyProbe) return;
  w.__locksyProbe = true;
  const send = (kind: string, data: unknown) => {
    const fn = w.__locksyGuard as ((k: string, d: unknown) => void) | undefined;
    try {
      fn?.(kind, data);
    } catch {
      /* page en cours de fermeture */
    }
  };
  document.addEventListener(
    "securitypolicyviolation",
    // Sans fichier source (Chromium) ou avec la source « debugger eval code »
    // (Firefox), la violation vient d'un code évalué par l'outillage
    // (page.evaluate, axe-core) : la CSP de Locksy interdit tout script en ligne
    // et eval, donc le produit a toujours un fichier ou une page pour source.
    (e) => e.sourceFile && !/debugger eval code/.test(e.sourceFile) && send("csp", { url: location.href, text: `${e.violatedDirective} : ${e.blockedURI || "en ligne"} (${e.sourceFile || location.href}:${e.lineNumber || 0})` }),
    true,
  );
  const seen = new Set<string>();
  const visible = (el: Element) =>
    !el.closest("[data-technical], script, style, noscript, template") &&
    (typeof (el as HTMLElement).checkVisibility === "function"
      ? (el as HTMLElement).checkVisibility({ visibilityProperty: true } as CheckVisibilityOptions)
      : (el as HTMLElement).offsetParent !== null);
  const collect = () => {
    if (!document.body) return;
    const fresh: string[] = [];
    const add = (s: string | null) => {
      const t = (s || "").replace(/\s+/g, " ").trim();
      if (t && !seen.has(t)) {
        seen.add(t);
        fresh.push(t);
      }
    };
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const parent = n.parentElement;
      if (parent && n.nodeValue?.trim() && visible(parent)) add(n.nodeValue);
    }
    for (const el of document.body.querySelectorAll("[aria-label], [title], [placeholder], [alt]")) {
      if (!visible(el)) continue;
      for (const a of ["aria-label", "title", "placeholder", "alt"]) add(el.getAttribute(a));
    }
    add(document.title);
    if (fresh.length) send("text", { url: location.href, lines: fresh });
  };
  let timer: ReturnType<typeof setTimeout> | 0 = 0;
  const schedule = () => {
    if (!timer) timer = setTimeout(() => { timer = 0; collect(); }, 120);
  };
  w.__locksyFlush = () => {
    if (timer) clearTimeout(timer);
    timer = 0;
    collect();
  };
  const start = () => {
    new MutationObserver(schedule).observe(document.documentElement, {
      subtree: true, childList: true, characterData: true, attributes: true,
      attributeFilter: ["aria-label", "title", "placeholder", "alt", "hidden", "class", "open"],
    });
    schedule();
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
}

/** Message émis par du code évalué par Playwright ou axe (voir pageProbe). */
function fromTooling(msg: ConsoleMessage): boolean {
  const url = msg.location().url;
  return !url || /debugger eval code/.test(url) || /file: "debugger eval code/.test(msg.text());
}

export class Guards {
  readonly csp: string[] = [];
  readonly console: string[] = [];
  readonly text: TextFinding[] = [];
  // Seul message toléré d'office : Chromium signale que l'en-tête COOP est
  // ignoré parce que le banc parle HTTP à « locksy:8743 » (origine non sûre).
  // C'est un artefact du réseau de test ; en production, Locksy est en HTTPS.
  private readonly allowed: RegExp[] = [/^The Cross-Origin-Opener-Policy header has been ignored, because the URL's origin was untrustworthy/];
  private readonly watched = new WeakSet<BrowserContext>();

  /** Autorise des erreurs de console attendues (réseau coupé, 4xx volontaire…). */
  allow(re: RegExp) {
    this.allowed.push(re);
  }

  async watch(context: BrowserContext) {
    if (this.watched.has(context)) return;
    this.watched.add(context);
    await context.exposeBinding("__locksyGuard", (_source, kind: string, data: unknown) => {
      if (kind === "csp") {
        const { url, text } = data as { url: string; text: string };
        if (ours(url)) this.csp.push(text);
      }
      if (kind === "text") {
        const { url, lines } = data as { url: string; lines: string[] };
        if (!ours(url)) return;
        for (const line of lines) for (const rule of findForbidden(line)) this.text.push({ rule, text: line, url });
      }
    });
    await context.addInitScript(pageProbe);
    for (const page of context.pages()) this.attach(page);
    context.on("page", (page) => this.attach(page));
  }

  private attach(page: Page) {
    page.on("console", (msg: ConsoleMessage) => {
      const text = msg.text();
      // Chromium : « Refused to … because it violates the following Content Security Policy » ;
      // Firefox : « Content-Security-Policy: … ».
      if (/Refused to |Content[- ]Security[- ]Policy/i.test(text)) {
        if (ours(page.url()) && !fromTooling(msg)) this.csp.push(text);
      }
      else if (msg.type() === "error" && !this.allowed.some((re) => re.test(text))) {
        const loc = msg.location();
        this.console.push(`${text}${loc.url ? ` (${loc.url}:${loc.lineNumber})` : ""}`);
      }
    });
    page.on("pageerror", (err) => {
      const text = `${err.name}: ${err.message}`;
      if (!this.allowed.some((re) => re.test(text))) this.console.push(`Exception non rattrapée : ${text}`);
    });
  }

  /** Dernier relevé des textes de toutes les pages du contexte (avant fermeture). */
  async flush(context: BrowserContext) {
    await Promise.all(
      context.pages().map((p) =>
        p.evaluate(() => (window as unknown as { __locksyFlush?: () => void }).__locksyFlush?.()).catch(() => undefined),
      ),
    );
  }

  /** Rapport des textes interdits, joint au test ; renvoie les constats dédupliqués. */
  async reportText(testInfo: TestInfo): Promise<TextFinding[]> {
    const unique = [...new Map(this.text.map((f) => [`${f.rule}|${f.text}`, f])).values()];
    if (unique.length) {
      await testInfo.attach("textGuard.json", { body: JSON.stringify(unique, null, 2), contentType: "application/json" });
      for (const f of unique) testInfo.annotations.push({ type: "textGuard", description: `${f.rule} : « ${f.text} »` });
    }
    return unique;
  }
}
