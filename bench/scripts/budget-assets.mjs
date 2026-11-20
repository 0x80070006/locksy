#!/usr/bin/env node
// Budget des ressources du front (lot Q6, cahier 00 §6.5, stratégie 05 §7) :
// mesure, en octets bruts et après gzip niveau 9, le module WebAssembly, le
// JavaScript (total et premier écran) et les feuilles de style, puis les
// compare aux budgets. Node 20 ou plus, aucune dépendance.
//
// Usage :
//   node bench/scripts/budget-assets.mjs [--web <dossier>] [--wasm <fichier> | --image <étiquette>]
//                                        [--json <fichier>] [--strict] [--self-test]
//
// Mesures (1 Ko = 1 024 o ; « gzip » = somme des fichiers compressés un à un,
// comme un serveur qui compresse chaque réponse) :
//   locksy.wasm               ≤ 700 Ko bruts, ≤ 260 Ko gzip ;
//   locksy-import.wasm        pour information ;
//   JS total (web/js/**/*.js) ≤ 240 Ko bruts, ≤ 70 Ko gzip ; web/vendor à part ;
//   JS du premier écran       ≤ 120 Ko bruts : fermeture des imports STATIQUES
//                             (import … from, export … from, import "…") depuis
//                             les <script type="module"> de index.html ; les
//                             import() dynamiques en sont exclus ;
//   CSS du premier écran      ≤ 40 Ko bruts : app.css et ses @import ; total de
//                             web/css/*.css et admin.css (chargée à la demande)
//                             pour information.
//
// Verdicts : « conforme », « dépassé (souhaitable) » (budget « S » du cahier :
// un dépassement est rapporté avec son levier, sans échec sauf --strict),
// « information », « non mesuré ».
//
// Codes de sortie : 0 ; 1 avec --strict si un budget est dépassé (ou si
// --self-test échoue) ; 2 usage invalide (option inconnue, dossier ou fichier
// introuvable, image illisible).

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const KO = 1024;

const USAGE = `Budget des ressources du front de Locksy (wasm, JS, CSS).

Usage : node bench/scripts/budget-assets.mjs [options]

  --web <dossier>      dossier web à mesurer (défaut : web/)
  --wasm <fichier>     module locksy.wasm à mesurer (locksy-import.wasm est
                       cherché à côté)
  --image <étiquette>  extrait /app/web/locksy.wasm et locksy-import.wasm de
                       l'image Docker (docker create, docker cp, docker rm)
                       Défaut sans --wasm ni --image : le plus récent des
                       e2e/.state/*/locksy.wasm, s'il existe.
  --json <fichier>     écrit aussi le résultat en JSON
  --strict             sort en 1 si un budget est dépassé
  --self-test          vérifie l'outil sur un mini-dossier temporaire
  -h, --help           affiche cette aide

Codes de sortie : 0 ; 1 budget dépassé avec --strict (ou auto-test en échec) ;
2 usage invalide.`;

// ---------------------------------------------------------------- Budgets et leviers

const BUDGETS = {
  wasm: { brut: 700 * KO, gzip: 260 * KO },
  js: { brut: 240 * KO, gzip: 70 * KO },
  jsFirst: { brut: 120 * KO },
  css: { brut: 40 * KO },
};

const LEVIERS = {
  wasm: "wasm-opt -Oz (binaryen) après la compilation ; zstd côté serveur en plus du gzip.",
  js: "catalogue i18n découpé par domaine et chargé à la demande.",
  jsFirst: "catalogue i18n découpé par domaine (seul le domaine de l'accès au premier écran) ; vues chargées à la demande ; modulepreload des modules restants.",
  css: "feuilles propres à un écran chargées à la demande (comme admin.css).",
};

class UsageError extends Error {}

// ---------------------------------------------------------------- Mesures élémentaires

/** Taille brute et gzip -9 d'un fichier. */
function sizes(file) {
  const buf = readFileSync(file);
  return { brut: buf.length, gzip: gzipSync(buf, { level: 9 }).length };
}

/** Somme des tailles d'une liste de fichiers. */
function total(files) {
  return files.reduce((acc, f) => {
    const s = sizes(f);
    return { brut: acc.brut + s.brut, gzip: acc.gzip + s.gzip };
  }, { brut: 0, gzip: 0 });
}

/** Fichiers d'un dossier (récursif) dont le nom vérifie `re`, triés. */
function walk(dir, re) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p, re));
    else if (re.test(entry.name)) out.push(p);
  }
  return out.sort();
}

// ---------------------------------------------------------------- Fermeture des imports

// Déclarations en début de ligne seulement : un import en commentaire « // »
// ou dans une chaîne n'est pas pris. Les import() dynamiques sont exclus.
const STATIC_FROM = /^[ \t]*(?:import|export)\s+(?:[\w$]+\s*,?\s*)?(?:\{[^}]*\}|\*(?:\s+as\s+[\w$]+)?)?\s*from\s*(["'])([^"'\n]+)\1/gm;
const BARE_IMPORT = /^[ \t]*import\s*(["'])([^"'\n]+)\1/gm;

/** Spécificateurs des imports statiques d'un module. */
export function staticImports(source) {
  const out = [];
  for (const re of [STATIC_FROM, BARE_IMPORT]) {
    re.lastIndex = 0;
    for (let m = re.exec(source); m; m = re.exec(source)) out.push(m[2]);
  }
  return out;
}

/** Fichier local visé par une adresse (absolue « /js/… » ou relative), ou null. */
function localTarget(webDir, fromFile, spec) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(spec) || spec.startsWith("//")) return null; // autre origine
  const clean = spec.split(/[?#]/)[0];
  if (clean.startsWith("/")) return join(webDir, clean);
  if (clean.startsWith("./") || clean.startsWith("../")) return resolve(dirname(fromFile), clean);
  return null; // spécificateur nu : aucune carte d'imports dans Locksy
}

/** Points d'entrée <script type="module" src="…"> d'une page HTML. */
export function moduleEntries(webDir, htmlFile) {
  const html = readFileSync(htmlFile, "utf8");
  const out = [];
  for (const m of html.matchAll(/<script\b[^>]*>/gi)) {
    const tag = m[0];
    if (!/\btype\s*=\s*["']?module\b/i.test(tag)) continue;
    const src = /\bsrc\s*=\s*(["'])([^"']+)\1/i.exec(tag);
    if (!src) continue;
    const file = localTarget(webDir, htmlFile, src[2]);
    if (file) out.push(file);
  }
  return out;
}

/** Fermeture des imports statiques depuis `entries` ; `missing` liste les cibles absentes. */
export function importClosure(webDir, entries) {
  const seen = new Set();
  const missing = [];
  const stack = [...entries];
  while (stack.length) {
    const file = stack.pop();
    if (seen.has(file)) continue;
    if (!existsSync(file)) {
      missing.push(file);
      continue;
    }
    seen.add(file);
    for (const spec of staticImports(readFileSync(file, "utf8"))) {
      const target = localTarget(webDir, file, spec);
      if (target && !seen.has(target)) stack.push(target);
    }
  }
  return { files: [...seen].sort(), missing };
}

/** Feuille CSS et ses @import (récursif, même dossier ou relatif). */
export function cssClosure(file) {
  const seen = new Set();
  const visit = (f) => {
    if (seen.has(f) || !existsSync(f)) return;
    seen.add(f);
    const css = readFileSync(f, "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
    for (const m of css.matchAll(/@import\s+(?:url\(\s*)?(["']?)([^"')\s;]+)\1\s*\)?/g)) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(m[2])) continue;
      visit(resolve(dirname(f), m[2]));
    }
  };
  visit(file);
  return [...seen].sort();
}

// ---------------------------------------------------------------- Module WebAssembly

/** Plus récent des e2e/.state/*\/locksy.wasm, ou null. */
function defaultWasm() {
  const state = join(REPO, "e2e", ".state");
  if (!existsSync(state)) return null;
  let best = null;
  for (const d of readdirSync(state, { withFileTypes: true })) {
    if (!d.isDirectory()) continue;
    const f = join(state, d.name, "locksy.wasm");
    if (!existsSync(f)) continue;
    const t = statSync(f).mtimeMs;
    if (!best || t > best.t) best = { f, t };
  }
  return best?.f ?? null;
}

/** Extrait les modules de l'image dans un dossier temporaire (comme e2e/tools/run.sh). */
function wasmFromImage(image) {
  const dir = mkdtempSync(join(tmpdir(), "locksy-budget-"));
  const name = `locksy-budget-${process.pid}-${Date.now()}`;
  const docker = (...args) => execFileSync("docker", args, { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, MSYS_NO_PATHCONV: "1" } });
  try {
    docker("create", "--name", name, image);
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw new UsageError(`image « ${image} » illisible : ${String(e.stderr || e.message).trim()}`);
  }
  try {
    for (const f of ["locksy.wasm", "locksy-import.wasm"]) {
      try {
        docker("cp", `${name}:/app/web/${f}`, join(dir, f));
      } catch {
        // locksy-import.wasm est facultatif ; locksy.wasm absent est signalé plus bas.
      }
    }
  } finally {
    try { docker("rm", name); } catch { /* conteneur jamais démarré : rien à retenir */ }
  }
  return { dir, wasm: join(dir, "locksy.wasm") };
}

// ---------------------------------------------------------------- Évaluation

const ko = (n) => `${(n / KO).toLocaleString("fr-FR", { maximumFractionDigits: 1, minimumFractionDigits: 1 })} Ko`;

/** Ligne de mesure : verdict selon les budgets fournis (brut et/ou gzip). */
function ligne(id, libelle, mesure, budget, levier, note) {
  if (!mesure) return { id, libelle, brut: null, gzip: null, budget: budget || null, verdict: "non mesuré", levier: null, note: note || null };
  if (!budget) return { id, libelle, ...mesure, budget: null, verdict: "information", levier: null, note: note || null };
  const over = (budget.brut !== undefined && mesure.brut > budget.brut) || (budget.gzip !== undefined && mesure.gzip > budget.gzip);
  return { id, libelle, ...mesure, budget, verdict: over ? "dépassé (souhaitable)" : "conforme", levier: over ? levier : null, note: note || null };
}

/** Mesure complète d'un dossier web et d'un module wasm (chemins absolus). */
export function measure({ webDir, wasm, importWasm }) {
  const jsDir = join(webDir, "js");
  const jsFiles = walk(jsDir, /\.js$/);
  const vendorFiles = walk(join(webDir, "vendor"), /\.m?js$/);
  const catalog = jsFiles.filter((f) => f.split(sep).join("/").includes("/i18n/"));
  const index = join(webDir, "index.html");
  const first = existsSync(index) ? importClosure(webDir, moduleEntries(webDir, index)) : { files: [], missing: [] };
  const appCss = join(webDir, "css", "app.css");
  const cssFirst = existsSync(appCss) ? cssClosure(appCss) : [];
  const cssAll = walk(join(webDir, "css"), /\.css$/).filter((f) => dirname(f) === join(webDir, "css"));
  const adminCss = join(webDir, "css", "admin.css");

  const rel = (f) => relative(webDir, f).split(sep).join("/");
  const lignes = [
    ligne("wasm", "locksy.wasm", wasm && existsSync(wasm) ? sizes(wasm) : null, BUDGETS.wasm, LEVIERS.wasm,
      wasm && existsSync(wasm) ? null : "module introuvable : --wasm <fichier> ou --image <étiquette>"),
    ligne("wasm_import", "locksy-import.wasm (lecteurs d'import, à la demande)", importWasm && existsSync(importWasm) ? sizes(importWasm) : null, null, null,
      importWasm && existsSync(importWasm) ? null : "absent à côté de locksy.wasm"),
    ligne("js_total", `JS total (js/**/*.js, ${jsFiles.length} fichiers)`, jsFiles.length ? total(jsFiles) : null, BUDGETS.js, LEVIERS.js),
    ligne("js_i18n", "  dont catalogue i18n", catalog.length ? total(catalog) : null, null, null),
    ligne("js_vendor", `JS tiers (vendor/, ${vendorFiles.length} fichier(s), à la demande)`, vendorFiles.length ? total(vendorFiles) : null, null, null),
    ligne("js_first", `JS du premier écran (${first.files.length} modules)`, first.files.length ? total(first.files) : null, BUDGETS.jsFirst, LEVIERS.jsFirst,
      first.missing.length ? `imports introuvables : ${first.missing.map(rel).join(", ")}` : null),
    ligne("css_first", `CSS du premier écran (app.css et ${Math.max(0, cssFirst.length - 1)} @import)`, cssFirst.length ? total(cssFirst) : null, BUDGETS.css, LEVIERS.css),
    ligne("css_total", `CSS total (css/*.css, ${cssAll.length} fichiers)`, cssAll.length ? total(cssAll) : null, null, null),
    ligne("css_admin", "  dont admin.css (à la demande)", existsSync(adminCss) ? sizes(adminCss) : null, null, null),
  ];
  return { lignes, premierEcran: first.files.map(rel), depasse: lignes.some((l) => l.verdict.startsWith("dépassé")) };
}

// ---------------------------------------------------------------- Affichage

function table(rows) {
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => r[i].length)));
  return rows.map((r) => r.map((c, i) => c.padEnd(widths[i])).join("  ").trimEnd()).join("\n");
}

function render(result, entrees) {
  const budgetText = (b) => !b ? "—" : [b.brut !== undefined ? `${ko(b.brut)} bruts` : null, b.gzip !== undefined ? `${ko(b.gzip)} gzip` : null].filter(Boolean).join(" / ");
  const rows = [["Mesure", "Brut", "Gzip -9", "Budget", "Verdict"]];
  for (const l of result.lignes) {
    rows.push([l.libelle, l.brut === null ? "—" : ko(l.brut), l.gzip === null ? "—" : ko(l.gzip), budgetText(l.budget), l.verdict]);
  }
  const out = [
    "Budget des ressources du front de Locksy (1 Ko = 1 024 o)",
    `Dossier web : ${entrees.web}`,
    `Module wasm : ${entrees.wasm || "aucun"}`,
    "",
    table(rows),
    "",
  ];
  const leviers = result.lignes.filter((l) => l.levier);
  if (leviers.length) {
    out.push("Leviers proposés :");
    for (const l of leviers) out.push(`  - ${l.libelle.trim()} : ${l.levier}`);
    out.push("");
  }
  const notes = result.lignes.filter((l) => l.note);
  for (const l of notes) out.push(`Remarque, ${l.libelle.trim()} : ${l.note}.`);
  out.push("Le serveur compresse l'interface web en gzip (JS, CSS, wasm) : le volume transféré est celui de la colonne gzip.");
  out.push(result.depasse
    ? "Bilan : au moins un budget souhaitable est dépassé (voir les leviers)."
    : "Bilan : tous les budgets mesurés sont respectés.");
  return out.join("\n");
}

// ---------------------------------------------------------------- Auto-test

function selfTest() {
  const dir = mkdtempSync(join(tmpdir(), "locksy-budget-test-"));
  const checks = [];
  const check = (label, ok, detail = "") => checks.push({ label, ok, detail });
  const write = (p, content) => {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    writeFileSync(join(dir, p), content);
  };
  try {
    write("index.html", '<!doctype html><link rel="stylesheet" href="/css/app.css">\n<script type="module" src="/js/app.js"></script>\n<script src="/js/classique.js"></script>');
    write("js/app.js", [
      'import { a,',
      '  b } from "./a.js";',
      "import * as B from './sous/b.js';",
      'import "./effet.js";',
      'export { c } from "./c.js";',
      '// import x from "./commentaire.js";',
      'const v = () => import("./dynamique.js");',
      'const s = "import y from \'./chaine.js\'";',
      "",
    ].join("\n"));
    write("js/a.js", 'export const a = 1, b = 2;\nimport def, { z } from "/js/sous/b.js";\n');
    write("js/sous/b.js", 'export * from "../c.js";\n');
    write("js/c.js", "export const c = 3;\n");
    write("js/effet.js", "globalThis.x = 1;\n");
    write("js/dynamique.js", "export default 1;\n");
    write("js/commentaire.js", "x\n");
    write("js/chaine.js", "x\n");
    write("js/classique.js", "x\n");
    write("js/i18n/fr.js", `export default ${JSON.stringify({ texte: "é".repeat(500) })};\n`);
    write("css/app.css", '/* @import url("oublie.css"); */\n@import url("a.css");\n@import "b.css";\n');
    write("css/a.css", "a{color:red}\n");
    write("css/b.css", "b{color:blue}\n");
    write("css/admin.css", "c{color:green}\n");
    write("locksy.wasm", Buffer.alloc(4096, 7));

    const webDir = dir;
    const entries = moduleEntries(webDir, join(dir, "index.html"));
    check("un seul point d'entrée module (le script classique est ignoré)", entries.length === 1 && entries[0] === join(dir, "js", "app.js"), entries.join(", "));
    const { files, missing } = importClosure(webDir, entries);
    const names = files.map((f) => relative(dir, f).split(sep).join("/")).sort();
    const expected = ["js/a.js", "js/app.js", "js/c.js", "js/effet.js", "js/sous/b.js"];
    check("fermeture des imports statiques (multiligne, absolu, export from, import nu)", JSON.stringify(names) === JSON.stringify(expected), names.join(", "));
    check("aucun import introuvable", missing.length === 0, missing.join(", "));
    const css = cssClosure(join(dir, "css", "app.css")).map((f) => relative(dir, f).split(sep).join("/")).sort();
    check("CSS : app.css et ses @import, commentaires ignorés", JSON.stringify(css) === JSON.stringify(["css/a.css", "css/app.css", "css/b.css"]), css.join(", "));

    const r = measure({ webDir, wasm: join(dir, "locksy.wasm"), importWasm: join(dir, "absent.wasm") });
    const by = Object.fromEntries(r.lignes.map((l) => [l.id, l]));
    const sum = (ps) => ps.reduce((n, p) => n + readFileSync(join(dir, p)).length, 0);
    check("taille brute du premier écran = somme des modules", by.js_first.brut === sum(expected), `${by.js_first.brut} o`);
    check("JS total = tous les js/**/*.js", by.js_total.brut === sum(["js/a.js", "js/app.js", "js/c.js", "js/effet.js", "js/sous/b.js", "js/dynamique.js", "js/commentaire.js", "js/chaine.js", "js/classique.js", "js/i18n/fr.js"]), `${by.js_total.brut} o`);
    check("gzip -9 calculé fichier par fichier", by.wasm.gzip === gzipSync(Buffer.alloc(4096, 7), { level: 9 }).length && by.wasm.gzip < by.wasm.brut, `${by.wasm.gzip} o`);
    check("catalogue i18n compté à part", by.js_i18n.brut === sum(["js/i18n/fr.js"]), `${by.js_i18n.brut} o`);
    check("mini-dossier sous les budgets : conforme", by.js_first.verdict === "conforme" && by.wasm.verdict === "conforme" && !r.depasse);
    check("module absent : non mesuré", by.wasm_import.verdict === "non mesuré");

    write("js/gros.js", "x".repeat(250 * KO));
    const r2 = measure({ webDir, wasm: join(dir, "locksy.wasm") });
    const total2 = r2.lignes.find((l) => l.id === "js_total");
    check("dépassement du JS total : verdict « dépassé (souhaitable) » et levier", total2.verdict === "dépassé (souhaitable)" && /i18n/.test(total2.levier || "") && r2.depasse);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  for (const c of checks) console.log(`${c.ok ? "ok    " : "ÉCHEC "} ${c.label}${c.ok || !c.detail ? "" : ` (${c.detail})`}`);
  const failed = checks.filter((c) => !c.ok).length;
  console.log(failed ? `Auto-test : ${failed} vérification(s) en échec sur ${checks.length}.` : `Auto-test : ${checks.length} vérifications réussies.`);
  return failed ? 1 : 0;
}

// ---------------------------------------------------------------- Point d'entrée

function parseArgs(argv) {
  const opts = { web: join(REPO, "web"), wasm: null, image: null, json: null, strict: false, selfTest: false, help: false };
  const value = (i, name) => {
    if (i + 1 >= argv.length || argv[i + 1].startsWith("--")) throw new UsageError(`valeur manquante après ${name}`);
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--web": opts.web = resolve(value(i, a)); i++; break;
      case "--wasm": opts.wasm = resolve(value(i, a)); i++; break;
      case "--image": opts.image = value(i, a); i++; break;
      case "--json": opts.json = resolve(value(i, a)); i++; break;
      case "--strict": opts.strict = true; break;
      case "--self-test": opts.selfTest = true; break;
      case "-h": case "--help": opts.help = true; break;
      default: throw new UsageError(`option inconnue : ${a}`);
    }
  }
  if (opts.wasm && opts.image) throw new UsageError("--wasm et --image s'excluent");
  return opts;
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    console.error(`budget-assets : ${e.message}\n\n${USAGE}`);
    return 2;
  }
  if (opts.help) {
    console.log(USAGE);
    return 0;
  }
  if (opts.selfTest) return selfTest();

  let tmp = null;
  try {
    if (!existsSync(join(opts.web, "js"))) throw new UsageError(`dossier web introuvable ou sans js/ : ${opts.web}`);
    let wasm = opts.wasm;
    if (wasm && !existsSync(wasm)) throw new UsageError(`module introuvable : ${wasm}`);
    if (opts.image) {
      const x = wasmFromImage(opts.image);
      tmp = x.dir;
      wasm = x.wasm;
      if (!existsSync(wasm)) throw new UsageError(`/app/web/locksy.wasm absent de l'image « ${opts.image} »`);
    }
    wasm ||= defaultWasm();
    const importWasm = wasm ? join(dirname(wasm), "locksy-import.wasm") : null;
    const entrees = {
      web: relative(REPO, opts.web) || ".",
      wasm: opts.image ? `image ${opts.image}` : wasm ? relative(REPO, wasm).split(sep).join("/") : null,
    };
    const result = measure({ webDir: opts.web, wasm, importWasm });
    console.log(render(result, entrees));
    if (opts.json) {
      mkdirSync(dirname(opts.json), { recursive: true });
      writeFileSync(opts.json, `${JSON.stringify({ date: new Date().toISOString(), entrees, unite: "octets (1 Ko = 1 024 o)", compression_serveur: "gzip", ...result }, null, 2)}\n`);
      console.log(`Résultat JSON : ${relative(process.cwd(), opts.json) || opts.json}`);
    }
    return opts.strict && result.depasse ? 1 : 0;
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    console.error(`budget-assets : ${e.message}`);
    return 2;
  } finally {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
