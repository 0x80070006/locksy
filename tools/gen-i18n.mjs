#!/usr/bin/env node
// Génère le catalogue des textes de l'interface à partir des sources
// design/i18n/fr/*.json (une source par domaine, chacune propriété d'un lot).
//
//   node tools/gen-i18n.mjs            écrit web/js/i18n/fr.js et design/i18n/fr.gen.json
//   node tools/gen-i18n.mjs --check    sort en 1 si ces fichiers ne sont pas à jour
//   options : --src <dossier> --out-js <fichier> --out-json <fichier>
//
// Format d'une source : un objet JSON PLAT « clé complète -> valeur ».
//   - valeur : une chaîne, un objet de pluriel { one, other[, many] } ou, pour
//     les seules clés finissant par « .synonyms », un tableau de chaînes ;
//   - paramètres sous la forme {nom} ; aucune balise HTML ;
//   - préfixe obligatoire : nom du fichier sans « .json », « - » remplacé par
//     « _ » (settings-user.json -> settings_user.) ; les fichiers errors.*.json
//     utilisent tous le préfixe « errors. ».
// Toute erreur (préfixe, clé en double, valeur mal formée) fait sortir en 1.
// Sans dépendance : Node 20 ou plus.

import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULT_SRC = join(ROOT, "design", "i18n", "fr");
export const DEFAULT_OUT_JS = join(ROOT, "web", "js", "i18n", "fr.js");
export const DEFAULT_OUT_JSON = join(ROOT, "design", "i18n", "fr.gen.json");

export const KEY_RE = /^[a-z0-9_]+(\.[a-z0-9_-]+)+$/;
const FILE_RE = /^[a-z0-9-]+\.json$/;
const ERRORS_FILE_RE = /^errors(\.[a-z0-9-]+)?\.json$/;
const PLURAL_FORMS = new Set(["one", "other", "many"]);
const HTML_RE = /<\/?[a-zA-Z!][^>]*>|&[a-zA-Z]+;|&#\d+;/;
const PARAM_RE = /\{([a-z0-9_]+)\}/g;

/** Préfixe imposé aux clés d'un fichier source, ou null si le nom est invalide. */
export function prefixFor(fileName) {
  if (ERRORS_FILE_RE.test(fileName)) return "errors";
  if (!FILE_RE.test(fileName)) return null;
  return fileName.slice(0, -".json".length).replace(/-/g, "_");
}

/**
 * Clés de premier niveau d'un texte JSON, dans l'ordre, doublons compris
 * (JSON.parse garde silencieusement la dernière occurrence).
 */
export function topLevelKeys(text) {
  const keys = [];
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "\"") {
      let j = i + 1;
      while (j < text.length && text[j] !== "\"") j += text[j] === "\\" ? 2 : 1;
      if (depth === 1 && /^\s*:/.test(text.slice(j + 1, j + 40))) {
        keys.push(JSON.parse(text.slice(i, j + 1)));
      }
      i = j;
    } else if (ch === "{" || ch === "[") {
      depth++;
    } else if (ch === "}" || ch === "]") {
      depth--;
    }
  }
  return keys;
}

/** Erreurs d'une chaîne du catalogue (vide, HTML, accolades mal formées). */
function stringProblems(s) {
  const out = [];
  if (!s.trim()) out.push("texte vide");
  if (HTML_RE.test(s)) out.push("balise ou entité HTML interdite");
  const rest = s.replace(PARAM_RE, "");
  if (/[{}]/.test(rest)) out.push("accolade hors d'un paramètre {nom} (minuscules, chiffres, « _ »)");
  return out;
}

/** Erreurs de la valeur d'une clé ; tableau vide si elle est valide. */
export function valueProblems(key, value) {
  if (key.endsWith(".synonyms")) {
    if (!Array.isArray(value)) return ["une clé « .synonyms » attend un tableau de chaînes"];
    const out = [];
    value.forEach((v, i) => {
      if (typeof v !== "string") out.push(`synonyme n° ${i + 1} : chaîne attendue`);
      else for (const p of stringProblems(v)) out.push(`synonyme n° ${i + 1} : ${p}`);
    });
    return out;
  }
  if (typeof value === "string") return stringProblems(value);
  if (Array.isArray(value)) return ["tableau réservé aux clés finissant par « .synonyms »"];
  if (value && typeof value === "object") {
    const forms = Object.keys(value);
    const out = [];
    for (const f of forms) if (!PLURAL_FORMS.has(f)) out.push(`forme de pluriel inconnue « ${f} » (one, other, many)`);
    for (const f of ["one", "other"]) if (!forms.includes(f)) out.push(`forme de pluriel « ${f} » manquante`);
    for (const f of forms) {
      if (!PLURAL_FORMS.has(f)) continue;
      if (typeof value[f] !== "string") out.push(`forme « ${f} » : chaîne attendue`);
      else for (const p of stringProblems(value[f])) out.push(`forme « ${f} » : ${p}`);
    }
    return out;
  }
  return ["valeur attendue : chaîne, pluriel { one, other } ou tableau de synonymes"];
}

/**
 * Lit et valide toutes les sources d'un dossier.
 * Renvoie { catalog, errors, files } : catalog est un objet aux clés triées,
 * errors une liste de messages « fichier : problème » (vide si tout va bien).
 */
export function buildCatalog(srcDir = DEFAULT_SRC) {
  const errors = [];
  const origin = new Map(); // clé -> fichier qui la définit
  const entries = new Map();
  if (!existsSync(srcDir)) {
    return { catalog: {}, errors: [`dossier des sources introuvable : ${srcDir}`], files: [] };
  }
  const files = readdirSync(srcDir).filter((f) => f.endsWith(".json")).sort();
  if (!files.length) errors.push(`aucune source *.json dans ${srcDir}`);
  for (const file of files) {
    const prefix = prefixFor(file);
    if (!prefix) {
      errors.push(`${file} : nom de fichier invalide (minuscules, chiffres et « - », ou errors.<domaine>.json)`);
      continue;
    }
    const text = readFileSync(join(srcDir, file), "utf8");
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      errors.push(`${file} : JSON invalide (${e.message})`);
      continue;
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      errors.push(`${file} : un objet JSON plat « clé -> texte » est attendu`);
      continue;
    }
    const seen = new Set();
    for (const key of topLevelKeys(text)) {
      if (seen.has(key)) errors.push(`${file} : clé « ${key} » présente deux fois dans le fichier`);
      seen.add(key);
    }
    for (const [key, value] of Object.entries(data)) {
      if (!KEY_RE.test(key)) {
        errors.push(`${file} : clé « ${key} » mal formée (attendu : domaine.ecran.element, minuscules et « _ »)`);
        continue;
      }
      if (key.split(".")[0] !== prefix) {
        errors.push(`${file} : la clé « ${key} » doit commencer par « ${prefix}. »`);
        continue;
      }
      for (const p of valueProblems(key, value)) errors.push(`${file} : ${key} : ${p}`);
      if (origin.has(key)) {
        errors.push(`clé « ${key} » définie deux fois : dans ${origin.get(key)} et dans ${file}`);
        continue;
      }
      origin.set(key, file);
      entries.set(key, value);
    }
  }
  const catalog = {};
  for (const key of [...entries.keys()].sort()) catalog[key] = entries.get(key);
  return { catalog, errors, files };
}

const HEADER = [
  "// Fichier généré par tools/gen-i18n.mjs à partir de design/i18n/fr/*.json.",
  "// Ne pas le modifier à la main : changez la source puis lancez « node tools/gen-i18n.mjs ».",
];

/** Module ESM du catalogue (valeurs gelées, une clé par ligne, LF final). */
export function renderJs(catalog) {
  const lines = Object.entries(catalog).map(([key, value]) => {
    const v = typeof value === "string" ? JSON.stringify(value) : `Object.freeze(${JSON.stringify(value)})`;
    return `  ${JSON.stringify(key)}: ${v},`;
  });
  return [...HEADER, "export default Object.freeze({", ...lines, "});", ""].join("\n");
}

/** Même contenu en JSON indenté (relu par les outils et le client Windows). */
export function renderJson(catalog) {
  return `${JSON.stringify(catalog, null, 2)}\n`;
}

function parseArgs(argv) {
  const opts = { check: false, src: DEFAULT_SRC, outJs: DEFAULT_OUT_JS, outJson: DEFAULT_OUT_JSON };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`option ${a} : valeur manquante`);
      return resolve(argv[++i]);
    };
    if (a === "--check") opts.check = true;
    else if (a === "--src") opts.src = next();
    else if (a === "--out-js") opts.outJs = next();
    else if (a === "--out-json") opts.outJson = next();
    else throw new Error(`option inconnue : ${a}`);
  }
  return opts;
}

/** Chemin affiché : relatif au dépôt s'il s'y trouve, absolu sinon. */
function rel(p) {
  const r = relative(ROOT, p).replace(/\\/g, "/");
  return r && !r.startsWith("../") && !/^[a-z]:/i.test(r) ? r : p;
}

/** Point d'entrée ; renvoie le code de sortie (0 ou 1). */
export function main(argv = process.argv.slice(2), log = console) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    log.error(`gen-i18n : ${e.message}`);
    return 1;
  }
  const { catalog, errors, files } = buildCatalog(opts.src);
  if (errors.length) {
    for (const e of errors) log.error(`gen-i18n : ${e}`);
    log.error(`gen-i18n : ${errors.length} erreur(s), rien n'a été écrit.`);
    return 1;
  }
  const outputs = [[opts.outJs, renderJs(catalog)], [opts.outJson, renderJson(catalog)]];
  const count = Object.keys(catalog).length;
  if (opts.check) {
    const stale = outputs.filter(([file, text]) => !existsSync(file) || readFileSync(file, "utf8") !== text);
    for (const [file] of stale) log.error(`gen-i18n : ${rel(file)} n'est pas à jour, lancez « node tools/gen-i18n.mjs ».`);
    if (stale.length) return 1;
    log.log(`gen-i18n : catalogue à jour (${count} clés, ${files.length} sources).`);
    return 0;
  }
  for (const [file, text] of outputs) {
    mkdirSync(dirname(file), { recursive: true });
    if (!existsSync(file) || readFileSync(file, "utf8") !== text) writeFileSync(file, text);
  }
  log.log(`gen-i18n : ${count} clés (${files.length} sources) -> ${outputs.map(([f]) => rel(f)).join(", ")}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = main();
}
