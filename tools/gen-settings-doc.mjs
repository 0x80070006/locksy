#!/usr/bin/env node
// Génère la documentation des réglages de l'organisation (docs/Reglages.md)
// à partir du registre unique du serveur et du catalogue des textes.
//
//   node tools/gen-settings-doc.mjs            écrit docs/Reglages.md
//   node tools/gen-settings-doc.mjs --check    sort en 1 si ce fichier n'est pas à jour
//   options : --out <fichier> --registry <settings.rs> --catalog <fr.gen.json>
//
// Sources :
//   - `pub static REGISTRY` de crates/locksy-core/src/settings.rs (bloc compris
//     entre « pub static REGISTRY » et « const ZERO_IS_UNLIMITED »), lu par un
//     petit analyseur d'expressions Rust : appels `s("clé", Sec::X, ordre, KIND,
//     DÉFAUT)` suivis de modificateurs chaînés (.owner(), .clients()…), tables
//     de valeurs proposées (DURATIONS_MIN…) et constantes (DEFAULT_ACCENT) ;
//   - design/i18n/fr.gen.json : `settings.<clé>.label` (obligatoire), `.help`,
//     `.unit`, `.value.<valeur>` et `settings.section.<id>.label`.
//
// Autocontrôle : le nombre d'entrées analysées doit égaler le nombre de
// `s("` du bloc. Clé en double, modificateur ou type inconnu, libellé absent :
// erreur, rien n'est écrit, sortie en 1. La sortie est déterministe (ordre des
// sections du registre, puis ordre d'affichage ; aucune date).
// Sans dépendance : Node 20 ou plus.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULT_REGISTRY = join(ROOT, "crates", "locksy-core", "src", "settings.rs");
export const DEFAULT_CATALOG = join(ROOT, "design", "i18n", "fr.gen.json");
export const DEFAULT_OUT = join(ROOT, "docs", "Reglages.md");

const BLOCK_START = "pub static REGISTRY";
const BLOCK_END = "const ZERO_IS_UNLIMITED";
const ENTRY_RE = /(?<![A-Za-z0-9_])s\(\s*"/g;
/** Espace fine insécable : séparateur des milliers (« 1 440 »). */
const NNBSP = " ";

// ------------------------------------------------------------------ Lecture du Rust

/**
 * Découpe un source Rust en jetons : chaînes, identifiants, nombres,
 * « :: » et ponctuation. Les commentaires sont ignorés.
 */
export function tokenize(src) {
  const out = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (/\s/.test(ch)) { i++; continue; }
    if (src.startsWith("//", i)) {
      const end = src.indexOf("\n", i);
      i = end < 0 ? src.length : end + 1;
      continue;
    }
    if (src.startsWith("/*", i)) {
      const end = src.indexOf("*/", i + 2);
      i = end < 0 ? src.length : end + 2;
      continue;
    }
    if (ch === "\"") {
      let j = i + 1;
      let value = "";
      while (j < src.length && src[j] !== "\"") {
        if (src[j] === "\\") {
          const next = src[j + 1];
          value += next === "n" ? "\n" : next === "t" ? "\t" : next;
          j += 2;
        } else {
          value += src[j++];
        }
      }
      if (j >= src.length) throw new Error("chaîne non terminée");
      out.push({ t: "str", v: value });
      i = j + 1;
      continue;
    }
    const ident = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i, i + 200));
    if (ident) {
      out.push({ t: "id", v: ident[0] });
      i += ident[0].length;
      continue;
    }
    const num = /^[0-9][0-9_]*/.exec(src.slice(i, i + 60));
    if (num) {
      out.push({ t: "num", v: Number(num[0].replace(/_/g, "")) });
      i += num[0].length;
      continue;
    }
    if (src.startsWith("::", i)) {
      out.push({ t: "p", v: "::" });
      i += 2;
      continue;
    }
    out.push({ t: "p", v: ch });
    i++;
  }
  return out;
}

/** Analyseur d'expressions sur une liste de jetons. */
class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }

  peek(offset = 0) {
    return this.tokens[this.pos + offset];
  }

  isP(v, offset = 0) {
    const tok = this.peek(offset);
    return tok?.t === "p" && tok.v === v;
  }

  expectP(v) {
    if (!this.isP(v)) throw new Error(`« ${v} » attendu, trouvé ${describe(this.peek())}`);
    this.pos++;
  }

  /** Expression : littéral, tableau, chemin, appel ou structure, suivi d'appels chaînés. */
  expr() {
    let node = this.primary();
    while (this.isP(".") && this.peek(1)?.t === "id" && this.isP("(", 2)) {
      this.pos++;
      const name = this.peek().v;
      this.pos++;
      node = { t: "method", target: node, name, args: this.args() };
    }
    return node;
  }

  primary() {
    const tok = this.peek();
    if (!tok) throw new Error("fin inattendue");
    if (this.isP("&")) {
      this.pos++;
      return this.primary();
    }
    if (this.isP("-") && this.peek(1)?.t === "num") {
      this.pos += 2;
      return { t: "num", v: -this.tokens[this.pos - 1].v };
    }
    if (this.isP("[")) {
      this.pos++;
      const items = [];
      while (!this.isP("]")) {
        items.push(this.expr());
        if (!this.isP("]")) this.expectP(",");
      }
      this.pos++;
      return { t: "array", items };
    }
    if (tok.t === "str" || tok.t === "num") {
      this.pos++;
      return tok;
    }
    if (tok.t === "id") {
      let name = tok.v;
      this.pos++;
      while (this.isP("::") && this.peek(1)?.t === "id") {
        name += `::${this.peek(1).v}`;
        this.pos += 2;
      }
      if (this.isP("(")) return { t: "call", name, args: this.args() };
      if (this.isP("{")) {
        this.pos++;
        const fields = {};
        while (!this.isP("}")) {
          const field = this.peek();
          if (field?.t !== "id") throw new Error(`champ attendu, trouvé ${describe(field)}`);
          this.pos++;
          this.expectP(":");
          fields[field.v] = this.expr();
          if (!this.isP("}")) this.expectP(",");
        }
        this.pos++;
        return { t: "struct", name, fields };
      }
      return { t: "path", v: name };
    }
    throw new Error(`expression attendue, trouvé ${describe(tok)}`);
  }

  args() {
    this.expectP("(");
    const out = [];
    while (!this.isP(")")) {
      out.push(this.expr());
      if (!this.isP(")")) this.expectP(",");
    }
    this.pos++;
    return out;
  }
}

function describe(tok) {
  if (!tok) return "la fin du texte";
  return tok.t === "str" ? `la chaîne « ${tok.v} »` : `« ${tok.v} »`;
}

/** Constantes du fichier (`const NOM: type = valeur;`), sous forme d'expressions. */
function readConstants(tokens) {
  const consts = new Map();
  for (let i = 0; i < tokens.length - 3; i++) {
    const tok = tokens[i];
    if (tok.t !== "id" || tok.v !== "const" || tokens[i + 1]?.t !== "id" || tokens[i + 2]?.v !== ":") continue;
    const name = tokens[i + 1].v;
    if (!/^[A-Z][A-Z0-9_]*$/.test(name)) continue;
    let j = i + 3;
    let depth = 0;
    while (j < tokens.length && !(depth === 0 && tokens[j].t === "p" && tokens[j].v === "=")) {
      if (tokens[j].t === "p" && "([{".includes(tokens[j].v)) depth++;
      if (tokens[j].t === "p" && ")]}".includes(tokens[j].v)) depth--;
      j++;
    }
    const parser = new Parser(tokens);
    parser.pos = j + 1;
    try {
      consts.set(name, parser.expr());
    } catch {
      // Constante d'une autre forme (fonction, type complexe) : sans intérêt ici.
    }
  }
  return consts;
}

/** Variantes de l'énumération `Section`, dans l'ordre d'affichage. */
function readSections(tokens) {
  for (let i = 0; i < tokens.length - 2; i++) {
    if (tokens[i].v !== "enum" || tokens[i + 1].v !== "Section" || tokens[i + 2].v !== "{") continue;
    const out = [];
    for (let j = i + 3; j < tokens.length && tokens[j].v !== "}"; j++) {
      if (tokens[j].t === "id") out.push(tokens[j].v);
    }
    return out;
  }
  return [];
}

const KNOWN_MODIFIERS = new Set(["owner", "clients", "public", "modal", "admin_max", "up", "down", "adv", "pre", "syn", "capped", "checked", "v1"]);
const SIMPLE_KINDS = Object.freeze({
  "Kind::Bool": "bool",
  "Kind::Email": "email",
  "Kind::Emails": "emails",
  "Kind::Color": "color",
  "Kind::Cidrs": "cidrs",
  "Kind::Domains": "domains",
  "Kind::Roles": "roles",
  "Kind::Secret": "secret",
});
const UNITS = Object.freeze({
  Seconds: "seconds", Minutes: "minutes", Hours: "hours", Days: "days", Mib: "mib", Count: "count", Percent: "percent",
});
const MODES = Object.freeze({ Free: "free", Default: "default", Enforced: "enforced" });

/**
 * Analyse le registre d'un source Rust.
 * Renvoie { defs, sections, zeroUnlimited, errors } ; `defs` suit l'ordre du source.
 */
export function parseRegistry(source) {
  const errors = [];
  const start = source.indexOf(BLOCK_START);
  const end = source.indexOf(BLOCK_END, start);
  if (start < 0 || end < 0) {
    return { defs: [], sections: [], zeroUnlimited: [], errors: [`bloc introuvable entre « ${BLOCK_START} » et « ${BLOCK_END} »`] };
  }
  let all;
  let block;
  try {
    all = tokenize(source);
    block = tokenize(source.slice(start, end));
  } catch (e) {
    return { defs: [], sections: [], zeroUnlimited: [], errors: [`lecture impossible : ${e.message}`] };
  }
  const consts = readConstants(all);
  const variants = readSections(all);
  const sections = variants.map((v) => v.toLowerCase());
  const resolve = (node) => (node?.t === "path" && consts.has(node.v) ? resolve(consts.get(node.v)) : node);

  const defs = [];
  const seen = new Set();
  const parser = new Parser(block);
  const open = block.findIndex((tok, i) => tok.v === "=" && block[i + 1]?.v === "&" && block[i + 2]?.v === "[");
  if (open < 0) return { defs, sections, zeroUnlimited: [], errors: ["« = &[ » introuvable après « pub static REGISTRY »"] };
  parser.pos = open + 3;
  try {
    while (!parser.isP("]")) {
      const node = parser.expr();
      if (!parser.isP("]")) parser.expectP(",");
      const def = interpret(node, { resolve, variants, errors });
      if (!def) continue;
      if (seen.has(def.key)) errors.push(`clé en double : ${def.key}`);
      seen.add(def.key);
      defs.push(def);
    }
  } catch (e) {
    errors.push(`registre illisible après ${defs.length} entrée(s) : ${e.message}`);
  }
  const expected = (source.slice(start, end).match(ENTRY_RE) || []).length;
  if (expected !== defs.length) errors.push(`${defs.length} entrée(s) analysée(s) pour ${expected} « s("…") » dans le bloc`);

  const zero = resolve({ t: "path", v: "ZERO_IS_UNLIMITED" });
  const zeroUnlimited = zero?.t === "array" ? zero.items.map(resolve).filter((n) => n?.t === "str").map((n) => n.v) : [];
  return { defs, sections, zeroUnlimited, errors };
}

/** Transforme une entrée `s(…).modificateur(…)…` en définition. */
function interpret(node, { resolve, variants, errors }) {
  const chain = [];
  let cur = node;
  while (cur?.t === "method") {
    chain.unshift(cur);
    cur = cur.target;
  }
  if (cur?.t !== "call" || cur.name !== "s" || cur.args.length !== 5) {
    errors.push("entrée qui n'est pas un appel s(clé, section, ordre, type, défaut)");
    return null;
  }
  const [keyN, secN, orderN, kindN, defN] = cur.args;
  if (keyN.t !== "str") {
    errors.push("clé d'entrée qui n'est pas une chaîne");
    return null;
  }
  const key = keyN.v;
  const fail = (msg) => { errors.push(`${key} : ${msg}`); };

  const variant = secN.t === "path" ? secN.v.replace(/^(Sec|Section)::/, "") : null;
  if (!variant || !variants.includes(variant)) fail(`section inconnue ${secN.v ?? "?"}`);
  if (orderN.t !== "num") fail("ordre d'affichage qui n'est pas un nombre");

  const def = {
    key,
    section: (variant || "").toLowerCase(),
    order: orderN.v,
    kind: readKind(kindN, resolve, fail),
    default: readDefault(defN, resolve, fail),
    scope: "org",
    ownerOnly: false,
    client: false,
    modes: false,
    defaultMode: null,
    adminMax: null,
    safer: "na",
    hostCap: null,
    advanced: false,
    presets: [],
    synonyms: [],
    check: null,
    since: 2,
  };
  for (const m of chain) {
    if (!KNOWN_MODIFIERS.has(m.name)) {
      fail(`modificateur inconnu .${m.name}()`);
      continue;
    }
    const arg = m.args[0] ? resolve(m.args[0]) : undefined;
    switch (m.name) {
      case "owner": def.ownerOnly = true; break;
      case "clients": def.client = true; def.scope = "policy"; break;
      case "public": def.scope = "public"; break;
      case "up": def.safer = "higher"; break;
      case "down": def.safer = "lower"; break;
      case "adv": def.advanced = true; break;
      case "v1": def.since = 1; break;
      case "modal": {
        const mode = arg?.t === "path" ? MODES[arg.v.replace(/^Mode::/, "")] : undefined;
        if (!mode) fail(".modal() attend Mode::Free, Mode::Default ou Mode::Enforced");
        def.modes = true;
        def.defaultMode = mode || null;
        break;
      }
      case "admin_max":
        if (arg?.t !== "num") fail(".admin_max() attend un nombre");
        def.adminMax = arg?.v ?? null;
        break;
      case "pre":
        if (arg?.t !== "array") fail(".pre() attend un tableau ou une table de valeurs");
        def.presets = (arg?.items || []).map(resolve).map((n) => n.v);
        break;
      case "syn":
        if (arg?.t !== "array") fail(".syn() attend un tableau de chaînes");
        def.synonyms = (arg?.items || []).map(resolve).map((n) => n.v);
        break;
      case "capped":
        if (arg?.t !== "str") fail(".capped() attend le nom d'une variable");
        def.hostCap = arg?.v ?? null;
        break;
      case "checked":
        if (arg?.t !== "path") fail(".checked() attend le nom d'une fonction");
        def.check = arg?.v ?? null;
        break;
    }
  }
  return def;
}

function readKind(node, resolve, fail) {
  const n = resolve(node);
  if (n?.t === "path" && SIMPLE_KINDS[n.v]) return { type: SIMPLE_KINDS[n.v] };
  const num = (x, what) => {
    const r = resolve(x);
    if (r?.t !== "num") fail(`${what} attendu`);
    return r?.v;
  };
  if (n?.t === "call") {
    if (n.name === "int" && n.args.length === 3) {
      const unit = n.args[2].t === "path" ? UNITS[n.args[2].v.replace(/^Unit::/, "")] : undefined;
      if (!unit) fail(`unité inconnue ${n.args[2].v ?? "?"}`);
      return { type: "int", min: num(n.args[0], "minimum"), max: num(n.args[1], "maximum"), unit };
    }
    if ((n.name === "text" || n.name === "multiline") && n.args.length === 1) {
      return { type: "text", maxLen: num(n.args[0], "longueur"), multiline: n.name === "multiline" };
    }
    if (n.name === "Kind::Enum" && n.args.length === 1) {
      const arr = resolve(n.args[0]);
      if (arr?.t !== "array") fail("Kind::Enum attend un tableau de chaînes");
      return { type: "enum", values: (arr?.items || []).map(resolve).map((x) => x.v) };
    }
  }
  if (n?.t === "struct") {
    const f = n.fields;
    if (n.name === "Kind::Words") return { type: "words", max: num(f.max, "max") };
    if (n.name === "Kind::Image") return { type: "image", maxBytes: num(f.max_bytes, "max_bytes") };
    if (n.name === "Kind::Url") return { type: "url", httpsOnly: resolve(f.https_only)?.v === "true" };
    if (n.name === "Kind::Int") {
      const unit = f.unit?.t === "path" ? UNITS[f.unit.v.replace(/^Unit::/, "")] : undefined;
      if (!unit) fail("unité inconnue");
      return { type: "int", min: num(f.min, "min"), max: num(f.max, "max"), unit };
    }
    if (n.name === "Kind::Text") return { type: "text", maxLen: num(f.max_len, "max_len"), multiline: resolve(f.multiline)?.v === "true" };
  }
  fail(`type inconnu ${n?.name ?? n?.v ?? "?"}`);
  return { type: "unknown" };
}

function readDefault(node, resolve, fail) {
  const n = resolve(node);
  if (n?.t === "call" && n.args.length === 1) {
    const a = resolve(n.args[0]);
    switch (n.name) {
      case "B":
      case "Def::Bool":
        if (a?.t !== "path" || !["true", "false"].includes(a.v)) break;
        return a.v === "true";
      case "I":
      case "Def::Int":
        if (a?.t !== "num") break;
        return a.v;
      case "S":
      case "Def::Str":
        if (a?.t !== "str") break;
        return a.v;
      case "L":
      case "Def::List":
        if (a?.t !== "array") break;
        return a.items.map(resolve).map((x) => x.v);
    }
  }
  fail("valeur par défaut illisible (B, I, S ou L attendu)");
  return null;
}

// ------------------------------------------------------------------ Rendu Markdown

/** Nombre à la française : « 1 440 », « -5 ». */
export function frNumber(n) {
  const s = String(Math.abs(n)).replace(/\B(?=(\d{3})+(?!\d))/g, NNBSP);
  return n < 0 ? `-${s}` : s;
}

const UNIT_FALLBACK = Object.freeze({ seconds: "s", minutes: "min", hours: "h", days: "jours", mib: "Mio", count: "", percent: "%" });

/** Équivalent lisible d'une durée (« 1 440 min » -> « 1 jour »), ou null. */
function humanDuration(n, unit) {
  const plural = (v, one, other) => `${frNumber(v)} ${v > 1 ? other : one}`;
  const seconds = { seconds: 1, minutes: 60, hours: 3600, days: 86_400 }[unit];
  if (!seconds || n <= 0) return null;
  const total = n * seconds;
  const steps = [[31_536_000, "an", "ans"], [86_400, "jour", "jours"], [3600, "heure", "heures"], [60, "minute", "minutes"]];
  for (const [size, one, other] of steps) {
    if (size > seconds && total % size === 0) return plural(total / size, one, other);
  }
  return null;
}

/** Échappe un texte destiné à une cellule de tableau Markdown. */
export function cell(text) {
  return String(text).replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function code(text) {
  const s = String(text);
  return s.includes("`") ? `\`\` ${s} \`\`` : `\`${s}\``;
}

/** Ancre de titre, à la manière des forges courantes. */
export function slug(title) {
  return title.toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, "").trim().replace(/\s+/g, "-");
}

/**
 * Produit le Markdown. Renvoie { text, errors } ; `errors` liste les textes
 * obligatoires absents (libellé d'un réglage ou d'une section).
 */
export function renderDoc(parsed, catalog) {
  const errors = [];
  const { defs, sections, zeroUnlimited } = parsed;
  const zero = new Set(zeroUnlimited);
  const text = (k) => (typeof catalog[k] === "string" ? catalog[k] : null);
  const label = (d) => {
    const v = text(`settings.${d.key}.label`);
    if (!v) errors.push(`libellé absent : settings.${d.key}.label (design/i18n/fr/settings.json)`);
    return v || d.key;
  };
  const sectionLabel = (id) => {
    const v = text(`settings.section.${id}.label`);
    if (!v) errors.push(`libellé absent : settings.section.${id}.label`);
    return v || id;
  };
  const unitOf = (d) => text(`settings.${d.key}.unit`) ?? UNIT_FALLBACK[d.kind.unit] ?? "";
  const withUnit = (d, n) => {
    // « 1 jour », « 0 jour » : singulier pour 0 et 1, comme dans l'interface.
    const u = d.kind.unit === "days" && Math.abs(n) <= 1 ? "jour" : unitOf(d);
    const base = u ? `${frNumber(n)} ${u}` : frNumber(n);
    const human = humanDuration(n, d.kind.unit);
    return human ? `${base} (${human})` : base;
  };
  const valueLabel = (d, v) => {
    const l = text(`settings.${d.key}.value.${String(v).toLowerCase()}`);
    return l ? `« ${l} » (${code(v)})` : code(v);
  };
  const yesNo = (b) => (b ? "oui" : "non");

  const allowed = (d) => {
    const k = d.kind;
    switch (k.type) {
      case "bool": return "oui ou non";
      case "int": {
        const u = unitOf(d);
        const range = `${frNumber(k.min)} à ${frNumber(k.max)}${u ? ` ${u}` : ""}`;
        return zero.has(d.key) ? `${range} ; 0 = sans limite` : range;
      }
      case "enum": return k.values.map((v) => valueLabel(d, v)).join(", ");
      case "text": return `${k.multiline ? "texte sur plusieurs lignes" : "texte"}, ${frNumber(k.maxLen)} caractères au plus`;
      case "url": return k.httpsOnly ? "adresse en https://" : "adresse web";
      case "email": return "adresse e-mail";
      case "emails": return "liste d'adresses e-mail";
      case "color": return "couleur #rrggbb, lisible sur fond clair et sombre";
      case "cidrs": return "liste d'adresses ou de réseaux IP (ex. 192.168.0.0/24)";
      case "domains": return "liste de domaines";
      case "roles": return `liste de rôles parmi ${code("owner")}, ${code("admin")}, ${code("user")}`;
      case "words": return `liste de mots, ${frNumber(k.max)} au plus`;
      case "secret": return "secret, chiffré par le serveur et jamais réaffiché";
      case "image": return `image PNG ou WebP, ${frNumber(Math.round(k.maxBytes / 1024))} Kio au plus`;
      default: return "?";
    }
  };

  const defaultText = (d) => {
    const v = d.default;
    switch (d.kind.type) {
      case "bool": return yesNo(v);
      case "int": return zero.has(d.key) && v === 0 ? "0 (sans limite)" : withUnit(d, v);
      case "enum": return valueLabel(d, v);
      case "secret": return "(non défini)";
      case "image": return v ? "(image)" : text("ui.setting.image.default") || "(aucune)";
      default:
        if (Array.isArray(v)) return v.length ? v.map(code).join(", ") : "(aucun)";
        return v === "" || v === null ? "(vide)" : code(v);
    }
  };

  const modesText = (d) => {
    if (!d.modes) return "—";
    const names = ["free", "default", "enforced"].map((m) => text(`settings.mode.${m}`) || m);
    let s = `${names.join(", ")} ; mode initial : ${text(`settings.mode.${d.defaultMode}`) || d.defaultMode}`;
    if (d.adminMax !== null) s += ` ; choix des utilisateurs limité à ${withUnit(d, d.adminMax)} au plus`;
    return s;
  };

  const broadcast = (d) => (d.client ? "oui" : d.scope === "public" ? "page de connexion" : "non");

  const saferText = (d) => {
    if (d.safer === "na") return "—";
    const up = d.safer === "higher";
    switch (d.kind.type) {
      case "bool": return up ? "activé" : "désactivé";
      case "enum": return `vers ${valueLabel(d, up ? d.kind.values.at(-1) : d.kind.values[0])}`;
      case "int":
        if (!up && zero.has(d.key)) return "plus bas (0, sans limite, est le moins sûr)";
        return up ? "plus haut" : "plus bas";
      default:
        return up ? "plus d'entrées" : "moins d'entrées";
    }
  };

  const ordered = [...defs].sort((a, b) => sections.indexOf(a.section) - sections.indexOf(b.section) || a.order - b.order || a.key.localeCompare(b.key));
  const bySection = sections.map((id) => ({ id, label: sectionLabel(id), defs: ordered.filter((d) => d.section === id) })).filter((s) => s.defs.length);

  const lines = [];
  const push = (...l) => lines.push(...l);
  push(
    "# Réglages de l'organisation",
    "",
    "<!-- Fichier généré par « node tools/gen-settings-doc.mjs » depuis crates/locksy-core/src/settings.rs",
    "     et design/i18n/fr.gen.json : ne le modifiez pas à la main. -->",
    "",
    `Cette page décrit les ${frNumber(defs.length)} réglages que les propriétaires et les administrateurs`,
    "modifient dans **Administration > Réglages** (`#/admin/reglages/<section>`). Elle est générée depuis",
    "le registre unique du serveur : chaque réglage y a sa ligne, avec ses bornes et sa valeur par",
    "défaut. Le parcours de l'écran est décrit dans le [guide administrateur](Administration.md#réglages).",
    "",
    "## Qui décide de la valeur",
    "",
    "| Niveau | Qui | Où |",
    "|---|---|---|",
    "| Constantes | personne | le code : formats chiffrés, planchers de dérivation, règle du dernier propriétaire |",
    "| Hébergeur | l'exploitant du serveur | variables `LOCKSY_*`, dont `LOCKSY_SETTINGS_FILE` ([Exploitation](Exploitation.md#variables-denvironnement)) |",
    "| Organisation | propriétaires et administrateurs | Administration > Réglages (cette page) |",
    "| Poste de travail | le service informatique | GPO, Intune, stratégies du navigateur ([Extension navigateur](Extension-navigateur.md)) |",
    "| Personne | chaque utilisateur | Paramètres > Préférences, chiffrées et synchronisées entre ses appareils |",
    "",
    "Sur le serveur, la valeur appliquée est, dans l'ordre : la valeur fixée par l'hébergeur, sinon",
    "celle de l'organisation, sinon la valeur par défaut du tableau ; elle reste toujours dans les",
    "bornes du tableau et sous le plafond éventuel de l'hébergeur. Le serveur reste la barrière : un",
    "réglage qu'il peut vérifier y est appliqué, même si un poste l'ignore.",
    "",
    "## Réglages diffusés aux postes et modes",
    "",
    "Les réglages marqués « Diffusé aux postes » sont envoyés à l'interface web et à l'extension après",
    "la connexion. Ceux qui ont des **modes** se règlent en deux temps : la valeur, puis la liberté",
    "laissée aux utilisateurs (« Pour les utilisateurs ») :",
    "",
    `- **${text("settings.mode.free") || "free"}** : chaque personne choisit dans les bornes du tableau ;`,
    `- **${text("settings.mode.default") || "default"}** : la valeur est proposée ; chacun peut la changer, sans dépasser la limite`,
    "  choisie par l'administrateur (« Ils peuvent choisir au plus ») ;",
    `- **${text("settings.mode.enforced") || "enforced"}** : la valeur s'applique à tous, sans choix possible.`,
    "",
    "Sur un poste, une valeur imposée par le service informatique (GPO, Intune) l'emporte quand elle",
    "est plus stricte. Le client Windows 1.1 ne lit pas encore ces réglages : il garde sa politique",
    "locale ([Client Windows](Client-Windows.md#politique-dentreprise)) ; sa refonte arrive en 1.2.",
    "",
    "## Réglages fixés par l'hébergeur",
    "",
    "`LOCKSY_SETTINGS_FILE` désigne un fichier JSON qui fixe des réglages pour toute l'instance. Chaque",
    "clé du fichier est verrouillée : elle s'affiche avec la mention « Fixé par l'hébergeur » et ne se",
    "modifie plus dans l'interface. Le fichier est vérifié au démarrage contre ce registre : une clé",
    "inconnue, une valeur hors bornes ou un secret (le mot de passe du serveur d'envoi, qui se",
    "saisit dans l'interface) arrêtent le serveur avec un message clair.",
    "",
    "```json",
    "{",
    "  \"twofa.required\": true,",
    "  \"session.idle_minutes\": 30,",
    "  \"client.autolock_minutes\": { \"value\": 5, \"mode\": \"enforced\" }",
    "}",
    "```",
    "",
    "Pour un réglage à modes, la forme objet précise aussi `mode` (`free`, `default` ou `enforced`),",
    "`min` et `max`. De même, `LOCKSY_SYSLOG` fixe l'adresse du transfert vers l'outil de",
    "supervision. La colonne « Plafond de l'hébergeur » nomme la variable qui borne un réglage par",
    "le haut.",
    "",
    "## Lire les tableaux",
    "",
    "- **Valeurs admises** et **Défaut** : bornes et valeur d'une organisation neuve.",
    "- **Modes** : réglages dont la liberté laissée aux utilisateurs se choisit (voir plus haut).",
    "- **Diffusé aux postes** : « oui » pour la politique envoyée après connexion, « page de connexion »",
    "  pour les textes et règles affichés avant la connexion, « non » pour un réglage du serveur seul.",
    "- **Propriétaire seulement** : un administrateur voit le réglage mais ne peut pas le modifier.",
    "- **Sens le plus sûr** : changer un réglage dans l'autre sens **abaisse la sécurité**. L'écran le",
    "  signale, demande le mot de passe maître, inscrit l'événement au journal et prévient les",
    "  propriétaires par e-mail quand la notification correspondante est active (section E-mails).",
    "- Les réglages marqués « avancé » sont repliés sous « Réglages avancés » dans leur section.",
    "",
    "## Sections",
    "",
    ...bySection.map((s) => `- [${s.label}](#${slug(s.label)}) : ${frNumber(s.defs.length)} réglage${s.defs.length > 1 ? "s" : ""}, \`#/admin/reglages/${s.id}\``),
    "",
  );

  const header = [
    "Réglage", "Clé", "Valeurs admises", "Défaut", "Modes", "Diffusé aux postes",
    "Propriétaire seulement", "Plafond de l'hébergeur (variable)", "Sens le plus sûr",
  ];
  for (const s of bySection) {
    push(`## ${s.label}`, "");
    const help = text(`settings.section.${s.id}.help`);
    if (help) push(help, "");
    push(`| ${header.join(" | ")} |`, `|${header.map(() => "---").join("|")}|`);
    for (const d of s.defs) {
      const row = [
        `${label(d)}${d.advanced ? " (avancé)" : ""}`,
        code(d.key),
        allowed(d),
        defaultText(d),
        modesText(d),
        broadcast(d),
        yesNo(d.ownerOnly),
        d.hostCap ? code(d.hostCap) : "—",
        saferText(d),
      ];
      push(`| ${row.map(cell).join(" | ")} |`);
    }
    push("");
    const details = [];
    for (const d of s.defs) {
      const parts = [];
      const h = text(`settings.${d.key}.help`);
      if (h) parts.push(h);
      if (d.presets.length) parts.push(`Valeurs proposées : ${d.presets.map((n) => (n === 0 && zero.has(d.key) ? "sans limite" : withUnit(d, n))).join(", ")}.`);
      if (parts.length) details.push(`- **${label(d)}** : ${parts.join(" ")}`);
    }
    if (details.length) push("En détail :", "", ...details, "");
  }
  return { text: `${lines.join("\n").replace(/\n+$/, "")}\n`, errors: [...new Set(errors)] };
}

// ------------------------------------------------------------------ Ligne de commande

function parseArgs(argv) {
  const opts = { check: false, out: DEFAULT_OUT, registry: DEFAULT_REGISTRY, catalog: DEFAULT_CATALOG };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") opts.check = true;
    else if (a === "--out" || a === "--registry" || a === "--catalog") {
      if (!argv[i + 1]) throw new Error(`${a} attend un chemin`);
      opts[a.slice(2)] = resolve(argv[++i]);
    } else throw new Error(`option inconnue « ${a} » (--check, --out, --registry, --catalog)`);
  }
  return opts;
}

/** Chemin affiché : relatif au dépôt s'il s'y trouve, absolu sinon. */
function rel(p) {
  const r = relative(ROOT, p).replace(/\\/g, "/");
  return r && !r.startsWith("../") && !/^[a-z]:/i.test(r) ? r : p;
}

/** Construit le document ; renvoie { text, count, errors }. */
export function build({ registry = DEFAULT_REGISTRY, catalog = DEFAULT_CATALOG } = {}) {
  const parsed = parseRegistry(readFileSync(registry, "utf8"));
  if (parsed.errors.length) return { text: "", count: 0, errors: parsed.errors };
  const { text, errors } = renderDoc(parsed, JSON.parse(readFileSync(catalog, "utf8")));
  return { text, count: parsed.defs.length, errors };
}

/** Point d'entrée ; renvoie le code de sortie (0 ou 1). */
export function main(argv = process.argv.slice(2), log = console) {
  let opts;
  let result;
  try {
    opts = parseArgs(argv);
    result = build(opts);
  } catch (e) {
    log.error(`gen-settings-doc : ${e.message}`);
    return 1;
  }
  if (result.errors.length) {
    for (const e of result.errors) log.error(`gen-settings-doc : ${e}`);
    log.error(`gen-settings-doc : ${result.errors.length} erreur(s), rien n'a été écrit.`);
    return 1;
  }
  const current = existsSync(opts.out) ? readFileSync(opts.out, "utf8") : null;
  if (opts.check) {
    if (current !== result.text) {
      log.error(`gen-settings-doc : ${rel(opts.out)} n'est pas à jour, lancez « node tools/gen-settings-doc.mjs ».`);
      return 1;
    }
    log.log(`gen-settings-doc : ${rel(opts.out)} à jour (${result.count} réglages).`);
    return 0;
  }
  if (current !== result.text) {
    mkdirSync(dirname(opts.out), { recursive: true });
    writeFileSync(opts.out, result.text);
  }
  log.log(`gen-settings-doc : ${result.count} réglages -> ${rel(opts.out)}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = main();
}
