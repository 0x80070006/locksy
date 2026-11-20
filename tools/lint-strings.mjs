#!/usr/bin/env node
// Relève les textes affichables écrits en dur dans les vues (règle R3 : tout
// libellé passe par t()).
//
//   node tools/lint-strings.mjs            rapport « fichier:ligne: texte » + total, sortie 0
//   node tools/lint-strings.mjs --strict   idem, sortie 1 s'il reste au moins un texte
//   node tools/lint-strings.mjs --json     sortie machine { total, findings[] }
//   node tools/lint-strings.mjs <chemin>…  analyse ces fichiers ou dossiers au lieu
//                                          de web/js/views et extension/src
//
// Analyse légère par jetons, sans dépendance. Un littéral est relevé selon
// l'endroit où il apparaît (champ « rule » de la sortie JSON) :
//   h-child  enfant texte de h(tag, attrs, …enfants) ;
//   attr     attribut aria-label, title, placeholder ou alt (objet, affectation,
//            setAttribute) ;
//   prop     propriété label, text, message, title ou *Label, *Text, *Message,
//            *Title (objets, paramètres par défaut, affectations) ;
//   toast    premier argument de toast(), notify(), announce() ;
//   prose    ailleurs, un littéral qui ressemble à une phrase française
//            (majuscule initiale, lettre accentuée ou mot outil).
// Sont ignorés : les littéraux sans lettre, les clés (« vault.detail.copy »),
// les URL et chemins, les imports, les arguments de t(), plural(), has(),
// tList(), errorText(), fieldErrorText(), les classes, identifiants et autres
// attributs techniques, les comparaisons et les étiquettes « case ».

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULT_TARGETS = ["web/js/views", "extension/src"];
/** Fichiers jamais embarqués dans le produit (tests, simulation de développement). */
const SKIP_RE = /(^|\/)(test|tests|node_modules)\/|(^|\/)dev-fake\.js$|\.test\.m?js$/;

const KEY_RE = /^[a-z0-9_]+(\.[a-z0-9_-]+)+$/;
const URL_RE = /^(https?:|mailto:|data:|blob:|chrome-extension:|moz-extension:|\/|\.\.?\/|#)/;
const FILE_NAME_RE = /^[\w.-]+\.[a-z0-9]{2,5}$/i;
const LETTER_RE = /\p{L}/u;
/** Nom de touche ou raccourci clavier (KeyboardEvent.key, « Ctrl+Shift+C ») : identifiant technique. */
const KEY_NAME_RE = /^(?:(?:Ctrl|Alt|Shift|Meta)\+)*(?:[A-Z]|Arrow(?:Up|Down|Left|Right)|Home|End|Enter|Escape|Tab|CapsLock|Backspace|Delete|Letter|Page(?:Up|Down)|F\d{1,2})$/;
const STOP_WORDS = new Set(("à au aux avec ce ces cette dans de des du en est et il la le les leur mais ne ni "
  + "nos notre ou par pas plus pour qui que sa se ses son sur un une vos votre vous").split(" "));

const T_FUNCS = new Set(["t", "plural", "has", "tList", "errorText", "fieldErrorText"]);
const TOAST_FUNCS = new Set(["toast", "notify", "announce"]);
const ATTR_NAMES = new Set(["aria-label", "ariaLabel", "title", "placeholder", "alt"]);
const DISPLAY_PROP_RE = /^(label|text|message|[a-zA-Z]+(Label|Text|Message|Title))$/;
const TECH_PROPS = new Set(["class", "className", "id", "href", "src", "type", "role", "name", "autocomplete",
  "rel", "target", "for", "htmlFor", "d", "viewBox", "fill", "stroke", "method", "key", "accept", "inputmode",
  "pattern", "download", "lang", "dir", "kind", "tone", "icon", "code", "mode", "cache", "credentials",
  "path", "url", "event", "authorization", "tag", "format", "alg", "status", "value"]);
const TECH_CALLS = new Set(["querySelector", "querySelectorAll", "closest", "matches", "getElementById",
  "addEventListener", "removeEventListener", "dispatchEvent", "getAttribute", "removeAttribute", "hasAttribute",
  "toggleAttribute", "createElement", "createElementNS", "setProperty", "getPropertyValue", "matchMedia",
  "api", "call", "fetch", "download", "require", "import", "execCommand", "getItem", "setItem", "removeItem",
  "postMessage", "sendMessage", "get", "set", "Event", "CustomEvent", "toLocaleString", "toLocaleDateString",
  "startsWith", "endsWith", "includes", "indexOf", "split", "replace", "replaceAll", "join", "padStart",
  "icon", "iconName", "Blob", "URL", "URLSearchParams", "RegExp", "Symbol"]);
const CONSOLE_OBJECTS = new Set(["console"]);
const KEYWORDS_BEFORE_REGEX = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
  "throw", "case", "do", "else", "yield", "await"]);
const NOT_CALLEES = new Set(["if", "for", "while", "switch", "catch", "function", "return", "typeof", "await",
  "with", "of", "in", "new", "delete", "void", "throw", "case", "yield"]);
const COMPARISONS = new Set(["===", "!==", "==", "!="]);
const PUNCT_RE = /^(===|!==|\.\.\.|\?\?=|\*\*=|==|!=|=>|<=|>=|&&|\|\||\?\?|\?\.|\+\+|--|\+=|-=|\*=|\/=|%=|&=|\|=|\*\*)/;

// ------------------------------------------------------------------ Jetons

function decodeEscapes(raw) {
  return raw.replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|\r\n|[\s\S])/g, (_, e) => {
    if (e[0] === "u" && e.length > 1) return String.fromCodePoint(parseInt(e.replace(/[u{}]/g, ""), 16));
    if (e[0] === "x" && e.length === 3) return String.fromCharCode(parseInt(e.slice(1), 16));
    return { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v", 0: "\0" }[e] ?? (e === "\n" || e === "\r\n" ? "" : e);
  });
}

/**
 * Découpe un source JavaScript en jetons { type, value, line, column }.
 * type : "str" (chaîne ou gabarit ; `subst` vrai si le gabarit a des
 * ${…}), "ident", "num", "punct", "regex". Les commentaires disparaissent ;
 * les expressions des gabarits sont découpées à leur place.
 */
export function tokenize(src) {
  const tokens = [];
  let i = 0;
  let line = 1;
  let lineStart = 0;
  const templateDepth = []; // profondeur d'accolades à laquelle chaque ${ s'est ouvert
  let braces = 0;

  const prevSignificant = () => tokens[tokens.length - 1];
  const regexAllowed = () => {
    const p = prevSignificant();
    if (!p) return true;
    if (p.type === "ident") return KEYWORDS_BEFORE_REGEX.has(p.value);
    if (p.type === "num" || p.type === "str" || p.type === "regex") return false;
    return ![")", "]", "}"].includes(p.value);
  };
  const advance = (to) => {
    for (; i < to; i++) {
      if (src[i] === "\n") {
        line++;
        lineStart = i + 1;
      }
    }
  };
  const push = (type, value, startLine, startCol, extra = {}) => tokens.push({ type, value, line: startLine, column: startCol, ...extra });

  // Lit la suite d'un gabarit à partir de i (juste après ` ou }) jusqu'à ` ou ${.
  const scanTemplatePart = () => {
    let raw = "";
    while (i < src.length) {
      const ch = src[i];
      if (ch === "\\") {
        raw += src.slice(i, i + 2);
        advance(i + 2);
        continue;
      }
      if (ch === "`") {
        advance(i + 1);
        return { raw, end: "`" };
      }
      if (ch === "$" && src[i + 1] === "{") {
        advance(i + 2);
        return { raw, end: "${" };
      }
      raw += ch;
      advance(i + 1);
    }
    return { raw, end: "eof" };
  };

  // Gabarit complet : on émet un jeton « str » (parties fixes reliées par
  // « ${…} »), puis les jetons des expressions, découpés récursivement.
  const scanTemplate = (startLine, startCol) => {
    const parts = [];
    const inner = [];
    for (;;) {
      const part = scanTemplatePart();
      parts.push(decodeEscapes(part.raw));
      if (part.end !== "${") break;
      const sub = tokenizeExpression();
      inner.push(...sub);
    }
    const token = { type: "str", value: parts.join("${…}"), line: startLine, column: startCol, subst: parts.length > 1 };
    tokens.push(token, ...inner);
  };

  // Expression d'un ${…} : jetons jusqu'à l'accolade fermante correspondante.
  const tokenizeExpression = () => {
    const saved = tokens.splice(0, tokens.length);
    templateDepth.push(braces);
    scan(true);
    templateDepth.pop();
    const sub = tokens.splice(0, tokens.length);
    tokens.push(...saved);
    return sub;
  };

  const scan = (inTemplate) => {
    while (i < src.length) {
      const ch = src[i];
      const col = i - lineStart + 1;
      if (ch === "\n" || ch === " " || ch === "\t" || ch === "\r" || ch === "\f" || ch === "\v" || ch === " " || ch === "﻿") {
        advance(i + 1);
        continue;
      }
      if (ch === "/" && src[i + 1] === "/") {
        const end = src.indexOf("\n", i);
        advance(end === -1 ? src.length : end);
        continue;
      }
      if (ch === "/" && src[i + 1] === "*") {
        const end = src.indexOf("*/", i + 2);
        advance(end === -1 ? src.length : end + 2);
        continue;
      }
      const startLine = line;
      if (ch === "\"" || ch === "'") {
        let j = i + 1;
        while (j < src.length && src[j] !== ch && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
        const raw = src.slice(i + 1, j);
        advance(Math.min(j + 1, src.length));
        push("str", decodeEscapes(raw), startLine, col, { subst: false });
        continue;
      }
      if (ch === "`") {
        advance(i + 1);
        scanTemplate(startLine, col);
        continue;
      }
      if (ch === "/" && regexAllowed()) {
        let j = i + 1;
        let inClass = false;
        while (j < src.length && src[j] !== "\n") {
          if (src[j] === "\\") { j += 2; continue; }
          if (src[j] === "[") inClass = true;
          else if (src[j] === "]") inClass = false;
          else if (src[j] === "/" && !inClass) break;
          j++;
        }
        j++;
        while (j < src.length && /[a-z]/i.test(src[j])) j++;
        const value = src.slice(i, j);
        advance(j);
        push("regex", value, startLine, col);
        continue;
      }
      const ident = /^[A-Za-z_$À-￿][\w$À-￿]*/.exec(src.slice(i, i + 200));
      if (ident) {
        advance(i + ident[0].length);
        push("ident", ident[0], startLine, col);
        continue;
      }
      const num = /^(0[xob][\da-f_]+n?|\d[\d_]*(\.\d*)?(e[+-]?\d+)?n?|\.\d+(e[+-]?\d+)?)/i.exec(src.slice(i, i + 100));
      if (num) {
        advance(i + num[0].length);
        push("num", num[0], startLine, col);
        continue;
      }
      const op = PUNCT_RE.exec(src.slice(i, i + 4));
      const value = op ? op[0] : ch;
      if (value === "{") braces++;
      if (value === "}") {
        if (inTemplate && braces === templateDepth[templateDepth.length - 1]) {
          advance(i + 1);
          return;
        }
        braces--;
      }
      advance(i + value.length);
      push("punct", value, startLine, col);
    }
  };

  scan(false);
  return tokens;
}

// ------------------------------------------------------------------ Analyse

/** Vrai si le texte ressemble à une phrase française (et non à un nom technique). */
export function looksLikeProse(text) {
  if (/^\p{Lu}\p{Ll}/u.test(text)) return true;
  if (/[À-ÖØ-öø-ÿœŒ]/.test(text)) return true;
  const words = text.toLowerCase().split(/[\s  ]+/).filter(Boolean);
  return words.length > 1 && words.some((w) => STOP_WORDS.has(w.replace(/[^\p{L}]/gu, "")));
}

/** Littéral jamais relevé, quel que soit l'endroit : sans lettre, clé, URL, nom de fichier. */
function ignoredLiteral(tok) {
  const text = tok.value;
  if (!LETTER_RE.test(text.replace(/\$\{…\}/g, ""))) return true;
  if (tok.subst) return false;
  const trimmed = text.trim();
  return KEY_RE.test(trimmed) || KEY_NAME_RE.test(trimmed) || URL_RE.test(trimmed) || (FILE_NAME_RE.test(trimmed) && !/\s/.test(trimmed))
    || /:\/\//.test(trimmed) && !/\s/.test(trimmed);
}

/** Classe un nom de propriété ou de variable : "attr", "prop", "tech" ou null. */
function classifyName(name) {
  if (ATTR_NAMES.has(name)) return "attr";
  if (DISPLAY_PROP_RE.test(name) || name === "textContent" || name === "innerText") return "prop";
  if (TECH_PROPS.has(name) || name.startsWith("data-")) return "tech";
  return null;
}

/**
 * Textes en dur d'un source : liste de { file, line, column, text, rule }.
 */
export function lintSource(src, file = "<source>") {
  const tokens = tokenize(src);
  const findings = [];
  const frames = [];
  const report = (tok, rule) => findings.push({ file, line: tok.line, column: tok.column, text: tok.value, rule });

  for (let k = 0; k < tokens.length; k++) {
    const tok = tokens[k];
    const prev = tokens[k - 1];
    const prev2 = tokens[k - 2];
    const prev3 = tokens[k - 3];
    const next = tokens[k + 1];
    const top = frames[frames.length - 1];

    if (tok.type === "punct") {
      if (tok.value === "(") {
        let callee = null;
        let owner = null;
        if (prev?.type === "ident" && !NOT_CALLEES.has(prev.value)) {
          callee = prev.value;
          if (prev2?.value === "." || prev2?.value === "?.") owner = prev3?.type === "ident" ? prev3.value : null;
        } else if (prev?.value === "?." && prev2?.type === "ident") {
          callee = prev2.value;
        }
        frames.push({ open: "(", callee, owner, arg: 0, arg0: undefined });
      } else if (tok.value === "[") {
        frames.push({ open: "[" });
      } else if (tok.value === "{") {
        frames.push({ open: "{", prop: null });
      } else if (tok.value === ")" || tok.value === "]" || tok.value === "}") {
        frames.pop();
      } else if (tok.value === ",") {
        if (top?.open === "(") top.arg++;
        else if (top?.open === "{") top.prop = null;
      } else if (tok.value === ":" && top?.open === "{"
        && (prev?.type === "ident" || prev?.type === "str" || prev?.type === "num")
        && (prev2?.value === "{" || prev2?.value === ",")) {
        top.prop = prev.value;
      }
      continue;
    }
    if (tok.type !== "str") continue;

    // Contextes qui ne sont jamais des textes affichés.
    if (top?.open === "(" && top.arg === 0 && top.arg0 === undefined) top.arg0 = tok.value;
    if (top?.open === "{" && next?.value === ":" && (prev?.value === "{" || prev?.value === ",")) continue; // clé
    if (prev?.type === "ident" && (prev.value === "from" || prev.value === "import" || prev.value === "case")) continue;
    if (COMPARISONS.has(prev?.value) || COMPARISONS.has(next?.value) || next?.value === "in") continue;
    if (frames.some((f) => f.open === "(" && T_FUNCS.has(f.callee))) continue;
    if (ignoredLiteral(tok)) continue;

    // Affectation ou valeur par défaut : nom = "texte".
    if (prev?.value === "=" && prev2?.type === "ident") {
      const kind = classifyName(prev2.value);
      if (kind === "tech") continue;
      if (kind) {
        report(tok, kind);
        continue;
      }
    }

    // Cadre englobant significatif : on traverse crochets et parenthèses de groupement.
    let frame = null;
    for (let f = frames.length - 1; f >= 0; f--) {
      const fr = frames[f];
      if (fr.open === "[" || (fr.open === "(" && !fr.callee)) continue;
      frame = fr;
      break;
    }

    let rule = null;
    if (frame?.open === "(") {
      if (CONSOLE_OBJECTS.has(frame.owner)) continue;
      if (frame.callee === "h") {
        if (frame.arg < 2) continue;
        rule = "h-child";
      } else if (TOAST_FUNCS.has(frame.callee)) {
        if (frame.arg !== 0) continue;
        rule = "toast";
      } else if (frame.callee === "setAttribute") {
        if (frame.arg !== 1) continue;
        const kind = classifyName(frame.arg0 ?? "");
        if (kind === "tech" || (!kind && !looksLikeProse(tok.value))) continue;
        rule = kind || "prose";
      } else if (TECH_CALLS.has(frame.callee)) {
        continue;
      }
    } else if (frame?.open === "{" && frame.prop) {
      const kind = classifyName(frame.prop);
      if (kind === "tech") continue;
      rule = kind;
    }
    if (!rule) {
      if (!looksLikeProse(tok.value)) continue;
      rule = "prose";
    }
    report(tok, rule);
  }
  return findings;
}

/** Fichiers .js et .mjs à analyser sous les cibles, triés. */
export function listTargets(targets, root = ROOT) {
  const out = [];
  const walk = (abs) => {
    const st = statSync(abs);
    if (st.isDirectory()) {
      for (const name of readdirSync(abs).sort()) walk(join(abs, name));
    } else if (/\.m?js$/.test(abs)) {
      // Chemin relatif au dépôt, ou absolu pour un fichier hors du dépôt.
      let rel = relative(root, abs).replace(/\\/g, "/");
      if (rel.startsWith("../") || /^[a-z]:/i.test(rel)) rel = abs.replace(/\\/g, "/");
      if (!SKIP_RE.test(rel)) out.push(rel);
    }
  };
  for (const t of targets) {
    const abs = resolve(root, t);
    if (existsSync(abs)) walk(abs);
  }
  return [...new Set(out)].sort();
}

/** Point d'entrée ; renvoie le code de sortie. */
export function main(argv = process.argv.slice(2), log = console) {
  const strict = argv.includes("--strict");
  const json = argv.includes("--json");
  const unknown = argv.filter((a) => a.startsWith("--") && a !== "--strict" && a !== "--json");
  if (unknown.length) {
    log.error(`lint-strings : option inconnue : ${unknown.join(" ")}`);
    return 2;
  }
  const paths = argv.filter((a) => !a.startsWith("--"));
  const files = listTargets(paths.length ? paths : DEFAULT_TARGETS);
  const findings = files.flatMap((f) => lintSource(readFileSync(resolve(ROOT, f), "utf8"), f));
  if (json) {
    log.log(JSON.stringify({ total: findings.length, files: files.length, findings }, null, 2));
  } else {
    for (const f of findings) log.log(`${f.file}:${f.line}: ${f.text.replace(/\s+/g, " ")}`);
    const mode = strict ? "mode bloquant" : "mode rapport";
    log.log(`lint-strings : ${findings.length} texte(s) en dur à passer par t(), dans ${files.length} fichier(s) analysé(s) (${mode}).`);
  }
  return strict && findings.length > 0 ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = main();
}
