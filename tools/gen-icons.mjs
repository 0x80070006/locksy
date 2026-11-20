#!/usr/bin/env node
// Générateur du sprite d'icônes (cahier 00, §2.6 et contrat C7.4).
//
// design/icons/<nom>.svg (24×24, trait 1,75, currentColor) → web/icons/sprite.svg,
// un <symbol id="<nom>"> par icône, les attributs de trait portés par les enfants.
//
// Les sources passent par une liste blanche stricte. Le générateur REFUSE
// (code 1, message clair) : <script>, <style>, <foreignObject>, un attribut
// on…=, un href ou xlink:href qui n'est pas un fragment local « #… », un DTD
// ou une entité, un fichier sans viewBox "0 0 24 24", un nom qui n'est pas en
// minuscules et tirets, ainsi que tout élément ou attribut hors liste blanche.
//
// Usage : node tools/gen-icons.mjs [--check] [--src <dossier>] [--out <fichier>]
// Aucune dépendance.

import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const ICONS_DIR = "design/icons";
export const SPRITE_PATH = "web/icons/sprite.svg";

/** Icônes exigées par le cahier (§2.6) et le contrat C7.4. */
export const REQUIRED_ICONS = Object.freeze([
  "copy", "eye", "eye-off", "lock", "unlock", "key", "note", "card", "id", "ssh", "star", "star-filled",
  "share", "link", "trash", "restore", "more", "plus", "search", "close", "check", "warn", "error", "info",
  "shield", "user", "users", "settings", "logout", "generate", "history", "attachment", "external",
  "chevron-right", "chevron-down", "arrow-left", "filter", "download", "upload", "qr", "clock", "building",
  "server", "mail", "menu", "edit", "folder", "refresh", "vault", "health",
]);

const NAME = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const SHAPES = new Set(["path", "circle", "rect", "line", "polyline", "polygon", "ellipse"]);
const GEOMETRY = new Set(["d", "cx", "cy", "r", "rx", "ry", "x", "y", "width", "height", "x1", "y1", "x2", "y2", "points"]);
/** Attributs de présentation hérités de la racine, dans cet ordre, par chaque enfant. */
const PAINT = ["fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin"];
const ROOT_ATTRS = new Set(["xmlns", "viewBox", ...PAINT]);
const SAFE_VALUE = /^[-\w.,# ]*$/;

/** Erreur de validation d'une icône (message destiné à l'auteur du SVG). */
export class IconError extends Error {}

function parseAttrs(raw, where) {
  const attrs = [];
  const rest = raw.replace(/([A-Za-z_][-\w:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g, (_, k, a, b) => {
    attrs.push([k, a ?? b]);
    return "";
  });
  if (rest.replace(/\/\s*$/, "").trim()) throw new IconError(`${where} : attribut illisible « ${rest.trim()} ».`);
  return attrs;
}

/**
 * Valide le texte d'une icône et renvoie ses enfants normalisés :
 * [{ tag, attrs: [[nom, valeur], …] }], attributs de trait compris.
 */
export function parseIcon(name, text) {
  const where = `${name}.svg`;
  if (!NAME.test(name)) throw new IconError(`${where} : nom refusé, seules les minuscules, chiffres et tirets sont admis.`);
  const dangers = [
    [/<\s*script/i, "balise <script> interdite"],
    [/<\s*style/i, "balise <style> interdite"],
    [/<\s*foreignObject/i, "balise <foreignObject> interdite"],
    [/<!\s*(DOCTYPE|ENTITY)/i, "DTD ou entité interdite"],
    [/[\s"']on[a-z]+\s*=/i, "attribut d'événement on…= interdit"],
    [/javascript:/i, "URL javascript: interdite"],
  ];
  for (const [re, msg] of dangers) if (re.test(text)) throw new IconError(`${where} : ${msg}.`);
  for (const m of text.matchAll(/(?:xlink:)?href\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)) {
    const target = (m[1] ?? m[2]).trim();
    if (!target.startsWith("#")) throw new IconError(`${where} : lien externe interdit (href="${target}"), seul un fragment local « #… » est admis.`);
  }

  const body = text.replace(/<!--[\s\S]*?-->/g, "").replace(/<\?xml[\s\S]*?\?>/, "").trim();
  const root = /^<svg\b([^>]*)>([\s\S]*)<\/svg>$/.exec(body);
  if (!root) throw new IconError(`${where} : le fichier doit contenir un unique élément <svg>…</svg>.`);
  const rootAttrs = parseAttrs(root[1], where);
  const viewBox = rootAttrs.find(([k]) => k === "viewBox")?.[1];
  if (viewBox?.trim().split(/\s+/).join(" ") !== "0 0 24 24") throw new IconError(`${where} : viewBox "0 0 24 24" obligatoire.`);
  for (const [k, v] of rootAttrs) {
    if (!ROOT_ATTRS.has(k)) throw new IconError(`${where} : attribut <svg ${k}> non autorisé.`);
    if (k !== "xmlns" && !SAFE_VALUE.test(v)) throw new IconError(`${where} : valeur refusée pour ${k}.`);
  }
  const inherited = PAINT.map((k) => [k, rootAttrs.find(([a]) => a === k)?.[1]]).filter(([, v]) => v !== undefined);

  const children = [];
  const rest = root[2].replace(/<([A-Za-z][-\w:]*)\b([^>]*?)\/>/g, (_, tag, raw) => {
    if (!SHAPES.has(tag)) throw new IconError(`${where} : élément <${tag}> non autorisé.`);
    const own = parseAttrs(raw, where);
    for (const [k, v] of own) {
      if (!GEOMETRY.has(k) && !PAINT.includes(k)) throw new IconError(`${where} : attribut ${k} non autorisé sur <${tag}>.`);
      if (!SAFE_VALUE.test(v)) throw new IconError(`${where} : valeur refusée pour ${k}.`);
    }
    const names = new Set(own.map(([k]) => k));
    children.push({ tag, attrs: [...own, ...inherited.filter(([k]) => !names.has(k))] });
    return "";
  });
  if (rest.trim()) throw new IconError(`${where} : contenu non autorisé « ${rest.trim().slice(0, 60)} » (seules des formes auto-fermantes sont admises).`);
  if (!children.length) throw new IconError(`${where} : aucune forme.`);
  return children;
}

/** Sprite à partir de { nom: enfants } ; ordre alphabétique, sortie déterministe. */
export function buildSprite(icons) {
  const lines = [
    '<svg xmlns="http://www.w3.org/2000/svg">',
    "<!-- Fichier généré par tools/gen-icons.mjs, ne pas modifier. Source : design/icons/*.svg. -->",
  ];
  for (const name of Object.keys(icons).sort()) {
    const kids = icons[name].map(({ tag, attrs }) => `<${tag} ${attrs.map(([k, v]) => `${k}="${v}"`).join(" ")}/>`).join("");
    lines.push(`<symbol id="${name}" viewBox="0 0 24 24">${kids}</symbol>`);
  }
  lines.push("</svg>");
  return `${lines.join("\n")}\n`;
}

/** Lit et valide toutes les icônes d'un dossier : { nom: enfants }. */
export function loadIcons(dir) {
  const icons = {};
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".svg")).sort()) {
    const name = file.slice(0, -".svg".length);
    icons[name] = parseIcon(name, readFileSync(join(dir, file), "utf8"));
  }
  return icons;
}

/**
 * Génère (ou compare) le sprite. Renvoie { stale: bool, missing: [noms] }.
 * Lève IconError sur une source refusée.
 */
export function run({ src = join(repo, ICONS_DIR), out = join(repo, SPRITE_PATH), check = false, requireAll = true } = {}) {
  const icons = loadIcons(src);
  const missing = requireAll ? REQUIRED_ICONS.filter((n) => !(n in icons)) : [];
  if (missing.length) return { stale: false, missing };
  const content = buildSprite(icons);
  const stale = !existsSync(out) || readFileSync(out, "utf8") !== content;
  if (stale && !check) writeFileSync(out, content);
  return { stale, missing };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const argv = process.argv.slice(2);
  const opt = (flag) => (argv.includes(flag) ? resolve(argv[argv.indexOf(flag) + 1]) : undefined);
  const check = argv.includes("--check");
  try {
    const src = opt("--src");
    const { stale, missing } = run({ src, out: opt("--out"), check, requireAll: !src });
    if (missing.length) {
      console.error(`gen-icons : icônes manquantes dans design/icons : ${missing.join(", ")}.`);
      process.exitCode = 1;
    } else if (check && stale) {
      console.error("gen-icons : web/icons/sprite.svg est périmé. Relancez : node tools/gen-icons.mjs");
      process.exitCode = 1;
    } else {
      console.log(check ? "Sprite à jour." : stale ? "écrit : web/icons/sprite.svg" : "Sprite déjà à jour.");
    }
  } catch (e) {
    console.error(e instanceof IconError ? `gen-icons : refusé, ${e.message}` : `gen-icons : ${e.message}`);
    process.exitCode = 1;
  }
}
