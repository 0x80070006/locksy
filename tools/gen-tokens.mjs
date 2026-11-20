#!/usr/bin/env node
// Générateur des jetons du design system (cahier 00, §2.1, 2.7 et contrat C7).
//
// design/tokens.json → web/css/tokens.css (propriétés personnalisées CSS)
//                    → crates/locksy-desktop/src/theme_tokens.rs (constantes egui)
//
// Les fonctions exportées sont pures : même entrée, même sortie, octet pour
// octet (ordre fixe, fins de ligne LF, saut de ligne final).
//
// Usage : node tools/gen-tokens.mjs           écrit les fichiers générés
//         node tools/gen-tokens.mjs --check   code 1 si un fichier diffère
// Aucune dépendance.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const TOKENS_PATH = "design/tokens.json";
export const CSS_PATH = "web/css/tokens.css";
export const RUST_PATH = "crates/locksy-desktop/src/theme_tokens.rs";

const HEADER = "Fichier généré par tools/gen-tokens.mjs, ne pas modifier. Source : design/tokens.json.";
const BASE_THEMES = ["light", "dark"];
const MORE_THEMES = ["light-more", "dark-more"];
const THEME_LABELS = {
  light: "claire",
  dark: "sombre",
  "light-more": "claire en contraste renforcé",
  "dark-more": "sombre en contraste renforcé",
};
const HEX = /^#[0-9a-f]{6}$/;
const RGBA = /^rgb\((\d{1,3}) (\d{1,3}) (\d{1,3}) \/ (0|1|0?\.\d+)\)$/;

// ------------------------------------------------------------------ Contrôles

/** Vérifie la forme de tokens.json (C7.1) ; lève une erreur explicite sinon. */
export function validateTokens(tokens) {
  const fail = (msg) => {
    throw new Error(`design/tokens.json : ${msg}`);
  };
  const names = Object.keys(tokens.color?.light || {});
  if (!names.length) fail("color.light est vide.");
  for (const theme of BASE_THEMES) {
    const palette = tokens.color[theme] || fail(`thème ${theme} absent.`);
    const keys = Object.keys(palette);
    if (keys.join() !== names.join()) fail(`color.${theme} doit déclarer les mêmes jetons, dans le même ordre, que color.light.`);
    for (const [k, v] of Object.entries(palette)) {
      if (!HEX.test(v) && !RGBA.test(v)) fail(`color.${theme}.${k} : « ${v} » n'est ni #rrggbb ni rgb(r g b / a).`);
    }
  }
  for (const theme of MORE_THEMES) {
    for (const [k, v] of Object.entries(tokens.color[theme] || fail(`thème ${theme} absent.`))) {
      if (!names.includes(k)) fail(`color.${theme}.${k} ne surcharge aucun jeton existant.`);
      if (!HEX.test(v)) fail(`color.${theme}.${k} : « ${v} » n'est pas #rrggbb.`);
    }
  }
  if (!Array.isArray(tokens.tile) || tokens.tile.length !== 8 || !tokens.tile.every((c) => HEX.test(c))) {
    fail("tile doit contenir 8 couleurs #rrggbb.");
  }
  return tokens;
}

/** Lit et valide design/tokens.json. */
export function loadTokens(root = repo) {
  return validateTokens(JSON.parse(readFileSync(join(root, TOKENS_PATH), "utf8")));
}

// ------------------------------------------------------------------ CSS

/** 16 px = 1 rem : les dimensions suivent la taille du texte choisie. */
const rem = (px) => `${Number((px / 16).toFixed(4))}rem`;

/** Palette complète d'un thème « -more » : sa base plus ses surcharges. */
function resolved(tokens, theme) {
  const base = theme.replace(/-more$/, "");
  return { ...tokens.color[base], ...tokens.color[theme] };
}

/** Jetons surchargés par le contraste renforcé, union des deux thèmes. */
function moreKeys(tokens) {
  const set = new Set(MORE_THEMES.flatMap((t) => Object.keys(tokens.color[t])));
  return Object.keys(tokens.color.light).filter((k) => set.has(k));
}

function block(selector, decls, indent = "") {
  const body = decls.map(([k, v]) => `${indent}  ${k}: ${v};`).join("\n");
  return `${indent}${selector} {\n${body}\n${indent}}`;
}

const colorDecls = (palette, keys) => keys.map((k) => [`--color-${k}`, palette[k]]);

/** Contenu complet de web/css/tokens.css. */
export function buildCss(tokens) {
  validateTokens(tokens);
  const all = Object.keys(tokens.color.light);
  const more = moreKeys(tokens);
  const light = colorDecls(tokens.color.light, all);
  const dark = colorDecls(tokens.color.dark, all);
  const lightMore = colorDecls(resolved(tokens, "light-more"), more);
  const darkMore = colorDecls(resolved(tokens, "dark-more"), more);
  const scheme = (s) => [["color-scheme", s]];

  const dims = [
    ["--font-sans", tokens.font.sans],
    ["--font-mono", tokens.font.mono],
    ...Object.entries(tokens.text).flatMap(([k, t]) => [[`--text-${k}`, t.size], [`--leading-${k}`, String(t.line)]]),
    ...Object.entries(tokens.space).map(([k, px]) => [`--space-${k}`, rem(px)]),
    ...Object.entries(tokens.radius).map(([k, px]) => [`--radius-${k}`, `${px}px`]),
    ...Object.entries(tokens.shadow).map(([k, v]) => [`--shadow-${k}`, v]),
    ...Object.entries(tokens.duration).map(([k, ms]) => [`--duration-${k}`, `${ms}ms`]),
    ["--ease", tokens.ease],
    ["--control-h", rem(tokens.size["control-h"].fine)],
    ["--target-min", rem(tokens.size["target-min"].fine)],
    ["--row-h", rem(tokens.size["row-h"].comfortable)],
    ["--measure", tokens.size.measure],
    ...["sidebar-w", "list-w", "drawer-w", "detail-max"].map((k) => [`--${k}`, rem(tokens.size[k])]),
  ];

  const parts = [
    `/* ${HEADER} */`,
    block(':root,\n[data-theme="light"]', [...scheme("light"), ...light]),
    block('[data-theme="dark"]', [...scheme("dark"), ...dark]),
    `@media (prefers-color-scheme: dark) {\n${block(':root:not([data-theme="light"])', [...scheme("dark"), ...dark], "  ")}\n}`,
    "/* Contraste renforcé choisi */",
    block('[data-contrast="more"]', lightMore),
    block('[data-theme="dark"][data-contrast="more"]', darkMore),
    `@media (prefers-color-scheme: dark) {\n${block(':root:not([data-theme="light"])[data-contrast="more"]', darkMore, "  ")}\n}`,
    "/* Contraste renforcé du système */",
    `@media (prefers-contrast: more) {\n${block(":root:not([data-contrast])", lightMore, "  ")}\n${block('[data-theme="dark"]:not([data-contrast])', darkMore, "  ")}\n}`,
    `@media (prefers-contrast: more) and (prefers-color-scheme: dark) {\n${block(':root:not([data-theme="light"]):not([data-contrast])', darkMore, "  ")}\n}`,
    "/* Typographie, espacements, rayons, ombres, mouvement, dimensions */",
    block(":root", dims),
    `@media (pointer: coarse) {\n${block(":root", [["--control-h", rem(tokens.size["control-h"].coarse)], ["--target-min", rem(tokens.size["target-min"].coarse)]], "  ")}\n}`,
    block('[data-density="compact"]', [["--row-h", rem(tokens.size["row-h"].compact)]]),
  ];
  return `${parts.join("\n\n")}\n`;
}

// ------------------------------------------------------------------ Rust

const constName = (k) => k.toUpperCase().replace(/-/g, "_").replace(/^2XL$/, "XXL");
const f32 = (n) => (Number.isInteger(n) ? `${n}.0` : String(n));

function rgb(hex) {
  return [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
}

/** Expression Color32 d'une valeur de jeton (#rrggbb ou voile rgb(r g b / a) prémultiplié). */
function color32(value) {
  if (HEX.test(value)) return `Color32::from_rgb(${rgb(value).join(", ")})`;
  const m = RGBA.exec(value);
  const a = Number(m[4]);
  const [r, g, b] = [m[1], m[2], m[3]].map((c) => Math.round(Number(c) * a));
  return `Color32::from_rgba_premultiplied(${r}, ${g}, ${b}, ${Math.round(a * 255)})`;
}

/** Contenu complet de crates/locksy-desktop/src/theme_tokens.rs (contrat C7.5). */
export function buildRust(tokens) {
  validateTokens(tokens);
  const out = [
    `// ${HEADER}`,
    "// Couleurs et dimensions du design system pour le client Windows (egui), cahier 00, §2.7.",
    "#![allow(dead_code)]",
    "",
    "use eframe::egui::Color32;",
  ];
  for (const theme of [...BASE_THEMES, ...MORE_THEMES]) {
    const palette = theme.endsWith("-more") ? resolved(tokens, theme) : tokens.color[theme];
    out.push("", `/// Palette ${THEME_LABELS[theme]}.`);
    out.push(`pub mod ${theme.replace(/-/g, "_")} {`, "    use super::Color32;", "");
    for (const k of Object.keys(tokens.color.light)) {
      out.push(`    pub const ${constName(k)}: Color32 = ${color32(palette[k])};`);
    }
    out.push("}");
  }
  out.push("", "/// Couleurs des pastilles d'initiale, dans l'ordre de colorFor().");
  out.push(`pub const TILES: [Color32; ${tokens.tile.length}] = [`);
  for (const c of tokens.tile) out.push(`    ${color32(c)},`);
  out.push("];", "", "// Espacements, rayons et tailles de texte, en points.");
  for (const [k, px] of Object.entries(tokens.space)) out.push(`pub const SPACE_${k}: f32 = ${f32(px)};`);
  for (const [k, px] of Object.entries(tokens.radius)) out.push(`pub const RADIUS_${constName(k)}: f32 = ${f32(px)};`);
  for (const [k, t] of Object.entries(tokens.text)) out.push(`pub const TEXT_${constName(k)}: f32 = ${f32(t.px)};`);
  out.push(`pub const CONTROL_H: f32 = ${f32(tokens.size["control-h"].fine)};`);
  out.push(`pub const ROW_H_COMFORTABLE: f32 = ${f32(tokens.size["row-h"].comfortable)};`);
  out.push(`pub const ROW_H_COMPACT: f32 = ${f32(tokens.size["row-h"].compact)};`);
  return `${out.join("\n")}\n`;
}

// ------------------------------------------------------------------ CLI

/** Fichiers générés : [{ path relatif au dépôt, content }]. */
export function outputs(tokens) {
  return [
    { path: CSS_PATH, content: buildCss(tokens) },
    { path: RUST_PATH, content: buildRust(tokens) },
  ];
}

/** Écrit (ou compare en mode check) ; renvoie la liste des fichiers différents. */
export function run({ root = repo, check = false, log = console.log } = {}) {
  const stale = [];
  for (const { path, content } of outputs(loadTokens(root))) {
    const file = join(root, path);
    const current = existsSync(file) ? readFileSync(file, "utf8") : null;
    if (current === content) continue;
    stale.push(path);
    if (!check) {
      writeFileSync(file, content);
      log(`écrit : ${path}`);
    }
  }
  return stale;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const check = process.argv.includes("--check");
  try {
    const stale = run({ check });
    if (check && stale.length) {
      console.error(`Fichiers générés périmés : ${stale.join(", ")}. Relancez : node tools/gen-tokens.mjs`);
      process.exitCode = 1;
    } else if (check) {
      console.log("Jetons à jour.");
    }
  } catch (e) {
    console.error(`gen-tokens : ${e.message}`);
    process.exitCode = 1;
  }
}
