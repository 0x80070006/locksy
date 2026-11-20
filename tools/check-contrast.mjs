#!/usr/bin/env node
// Vérification des contrastes du design system (cahier 00, §2.2 et règle A13).
//
// Lit design/tokens.json, résout chaque thème (clair, sombre, et leurs
// variantes « contraste renforcé » qui ne portent que des surcharges), puis
// calcule le ratio WCAG 2.x de chaque paire déclarée dans « contrast ».
// Sortie : une ligne par paire et par thème. Code 1 au premier ratio sous son
// seuil, ou si un ratio attendu (« expect », valeurs du cahier) n'est pas
// reproduit à 0,01 près.
//
// Usage : node tools/check-contrast.mjs [--tokens <chemin>]
// Aucune dépendance.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Thèmes vérifiés, dans l'ordre d'affichage. */
export const THEMES = ["light", "dark", "light-more", "dark-more"];

/** Écart toléré entre le ratio calculé et le ratio annoncé par le cahier. */
export const TOLERANCE = 0.01;

/** Couleur « #rgb » ou « #rrggbb » → [r, g, b] (0-255), ou null si illisible. */
export function parseHex(hex) {
  const m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(String(hex).trim());
  if (!m) return null;
  const s = m[1].length === 3 ? [...m[1]].map((c) => c + c).join("") : m[1];
  return [0, 2, 4].map((i) => parseInt(s.slice(i, i + 2), 16));
}

/** Luminance relative WCAG 2.x d'une couleur [r, g, b]. */
export function luminance([r, g, b]) {
  const lin = (c) => {
    const v = c / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

/** Ratio de contraste WCAG 2.x entre deux couleurs hexadécimales (≥ 1). */
export function ratio(a, b) {
  const ca = parseHex(a);
  const cb = parseHex(b);
  if (!ca || !cb) throw new Error(`Couleur illisible : ${ca ? b : a}`);
  const [hi, lo] = [luminance(ca), luminance(cb)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** Palette complète d'un thème : les variantes « -more » héritent de leur base. */
export function resolveTheme(tokens, theme) {
  const base = theme.endsWith("-more") ? theme.slice(0, -"-more".length) : null;
  return { ...(base ? tokens.color[base] : {}), ...tokens.color[theme] };
}

/** Valeur d'une référence de paire : nom de couleur du thème ou « tile.N ». */
function lookup(tokens, palette, ref) {
  const tile = /^tile\.(\d+)$/.exec(ref);
  const value = tile ? tokens.tile[Number(tile[1])] : palette[ref];
  if (value === undefined) throw new Error(`Jeton de couleur inconnu dans une paire : ${ref}`);
  return value;
}

/**
 * Calcule toutes les paires. Renvoie la liste des résultats, sans rien afficher :
 * [{ fg, bg, theme, ratio, min, expect, ok, reason }].
 */
export function checkAll(tokens) {
  const out = [];
  for (const pair of tokens.contrast) {
    for (const theme of pair.themes || THEMES) {
      const palette = resolveTheme(tokens, theme);
      const r = ratio(lookup(tokens, palette, pair.fg), lookup(tokens, palette, pair.bg));
      const expect = pair.expect?.[theme];
      let reason = null;
      if (r < pair.min) reason = `sous le seuil ${pair.min}`;
      else if (expect !== undefined && Math.abs(Math.round(r * 100) / 100 - expect) > TOLERANCE + 1e-9) {
        reason = `attendu ${expect.toFixed(2)} (cahier)`;
      }
      out.push({ fg: pair.fg, bg: pair.bg, theme, ratio: r, min: pair.min, expect, ok: !reason, reason });
    }
  }
  return out;
}

/** Format français d'un ratio : « 4,53 ». */
const fr = (n) => n.toFixed(2).replace(".", ",");

function main(argv) {
  const i = argv.indexOf("--tokens");
  const path = i >= 0 ? resolve(argv[i + 1]) : join(repo, "design", "tokens.json");
  const tokens = JSON.parse(readFileSync(path, "utf8"));
  const results = checkAll(tokens);
  for (const r of results) {
    const line = `${r.theme.padEnd(10)} ${r.fg.padEnd(14)} sur ${r.bg.padEnd(12)} ${fr(r.ratio).padStart(6)}:1  (seuil ${fr(r.min)})`;
    if (!r.ok) {
      console.error(`ÉCHEC  ${line} : ${r.reason}`);
      return 1;
    }
    console.log(`ok     ${line}`);
  }
  console.log(`${results.length} vérifications de contraste réussies.`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (e) {
    console.error(`check-contrast : ${e.message}`);
    process.exitCode = 1;
  }
}
