// Tests du design system (lot L1, cahier 00 §2 et fiche L1) : générateurs
// déterministes, contrastes, refus des SVG dangereux, règles CSS (R4, budget,
// @import seuls, contrats de classes) et constantes Rust.
// Lancement : node --test tools/test

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildCss, buildRust, loadTokens, run as runTokens, validateTokens } from "../gen-tokens.mjs";
import { checkAll, ratio } from "../check-contrast.mjs";
import { REQUIRED_ICONS, parseIcon, run as runIcons } from "../gen-icons.mjs";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (p) => readFileSync(join(repo, p), "utf8");
const cssDir = join(repo, "web", "css");
const cssFiles = () => readdirSync(cssDir).filter((f) => f.endsWith(".css")).sort();
const stripComments = (css) => css.replace(/\/\*[\s\S]*?\*\//g, "");
const node = (args) => spawnSync(process.execPath, args, { cwd: repo, encoding: "utf8" });

/** Budget du cahier §6.5 : « CSS brut ≤ 40 Ko ». */
const CSS_BUDGET = 40 * 1024;

const VALID_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M5 12h14"/></svg>\n';

// ------------------------------------------------------------------ Générateurs

test("gen-tokens --check : les fichiers générés sont à jour", () => {
  assert.deepEqual(runTokens({ check: true }), []);
  const r = node(["tools/gen-tokens.mjs", "--check"]);
  assert.equal(r.status, 0, r.stderr);
});

test("gen-tokens : sortie déterministe, LF, en-tête et saut de ligne final", () => {
  const tokens = loadTokens();
  for (const out of [buildCss(tokens), buildRust(tokens)]) {
    assert.ok(out.includes("Fichier généré par tools/gen-tokens.mjs, ne pas modifier"));
    assert.ok(!out.includes("\r"));
    assert.ok(out.endsWith("\n") && !out.endsWith("\n\n"));
  }
  assert.equal(buildCss(loadTokens()), buildCss(loadTokens()));
  assert.equal(buildRust(loadTokens()), buildRust(loadTokens()));
});

test("gen-tokens refuse un tokens.json incohérent", () => {
  const broken = structuredClone(loadTokens());
  delete broken.color.dark.focus;
  assert.throws(() => validateTokens(broken), /color\.dark/);
  const badMore = structuredClone(loadTokens());
  badMore.color["light-more"].inconnu = "#000000";
  assert.throws(() => validateTokens(badMore), /ne surcharge aucun jeton/);
});

test("gen-icons --check : le sprite est à jour et contient toutes les icônes exigées", () => {
  assert.deepEqual(runIcons({ check: true }), { stale: false, missing: [] });
  const r = node(["tools/gen-icons.mjs", "--check"]);
  assert.equal(r.status, 0, r.stderr);
  const sprite = read("web/icons/sprite.svg");
  for (const name of REQUIRED_ICONS) assert.ok(sprite.includes(`<symbol id="${name}" viewBox="0 0 24 24">`), name);
  assert.ok(!/\sstyle=/.test(sprite), "aucun attribut style dans le sprite");
  // Attributs de trait portés par les enfants, pas par la racine.
  assert.match(sprite, /<path d="[^"]+" fill="none" stroke="currentColor" stroke-width="1.75"/);
});

// ------------------------------------------------------------------ Icônes : refus

const DANGEROUS = {
  script: ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><script>alert(1)</script><path d="M1 1h2"/></svg>', /<script>/],
  style: ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><style>path{fill:red}</style><path d="M1 1h2"/></svg>', /<style>/],
  foreign: ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><foreignObject/><path d="M1 1h2"/></svg>', /<foreignObject>/],
  onload: ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" onload="x()"><path d="M1 1h2"/></svg>', /on…=/],
  onclick: ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path onclick="x()" d="M1 1h2"/></svg>', /on…=/],
  href: ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><use href="https://exemple.test/a.svg#x"/></svg>', /lien externe/],
  xlink: ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><use xlink:href="data:image/svg+xml;base64,AA"/></svg>', /lien externe/],
  javascript: ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><a href="javascript:x()"><path d="M1 1h2"/></a></svg>', /javascript:|lien externe/],
  entity: ['<!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M1 1h2"/></svg>', /DTD/],
  noviewbox: ['<svg xmlns="http://www.w3.org/2000/svg"><path d="M1 1h2"/></svg>', /viewBox/],
  viewbox32: ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><path d="M1 1h2"/></svg>', /viewBox/],
  image: ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><image width="2" height="2"/></svg>', /<image> non autorisé/],
};

test("gen-icons : parseIcon refuse chaque SVG dangereux avec un message clair", () => {
  for (const [name, [svg, message]] of Object.entries(DANGEROUS)) {
    assert.throws(() => parseIcon(name, svg), message, name);
  }
  assert.throws(() => parseIcon("Copie", VALID_SVG), /minuscules/);
  assert.throws(() => parseIcon("copie_2", VALID_SVG), /minuscules/);
  assert.equal(parseIcon("copie-2", VALID_SVG).length, 1);
});

test("gen-icons (CLI) : code 1 sur un fichier dangereux, aucun sprite écrit", () => {
  const dir = mkdtempSync(join(tmpdir(), "locksy-icons-"));
  try {
    for (const [name, [svg]] of Object.entries(DANGEROUS)) {
      const src = join(dir, name);
      mkdirSync(src);
      writeFileSync(join(src, "ok.svg"), VALID_SVG);
      writeFileSync(join(src, `${name}.svg`), svg);
      const out = join(dir, `${name}-sprite.svg`);
      const r = node(["tools/gen-icons.mjs", "--src", src, "--out", out]);
      assert.equal(r.status, 1, `${name} : ${r.stdout}`);
      assert.match(r.stderr, /gen-icons : refusé/, name);
      assert.throws(() => readFileSync(out), /ENOENT/, `${name} : sprite écrit malgré le refus`);
    }
    const bad = join(dir, "nom");
    mkdirSync(bad);
    writeFileSync(join(bad, "Majuscule.svg"), VALID_SVG);
    assert.equal(node(["tools/gen-icons.mjs", "--src", bad, "--out", join(dir, "n.svg")]).status, 1);
    // Une source saine produit un sprite.
    const good = join(dir, "sain");
    mkdirSync(good);
    writeFileSync(join(good, "trait.svg"), VALID_SVG);
    const out = join(dir, "sain.svg");
    assert.equal(node(["tools/gen-icons.mjs", "--src", good, "--out", out]).status, 0);
    assert.match(readFileSync(out, "utf8"), /<symbol id="trait" viewBox="0 0 24 24"><path d="M5 12h14" fill="none"/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ Contrastes

test("check-contrast : formule WCAG et ratios du cahier reproduits", () => {
  assert.equal(ratio("#000000", "#ffffff"), 21);
  assert.equal(ratio("#fff", "#ffffff"), 1);
  assert.equal(ratio("#142033", "#ffffff").toFixed(2), "16.35");
  const results = checkAll(loadTokens());
  const failed = results.filter((r) => !r.ok);
  assert.deepEqual(failed, []);
  for (const theme of ["light", "dark", "light-more", "dark-more"]) {
    assert.ok(results.some((r) => r.theme === theme), `aucune paire vérifiée en ${theme}`);
  }
  const r = node(["tools/check-contrast.mjs"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /light-more .* sur surface/);
});

test("check-contrast (CLI) : code 1 au premier ratio sous son seuil", () => {
  const dir = mkdtempSync(join(tmpdir(), "locksy-contrast-"));
  try {
    const tokens = loadTokens();
    tokens.color.light["text-muted"] = "#b0b8c4";
    const file = join(dir, "tokens.json");
    writeFileSync(file, JSON.stringify(tokens));
    const r = node(["tools/check-contrast.mjs", "--tokens", file]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /ÉCHEC .*text-muted/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tokens.json : surfaces lues par le contrôle d'accent du serveur (L4)", () => {
  const tokens = JSON.parse(read("design/tokens.json"));
  assert.equal(tokens.color.light.surface, "#ffffff");
  assert.equal(tokens.color.dark.surface, "#161e28");
  assert.equal(tokens.tile.length, 8);
});

// ------------------------------------------------------------------ CSS

test("R4 : aucune couleur en dur hors tokens.css", () => {
  const re = /:\s*#[0-9a-fA-F]{3,8}\b|rgba?\(/;
  for (const f of cssFiles().filter((f) => f !== "tokens.css")) {
    readFileSync(join(cssDir, f), "utf8").split("\n").forEach((line, i) => {
      assert.ok(!re.test(line), `${f}:${i + 1} : ${line.trim()}`);
    });
  }
});

test("app.css ne contient que les @import, dans l'ordre du contrat C7.3", () => {
  const lines = stripComments(read("web/css/app.css")).split("\n").map((l) => l.trim()).filter(Boolean);
  assert.deepEqual(lines, ["tokens", "base", "components", "layout"].map((n) => `@import url("${n}.css");`));
});

test("budget : CSS brut ≤ 40 Ko, legacy.css supprimé (fin de vague 2)", () => {
  assert.ok(!cssFiles().includes("legacy.css"), "legacy.css ne doit plus exister");
  const total = cssFiles().reduce((a, f) => a + readFileSync(join(cssDir, f)).length, 0);
  assert.ok(total <= CSS_BUDGET, `CSS ${total} octets > ${CSS_BUDGET}`);
});

test("CSS : aucune opacité d'état hors :disabled", () => {
  for (const f of cssFiles()) {
    for (const m of stripComments(readFileSync(join(cssDir, f), "utf8")).matchAll(/([^{}]*)\{([^{}]*)\}/g)) {
      if (/(^|;)\s*opacity\s*:/.test(m[2])) assert.match(m[1], /:disabled/, `${f} : opacity sur « ${m[1].trim()} »`);
    }
  }
});

test("CSS : aucune largeur fixe au-dessus de 360 px hors min() ou max()", () => {
  const re = /(?:^|[;{\s])((?:min-|max-)?(?:width|inline-size))\s*:\s*([^;}]+)/g;
  for (const f of cssFiles()) {
    for (const m of stripComments(readFileSync(join(cssDir, f), "utf8")).matchAll(re)) {
      const value = m[2].trim();
      if (/\b(min|max|clamp|calc)\(/.test(value)) continue;
      for (const [, n, unit] of value.matchAll(/([\d.]+)(px|rem|em)\b/g)) {
        const px = unit === "px" ? Number(n) : Number(n) * 16;
        assert.ok(px <= 360, `${f} : ${m[1]}: ${value}`);
      }
    }
  }
});

test("CSS : media queries en em, aucune police ni ressource distante", () => {
  for (const f of cssFiles()) {
    const css = stripComments(readFileSync(join(cssDir, f), "utf8"));
    for (const [q] of css.matchAll(/@media[^{]*/g)) {
      if (/width/.test(q)) assert.match(q, /\d(\.\d+)?em\)/, `${f} : ${q}`);
      assert.ok(!/\dpx/.test(q), `${f} : ${q}`);
    }
    assert.ok(!/@font-face/.test(css), `${f} : @font-face`);
    const urls = [...css.matchAll(/url\(\s*"?([^")]*)/g)].map((m) => m[1]);
    for (const u of urls) assert.match(u, /^[a-z-]+\.css$/, `${f} : url(${u})`);
  }
});

test("tokens.css : thèmes, contraste renforcé, pointeur et densité (C7.2)", () => {
  const css = read("web/css/tokens.css");
  for (const needle of [
    ':root,\n[data-theme="light"] {',
    '[data-theme="dark"] {',
    '@media (prefers-color-scheme: dark) {\n  :root:not([data-theme="light"]) {',
    '[data-contrast="more"] {',
    '[data-theme="dark"][data-contrast="more"] {',
    "@media (prefers-contrast: more) {\n  :root:not([data-contrast]) {",
    '[data-theme="dark"]:not([data-contrast]) {',
    "@media (pointer: coarse) {",
    '[data-density="compact"] {',
    "--color-text-muted:",
    "--control-h: 2.5rem;",
    "--row-h: 3.5rem;",
  ]) assert.ok(css.includes(needle), needle);
});

test("aucun alias historique ; chaque variable du popup de l'extension est définie", () => {
  assert.equal(loadTokens().legacy, undefined);
  const css = read("web/css/tokens.css");
  const defined = new Set([...css.matchAll(/^\s*(--[\w-]+):/gm)].map((m) => m[1]));
  for (const name of ["--bg", "--ink", "--line", "--bad"]) assert.ok(!defined.has(name), name);
  const popup = read("extension/src/popup.css");
  for (const [, name] of popup.matchAll(/var\((--[\w-]+)/g)) assert.ok(defined.has(name), `popup.css : ${name}`);
});

test("classes contractuelles (annexe B.2 et C7.3) toutes stylées", () => {
  const css = cssFiles().map((f) => stripComments(readFileSync(join(cssDir, f), "utf8"))).join("\n");
  const classes = `c-button c-button--primary c-button--quiet c-button--danger c-button--icon c-field c-field__label c-field__help
    c-field__error c-field__control c-field__suffix c-field__count c-input c-select c-textarea c-toggle c-segmented c-radio-cards
    c-chips c-search c-password__strength c-password__caps c-otp c-secret-row__value c-secret-row__actions c-secret__group
    c-secret__digit c-secret__symbol c-totp__code c-totp__ring c-strength c-strength__bar c-strength__label c-issue c-audience
    c-badge c-avatar c-card c-stat c-alert c-status c-empty c-skeleton c-dialog c-dialog__form c-dialog__title c-dialog__desc
    c-dialog__actions c-panel c-popover c-menu c-menu__item c-menu__sep c-tabs__list c-tabs__tab c-tabs__panel c-sidenav
    c-sidenav__item c-sidenav__count c-sidenav__group c-wizard c-wizard__steps c-wizard__step c-item-list c-item-list__row
    c-item-list__main c-item-list__title c-item-list__sub c-item-list__actions c-item-list__check c-table c-table__scroll
    c-table__bulkbar c-table__pager c-table__select c-filters c-setting c-setting__head c-setting__badges c-setting__mode
    c-setting__reset c-setting__value c-policy-hint c-diff c-diff__row c-save-bar c-toast c-toasts c-qr-drop c-icon c-tech
    c-skip-link c-kbd c-hotkeys l-shell l-sidebar l-topbar l-main l-split l-stack l-cluster l-grid l-actionbar
    u-sr-only u-mono u-muted u-nowrap`.split(/\s+/);
  for (const c of classes) assert.match(css, new RegExp(`\\.${c}(?![\\w-])`), `.${c}`);
  for (const sel of ['.c-icon[data-size="sm"]', '.c-dialog[data-size="lg"]', '.c-panel[data-mobile="sheet"]', '.c-diff__row[data-lowered]',
    '.c-strength[data-level="4"]', '[data-tone="danger"]', '.l-stack[data-gap="6"]', 'html[data-text-scale="125"]', "@media (forced-colors: active)",
    "@media (prefers-reduced-motion: reduce)", "::backdrop", ":focus-visible"]) {
    assert.ok(css.includes(sel), sel);
  }
});

// ------------------------------------------------------------------ Rust

test("theme_tokens.rs : forme du contrat C7.5", () => {
  const rs = read("crates/locksy-desktop/src/theme_tokens.rs");
  for (const needle of ["#![allow(dead_code)]", "use eframe::egui::Color32;", "pub mod light {", "pub mod dark {", "pub mod light_more {",
    "pub mod dark_more {", "pub const TILES: [Color32; 8]", "pub const SPACE_1: f32 = 4.0;", "pub const SPACE_7: f32 = 48.0;",
    "pub const RADIUS_FULL: f32 = 999.0;", "pub const TEXT_XXL: f32 = 28.0;", "pub const TEXT_CODE: f32 = 24.0;", "pub const CONTROL_H: f32 = 40.0;",
    "pub const ROW_H_COMFORTABLE: f32 = 56.0;", "pub const ROW_H_COMPACT: f32 = 44.0;",
    "pub const SURFACE: Color32 = Color32::from_rgb(22, 30, 40);", "pub const BORDER_STRONG: Color32 = Color32::from_rgb(74, 85, 102);",
    "pub const SCRIM: Color32 = Color32::from_rgba_premultiplied(9, 14, 23, 115);", "pub const SCRIM: Color32 = Color32::from_rgba_premultiplied(0, 0, 0, 153);"]) {
    assert.ok(rs.includes(needle), needle);
  }
  assert.ok(!/include_(str|bytes)!/.test(rs), "aucune inclusion de fichier hors crate (C0-D8)");
});
