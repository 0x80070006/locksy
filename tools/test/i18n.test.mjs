// Tests du catalogue de textes (web/js/i18n.js), de son générateur
// (tools/gen-i18n.mjs) et du relevé des textes en dur (tools/lint-strings.mjs).
//   node --test tools/test
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, relative } from "node:path";
import { spawnSync } from "node:child_process";

import * as i18n from "../../web/js/i18n.js";
import { buildCatalog, renderJs, renderJson, prefixFor, topLevelKeys, ROOT, DEFAULT_SRC } from "../gen-i18n.mjs";
import { lintSource, tokenize, looksLikeProse } from "../lint-strings.mjs";
import { sharedClosure } from "../../extension/build.mjs";

const GEN = join(ROOT, "tools", "gen-i18n.mjs");
const LINT = join(ROOT, "tools", "lint-strings.mjs");
const SERVER_SRC = join(ROOT, "crates", "locksy-server", "src");
const WEB_JS = join(ROOT, "web", "js");

/** 18 novembre 2026, 14 h 20 à Paris (13 h 20 UTC). */
const NOV18 = Date.UTC(2026, 10, 18, 13, 20) / 1000;
const DAY = 86400;

before(() => i18n.configure({ timeZone: "Europe/Paris", dev: false }));
after(() => i18n.onMissing(null));

function tempDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "locksy-i18n-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function writeSources(dir, files) {
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), typeof content === "string" ? content : JSON.stringify(content, null, 2));
  }
}

function runNode(script, args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8", cwd: ROOT });
}

function walk(dir, filter, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, filter, out);
    else if (filter(full)) out.push(full);
  }
  return out;
}

// ------------------------------------------------------------------ t, plural

describe("t et plural", () => {
  test("texte simple et paramètres", () => {
    assert.equal(i18n.t("common.action.save"), "Enregistrer");
    assert.equal(i18n.t("common.title_suffix", { title: "Coffre" }), "Coffre · Locksy");
    assert.equal(i18n.t("common.state.empty_search", { q: "socite" }), "Aucun résultat pour « socite » dans tout le coffre.");
  });

  test("un paramètre absent laisse {nom}", () => {
    assert.equal(i18n.t("common.title_suffix"), "{title} · Locksy");
    assert.equal(i18n.t("common.title_suffix", { title: null }), "{title} · Locksy");
  });

  test("aucune interprétation HTML : le paramètre est recopié tel quel", () => {
    assert.equal(i18n.t("common.title_suffix", { title: "<b>x</b>" }), "<b>x</b> · Locksy");
  });

  test("pluriels 0, 1 et 2 (Intl.PluralRules fr-FR)", () => {
    assert.equal(i18n.plural("common.unit.days", 0), "0 jour");
    assert.equal(i18n.plural("common.unit.days", 1), "1 jour");
    assert.equal(i18n.plural("common.unit.days", 2), "2 jours");
    assert.equal(i18n.plural("common.unit.bytes", 1204), "1 204 octets");
    // t() avec un n numérique passe aussi par le pluriel.
    assert.equal(i18n.t("common.unit.minutes", { n: 1 }), "1 minute");
  });

  test("has", () => {
    assert.equal(i18n.has("common.app.name"), true);
    assert.equal(i18n.has("common.nexiste.pas"), false);
    assert.equal(i18n.has("constructor"), false);
  });

  test("clé absente : la clé est renvoyée et signalée une seule fois en mode dev", (t) => {
    const spy = t.mock.method(console, "error", () => {});
    const seen = [];
    i18n.onMissing((key) => seen.push(key));
    i18n.configure({ dev: true });
    try {
      assert.equal(i18n.t("test.absente.une"), "test.absente.une");
      assert.equal(i18n.t("test.absente.une"), "test.absente.une");
      assert.equal(i18n.plural("test.absente.deux", 3), "test.absente.deux");
      assert.equal(spy.mock.callCount(), 2);
      assert.match(spy.mock.calls[0].arguments[0], /test\.absente\.une/);
      assert.deepEqual(seen, ["test.absente.une", "test.absente.une", "test.absente.deux"]);
    } finally {
      i18n.configure({ dev: false });
      i18n.onMissing(null);
    }
  });

  test("clé absente hors mode dev : aucune sortie console", (t) => {
    const spy = t.mock.method(console, "error", () => {});
    assert.equal(i18n.t("test.absente.prod"), "test.absente.prod");
    assert.equal(spy.mock.callCount(), 0);
  });
});

// ------------------------------------------------------------------ formats

describe("formats", () => {
  test("fmtNumber groupe par une espace fine insécable (U+202F)", () => {
    assert.equal(i18n.fmtNumber(1204), "1 204");
    assert.equal(i18n.fmtNumber(0), "0");
    assert.equal(i18n.fmtNumber(3.5), "3,5");
  });

  test("fmtBytes en base 1024, une décimale sous 10", () => {
    assert.equal(i18n.fmtBytes(0), "0 octet");
    assert.equal(i18n.fmtBytes(512), "512 octets");
    assert.equal(i18n.fmtBytes(1024), "1 Ko");
    assert.equal(i18n.fmtBytes(12 * 1024), "12 Ko");
    assert.equal(i18n.fmtBytes(3.4 * 1024 * 1024), "3,4 Mo");
    assert.equal(i18n.fmtBytes(1.2 * 1024 ** 3), "1,2 Go");
    // Un arrondi qui atteint 1024 passe à l'unité suivante.
    assert.equal(i18n.fmtBytes(1023.97 * 1024), "1 Mo");
  });

  test("fmtDate : « 18 nov. à 14 h 20 », année ajoutée hors de l'année en cours", () => {
    assert.equal(i18n.fmtDate(NOV18, "datetime", NOV18), "18 nov. à 14 h 20");
    assert.equal(i18n.fmtDate(NOV18, undefined, NOV18 - 60 * DAY), "18 nov. à 14 h 20");
    assert.equal(i18n.fmtDate(NOV18, "datetime", NOV18 + 365 * DAY), "18 nov. 2026 à 14 h 20");
    assert.equal(i18n.fmtDate(new Date(NOV18 * 1000), "datetime", NOV18), "18 nov. à 14 h 20");
  });

  test("fmtDate : styles date, time et long", () => {
    assert.equal(i18n.fmtDate(NOV18, "date"), "18 nov. 2026");
    assert.equal(i18n.fmtDate(NOV18, "time"), "14 h 20");
    assert.equal(i18n.fmtDate(NOV18 - 5 * 3600 - 15 * 60, "time"), "9 h 05");
    assert.equal(i18n.fmtDate(NOV18, "long"), "mercredi 18 novembre 2026 à 14 h 20");
    assert.equal(i18n.fmtDate(Date.UTC(2026, 10, 1, 7, 5) / 1000, "long"), "dimanche 1er novembre 2026 à 8 h 05");
    assert.equal(i18n.fmtDate(null), "—");
  });

  test("fmtDate respecte le fuseau de configure()", () => {
    try {
      i18n.configure({ timeZone: "America/New_York" });
      assert.equal(i18n.fmtDate(NOV18, "time"), "8 h 20");
      i18n.configure({ timeZone: "Fuseau/Inconnu" }); // ignoré : fuseau du système
      assert.match(i18n.fmtDate(NOV18, "time"), /^\d{1,2} h \d{2}$/);
    } finally {
      i18n.configure({ timeZone: "Europe/Paris" });
    }
  });

  test("relTime : à l'instant, minutes, heures, jours, puis la date", () => {
    assert.equal(i18n.relTime(NOV18 - 10, NOV18), "à l'instant");
    assert.equal(i18n.relTime(NOV18 - 5 * 60, NOV18), "il y a 5 min");
    assert.equal(i18n.relTime(NOV18 - 2 * 3600, NOV18), "il y a 2 h");
    assert.equal(i18n.relTime(NOV18 - DAY, NOV18), "il y a 1 jour");
    assert.equal(i18n.relTime(NOV18 - 3 * DAY, NOV18), "il y a 3 jours");
    assert.equal(i18n.relTime(NOV18 - 30 * DAY, NOV18), "il y a 30 jours");
    assert.equal(i18n.relTime(NOV18 - 40 * DAY, NOV18 + 0), "9 oct. 2026");
  });

  test("relTime dans le futur", () => {
    assert.equal(i18n.relTime(NOV18 + 10, NOV18), "dans un instant");
    assert.equal(i18n.relTime(NOV18 + 15 * 60, NOV18), "dans 15 min");
    assert.equal(i18n.relTime(NOV18 + 3 * 3600, NOV18), "dans 3 h");
    assert.equal(i18n.relTime(NOV18 + 2 * DAY, NOV18), "dans 2 jours");
  });
});

// ------------------------------------------------------------------ erreurs

describe("errorText et fieldErrorText", () => {
  test("code connu, avec délai d'attente", () => {
    assert.equal(i18n.errorText({ code: "network", status: 0 }), "Serveur injoignable. Vérifiez votre connexion puis réessayez.");
    assert.equal(i18n.errorText({ code: "rate_limited", status: 429, retryAfter: 12 }), "Trop de tentatives. Réessayez dans 12 s.");
    assert.equal(i18n.errorText({ code: "rate_limited", status: 429, retry_after: 1204 }), "Trop de tentatives. Réessayez dans 1 204 s.");
  });

  test("paramètre manquant : le message du serveur prend le relais", () => {
    const err = { code: "rate_limited", status: 429, message: "Trop de tentatives. Réessayez dans 42 secondes." };
    assert.equal(i18n.errorText(err), err.message);
  });

  test("repli par statut", () => {
    assert.equal(i18n.errorText({ code: "inconnu_x", status: 503 }), i18n.t("errors.server_busy"));
    assert.equal(i18n.errorText({ code: "inconnu_x", status: 504 }), i18n.t("errors.timeout"));
    assert.equal(i18n.errorText({ code: "inconnu_x", status: 408 }), i18n.t("errors.timeout"));
    assert.equal(i18n.errorText({ code: "inconnu_x", status: 413 }), i18n.t("errors.payload_too_large"));
    assert.equal(i18n.errorText({ code: "inconnu_x", status: 422 }), i18n.t("errors.bad_request"));
  });

  test("repli sur le message reçu, puis message générique", () => {
    assert.equal(i18n.errorText({ code: "inconnu_x", status: 418, message: "Message du serveur." }), "Message du serveur.");
    assert.equal(i18n.errorText({ code: "inconnu_x", status: 418, message: "  " }), i18n.t("errors.unknown"));
    assert.equal(i18n.errorText(null), i18n.t("errors.unknown"));
    assert.equal(i18n.errorText(undefined), i18n.t("errors.unknown"));
    // Le texte d'une exception JavaScript (anglais, technique) n'est jamais affiché.
    assert.equal(i18n.errorText(new TypeError("x is undefined")), i18n.t("errors.unknown"));
  });

  test("fieldErrorText : code inconnu -> message générique de champ", () => {
    assert.equal(i18n.fieldErrorText({ code: "code_de_champ_inconnu" }), i18n.t("errors.invalid_input"));
    assert.equal(i18n.fieldErrorText(null), i18n.t("errors.invalid_input"));
  });

  test("fieldErrorText : nombres à la française (virgule décimale)", { skip: !i18n.has("errors.field.low_contrast") && "errors.field.low_contrast absent" }, () => {
    const text = i18n.fieldErrorText({ code: "low_contrast", ratio_light: 7.8412, ratio_dark: 2.14, suggestion: "#2f6f9e" });
    assert.match(text, /7,84/);
    assert.match(text, /2,14/);
    assert.doesNotMatch(text, /7\.84|2\.14/);
    assert.match(text, /#2f6f9e/);
  });

  test("fieldErrorText : paramètres transmis au texte errors.field.<code>", { skip: !i18n.has("errors.field.out_of_range") && "errors.field.out_of_range absent (fichier de L4)" }, () => {
    const text = i18n.fieldErrorText({ code: "out_of_range", min: 1, max: 30 });
    assert.doesNotMatch(text, /\{(min|max)\}/);
  });
});

// ------------------------------------------------------------------ générateur

describe("gen-i18n", () => {
  test("préfixe imposé par le nom du fichier", () => {
    assert.equal(prefixFor("common.json"), "common");
    assert.equal(prefixFor("settings-user.json"), "settings_user");
    assert.equal(prefixFor("errors.common.json"), "errors");
    assert.equal(prefixFor("errors.settings.json"), "errors");
    assert.equal(prefixFor("Mauvais nom.json"), null);
  });

  test("clés de premier niveau, doublons compris", () => {
    assert.deepEqual(topLevelKeys('{"a.b": "x", "a.c": {"one": "u", "other": "v"}, "a.b": "y"}'), ["a.b", "a.c", "a.b"]);
  });

  test("échoue sur une clé dupliquée entre deux fichiers, en citant les deux", (t) => {
    const dir = tempDir(t);
    writeSources(dir, {
      "errors.common.json": { "errors.network": "Serveur injoignable." },
      "errors.settings.json": { "errors.network": "Autre texte." },
    });
    const { errors } = buildCatalog(dir);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /errors\.network/);
    assert.match(errors[0], /errors\.common\.json/);
    assert.match(errors[0], /errors\.settings\.json/);
    const out = join(dir, "out");
    const run = runNode(GEN, ["--src", dir, "--out-js", join(out, "fr.js"), "--out-json", join(out, "fr.gen.json")]);
    assert.equal(run.status, 1, run.stderr);
    assert.match(run.stderr, /définie deux fois/);
    assert.equal(existsSync(out), false, "rien ne doit être écrit en cas d'erreur");
  });

  test("échoue sur un mauvais préfixe", (t) => {
    const dir = tempDir(t);
    writeSources(dir, { "vault.json": { "common.action.save": "Enregistrer" } });
    const { errors } = buildCatalog(dir);
    assert.match(errors.join("\n"), /doit commencer par « vault\. »/);
    const run = runNode(GEN, ["--src", dir, "--out-js", join(dir, "fr.js"), "--out-json", join(dir, "fr.gen.json")]);
    assert.equal(run.status, 1);
  });

  test("échoue sur les valeurs mal formées", (t) => {
    const dir = tempDir(t);
    writeSources(dir, {
      "demo.json": [
        "{",
        '  "demo.html": "Texte <b>gras</b>",',
        '  "demo.vide": " ",',
        '  "demo.accolade": "Valeur {Nom}",',
        '  "demo.pluriel": { "one": "un" },',
        '  "demo.tableau": ["a"],',
        '  "demo.items.synonyms": "pas un tableau",',
        '  "demo.nombre": 3,',
        '  "Demo.Majuscule": "x",',
        '  "demo.double": "a",',
        '  "demo.double": "b"',
        "}",
      ].join("\n"),
    });
    const msg = buildCatalog(dir).errors.join("\n");
    for (const expected of ["demo.html", "demo.vide", "demo.accolade", "demo.pluriel", "demo.tableau",
      "demo.items.synonyms", "demo.nombre", "Demo.Majuscule", "présente deux fois"]) {
      assert.ok(msg.includes(expected), `erreur attendue pour ${expected} :\n${msg}`);
    }
  });

  test("accepte les fichiers de domaine des autres lots sans modification", (t) => {
    const dir = tempDir(t);
    writeSources(dir, {
      "common.json": { "common.app.name": "Locksy" },
      "settings.json": {
        "settings.session.idle_minutes.label": "Fermer la session après",
        "settings.session.idle_minutes.synonyms": ["inactivité", "délai"],
        "settings.twofa.required.value.on": "Activée",
      },
      "settings-user.json": { "settings_user.theme.label": "Thème" },
      "errors.settings.json": { "errors.field.out_of_range": "Valeur entre {min} et {max}." },
      "ui.json": { "ui.dialog.items": { "one": "{n} élément", "other": "{n} éléments", "many": "{n} d'éléments" } },
    });
    const { catalog, errors } = buildCatalog(dir);
    assert.deepEqual(errors, []);
    assert.deepEqual(Object.keys(catalog), [...Object.keys(catalog)].sort());
    assert.equal(Object.keys(catalog).length, 7);
    assert.match(renderJs(catalog), /^\/\/ Fichier généré[\s\S]*export default Object\.freeze\(\{\n[\s\S]*\}\);\n$/);
    assert.equal(JSON.stringify(JSON.parse(renderJson(catalog))), JSON.stringify(catalog));
  });

  test("--check est propre sur le dépôt et détecte une sortie périmée", (t) => {
    const run = runNode(GEN, ["--check"]);
    assert.equal(run.status, 0, run.stderr);
    const dir = tempDir(t);
    const src = join(dir, "src");
    mkdirSync(src);
    writeSources(src, { "common.json": { "common.app.name": "Locksy" } });
    const js = join(dir, "fr.js");
    const json = join(dir, "fr.gen.json");
    assert.equal(runNode(GEN, ["--src", src, "--out-js", js, "--out-json", json]).status, 0);
    assert.equal(runNode(GEN, ["--src", src, "--out-js", js, "--out-json", json, "--check"]).status, 0);
    writeFileSync(js, `${readFileSync(js, "utf8")}// modifié\n`);
    const stale = runNode(GEN, ["--src", src, "--out-js", js, "--out-json", json, "--check"]);
    assert.equal(stale.status, 1);
    assert.match(stale.stderr, /n'est pas à jour/);
  });

  test("le catalogue embarqué correspond aux sources", async () => {
    const { catalog, errors } = buildCatalog(DEFAULT_SRC);
    assert.deepEqual(errors, []);
    const embedded = (await import("../../web/js/i18n/fr.js")).default;
    assert.deepEqual({ ...embedded }, JSON.parse(JSON.stringify(catalog)));
    assert.ok(Object.isFrozen(embedded));
  });
});

// ------------------------------------------------------------------ couverture

/**
 * Retire d'un source Rust les commentaires (imbriqués compris) et les modules
 * `#[cfg(test)] mod x { … }`, sans toucher aux chaînes.
 */
function stripRust(src) {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const rest = src.slice(i, i + 3);
    if (rest.startsWith("//")) {
      const end = src.indexOf("\n", i);
      i = end === -1 ? src.length : end;
    } else if (rest.startsWith("/*")) {
      let depth = 0;
      do {
        if (src.startsWith("/*", i)) { depth++; i += 2; }
        else if (src.startsWith("*/", i)) { depth--; i += 2; }
        else i++;
      } while (depth > 0 && i < src.length);
    } else if (/^r#*"/.test(src.slice(i, i + 10)) && !/[\w]/.test(src[i - 1] ?? "")) {
      const hashes = /^r(#*)"/.exec(src.slice(i))[1];
      const end = src.indexOf(`"${hashes}`, i + hashes.length + 2);
      const stop = end === -1 ? src.length : end + hashes.length + 1;
      out += src.slice(i, stop);
      i = stop;
    } else if (src[i] === "\"") {
      let j = i + 1;
      while (j < src.length && src[j] !== "\"") j += src[j] === "\\" ? 2 : 1;
      out += src.slice(i, j + 1);
      i = j + 1;
    } else if (src[i] === "'") {
      const ch = /^'(\\(u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'])'/.exec(src.slice(i, i + 12));
      const len = ch ? ch[0].length : 1;
      out += src.slice(i, i + len);
      i += len;
    } else {
      out += src[i++];
    }
  }
  return removeTestModules(out);
}

function removeTestModules(src) {
  const re = /#\[cfg\(test\)\]\s*(pub(\([^)]*\))?\s+)?mod\s+\w+\s*\{/g;
  let result = "";
  let last = 0;
  for (let m = re.exec(src); m; m = re.exec(src)) {
    let depth = 1;
    let j = m.index + m[0].length;
    while (j < src.length && depth > 0) {
      if (src[j] === "\"") {
        j++;
        while (j < src.length && src[j] !== "\"") j += src[j] === "\\" ? 2 : 1;
      } else if (src[j] === "{") depth++;
      else if (src[j] === "}") depth--;
      j++;
    }
    result += src.slice(last, m.index);
    last = j;
    re.lastIndex = j;
  }
  return result + src.slice(last);
}

const ARG = String.raw`(?:[^,()"]|\([^()]*\))+?`;
const CODE = String.raw`"([a-z0-9_]+)"`;
const SERVER_PATTERNS = [
  ["ApiError::new", new RegExp(String.raw`ApiError::new\(\s*${ARG},\s*${CODE}`, "g")],
  ["ApiError::unavailable", new RegExp(String.raw`ApiError::unavailable\(\s*${CODE}`, "g")],
  ["ExtError::new", new RegExp(String.raw`ExtError::new\(\s*${ARG},\s*${CODE}`, "g")],
];

/** Codes d'erreur du serveur : { codes: Map<code, fichiers>, nonLiteral: [] }. */
function serverErrorCodes() {
  const codes = new Map();
  const nonLiteral = [];
  const add = (code, file) => codes.set(code, [...(codes.get(code) ?? []), file]);
  // Les tests (src/tests/, http_tests.rs, modules #[cfg(test)]) ne produisent pas d'erreurs réelles.
  const files = walk(SERVER_SRC, (f) => f.endsWith(".rs"))
    .filter((f) => !/[\\/]tests[\\/]/.test(relative(SERVER_SRC, f)) && !f.endsWith("http_tests.rs"));
  for (const file of files) {
    const rel = relative(ROOT, file).replace(/\\/g, "/");
    const src = stripRust(readFileSync(file, "utf8"));
    for (const [name, re] of SERVER_PATTERNS) {
      const total = src.split(`${name}(`).length - 1;
      let found = 0;
      for (const m of src.matchAll(re)) {
        add(m[1], rel);
        found++;
      }
      if (found !== total) nonLiteral.push(`${rel} : ${total - found} appel(s) à ${name} sans code littéral`);
    }
    // Aides d'error.rs (bad_request, unauthorized, forbidden, not_found, conflict, rate_limited, internal).
    if (rel.endsWith("/error.rs")) {
      for (const m of src.matchAll(new RegExp(String.raw`Self::new\(\s*${ARG},\s*${CODE}`, "g"))) add(m[1], rel);
    }
  }
  return { codes, nonLiteral };
}

/** Codes d'erreur produits par le client web lui-même. */
function clientErrorCodes() {
  const codes = new Set(["network", "error", "download", "wrong_password", "kdf_downgrade", "key_mismatch"]);
  for (const file of walk(WEB_JS, (f) => f.endsWith(".js") && !f.includes(`${join("js", "i18n")}`))) {
    const src = readFileSync(file, "utf8");
    for (const m of src.matchAll(/clientError\(\s*"([a-z0-9_]+)"/g)) codes.add(m[1]);
    for (const m of src.matchAll(/new ApiError\(\s*[^,]+,\s*"([a-z0-9_]+)"/g)) codes.add(m[1]);
  }
  return codes;
}

describe("couverture des codes d'erreur", () => {
  test("l'extraction voit les appels sur plusieurs lignes et ignore commentaires et tests", () => {
    const src = [
      "// ApiError::new(StatusCode::OK, \"commentaire\", \"x\")",
      "/* ApiError::unavailable(\"bloc\", \"x\") /* imbriqué */ */",
      "fn f() { ApiError::new(",
      "    StatusCode::FORBIDDEN,",
      "    \"multi_ligne\",",
      "    format!(\"{}\", 'a'),",
      ") }",
      "#[cfg(test)]",
      "mod tests { fn g() { ApiError::unavailable(\"seulement_test\", \"}\"); } }",
      "fn h<'a>(x: &'a str) { ExtError::new(e.0, \"ext_code\", r#\"brut \"//\" \"#); }",
    ].join("\n");
    const stripped = stripRust(src);
    const found = SERVER_PATTERNS.flatMap(([, re]) => [...stripped.matchAll(re)].map((m) => m[1]));
    assert.deepEqual(found.sort(), ["ext_code", "multi_ligne"]);
  });

  test("tout code d'erreur du serveur et du client a sa traduction errors.<code>", () => {
    const { codes, nonLiteral } = serverErrorCodes();
    assert.deepEqual(nonLiteral, [], "chaque code d'erreur doit être une chaîne littérale (contrat C4.6)");
    // Socle attendu : les aides d'error.rs et les codes relevés le 17/11.
    for (const code of ["bad_request", "unauthorized", "forbidden", "not_found", "conflict", "rate_limited",
      "internal", "server_busy", "setup_token_required", "2fa_required", "not_ready"]) {
      assert.ok(codes.has(code), `extraction incomplète : ${code} non trouvé dans crates/locksy-server/src`);
    }
    const errorsFiles = readdirSync(DEFAULT_SRC).filter((f) => /^errors(\.[a-z0-9-]+)?\.json$/.test(f));
    const translated = new Set();
    for (const f of errorsFiles) {
      for (const key of Object.keys(JSON.parse(readFileSync(join(DEFAULT_SRC, f), "utf8")))) translated.add(key);
    }
    const missing = [];
    for (const [code, files] of codes) {
      if (!translated.has(`errors.${code}`)) missing.push(`errors.${code} (${[...new Set(files)].join(", ")})`);
    }
    for (const code of clientErrorCodes()) {
      if (!translated.has(`errors.${code}`)) missing.push(`errors.${code} (client web)`);
    }
    assert.deepEqual(missing, [], `codes sans traduction dans ${errorsFiles.join(", ")}`);
  });

  test("chaque clé littérale passée à t() ou plural() existe dans les sources", () => {
    const { catalog } = buildCatalog(DEFAULT_SRC);
    const roots = [WEB_JS, join(ROOT, "extension", "src")];
    const missing = [];
    for (const root of roots) {
      for (const file of walk(root, (f) => /\.m?js$/.test(f) && !/[\\/](test|i18n)[\\/]/.test(f))) {
        const src = readFileSync(file, "utf8");
        for (const m of src.matchAll(/(?<![\w.$])(?:t|plural|tList)\(\s*["']([a-z0-9_]+(?:\.[a-z0-9_-]+)+)["']/g)) {
          if (!(m[1] in catalog)) missing.push(`${relative(ROOT, file).replace(/\\/g, "/")} : ${m[1]}`);
        }
      }
    }
    assert.deepEqual(missing, []);
  });
});

// ------------------------------------------------------------------ catalogue

describe("rédaction du catalogue", () => {
  const { catalog } = buildCatalog(DEFAULT_SRC);
  // Seuls les fichiers de ce lot : les autres domaines ont leurs propres règles.
  const own = ["common.json", "errors.common.json"]
    .flatMap((f) => Object.entries(JSON.parse(readFileSync(join(DEFAULT_SRC, f), "utf8"))));
  const texts = (v) => (typeof v === "string" ? [v] : Array.isArray(v) ? v : Object.values(v));

  test("clés minimales du contrat C6", () => {
    const required = [
      "common.app.name", "common.title_suffix",
      ...["cancel", "undo", "close", "save", "confirm", "continue", "back", "next", "retry", "copy", "show", "hide",
        "edit", "open", "search", "clear_search", "reset", "more_actions", "move_to_trash", "delete_forever",
        "restore", "revoke", "lock", "logout", "stay", "discard", "generate", "create", "add", "share", "download",
        "import", "export", "select_all", "help"].map((a) => `common.action.${a}`),
      ...["loading", "saving", "enabled", "disabled", "offline", "busy_retry", "empty_search"].map((s) => `common.state.${s}`),
      ...["just_now", "minutes_ago", "hours_ago", "days_ago", "in_minutes", "in_hours", "in_days", "at", "hm"].map((s) => `common.time.${s}`),
      ...["seconds", "minutes", "hours", "days", "never", "bytes", "kb", "mb", "gb"].map((s) => `common.unit.${s}`),
      "common.glossary.technical_details",
      ...["unknown", "network", "error", "download", "timeout", "payload_too_large", "bad_request", "unauthorized",
        "forbidden", "not_found", "conflict", "rate_limited", "internal", "server_busy", "not_ready", "2fa_required",
        "account_disabled", "email_unverified", "extension_not_allowed", "invalid_config", "invalid_credentials",
        "invalid_setup_token", "invalid_totp", "ldap_unavailable", "quota_exceeded", "setup_token_required",
        "sso_busy", "sso_link_refused", "sso_required", "totp_required", "wrong_password", "kdf_downgrade",
        "key_mismatch"].map((c) => `errors.${c}`),
    ];
    assert.deepEqual(required.filter((k) => !(k in catalog)), []);
    for (const k of ["minutes_ago", "hours_ago", "days_ago", "in_minutes", "in_hours", "in_days"]) {
      assert.equal(typeof catalog[`common.time.${k}`], "object", `common.time.${k} doit être un pluriel`);
    }
  });

  test("libellés contractuels (annexe C et §2.11)", () => {
    assert.equal(catalog["common.action.move_to_trash"], "Mettre à la corbeille");
    assert.equal(catalog["common.action.delete_forever"], "Supprimer définitivement");
    assert.equal(catalog["common.action.logout"], "Se déconnecter");
    assert.equal(catalog["common.action.lock"], "Verrouiller");
    assert.equal(catalog["common.glossary.technical_details"], "Détails techniques");
    assert.equal(catalog["common.state.busy_retry"], "Le serveur est très sollicité. Réessayez dans quelques secondes.");
    assert.equal(catalog["errors.server_busy"], catalog["common.state.busy_retry"]);
  });

  test("règles de rédaction : ni point d'exclamation, ni code HTTP, ni mot interdit", () => {
    const forbidden = /!|\b[45]\d\d\b|\b(2FA|TOTP|OIDC|LDAP|login|token|share|bits|erreur \d+)\b/i;
    const problems = [];
    for (const [key, value] of own) {
      if (key.startsWith("common.glossary.enterprise_")) continue; // sous-titres imposés par le glossaire
      // « setup-token » est le nom réel du fichier à ouvrir sur le serveur.
      for (const text of texts(value)) if (forbidden.test(text.replace(/setup-token/g, ""))) problems.push(`${key} : ${text}`);
    }
    assert.deepEqual(problems, []);
  });

  test("chaque message d'erreur dit quoi faire (deux phrases ou une consigne)", () => {
    const vague = own.filter(([k, v]) => k.startsWith("errors.") && typeof v === "string"
      && !/(Réessayez|Rechargez|Reconnectez|Vérifiez|Contactez|contactez|Prévenez|prévenez|Saisissez|Activez|Utilisez|Copiez|Choisissez|Demandez|Supprimez|Connectez)/.test(v));
    assert.deepEqual(vague.map(([k]) => k), []);
  });
});

// ------------------------------------------------------------------ isolement

test("i18n.js reste hors des modules partagés avec l'extension (D5)", () => {
  const closure = sharedClosure(WEB_JS);
  assert.ok(!closure.includes("i18n.js"), closure.join(", "));
});

test("i18n.js s'importe sans DOM et ne produit aucun HTML", () => {
  const src = readFileSync(join(WEB_JS, "i18n.js"), "utf8").replace(/\/\/.*$/gm, "");
  assert.doesNotMatch(src, /\bdocument\b|innerHTML|insertAdjacentHTML|\bfetch\(/);
});

// ------------------------------------------------------------------ lint-strings

describe("lint-strings", () => {
  test("relève les contextes affichables", () => {
    const src = [
      'import { h, toast } from "../dom.js";',
      'const a = h("p", { class: "note muted", title: "Infobulle" }, "Texte visible", t("vault.ok"));',
      'el.setAttribute("aria-label", "Nom accessible");',
      'toast("Élément copié", "ok");',
      'notify({ text: "Action faite" });',
      'const b = { label: cond ? "Oui" : "Non", placeholder: "Saisir" };',
      "el.textContent = `Bonjour ${nom}`;",
      'function f({ confirmLabel = "Valider" } = {}) {}',
      'throw new Error("Impossible de lire le fichier.");',
    ].join("\n");
    const found = lintSource(src, "x.js").map((f) => `${f.line}:${f.rule}:${f.text}`);
    assert.deepEqual(found, [
      "2:attr:Infobulle",
      "2:h-child:Texte visible",
      "3:attr:Nom accessible",
      "4:toast:Élément copié",
      "5:prop:Action faite",
      "6:prop:Oui",
      "6:prop:Non",
      "6:attr:Saisir",
      "7:prop:Bonjour ${…}",
      "8:prop:Valider",
      "9:prose:Impossible de lire le fichier.",
    ]);
  });

  test("ignore clés, URL, classes, comparaisons, commentaires et textes passés par t()", () => {
    const src = [
      "// h(\"p\", {}, \"Commentaire ignoré\")",
      "/* toast(\"Bloc ignoré\") */",
      'const x = h("a", { href: "https://exemple.fr", class: "btn primary", id: "main" }, t("vault.detail.copy", { nom: "Paul" }));',
      'if (e.key === "Enter" || mode !== "Compact") h("span", {}, "•", 42, "vault.detail.title");',
      'const re = /"Faux texte"/; const y = 4 / 2;',
      'api("GET", "/api/vault"); console.error("Erreur de développement");',
      'h("p", {}, plural("vault.count", n));',
      'const k = { label: "Ctrl+Shift+C", text: "ArrowDown", title: "CapsLock" }; h("kbd", {}, "Ctrl+K");',
    ].join("\n");
    assert.deepEqual(lintSource(src, "y.js"), []);
  });

  test("jetons : gabarits imbriqués et expressions régulières", () => {
    const toks = tokenize("const a = `x ${f(`y ${'z'}`)} w`; const r = /[/]\"/g;");
    const strs = toks.filter((k) => k.type === "str").map((k) => k.value);
    assert.deepEqual(strs, ["x ${…} w", "y ${…}", "z"]);
    assert.equal(toks.filter((k) => k.type === "regex").length, 1);
  });

  test("looksLikeProse", () => {
    assert.equal(looksLikeProse("Copier"), true);
    assert.equal(looksLikeProse("mot de passe"), true);
    assert.equal(looksLikeProse("élément"), true);
    assert.equal(looksLikeProse("btn primary"), false);
    assert.equal(looksLikeProse("click"), false);
  });

  test("modes rapport, bloquant et JSON", (t) => {
    const dir = tempDir(t);
    const file = join(dir, "vue.js");
    writeFileSync(file, 'h("p", {}, "Texte en dur");\n');
    const report = runNode(LINT, [file]);
    assert.equal(report.status, 0, report.stderr);
    assert.match(report.stdout, /vue\.js:1: Texte en dur/);
    assert.match(report.stdout, /1 texte\(s\) en dur/);
    assert.equal(runNode(LINT, [file, "--strict"]).status, 1);
    const json = JSON.parse(runNode(LINT, [file, "--json"]).stdout);
    assert.equal(json.total, 1);
    assert.equal(json.findings[0].rule, "h-child");
    writeFileSync(file, 'h("p", {}, t("common.action.save"));\n');
    assert.equal(runNode(LINT, [file, "--strict"]).status, 0);
  });

  test("le dépôt s'analyse sans erreur (mode rapport)", () => {
    const run = runNode(LINT, ["--json"]);
    assert.equal(run.status, 0, run.stderr);
    const json = JSON.parse(run.stdout);
    assert.ok(json.files > 0);
    assert.equal(json.total, json.findings.length);
  });
});
