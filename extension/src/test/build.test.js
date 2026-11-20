// Construction de l'extension : imports partagés, copies de l'interface web,
// zip déterministe, contenu d'un build de production et de la variante des tests.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";
import {
  importsOf, sharedClosure, resolveShared, makeZip, crc32, crc32Fallback, parseArgs, workspaceVersion, shippedSources, build,
  finalManifest, checkRelease, SHARED_ENTRIES, UI_ENTRIES, startupModules, withModulePreload, PRELOAD_MARKER,
} from "../../build.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..", "..");

function tempDir(t) {
  const d = mkdtempSync(join(tmpdir(), "locksy-ext-"));
  t.after(() => rmSync(d, { recursive: true, force: true }));
  return d;
}

test("lecture des imports d'un module", () => {
  const src = [
    'import { a } from "./a.js";',
    "import * as B from './b.js';",
    'import {\n  c,\n  d,\n} from "./c.js";',
    'export { e } from "./e.js";',
    'import "./side.js";',
    'const m = await import("./dyn.js");',
    "const imports = { env: {} }; // pas un import",
    "export function importItems() {}",
  ].join("\n");
  assert.deepEqual(importsOf(src).sort(), ["./a.js", "./b.js", "./c.js", "./dyn.js", "./e.js", "./side.js"]);
  assert.throws(() => importsOf("const x = await import(nom);"), /non littéral/);
  // Expression non littérale admise explicitement, pour ce module seulement.
  assert.deepEqual(importsOf("const m = await import(decoderUrl);", "ui/qr.js", ["decoderUrl"]), []);
  assert.throws(() => importsOf("const m = await import(autre);", "ui/qr.js", ["decoderUrl"]), /non littéral/);
  // Un texte ou un commentaire qui contient « import ( » n'est pas un import.
  const texte = [
    'export default { "a.b": "Échec de l\'import (secrets non exportés)" };',
    "const s = `import (${x})`; // import(nom) en commentaire",
    "/* import(autre) */",
  ].join("\n");
  assert.deepEqual(importsOf(texte, "i18n/fr.js"), []);
});

test("résolution des imports : web/js, ui/ et i18n/ seulement", () => {
  assert.equal(resolveShared("vault.js", "./api.js"), "api.js");
  assert.equal(resolveShared("ui/core.js", "../i18n.js"), "i18n.js");
  assert.equal(resolveShared("ui/core.js", "./focus.js"), "ui/focus.js");
  assert.equal(resolveShared("i18n.js", "./i18n/fr.js"), "i18n/fr.js");
  assert.equal(resolveShared("ui/core.js", "../views/shell.js"), null);
  assert.equal(resolveShared("ui/core.js", "../../secret.js"), null);
  assert.equal(resolveShared("api.js", "./ui/sous/x.js"), null);
  assert.equal(resolveShared("api.js", "./app.js?x"), null);
});

test("fermeture transitive des modules partagés", (t) => {
  const d = tempDir(t);
  writeFileSync(join(d, "vault.js"), 'import { x } from "./pins.js";\nexport const v = 1;\n');
  writeFileSync(join(d, "pins.js"), 'import { y } from "./util.js";\nexport const x = 1;\n');
  writeFileSync(join(d, "util.js"), "export const y = 1;\n");
  writeFileSync(join(d, "api.js"), "export const a = 1;\n");
  assert.deepEqual(sharedClosure(d, ["vault.js", "api.js"]), ["api.js", "pins.js", "util.js", "vault.js"]);
  mkdirSync(join(d, "ui"));
  mkdirSync(join(d, "i18n"));
  writeFileSync(join(d, "ui", "index.js"), 'export { h } from "./core.js";\n');
  writeFileSync(join(d, "ui", "core.js"), 'import { t } from "../i18n.js";\nexport const h = t;\n');
  writeFileSync(join(d, "i18n.js"), 'import c from "./i18n/fr.js";\nexport const t = c;\n');
  writeFileSync(join(d, "i18n", "fr.js"), "export default {};\n");
  assert.deepEqual(sharedClosure(d, ["ui/index.js"]), ["i18n.js", "i18n/fr.js", "ui/core.js", "ui/index.js"]);
});

test("un import hors de web/js fait échouer la construction", (t) => {
  const d = tempDir(t);
  // Un fichier par cas : réécrire le même fichier en rafale échoue parfois
  // sous Windows (antivirus).
  ["../secret.js", "/abs.js", "https://cdn.example.com/x.js", "lodash", "./views/x.js", "./app.js?x", "./ui/../../x.js"].forEach((spec, i) => {
    writeFileSync(join(d, `m${i}.js`), `import { x } from "${spec}";\n`);
    assert.throws(() => sharedClosure(d, [`m${i}.js`]), /seuls les modules de web\/js/, spec);
  });
  writeFileSync(join(d, "absent.js.importer.js"), 'import { x } from "./absent.js";\n');
  assert.throws(() => sharedClosure(d, ["absent.js.importer.js"]), /introuvable/);
});

test("les vrais modules web partagés restent dans web/js (composants et textes compris)", () => {
  const list = sharedClosure(join(repo, "web", "js"), [...SHARED_ENTRIES, ...UI_ENTRIES]);
  for (const f of ["wasm.js", "aad.js", "api.js", "vault.js", "settings-client.js", "ui/index.js", "ui/totp.js", "ui/secret.js", "i18n.js", "i18n/fr.js"]) {
    assert.ok(list.includes(f), f);
  }
  assert.ok(!list.includes("app.js"), "app.js ne doit jamais être embarqué");
  assert.ok(!list.some((f) => f.startsWith("views/")), "aucune vue de l'application web");
});

test("manifeste : variante des tests seule à fixer l'accès aux sites", () => {
  const base = { name: "Locksy", version: "1.0.0", permissions: ["storage", "scripting"] };
  const release = finalManifest(base, { version: "1.2.3" });
  assert.equal(release.version, "1.2.3");
  assert.equal(release.host_permissions, undefined);
  const flags = "export const DEV = false;\nexport const TEST = false;\n";
  assert.doesNotThrow(() => checkRelease({ manifest: release, files: ["popup.js"], flags }));
  const testing = finalManifest(base, { version: "1.2.3", test: true });
  assert.deepEqual(testing.host_permissions, ["http://*/*", "https://*/*"]);
  assert.ok(testing.permissions.includes("clipboardRead"));
  assert.deepEqual(base.permissions, ["storage", "scripting"], "manifeste source inchangé");
  assert.throws(() => checkRelease({ manifest: testing, files: [], flags }), /host_permissions/);
  assert.throws(() => checkRelease({ manifest: { ...release, permissions: ["clipboardRead"] }, files: [], flags }), /presse-papiers/);
  assert.throws(() => checkRelease({ manifest: release, files: ["dev-fake.js"], flags }), /développement/);
  assert.throws(() => checkRelease({ manifest: release, files: [], flags: flags.replace("TEST = false", "TEST = true") }), /build-flags/);
});


test("CRC32 : implémentation locale identique à la référence", () => {
  const buf = Buffer.from("Locksy : coffre zéro connaissance");
  assert.equal(crc32Fallback(Buffer.from("123456789")), 0xcbf43926);
  assert.equal(crc32Fallback(buf), crc32(buf));
  if (typeof zlib.crc32 === "function") assert.equal(crc32Fallback(buf), zlib.crc32(buf) >>> 0);
});

/** Lecteur minimal du répertoire central, pour vérifier la structure produite. */
function readZip(zip) {
  const end = zip.length - 22;
  assert.equal(zip.readUInt32LE(end), 0x06054b50);
  const count = zip.readUInt16LE(end + 10);
  let p = zip.readUInt32LE(end + 16);
  const out = [];
  for (let i = 0; i < count; i++) {
    assert.equal(zip.readUInt32LE(p), 0x02014b50);
    const method = zip.readUInt16LE(p + 10);
    const time = zip.readUInt16LE(p + 12);
    const date = zip.readUInt16LE(p + 14);
    const crc = zip.readUInt32LE(p + 16);
    const size = zip.readUInt32LE(p + 24);
    const nlen = zip.readUInt16LE(p + 28);
    const xlen = zip.readUInt16LE(p + 30);
    const ext = zip.readUInt32LE(p + 38);
    const off = zip.readUInt32LE(p + 42);
    const name = zip.subarray(p + 46, p + 46 + nlen).toString("utf8");
    const lnlen = zip.readUInt16LE(off + 26);
    const data = zip.subarray(off + 30 + lnlen, off + 30 + lnlen + size);
    out.push({ name, method, time, date, crc, xlen, ext, data });
    p += 46 + nlen;
  }
  return out;
}

test("zip déterministe : mêmes octets quel que soit l'ordre, STORE, date fixe", () => {
  const files = [
    { name: "locksy-extension/popup.js", data: Buffer.from("console.log(1);\n") },
    { name: "locksy-extension/lib/a.js", data: Buffer.from("export const a = 1;\n") },
    { name: "locksy-extension/manifest.json", data: Buffer.from("{}\n") },
  ];
  const a = makeZip(files);
  const b = makeZip([...files].reverse());
  assert.ok(a.equals(b));
  const entries = readZip(a);
  assert.deepEqual(entries.map((e) => e.name), ["locksy-extension/lib/a.js", "locksy-extension/manifest.json", "locksy-extension/popup.js"]);
  for (const e of entries) {
    assert.equal(e.method, 0);
    assert.equal(e.time, 0);
    assert.equal(e.date, 0x21);
    assert.equal(e.xlen, 0);
    assert.equal(e.ext, 0);
    assert.equal(e.crc, crc32Fallback(e.data));
  }
  assert.equal(entries[0].data.toString(), "export const a = 1;\n");
  assert.throws(() => makeZip([{ name: "../evil.js", data: Buffer.alloc(0) }]), /invalide/);
});

test("arguments, version et fichiers embarqués", (t) => {
  assert.deepEqual(parseArgs(["--wasm", "x.wasm", "--dev", "--out", "o"]), { wasm: "x.wasm", dev: true, test: false, out: "o" });
  assert.equal(parseArgs(["--test"]).test, true);
  assert.throws(() => parseArgs(["--dev", "--test"]), /ne se combinent pas/);
  assert.throws(() => parseArgs(["--wasm"]), /manquante/);
  assert.throws(() => parseArgs(["--zip"]), /inconnu/);
  assert.equal(workspaceVersion('[workspace]\nmembers = []\n\n[workspace.package]\nversion = "1.2.3"\n'), "1.2.3");
  assert.equal(workspaceVersion('[workspace.package]\nversion = "2.0.0-rc.1"\n'), "2.0.0");
  assert.equal(workspaceVersion('[package]\nversion = "9.9.9"\n'), null);
  const d = tempDir(t);
  mkdirSync(join(d, "test"));
  for (const f of ["popup.js", "dev-fake.js", "test/x.test.js", "match.js"]) writeFileSync(join(d, f), "");
  assert.deepEqual(shippedSources(d, false), ["match.js", "popup.js"]);
  assert.deepEqual(shippedSources(d, true), ["dev-fake.js", "match.js", "popup.js"]);
});
test("préchargement du popup : imports statiques seulement, triés, liens à la place du repère", (t) => {
  const d = tempDir(t);
  mkdirSync(join(d, "popup"));
  mkdirSync(join(d, "lib", "ui"), { recursive: true });
  const lines = (...l) => `${l.join("\n")}\n`;
  writeFileSync(join(d, "popup.js"), lines('import { a } from "./popup/a.js";', 'import "./lib/ui/index.js";'));
  writeFileSync(join(d, "popup", "a.js"), lines(
    'export { b } from "../lib/ui/index.js";', 'const f = DEV ? await import("../dev-fake.js") : null;', "export const a = 1;"));
  writeFileSync(join(d, "lib", "ui", "index.js"), lines('import { c } from "./core.js";', "export const b = c;"));
  writeFileSync(join(d, "lib", "ui", "core.js"), lines('import "../../popup.js";', "export const c = 1;"));
  // Cycle vers l'entrée : jamais préchargée ; import() dynamique : ignoré.
  assert.deepEqual(startupModules(d, "popup.js"), ["lib/ui/core.js", "lib/ui/index.js", "popup/a.js"]);
  writeFileSync(join(d, "lib", "ui", "core.js"), lines('import "./absent.js";'));
  assert.throws(() => startupModules(d, "popup.js"), /absent de l'extension/);
  writeFileSync(join(d, "lib", "ui", "core.js"), lines('import x from "https://cdn.example.com/x.js";'));
  assert.throws(() => startupModules(d, "popup.js"), /modules relatifs/);

  const page = lines("<head>", `  ${PRELOAD_MARKER}`, '  <script type="module" src="popup.js"></script>', "</head>");
  assert.equal(withModulePreload(page, ["a.js", "b/c.js"]), lines(
    "<head>", '  <link rel="modulepreload" href="a.js">', '  <link rel="modulepreload" href="b/c.js">',
    '  <script type="module" src="popup.js"></script>', "</head>"));
  assert.throws(() => withModulePreload("<head></head>", ["a.js"]), /repère/);
  assert.throws(() => withModulePreload(`${PRELOAD_MARKER}${PRELOAD_MARKER}`, ["a.js"]), /repère/);
});

const WASM = join(repo, "dist", "release", "locksy.wasm");

test("build de production : copies de l'interface, pas de mode fake, archive reproductible", { skip: !existsSync(WASM) && "dist/release/locksy.wasm absent" }, (t) => {
  const out1 = tempDir(t);
  const out2 = tempDir(t);
  const quiet = () => {};
  const r1 = build({ wasm: WASM, out: out1, log: quiet });
  const r2 = build({ wasm: WASM, out: out2, log: quiet });
  assert.equal(r1.sha256, r2.sha256, "deux constructions = mêmes octets");
  assert.ok(readFileSync(r1.zipPath).equals(readFileSync(r2.zipPath)));
  assert.ok(!r1.files.includes("dev-fake.js"));
  assert.ok(!r1.files.some((f) => f.startsWith("test/")));
  assert.match(readFileSync(join(r1.dest, "lib", "build-flags.js"), "utf8"), /export const DEV = false;\nexport const TEST = false;/);
  assert.equal(readFileSync(join(out1, "locksy-extension.zip.sha256"), "utf8"), `${r1.sha256}  locksy-extension.zip\n`);
  const manifest = JSON.parse(readFileSync(join(r1.dest, "manifest.json"), "utf8"));
  assert.equal(manifest.background.service_worker, "background.js");
  assert.equal(manifest.host_permissions, undefined);
  for (const p of ["alarms", "offscreen", "idle", "clipboardWrite"]) assert.ok(manifest.permissions.includes(p), p);
  for (const f of [
    "background.js", "offscreen.html", "offscreen.js", "managed-schema.json", "match.js", "settings.js", "popup.html",
    "popup/list.js", "popup/save.js", "popup/fill.js", "lib/locksy.wasm", "lib/sprite.svg", "lib/css/app.css",
    "lib/css/tokens.css", "lib/css/components.css", "lib/ui/index.js", "lib/i18n.js", "lib/i18n/fr.js", "lib/settings-client.js",
  ]) {
    assert.ok(r1.files.includes(f), f);
  }
  assert.ok(readFileSync(join(r1.dest, "lib", "css", "components.css")).equals(readFileSync(join(repo, "web", "css", "components.css"))));
  assert.ok(!r1.files.some((f) => f.startsWith("lib/views/")));
  // Le popup ne référence que des fichiers embarqués.
  const html = readFileSync(join(r1.dest, "popup.html"), "utf8");
  for (const [, ref] of html.matchAll(/(?:href|src)="([^"]+)"/g)) assert.ok(r1.files.includes(ref), ref);
  // Toute la fermeture du popup est préchargée (vues jamais, dev-fake.js jamais).
  const preloaded = [...html.matchAll(/<link rel="modulepreload" href="([^"]+)">/g)].map((m) => m[1]);
  assert.deepEqual(preloaded, startupModules(r1.dest, "popup.js"));
  for (const f of ["lib/ui/index.js", "lib/i18n.js", "lib/i18n/fr.js", "lib/vault.js", "popup/list.js"]) assert.ok(preloaded.includes(f), f);
  assert.ok(!html.includes(PRELOAD_MARKER));

  const dev = build({ wasm: WASM, out: tempDir(t), dev: true, log: quiet });
  assert.ok(dev.files.includes("dev-fake.js"));
  assert.match(readFileSync(join(dev.dest, "lib", "build-flags.js"), "utf8"), /export const DEV = true;/);
  assert.throws(() => build({ wasm: join(out1, "absent.wasm"), out: tempDir(t), log: quiet }), /introuvable/);
});

test("variante des tests : dossier à part, accès aux sites fixé, aucune archive", { skip: !existsSync(WASM) && "dist/release/locksy.wasm absent" }, (t) => {
  const out = tempDir(t);
  const r = build({ wasm: WASM, out, test: true, log: () => {} });
  assert.match(r.dest, /locksy-extension-test$/);
  assert.equal(r.zipPath, null);
  assert.ok(!existsSync(join(out, "locksy-extension.zip")));
  const manifest = JSON.parse(readFileSync(join(r.dest, "manifest.json"), "utf8"));
  assert.deepEqual(manifest.host_permissions, ["http://*/*", "https://*/*"]);
  assert.match(readFileSync(join(r.dest, "lib", "build-flags.js"), "utf8"), /export const TEST = true;/);
  assert.throws(() => build({ wasm: WASM, out, test: true, dev: true, log: () => {} }), /ne se combinent pas/);
});
