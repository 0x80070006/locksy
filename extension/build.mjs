// Construit l'extension prête à charger et son archive de distribution.
//
// Usage : node extension/build.mjs [--wasm <chemin>] [--dev | --test] [--out <dossier>]
//   --wasm : module WebAssembly compilé (sinon $LOCKSY_WASM, sinon
//            <racine>/dist/release/locksy.wasm) ;
//   --dev  : embarque la simulation des API (dev-fake.js) pour tester le popup
//            comme une simple page ; jamais pour une version distribuée ;
//   --test : variante des tests de bout en bout (cahier 05, §4.7) :
//            <out>/locksy-extension-test, accès aux sites fixé dans le manifeste
//            (Playwright ne sait pas simuler le geste qui accorde activeTab),
//            lecture du presse-papiers, serveur http accepté ; jamais d'archive ;
//   --out  : dossier de sortie (défaut : extension/dist).
//
// Produit :
//   <out>/locksy-extension/          dossier à charger (« non empaqueté ») ;
//   <out>/locksy-extension.zip       archive déterministe (racine locksy-extension/) ;
//   <out>/locksy-extension.zip.sha256  « <hex>  locksy-extension.zip ».
//
// Copies de l'interface web (contrat C4.7), toutes vérifiées octet pour octet :
//   lib/      web/js/{wasm,aad,api,vault,settings-client}.js, les composants
//             web/js/ui/**, web/js/i18n.js et son catalogue web/js/i18n/**,
//             plus la fermeture de leurs imports relatifs (jamais hors de
//             web/js/, jamais web/js/views/) ;
//   lib/css/  web/css/*.css (app.css importe les autres par chemin relatif) ;
//   lib/sprite.svg  web/icons/sprite.svg (icônes des composants).
//
// Permissions (manifest.json) :
//   - activeTab + scripting : remplir l'onglet actif, à la demande seulement ;
//   - storage : adresse du serveur (local), session déverrouillée en mémoire
//     (session), politique d'entreprise (managed, managed-schema.json) ;
//   - alarms : verrouillage automatique et effacement du presse-papiers popup fermé ;
//   - offscreen + clipboardWrite : le service worker n'a pas de presse-papiers ;
//     il ouvre un document offscreen (raison CLIPBOARD) qui l'efface avec
//     document.execCommand("copy"), ce qu'autorise uniquement clipboardWrite ;
//   - idle : verrouiller quand la session Windows se verrouille ;
//   - identity : connexion d'entreprise (SSO) par launchWebAuthFlow.

import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, posix, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");

/** Modules de logique partagés avec l'extension (chiffrement, API, politique). */
export const SHARED_ENTRIES = ["wasm.js", "aad.js", "api.js", "vault.js", "settings-client.js"];
/** Composants et textes de l'interface (cahier §5.4 L14, contrat C4.7). */
export const UI_ENTRIES = ["ui/index.js", "i18n.js"];

/**
 * Imports dynamiques non littéraux admis, par module : leur cible n'est pas
 * dans la fermeture. ui/qr.js charge le décodeur de QR code vendorisé, dont
 * l'adresse est réglée par setQrDecoderUrl() ; dans l'extension, la CSP
 * (script-src 'self') la limite de toute façon aux fichiers embarqués, et le
 * popup ne lit jamais de QR code.
 */
export const DYNAMIC_IMPORTS = Object.freeze({ "ui/qr.js": ["decoderUrl"] });

/** Variante des tests : accès aux pages de test et lecture du presse-papiers. */
export const TEST_HOST_PERMISSIONS = Object.freeze(["http://*/*", "https://*/*"]);
export const TEST_PERMISSIONS = Object.freeze(["clipboardRead"]);

// ------------------------------------------------------------------ Arguments

export function parseArgs(argv) {
  const opts = { wasm: null, dev: false, test: false, out: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dev") opts.dev = true;
    else if (a === "--test") opts.test = true;
    else if (a === "--wasm" || a === "--out") {
      const v = argv[++i];
      if (!v || v.startsWith("--")) throw new Error(`Valeur manquante après ${a}.`);
      opts[a.slice(2)] = v;
    } else if (a === "--help" || a === "-h") opts.help = true;
    else throw new Error(`Argument inconnu : ${a}`);
  }
  if (opts.dev && opts.test) throw new Error("--dev et --test ne se combinent pas.");
  return opts;
}

// ------------------------------------------------------------------ Imports partagés

const STATIC_IMPORT = /^\s*(?:import|export)\s[^;]*?\bfrom\s*["']([^"']+)["']/gm;
const BARE_IMPORT = /^\s*import\s*["']([^"']+)["']/gm;
const DYNAMIC_IMPORT = /\bimport\s*\(\s*([^)]*?)\s*\)/g;
// Chaînes et gabarits (sauf l'argument littéral d'un import()), puis commentaires :
// retirés avant de chercher les import() dynamiques (« l'import (…) » d'un texte n'en est pas un).
const QUOTED = /(\bimport\s*\(\s*)?("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`)/g;
const COMMENTS = /\/\*[\s\S]*?\*\/|\/\/[^\n]*/g;

/** Source sans texte ni commentaire, pour la recherche des import() dynamiques. */
function codeOnly(source) {
  return source.replace(QUOTED, (m, imp) => (imp ? m : '""')).replace(COMMENTS, "");
}

/**
 * Spécificateurs importés par un module (imports statiques, ré-exports et
 * import() littéraux). `dynamic` liste les expressions non littérales admises
 * pour ce module (DYNAMIC_IMPORTS) ; toute autre fait échouer.
 */
export function importsOf(source, file = "module", dynamic = []) {
  const found = new Set();
  for (const re of [STATIC_IMPORT, BARE_IMPORT]) {
    for (const m of source.matchAll(re)) found.add(m[1]);
  }
  for (const m of codeOnly(source).matchAll(DYNAMIC_IMPORT)) {
    const lit = /^["']([^"']+)["']$/.exec(m[1]);
    if (lit) found.add(lit[1]);
    else if (!dynamic.includes(m[1])) {
      throw new Error(`${file} : import() non littéral (${m[1]}) : impossible de vérifier ce qui serait chargé.`);
    }
  }
  return [...found];
}

// Chemins admis dans web/js/ : modules de premier niveau, composants (ui/) et
// catalogue (i18n/). Jamais les vues (views/), qui supposent l'application web.
const ALLOWED_PATH = /^(?:[A-Za-z0-9_-]+\.js|ui\/[A-Za-z0-9_-]+\.js|i18n\/[A-Za-z0-9_-]+\.js)$/;
const RELATIVE_SPEC = /^\.{1,2}\/[A-Za-z0-9_./-]+\.js$/;

/**
 * Résout un import relatif de `from` (chemin dans web/js/, avec « / ») ; null
 * s'il sort des chemins admis (absolu, URL, module nu, remontée hors de
 * web/js/, vue, paramètre d'adresse…).
 */
export function resolveShared(from, spec) {
  if (!RELATIVE_SPEC.test(spec)) return null;
  const target = posix.normalize(posix.join(posix.dirname(from), spec));
  return ALLOWED_PATH.test(target) ? target : null;
}

/**
 * Fermeture transitive des imports des modules d'entrée (chemins relatifs à
 * `dir`, par exemple « vault.js » ou « ui/index.js »). Renvoie les chemins triés.
 */
export function sharedClosure(dir, entries = SHARED_ENTRIES) {
  const seen = new Set();
  const todo = [...entries];
  while (todo.length) {
    const name = todo.pop();
    if (seen.has(name)) continue;
    const file = join(dir, ...name.split("/"));
    if (!existsSync(file)) throw new Error(`Module partagé introuvable : web/js/${name}`);
    seen.add(name);
    for (const spec of importsOf(readFileSync(file, "utf8"), `web/js/${name}`, DYNAMIC_IMPORTS[name] || [])) {
      const target = resolveShared(name, spec);
      if (!target) {
        throw new Error(`web/js/${name} importe « ${spec} » : seuls les modules de web/js/, web/js/ui/ et web/js/i18n/ peuvent être partagés avec l'extension.`);
      }
      todo.push(target);
    }
  }
  return [...seen].sort(byteOrder);
}

// ------------------------------------------------------------------ Préchargement du popup

/** Repère de popup.html remplacé par les liens de préchargement. */
export const PRELOAD_MARKER = "<!-- modulepreload -->";

/**
 * Modules chargés au démarrage d'une page de l'extension : fermeture des
 * imports STATIQUES de `entry` (chemin relatif à `dir`), sans l'entrée
 * elle-même, triée. Les import() dynamiques (dev-fake.js) n'en font pas partie.
 */
export function startupModules(dir, entry) {
  const seen = new Set([entry]);
  const todo = [entry];
  while (todo.length) {
    const name = todo.pop();
    const source = readFileSync(join(dir, ...name.split("/")), "utf8");
    for (const re of [STATIC_IMPORT, BARE_IMPORT]) {
      for (const m of source.matchAll(re)) {
        if (!RELATIVE_SPEC.test(m[1])) throw new Error(`${name} importe « ${m[1]} » : seuls les modules relatifs de l'extension sont admis.`);
        const target = posix.normalize(posix.join(posix.dirname(name), m[1]));
        if (target.startsWith("../") || !existsSync(join(dir, ...target.split("/")))) throw new Error(`${name} importe « ${m[1]} », absent de l'extension.`);
        if (!seen.has(target)) {
          seen.add(target);
          todo.push(target);
        }
      }
    }
  }
  seen.delete(entry);
  return [...seen].sort(byteOrder);
}

/**
 * Remplace le repère de la page par un <link rel="modulepreload"> par
 * module : le navigateur demande toute la fermeture d'un coup au lieu de
 * la découvrir niveau par niveau (cahier §6.5, ouverture du popup < 400 ms).
 */
export function withModulePreload(html, modules) {
  const at = html.indexOf(PRELOAD_MARKER);
  if (at < 0 || html.indexOf(PRELOAD_MARKER, at + 1) >= 0) throw new Error(`popup.html doit contenir une fois le repère ${PRELOAD_MARKER}.`);
  const indent = /[ \t]*$/.exec(html.slice(0, at))[0];
  const links = modules.map((m) => `<link rel="modulepreload" href="${m}">`).join(`\n${indent}`);
  return html.slice(0, at) + links + html.slice(at + PRELOAD_MARKER.length);
}

// ------------------------------------------------------------------ Fichiers

/** Liste récursive (chemins relatifs avec « / »), triée. */
export function listFiles(dir, base = dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFiles(full, base));
    else if (entry.isFile()) out.push(relative(base, full).split(sep).join("/"));
  }
  return out.sort(byteOrder);
}

function byteOrder(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return Buffer.compare(x, y);
}

function copyInto(from, to) {
  mkdirSync(dirname(to), { recursive: true });
  copyFileSync(from, to);
}

/** Fichiers de src/ à embarquer : jamais les tests ; dev-fake.js seulement en --dev. */
export function shippedSources(srcDir, dev) {
  return listFiles(srcDir).filter((f) => !f.startsWith("test/") && (dev || f !== "dev-fake.js"));
}

// ------------------------------------------------------------------ Zip déterministe

let CRC_TABLE = null;
function crc32Fallback(buf) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export const crc32 = (buf) => (typeof zlib.crc32 === "function" ? zlib.crc32(buf) >>> 0 : crc32Fallback(buf));
export { crc32Fallback };

// Date DOS fixe : 1980-01-01 00:00 (heure 0, date (0 << 9) | (1 << 5) | 1).
const DOS_TIME = 0;
const DOS_DATE = 0x21;

/**
 * Archive zip déterministe, méthode STORE (aucune dépendance à la version de
 * zlib) : entrées triées, sans champ « extra », attributs externes nuls.
 * @param {{name: string, data: Buffer}[]} entries
 */
export function makeZip(entries) {
  const sorted = [...entries].sort((a, b) => byteOrder(a.name, b.name));
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data } of sorted) {
    if (!name || name.startsWith("/") || name.includes("\\") || name.split("/").includes("..")) {
      throw new Error(`Nom d'entrée invalide dans l'archive : ${name}`);
    }
    const nameBuf = Buffer.from(name, "utf8");
    const utf8 = /[^\x20-\x7e]/.test(name) ? 0x0800 : 0;
    const crc = crc32(data);
    const size = data.length;
    if (size > 0xfffffffe) throw new Error(`Fichier trop volumineux pour l'archive : ${name}`);

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(10, 4); // version requise : 1.0 (STORE)
    lh.writeUInt16LE(utf8, 6);
    lh.writeUInt16LE(0, 8); // méthode STORE
    lh.writeUInt16LE(DOS_TIME, 10);
    lh.writeUInt16LE(DOS_DATE, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(size, 18);
    lh.writeUInt32LE(size, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, nameBuf, data);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4); // créé par : 2.0, MS-DOS
    ch.writeUInt16LE(10, 6);
    ch.writeUInt16LE(utf8, 8);
    ch.writeUInt16LE(0, 10);
    ch.writeUInt16LE(DOS_TIME, 12);
    ch.writeUInt16LE(DOS_DATE, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(size, 20);
    ch.writeUInt32LE(size, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt16LE(0, 30); // extra
    ch.writeUInt16LE(0, 32); // commentaire
    ch.writeUInt16LE(0, 34); // disque
    ch.writeUInt16LE(0, 36); // attributs internes
    ch.writeUInt32LE(0, 38); // attributs externes
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, nameBuf);

    offset += 30 + nameBuf.length + size;
  }
  if (sorted.length > 0xffff) throw new Error("Trop de fichiers pour l'archive.");
  const central = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(sorted.length, 8);
  end.writeUInt16LE(sorted.length, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, central, end]);
}

// ------------------------------------------------------------------ Version

/** Version de [workspace.package] dans Cargo.toml, au format accepté par Chrome (1 à 4 entiers). */
export function workspaceVersion(cargoToml) {
  const section = /^\[workspace\.package\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(cargoToml);
  const v = section && /^\s*version\s*=\s*"([^"]+)"/m.exec(section[1]);
  if (!v) return null;
  const core = v[1].split(/[-+]/)[0];
  return /^\d+(\.\d+){0,3}$/.test(core) ? core : null;
}

// ------------------------------------------------------------------ Manifeste

/**
 * Manifeste final : version du dépôt ; pour la variante des tests, accès aux
 * pages de test et lecture du presse-papiers. Une version distribuable ne
 * porte JAMAIS ces permissions (vérifié par checkRelease).
 */
export function finalManifest(manifest, { version, test = false }) {
  const m = structuredClone(manifest);
  if (version) m.version = version;
  if (test) {
    m.name = `${m.name} (tests)`;
    m.host_permissions = [...TEST_HOST_PERMISSIONS];
    m.permissions = [...new Set([...(m.permissions || []), ...TEST_PERMISSIONS])];
  }
  return m;
}

/** Refuse une version distribuable qui porterait un réglage propre aux tests ou au développement. */
export function checkRelease({ manifest, files, flags }) {
  if (manifest.host_permissions?.length) throw new Error("Le manifeste distribué ne doit pas fixer d'accès aux sites (host_permissions).");
  if (TEST_PERMISSIONS.some((p) => manifest.permissions?.includes(p))) throw new Error("Le manifeste distribué ne doit pas lire le presse-papiers.");
  if (files.some((f) => f === "dev-fake.js" || f.startsWith("test/"))) throw new Error("Le build de production contient des fichiers de développement.");
  if (!/export const DEV = false;/.test(flags) || !/export const TEST = false;/.test(flags)) {
    throw new Error("lib/build-flags.js doit valoir DEV = false et TEST = false dans une version distribuée.");
  }
}

// ------------------------------------------------------------------ Construction

export function build({ wasm = null, dev = false, test = false, out = null, log = console.log } = {}) {
  if (dev && test) throw new Error("--dev et --test ne se combinent pas.");
  const outRoot = resolve(out || join(here, "dist"));
  const folder = test ? "locksy-extension-test" : "locksy-extension";
  const dest = join(outRoot, folder);
  const src = join(here, "src");
  const webJs = join(repo, "web", "js");
  const webCss = join(repo, "web", "css");
  const sprite = join(repo, "web", "icons", "sprite.svg");

  const wasmPath = resolve(wasm || process.env.LOCKSY_WASM || join(repo, "dist", "release", "locksy.wasm"));
  if (!existsSync(wasmPath) || !statSync(wasmPath).isFile()) {
    throw new Error(`locksy.wasm introuvable (${wasmPath}). Compilez-le (cargo build --release -p locksy-wasm --target wasm32-unknown-unknown) puis passez --wasm <chemin> ou LOCKSY_WASM.`);
  }
  // Fermeture calculée AVANT de toucher au dossier de sortie : un import
  // interdit ne laisse pas une extension à moitié construite.
  const shared = sharedClosure(webJs, [...SHARED_ENTRIES, ...UI_ENTRIES]);
  const css = readdirSync(webCss).filter((f) => f.endsWith(".css")).sort(byteOrder);
  if (!css.includes("app.css")) throw new Error("web/css/app.css introuvable.");

  rmSync(dest, { recursive: true, force: true });
  mkdirSync(join(dest, "lib"), { recursive: true });

  // [source, destination] de chaque copie de l'interface web, vérifiées à la fin.
  const copies = [
    ...shared.map((f) => [join(webJs, ...f.split("/")), join(dest, "lib", ...f.split("/"))]),
    ...css.map((f) => [join(webCss, f), join(dest, "lib", "css", f)]),
    [sprite, join(dest, "lib", "sprite.svg")],
  ];
  for (const f of shippedSources(src, dev)) copyInto(join(src, f), join(dest, f));
  for (const [from, to] of copies) copyInto(from, to);
  copyInto(wasmPath, join(dest, "lib", "locksy.wasm"));
  const flags = `// Généré par extension/build.mjs : ne pas modifier.\nexport const DEV = ${dev};\nexport const TEST = ${test};\n`;
  writeFileSync(join(dest, "lib", "build-flags.js"), flags);

  // Icônes : logo officiel (branding/png).
  for (const size of [16, 32, 48, 128]) {
    copyInto(join(repo, "branding", "png", `locksy-${size}.png`), join(dest, "icons", `${size}.png`));
  }

  // Préchargement des modules du popup (fermeture calculée sur la copie finale).
  const popupHtml = join(dest, "popup.html");
  const preloaded = startupModules(dest, "popup.js");
  writeFileSync(popupHtml, withModulePreload(readFileSync(popupHtml, "utf8"), preloaded));

  const manifestPath = join(dest, "manifest.json");
  const version = workspaceVersion(readFileSync(join(repo, "Cargo.toml"), "utf8"));
  const manifest = finalManifest(JSON.parse(readFileSync(manifestPath, "utf8")), { version, test });
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  // Copies identiques octet pour octet (une modification pendant la
  // construction les ferait diverger).
  for (const [from, to] of copies) {
    if (!readFileSync(to).equals(readFileSync(from))) {
      throw new Error(`${relative(dest, to).split(sep).join("/")} diffère de ${relative(repo, from).split(sep).join("/")} (modification pendant la construction ?).`);
    }
  }
  const files = listFiles(dest);
  if (!dev && !test) checkRelease({ manifest, files, flags });

  log(`Extension prête${dev ? " (mode développement)" : test ? " (variante des tests)" : ""} : ${dest}`);
  log(`Copies de l'interface web : ${shared.length} modules, ${css.length} feuilles de style, sprite d'icônes`);
  log(`Popup : ${preloaded.length} modules préchargés`);
  if (test) return { dest, zipPath: null, sha256: null, files, shared };

  // Archive déterministe et empreinte.
  const zip = makeZip(files.map((f) => ({ name: `locksy-extension/${f}`, data: readFileSync(join(dest, f)) })));
  const zipPath = join(outRoot, "locksy-extension.zip");
  writeFileSync(zipPath, zip);
  const sha256 = createHash("sha256").update(zip).digest("hex");
  writeFileSync(`${zipPath}.sha256`, `${sha256}  locksy-extension.zip\n`);
  log(`Archive : ${zipPath} (${files.length} fichiers, ${zip.length} octets)`);
  log(`SHA256  : ${sha256}`);
  return { dest, zipPath, sha256, files, shared };
}

// ------------------------------------------------------------------ Point d'entrée

const invoked = process.argv[1] && resolve(process.argv[1]).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();
if (invoked) {
  try {
    const opts = parseArgs(process.argv.slice(2));
    if (opts.help) {
      console.log("Usage : node extension/build.mjs [--wasm <chemin>] [--dev | --test] [--out <dossier>]");
    } else {
      build(opts);
    }
  } catch (e) {
    process.exitCode = 1;
    console.error(`Échec de la construction de l'extension : ${e.message}`);
  }
}
