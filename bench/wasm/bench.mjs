#!/usr/bin/env node
// Coût du pont WebAssembly sous Node (lot Q1, cahier 00 §6.3, audit 05 §2.5).
//
// Charge le vrai module locksy.wasm à travers web/js/wasm.js (fetch simulé, comme
// web/tests/vault.test.mjs) et mesure, via locksy_call exactement comme l'interface :
//   - le coût d'un appel : 10 000 « new_uuid » (opération peu coûteuse) ;
//   - 10 000 « decrypt » d'éléments de 1 Kio (déchiffrement du coffre à la synchronisation) ;
//   - une dérivation du mot de passe maître aux paramètres réels (64 Mio, t=3), pour information.
// Décision : une opération groupée « decrypt_many » est nécessaire si les 10 000 decrypt
// prennent 1,5 s ou plus.
//
// Usage :
//   node bench/wasm/bench.mjs [--wasm bench/.cache/locksy.wasm] [--rebuild] [--count 10000]
//                             [--no-kdf] [--update [--ref bench/baselines/criterion-ref.json]]
//   Sans --update, le résultat est seulement affiché. Avec --update, la section « wasm » de la
//   référence est réécrite (le reste du fichier est conservé).
//
// Module : bench/.cache/locksy.wasm est réutilisé s'il existe. Sinon (ou avec --rebuild), il est
// extrait de l'image du banc ($LOCKSY_IMAGE, défaut locksy-bench:local) si elle existe, ou compilé
// par la recette wasm dans le conteneur locksy-toolchain (volume locksy-tgt-wasm).
// Node 20 ou plus, aucune dépendance.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CACHE = join(repo, "bench", ".cache", "locksy.wasm");
/** Seuil de décision du cahier : au-delà, le déchiffrement du coffre doit passer par lots. */
const DECRYPT_MANY_LIMIT_MS = 1500;
const RULE = "decrypt_many nécessaire si 10 000 decrypt de 1 Kio prennent 1,5 s ou plus sous Node";
const nf = new Intl.NumberFormat("fr-FR", { maximumSignificantDigits: 3 });

// ------------------------------------------------------------------ Module

function docker(args, what) {
  const r = spawnSync("docker", args, { stdio: ["ignore", "inherit", "inherit"], env: { ...process.env, MSYS_NO_PATHCONV: "1" } });
  if (r.error || r.status !== 0) throw new Error(`${what} : échec de docker ${args[0]} (${r.error?.message ?? `code ${r.status}`}).`);
}

function imageExists(image) {
  return spawnSync("docker", ["image", "inspect", image], { stdio: "ignore" }).status === 0;
}

/** Produit bench/.cache/locksy.wasm selon la recette du contrat C10. */
function produceWasm() {
  mkdirSync(dirname(CACHE), { recursive: true });
  const image = process.env.LOCKSY_IMAGE || "locksy-bench:local";
  if (imageExists(image)) {
    console.log(`Extraction de locksy.wasm depuis l'image ${image}…`);
    const name = `locksy-q1-wasm-${process.pid}`;
    docker(["create", "--name", name, image], "création du conteneur");
    try {
      docker(["cp", `${name}:/app/web/locksy.wasm`, CACHE], "copie du module");
    } finally {
      docker(["rm", name], "suppression du conteneur");
    }
    return;
  }
  console.log("Compilation de locksy.wasm dans le conteneur locksy-toolchain…");
  const src = repo.replaceAll("\\", "/");
  docker(
    [
      "run", "--rm", "-v", `${src}:/src`, "-v", "locksy-reg:/usr/local/cargo/registry", "-v", "locksy-tgt-wasm:/src/target", "-w", "/src", "locksy-toolchain",
      "bash", "-c", "cargo build --release -p locksy-wasm --target wasm32-unknown-unknown && mkdir -p bench/.cache && cp target/wasm32-unknown-unknown/release/locksy_wasm.wasm bench/.cache/locksy.wasm",
    ],
    "compilation du module",
  );
}

/** Charge web/js/wasm.js avec un fetch simulé qui sert le module local. */
async function loadBridge(wasmPath) {
  const bytes = readFileSync(wasmPath);
  globalThis.fetch = async () => new Response(bytes, { headers: { "content-type": "application/wasm" } });
  const W = await import(pathToFileURL(join(repo, "web", "js", "wasm.js")).href);
  const A = await import(pathToFileURL(join(repo, "web", "js", "aad.js")).href);
  await W.loadCrypto("/locksy.wasm");
  return { W, A, size: bytes.length };
}

// ------------------------------------------------------------------ Mesures

/** Durée (ms) de n répétitions de fn, après un court échauffement. */
function time(n, fn) {
  for (let i = 0; i < Math.min(200, n); i++) fn(i);
  const t0 = performance.now();
  for (let i = 0; i < n; i++) fn(i);
  return performance.now() - t0;
}

function measure({ W, A }, count, withKdf) {
  const callMs = time(count, () => W.call("new_uuid"));

  const key = W.call("generate_key");
  const aad = A.item(W.call("new_uuid"), W.call("new_uuid"));
  // 1 Kio exactement en UTF-8 (les lettres accentuées occupent deux octets).
  const head = "Élément de test ";
  const plaintext = head + "x".repeat(1024 - Buffer.byteLength(head));
  const data = W.call("encrypt", { key, plaintext, aad });
  if (W.call("decrypt", { key, data, aad }) !== plaintext) throw new Error("decrypt ne restitue pas le texte d'origine.");
  const decryptMs = time(count, () => W.call("decrypt", { key, data, aad }));
  W.call("drop_key", { key });

  let deriveMs = null;
  if (withKdf) {
    const salt = Buffer.alloc(16, 7).toString("base64url");
    const t0 = performance.now();
    const mk = W.call("derive_master", { password: "cheval agrafe batterie correcte", kdf: { alg: "argon2id", m_kib: 64 * 1024, t: 3, p: 1, salt } });
    deriveMs = performance.now() - t0;
    W.call("drop_key", { key: mk.enc_key });
  }
  // Ramené à 10 000 appels si --count diffère, pour comparer au seuil du cahier.
  const decrypt10k = (decryptMs * 10000) / count;
  return {
    node: process.versions.node,
    call_overhead_us: round((callMs * 1000) / count, 2),
    decrypt_1KiB_x10000_ms: round(decrypt10k, 1),
    decrypt_many_required: decrypt10k >= DECRYPT_MANY_LIMIT_MS,
    ...(deriveMs === null ? {} : { derive_master_64MiB_t3_ms: round(deriveMs, 0) }),
    rule: RULE,
  };
}

function round(n, digits) {
  const f = 10 ** digits;
  return Math.round(n * f) / f;
}

// ------------------------------------------------------------------ Programme

async function main() {
  const { values } = parseArgs({
    options: {
      wasm: { type: "string", default: CACHE },
      rebuild: { type: "boolean", default: false },
      count: { type: "string", default: "10000" },
      "no-kdf": { type: "boolean", default: false },
      update: { type: "boolean", default: false },
      ref: { type: "string", default: join(repo, "bench", "baselines", "criterion-ref.json") },
    },
  });
  const count = Number(values.count);
  if (!Number.isInteger(count) || count < 100) throw new Error("--count attend un entier d'au moins 100.");
  const wasmPath = resolve(values.wasm);
  if (wasmPath === CACHE && (values.rebuild || !existsSync(CACHE))) produceWasm();
  if (!existsSync(wasmPath)) throw new Error(`${wasmPath} introuvable.`);

  const bridge = await loadBridge(wasmPath);
  console.log(`Module ${relative(repo, wasmPath) || wasmPath} (${nf.format(bridge.size / 1024)} Kio), Node ${process.versions.node}, ${nf.format(count)} appels par mesure.`);
  const wasm = measure(bridge, count, !values["no-kdf"]);
  console.log(`  Coût d'un appel locksy_call (new_uuid)   : ${nf.format(wasm.call_overhead_us)} µs`);
  console.log(`  10 000 decrypt de 1 Kio                  : ${nf.format(wasm.decrypt_1KiB_x10000_ms)} ms (seuil ${nf.format(DECRYPT_MANY_LIMIT_MS)} ms)`);
  if (wasm.derive_master_64MiB_t3_ms !== undefined) console.log(`  derive_master 64 Mio, t=3 (information)  : ${nf.format(wasm.derive_master_64MiB_t3_ms)} ms`);
  console.log(`Décision : decrypt_many ${wasm.decrypt_many_required ? "NÉCESSAIRE (à ajouter au module wasm et à vault.js)" : "non nécessaire"}.`);

  if (values.update) {
    if (!existsSync(values.ref)) throw new Error(`${values.ref} introuvable : enregistrez d'abord la référence criterion (criterion-gate.mjs --update).`);
    const ref = JSON.parse(readFileSync(values.ref, "utf8"));
    ref.wasm = wasm;
    writeFileSync(values.ref, `${JSON.stringify(ref, null, 2)}\n`);
    console.log(`Section wasm réécrite : ${values.ref}.`);
  }
  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    console.error(`Erreur : ${e.message}`);
    process.exitCode = 1;
  },
);
