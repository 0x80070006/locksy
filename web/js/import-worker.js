// Worker d'import : lit une base KDBX ou un export JSON chiffré hors du fil
// principal, avec le noyau WebAssembly (dérivation de clé, déchiffrement,
// lecture), pour que la page reste réactive pendant Argon2.
//
// Protocole (contrat C1.7, consommé par web/js/import.js) :
//   entrée  { type: "parse", id, format: "kdbx" | "bitwarden_json",
//             file: ArrayBuffer (transféré), password, keyfile?: ArrayBuffer }
//           { type: "dispose" }  → le worker se termine
//   sorties { type: "progress", id, phase: "kdf" | "decrypt" | "parse" | "map", ratio }
//           { type: "result", id, items: [{ data, folder, source_id }], folders, warnings: [{ code, index? }] }
//           { type: "error", id, code }  (codes d'ImportError, ou "worker_failed")
//
// Le mot de passe n'est jamais renvoyé ni journalisé ; les tampons reçus sont
// effacés après usage. Chargement : new Worker(new URL("./import-worker.js",
// import.meta.url), { type: "module" }).

import { loadCrypto, call, CryptoError } from "./wasm.js";

/** Codes d'erreur stables du noyau (libellés import.error.<code>). */
export const ERROR_CODES = Object.freeze([
  "wrong_password",
  "unsupported_format",
  "unsupported_version",
  "unsupported_cipher",
  "unsupported_kdf",
  "kdf_out_of_bounds",
  "corrupt",
  "integrity",
  "too_large",
  "keyfile_required",
]);

/** Échec sans code du noyau : module absent, mémoire épuisée, message invalide. */
export const WORKER_FAILED = "worker_failed";

const OPS = Object.freeze({ kdbx: "import_kdbx", bitwarden_json: "import_bitwarden_json" });

// Module complet d'abord (opérations d'import), puis module principal : tant
// que le serveur ne livre qu'un module, il contient aussi l'import.
const MODULES = ["/locksy-import.wasm", "/locksy.wasm"];

let ready = null;
// Après une erreur sans code (mémoire épuisée, par exemple), l'instance
// WebAssembly n'est plus fiable : les demandes suivantes échouent d'emblée.
let broken = false;

async function loadFirstModule(load) {
  let lastError = null;
  for (const url of MODULES) {
    try {
      await load(url);
      return;
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError;
}

/** Base64 standard d'un tampon, par tranches (fichiers de plusieurs dizaines de Mo). */
export function toBase64(bytes) {
  if (typeof bytes.toBase64 === "function") return bytes.toBase64();
  // Tranches multiples de 3 octets : les morceaux s'enchaînent sans remplissage.
  const CHUNK = 3 * 0x8000;
  const parts = [];
  for (let i = 0; i < bytes.length; i += CHUNK) {
    parts.push(btoa(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK))));
  }
  return parts.join("");
}

function codeOf(error) {
  if (error instanceof CryptoError && ERROR_CODES.includes(error.message)) return error.message;
  return WORKER_FAILED;
}

/**
 * Traite un message. `deps` permet de remplacer le noyau et l'envoi dans les
 * tests : { post, close, load, call }.
 */
export async function handleMessage(msg, deps) {
  const { post, close, load = loadCrypto, call: invoke = call } = deps;
  if (!msg || typeof msg !== "object") return;
  if (msg.type === "dispose") {
    close();
    return;
  }
  if (msg.type !== "parse") return;
  const { id, format } = msg;
  const file = msg.file instanceof ArrayBuffer ? new Uint8Array(msg.file) : null;
  const keyfile = msg.keyfile instanceof ArrayBuffer ? new Uint8Array(msg.keyfile) : null;
  let computing = false;
  try {
    if (!Object.hasOwn(OPS, format)) throw new CryptoError("unsupported_format");
    if (!file || broken) throw new Error(WORKER_FAILED);
    post({ type: "progress", id, phase: "kdf", ratio: 0 });
    ready ??= loadFirstModule(load);
    try {
      await ready;
    } catch (e) {
      ready = null;
      throw e;
    }
    const password = typeof msg.password === "string" ? msg.password : "";
    let args;
    if (format === "kdbx") {
      args = { data_b64: toBase64(file), password };
      if (keyfile) args.keyfile_b64 = toBase64(keyfile);
    } else {
      let text;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(file);
      } catch {
        throw new CryptoError("unsupported_format");
      }
      args = { text, password };
    }
    // Calcul synchrone : dérivation, déchiffrement et lecture en un appel.
    computing = true;
    const result = invoke(OPS[format], args);
    computing = false;
    args = null;
    post({ type: "progress", id, phase: "map", ratio: 1 });
    post({ type: "result", id, items: result.items, folders: result.folders, warnings: result.warnings });
  } catch (error) {
    const code = codeOf(error);
    if (computing && !(error instanceof CryptoError)) broken = true;
    post({ type: "error", id, code });
  } finally {
    file?.fill(0);
    keyfile?.fill(0);
  }
}

// Branchement sur le contexte du worker (absent sous Node, dans les tests).
if (typeof WorkerGlobalScope !== "undefined" && self instanceof WorkerGlobalScope) {
  const deps = { post: (m) => self.postMessage(m), close: () => self.close() };
  self.addEventListener("message", (event) => {
    handleMessage(event.data, deps);
  });
}
