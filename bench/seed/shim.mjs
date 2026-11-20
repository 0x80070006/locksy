// Environnement « navigateur » minimal pour exécuter le VRAI code client
// (web/js/vault.js et le module WebAssembly locksy.wasm) sous Node 20 ou plus.
//
// - sessionStorage et localStorage en mémoire (le jeton de session et les
//   épinglages restent dans le processus, jamais sur disque) ;
// - navigator.userAgent pour Node 20, qui n'a pas d'objet navigator ;
// - une enveloppe de globalThis.fetch qui sert /locksy.wasm depuis un fichier
//   ou une URL, ajoute à chaque requête l'X-Forwarded-For du compte en cours
//   (les limites par adresse IP du serveur s'appliquent alors par compte) et
//   retient la preuve d'authentification envoyée par le client, qui sert aux
//   injecteurs de charge (valeur de test, jamais un secret de production) ;
//   un 503 (porte Argon2 du serveur saturée) est retenté poliment.
//
// Ce module doit être importé AVANT web/js/api.js et web/js/vault.js. Chaque
// fil worker_threads a ses propres globales : un compte en cours par fil.

import { readFile } from "node:fs/promises";

function memoryStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
    clear: () => m.clear(),
    get length() { return m.size; },
  };
}

globalThis.sessionStorage = memoryStorage();
globalThis.localStorage = memoryStorage();
if (typeof globalThis.navigator === "undefined") {
  globalThis.navigator = { userAgent: `Node.js/${process.versions.node.split(".")[0]}` };
}

const realFetch = globalThis.fetch.bind(globalThis);
const BUSY_RETRIES = 5;
let wasmSource = null;
let wasmBytes = null;
let forwardedFor = null;
let lastAuthKey = null;

/**
 * Source du module WebAssembly : `{ file }` (chemin local) ou `{ url }`.
 * Le module est lu une seule fois par fil.
 */
export function setWasmSource(source) {
  wasmSource = source;
  wasmBytes = null;
}

/** Adresse annoncée par X-Forwarded-For pour les requêtes suivantes (null : aucune). */
export function setForwardedFor(ip) {
  forwardedFor = ip || null;
}

/** Dernière preuve d'authentification (auth_key) envoyée par le client, ou null. */
export function takeAuthKey() {
  const k = lastAuthKey;
  lastAuthKey = null;
  return k;
}

async function loadWasm() {
  if (!wasmBytes) {
    if (wasmSource?.file) {
      wasmBytes = await readFile(wasmSource.file);
    } else if (wasmSource?.url) {
      const res = await realFetch(wasmSource.url);
      if (!res.ok) throw new Error(`Module WebAssembly introuvable (${wasmSource.url} : HTTP ${res.status}).`);
      wasmBytes = Buffer.from(await res.arrayBuffer());
    } else {
      throw new Error("Source du module WebAssembly non définie (setWasmSource).");
    }
  }
  return new Response(wasmBytes, { headers: { "content-type": "application/wasm" } });
}

/** Retient l'auth_key des corps d'inscription et de connexion (JSON). */
function noteAuthKey(url, body) {
  if (typeof body !== "string" || !/\/api\/auth\/(register|login)$/.test(url)) return;
  try {
    const k = JSON.parse(body).auth_key;
    if (typeof k === "string" && k) lastAuthKey = k;
  } catch { /* corps non JSON : rien à retenir */ }
}

globalThis.fetch = async (input, init = {}) => {
  const url = String(input instanceof Request ? input.url : input);
  if (/\/locksy\.wasm(\?.*)?$/.test(url)) return loadWasm();
  const headers = new Headers(init.headers || {});
  if (forwardedFor) headers.set("x-forwarded-for", forwardedFor);
  if (!headers.has("user-agent")) headers.set("user-agent", "locksy-banc-semis");
  noteAuthKey(url, init.body);
  // Client poli : un 503 (porte Argon2 saturée) est retenté après 1 à 3 s.
  for (let attempt = 1; ; attempt++) {
    const res = await realFetch(input, { ...init, headers });
    if (res.status !== 503 || attempt > BUSY_RETRIES) return res;
    await res.body?.cancel();
    await new Promise((r) => setTimeout(r, 1000 + Math.random() * 2000));
  }
};
