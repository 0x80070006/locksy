// Outils communs des scénarios k6 du banc Locksy (mode d'emploi :
// bench/k6/README.md) : adresse du serveur, comptes semés, adresse
// X-Forwarded-For par utilisateur virtuel, connexion (code TOTP compris),
// requêtes étiquetées par route générique, données chiffrées factices.
import http from "k6/http";
import { check, sleep } from "k6";
import { SharedArray } from "k6/data";
import encoding from "k6/encoding";
import crypto from "k6/crypto";
import exec from "k6/execution";
import { status429, status503, status5xxOther, loginOk, dbLocked, syncBytes } from "./metrics.js";

export const BASE = (__ENV.BASE_URL || "http://locksy:8743").replace(/\/+$/, "");
export const API = `${BASE}/api`;
export const DATASET = __ENV.DATASET || "M";

/** Nombre entier lu dans l'environnement, avec défaut. */
export function envInt(name, fallback) {
  const v = parseInt(__ENV[name] || "", 10);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}
/** Durée k6 (« 30s », « 5m », « 2h ») lue dans l'environnement, avec défaut. */
export function envDuration(name, fallback) {
  const v = (__ENV[name] || "").trim();
  return /^\d+(ms|s|m|h)$/.test(v) ? v : fallback;
}
/** Durée k6 en secondes (« 1m30s » n'est pas accepté : une seule unité). */
export function seconds(d) {
  const m = /^(\d+)(ms|s|m|h)$/.exec(d);
  if (!m) return 0;
  return Number(m[1]) * { ms: 0.001, s: 1, m: 60, h: 3600 }[m[2]];
}

// Comptes du jeu (bench/seed/out/<jeu>/users.json, monté en /bench/out).
// Le mot de passe et la clé de récupération ne sont pas chargés : l'injecteur
// se connecte avec la preuve auth_key_b64, sans recalculer Argon2.
export const USERS = new SharedArray("comptes", () => {
  const path = __ENV.USERS_FILE || `/bench/out/${DATASET}/users.json`;
  const list = JSON.parse(open(path));
  if (!Array.isArray(list) || list.length === 0) {
    throw new Error(`Aucun compte dans ${path} : semez le jeu ${DATASET} (bash bench/scripts/seed.sh ${DATASET}).`);
  }
  return list.map((u) => ({
    email: u.email,
    auth_key_b64: u.auth_key_b64,
    role: u.role,
    xff: u.xff,
    collections: u.collections || [],
    totp_secret: u.totp_secret || "",
  }));
});

/** Compte attribué à un utilisateur virtuel (1, 2, … ; plusieurs VU par compte si le jeu est petit). */
export function userFor(vu) {
  return USERS[(vu - 1) % USERS.length];
}
/** Compte de l'utilisateur virtuel courant. */
export function myUser() {
  return userFor(exec.vu.idInTest);
}
/** Premier compte propriétaire (ou administrateur) du jeu. */
export function adminUser() {
  for (const role of ["owner", "admin"]) {
    for (let i = 0; i < USERS.length; i++) if (USERS[i].role === role) return USERS[i];
  }
  throw new Error("Aucun compte propriétaire ou administrateur dans le jeu.");
}

// Adresses clientes annoncées par X-Forwarded-For (le banc joue le proxy de
// confiance). Plages réservées : 10.200 comptes semés, 10.8/10.9 preflight,
// 10.120 connexions de capacité, 10.150 visiteurs des liens, 10.66 attaquants,
// 10.250.0.1 NAT d'entreprise.
export const NAT_IP = "10.250.0.1";
export function ipFor(prefix, n) {
  return `10.${prefix}.${(n >> 8) & 255}.${n & 255}`;
}

/**
 * Routes génériques (étiquette « name ») : aucune donnée d'URL (identifiant)
 * dans les étiquettes, un tableau lisible par route dans le rapport.
 */
export const ROUTES = {
  health: "sante",
  prelogin: "prelogin",
  login: "connexion",
  logout: "deconnexion",
  sync: "sync",
  syncDelta: "sync_delta",
  itemCreate: "element_creation",
  itemUpdate: "element_maj",
  itemTrash: "element_corbeille",
  itemConflict: "element_conflit",
  itemBatch: "import_lot",
  directory: "annuaire",
  members: "membres",
  shareCreate: "partage_creation",
  shareOpen: "partage_ouverture",
  attachmentUpload: "piece_jointe_envoi",
  attachmentDownload: "piece_jointe_lecture",
  attachmentDelete: "piece_jointe_suppression",
  attachmentTooLarge: "piece_jointe_trop_grosse",
  attachmentBodyTooLarge: "piece_jointe_corps_trop_gros",
  attachmentOverLimit: "piece_jointe_en_trop",
  me: "profil",
  sessions: "sessions",
  policy: "politique",
  settingsRead: "reglages_lecture",
  settingsWrite: "reglages_ecriture",
  counters: "compteurs",
};

// Statuts « attendus » par défaut ; un 401, 409, 413 ou 429 attendu par un
// scénario se déclare requête par requête (option expect).
http.setResponseCallback(http.expectedStatuses(200, 201, 204, 304));

/** Comptes séparés des 429, 503 et autres 5xx, et repérage d'une base verrouillée. */
function countStatus(res, name) {
  const tags = { name };
  if (res.status === 429) status429.add(1, tags);
  else if (res.status === 503) status503.add(1, tags);
  else if (res.status >= 500 || res.status === 0) status5xxOther.add(1, tags);
  if (res.status >= 500 && typeof res.body === "string" && /database (table )?is locked|SQLITE_BUSY/i.test(res.body)) {
    dbLocked.add(1, tags);
  }
}

/**
 * Requête vers l'API : étiquette de route, jeton, adresse cliente, statuts
 * attendus. `path` commence par « / » et s'entend sous /api.
 */
export function api(method, path, opts) {
  const o = opts || {};
  const headers = Object.assign({ "x-forwarded-for": o.ip || "10.200.0.1" }, o.headers || {});
  let body = null;
  if (o.body !== undefined && o.body !== null) {
    headers["content-type"] = "application/json";
    body = typeof o.body === "string" ? o.body : JSON.stringify(o.body);
  }
  if (o.token) headers.authorization = `Bearer ${o.token}`;
  const params = { headers, tags: Object.assign({ name: o.name }, o.tags || {}) };
  if (o.expect) params.responseCallback = http.expectedStatuses(...o.expect);
  if (o.timeout) params.timeout = o.timeout;
  const res = http.request(method, `${API}${path}`, body, params);
  countStatus(res, o.name);
  return res;
}

/** Délai d'un nouvel essai : Retry-After (borné à 10 s), sinon 1 s puis 3 s. */
export function retryDelay(res, attempt) {
  const ra = parseInt((res.headers && (res.headers["Retry-After"] || res.headers["retry-after"])) || "", 10);
  const base = Number.isFinite(ra) && ra >= 0 ? Math.min(ra, 10) : attempt === 0 ? 1 : 3;
  return base + Math.random() * 0.5;
}

/**
 * Client « poli » : réessaie un 503 (et un 429 si `on429`) après le délai
 * annoncé, au plus `max` fois, comme le client web (api.js).
 */
export function politely(fn, opts) {
  const o = opts || {};
  const max = o.max === undefined ? 5 : o.max;
  let res = fn();
  for (let attempt = 0; attempt < max; attempt++) {
    const retriable = res.status === 503 || (o.on429 && res.status === 429);
    if (!retriable) break;
    sleep(retryDelay(res, attempt));
    res = fn();
  }
  return res;
}

// ---------------------------------------------------------------- TOTP

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(s) {
  const clean = s.toUpperCase().replace(/[^A-Z2-7]/g, "");
  const out = [];
  let bits = 0;
  let value = 0;
  for (let i = 0; i < clean.length; i++) {
    value = (value << 5) | B32.indexOf(clean[i]);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out).buffer;
}

/** Code TOTP (RFC 6238, SHA-1, 6 chiffres, 30 s) d'un secret base32. */
export function totp(secret, at) {
  const counter = Math.floor((at === undefined ? Date.now() : at) / 30000);
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 255;
    c = Math.floor(c / 256);
  }
  const hex = crypto.hmac("sha1", base32Decode(secret), msg.buffer, "hex");
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
  const off = bytes[bytes.length - 1] & 15;
  const bin = ((bytes[off] & 127) << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
  return String(bin % 1000000).padStart(6, "0");
}

// ---------------------------------------------------------------- Connexion

/**
 * Connexion d'un compte semé : prelogin puis login avec sa preuve (et son
 * code TOTP s'il a la double authentification). Options : ip (défaut :
 * l'adresse du compte), retry (réessai poli des 503), on429 (réessai des 429),
 * expect (statuts attendus du login). Renvoie le jeton, ou null.
 */
export function login(u, opts) {
  const o = opts || {};
  const ip = o.ip || u.xff;
  const expect = o.expect || [200];
  const max = o.retry === false ? 0 : o.max === undefined ? 5 : o.max;
  const pre = politely(
    () => api("POST", "/auth/prelogin", { ip, name: ROUTES.prelogin, body: { email: u.email }, expect: [200], tags: o.tags }),
    { max, on429: o.on429 },
  );
  const res = politely(() => {
    const body = { email: u.email, auth_key: u.auth_key_b64, device: "k6" };
    if (u.totp_secret) body.totp = totp(u.totp_secret);
    return api("POST", "/auth/login", { ip, name: ROUTES.login, body, expect, tags: o.tags });
  }, { max, on429: o.on429 });
  const ok = check(res, {
    "prelogin accepté": () => pre.status === 200,
    "connexion acceptée": (r) => r.status === 200 && !!r.json("token"),
  });
  loginOk.add(ok, o.tags);
  return ok ? res.json("token") : null;
}

/** Déconnexion (jeton révoqué) ; une session fermée ne s'accumule pas en base. */
export function logout(token, ip, tags) {
  const res = api("POST", "/auth/logout", { token, ip, name: ROUTES.logout, tags });
  check(res, { "déconnexion acceptée": (r) => r.status === 204 || r.status === 200 });
  return res;
}

/** GET /sync (complet, ou depuis `since`) ; taille du corps relevée. */
export function sync(token, ip, opts) {
  const o = opts || {};
  const delta = o.since !== undefined && o.since !== null;
  const name = delta ? ROUTES.syncDelta : ROUTES.sync;
  const res = api("GET", delta ? `/sync?since=${encodeURIComponent(o.since)}` : "/sync", { token, ip, name, tags: o.tags, timeout: o.timeout });
  if (res.status === 200 && typeof res.body === "string") {
    syncBytes.add(res.body.length, Object.assign({ name }, o.tags || {}));
  }
  check(res, { "synchronisation 200": (r) => r.status === 200 });
  return res;
}

/** Champ JSON d'une réponse, sans exception si le corps n'est pas du JSON. */
export function jsonField(res, path) {
  try {
    return res.json(path);
  } catch (_) {
    return undefined;
  }
}

// ---------------------------------------------------------------- Données factices

/**
 * Chiffré factice mais bien formé (« v1. » + base64url du nonce, du contenu
 * et de l'étiquette) : accepté par le serveur, indéchiffrable par
 * l'interface. Ne jamais réutiliser un volume de charge pour les E2E.
 */
export function fakeCipher(plainLen) {
  return `v1.${encoding.b64encode(crypto.randomBytes(24 + plainLen + 16), "rawurl")}`;
}

/** UUID v4 aléatoire. */
export function uuid() {
  const b = new Uint8Array(crypto.randomBytes(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  let h = "";
  for (let i = 0; i < 16; i++) h += (b[i] + 0x100).toString(16).substr(1);
  return `${h.substr(0, 8)}-${h.substr(8, 4)}-${h.substr(12, 4)}-${h.substr(16, 4)}-${h.substr(20)}`;
}

/** Pause « humaine » : `s` secondes ± 50 %. */
export function think(s) {
  sleep(s * (0.5 + Math.random()));
}

/** Version du serveur (setup des scénarios, reprise dans le rapport). */
export function serverInfo() {
  const res = api("GET", "/health", { name: ROUTES.health });
  return { version: jsonField(res, "version") || "inconnue", statut: res.status };
}
