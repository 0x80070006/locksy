// Réglages vus par le client (cahier §4.1 et §4.9, contrat C4.2 de la vague 2) :
// politique de l'organisation, préférences personnelles chiffrées, réglages du
// poste et valeur effective de chaque clé.
//
// Exports :
//   configure({ vault, machine, estimator, storage })   branchements (app.js, extension, tests) :
//       vault      : module offrant encryptPrefs(doc) et decryptPrefs(cipher), détectés
//                    à l'exécution (absents : préférences gardées sur cet appareil seulement) ;
//       machine    : { clé: valeur } imposé par le poste (extension : storage.managed) ;
//       estimator  : (mot de passe) -> score 0..4 (ou { score }) pour checkMasterPolicy ;
//       storage    : remplaçant de localStorage (tests).
//   loadPublic({ force })      GET /settings/public (avant connexion), cache mémoire ; null si absent.
//   publicSettings()           dernière réponse de loadPublic (ou null).
//   loadPolicy(revision)       GET /settings/policy si `revision` diffère du cache (ETag sinon).
//   loadPrefs(revision?)       GET /me/prefs puis déchiffrement (AAD verrou:v1:prefs:<id>) ;
//                              revision (prefs_revision de /sync) : 0 = aucun document, pas de
//                              requête ; révision déjà en mémoire = aucune requête.
//   savePrefs(patch)           fusion, chiffrement, PUT If-Match ; 409 : recharge, refusionne,
//                              réessaie une fois. Renvoie le document fusionné.
//   prefs()                    document de préférences courant (copie).
//   effective(key)             { value, mode, min, max, source, clamped } ; source ∈
//                              policy | user | machine | default.
//   optionsFor(key, candidates)  [{ value, disabled, reason, params }] ; reason ∈ enforced |
//                              machine | above_max | below_min | never_forbidden | null.
//   consumeClampNotice(key)    vrai une seule fois quand une préférence a été ramenée
//                              dans les bornes (message « Votre organisation limite… »).
//   checkMasterPolicy(password, { email, name })  { ok, problems: [{ code, params }] } ;
//                              code ∈ empty | too_short | too_weak | contains_identity | banned_word.
//   subscribe(key, fn)         fn(effective(key)) à chaque changement ; renvoie le désabonnement.
//   localOnly(key, value?)     réglage « cet appareil seulement » (localStorage, clés non
//                              sensibles de LOCAL_KEYS, sous try/catch) ; null efface.
//   reset()                    oubli de la politique et des préférences (verrouillage, déconnexion).
//
// Ce module n'importe ni composant ni vue : il est copié tel quel dans
// l'extension. Aucune donnée sensible ne va dans localStorage (règle R5) :
// le document de préférences n'est jamais écrit en clair hors mémoire.

import { apiFull, ApiError } from "./api.js";

const LOCAL_STORAGE_KEY = "locksy.local";
/** Seules clés admises par localOnly() : affichage et confort de connexion. */
export const LOCAL_KEYS = Object.freeze([
  "ui.theme", "ui.contrast", "ui.text_scale", "ui.density",
  "auth.remember_email", "auth.last_email", "auth.last_windows_user",
  // false : l'apparence de cet appareil ne suit pas les préférences du compte.
  "prefs.sync",
]);
/** Préférences d'affichage recopiées sur l'appareil pour l'écran de connexion. */
const MIRRORED = Object.freeze(["ui.theme", "ui.contrast", "ui.text_scale", "ui.density"]);

/**
 * Style par défaut du générateur (« random » ou « words »), propriété `style`
 * du document. Écrit en raccourci de propriété : le contrôle R1 refuse toute
 * clé nommée ainsi dans web/js (elle viserait le style en ligne d'un élément).
 */
const style = "random";

/** Document de préférences par défaut (annexe A.10). */
export const DEFAULT_PREFS = Object.freeze({
  v: 1,
  ui: { theme: "system", contrast: "system", text_scale: 100, density: "comfortable", click_to_copy: false, sort: "name", default_collection: null, locale: "fr-FR" },
  lock: { minutes: 10, on_hide: false },
  clipboard: { seconds: 30 },
  generator: { style, length: 20, digits: true, symbols: true, avoid_ambiguous: true, words: 5, separator: "-", capitalize: true, number: true },
  share: { expiry_minutes: 1440, views: 1 },
  extension: { offer_save: true, copy_totp_after_fill: true },
  shortcuts: { single_key: true },
  favorites: [],
  links: {},
  onboarding: { hidden: false, done: [] },
});

/** Clé de politique -> chemin de la préférence qui la règle. */
export const PREF_PATHS = Object.freeze({
  "client.autolock_minutes": "lock.minutes",
  "client.lock_on_hide": "lock.on_hide",
  "client.clipboard_clear_seconds": "clipboard.seconds",
  "client.single_key_shortcuts": "shortcuts.single_key",
  "generator.length": "generator.length",
  "generator.avoid_ambiguous": "generator.avoid_ambiguous",
  "share.default_expiry_minutes": "share.expiry_minutes",
  "share.default_views": "share.views",
  "extension.offer_save": "extension.offer_save",
  "extension.copy_totp_after_fill": "extension.copy_totp_after_fill",
});

/** Défauts du registre (crates/locksy-core/src/settings.rs) quand la politique manque. */
const REGISTRY_DEFAULTS = Object.freeze({
  "client.autolock_minutes": { value: 10, min: 1, max: 1440 },
  "client.autolock_allow_never": { value: true },
  "client.lock_on_hide": { value: false },
  "client.lock_on_os_lock": { value: true },
  "client.clipboard_clear_seconds": { value: 30, min: 5, max: 600 },
  "client.remember_email": { value: true },
  "client.single_key_shortcuts": { value: true },
  "generator.length": { value: 20, min: 8, max: 128 },
  "generator.avoid_ambiguous": { value: true },
  "share.default_expiry_minutes": { value: 1440, min: 5, max: 43_200 },
  "share.default_views": { value: 1, min: 1, max: 100 },
  "extension.offer_save": { value: true },
  "extension.copy_totp_after_fill": { value: true },
  "vault.users_can_create_shared": { value: true },
});

/** Sens de la sécurité : « lower » = plus petit est plus sûr, « higher » l'inverse. */
const SAFER = Object.freeze({
  "client.autolock_minutes": "lower",
  "client.autolock_allow_never": "lower",
  "client.clipboard_clear_seconds": "lower",
  "client.lock_on_hide": "higher",
  "client.lock_on_os_lock": "higher",
  "client.remember_email": "lower",
  "share.default_expiry_minutes": "lower",
  "share.default_views": "lower",
  "generator.length": "higher",
});

/** Clés où 0 veut dire « Jamais » (permis seulement si client.autolock_allow_never). */
const NEVER_ZERO = new Set(["client.autolock_minutes"]);
const AUTOLOCK_REGISTRY_MAX = 1440;

/** Politique du mot de passe maître quand /settings/public manque (serveur 1.0). */
const DEFAULT_MASTER = Object.freeze({ min_length: 12, min_score: 3, forbid_identity: true, banned_words: [] });

const st = {
  vault: null,
  machine: {},
  estimator: null,
  storage: undefined,
  public: null,
  publicPromise: null,
  policy: null,
  policyRevision: null,
  policyEtag: null,
  /** Document affiché : défauts complétés par les choix de la personne. */
  prefs: null,
  /**
   * Choix explicites de la personne (document chiffré tel qu'enregistré, sans
   * les défauts) : seuls eux l'emportent sur la valeur « Par défaut » de
   * l'organisation (§4.1). Le document enregistré ne contient qu'eux.
   */
  own: null,
  prefsRevision: 0,
  prefsLoaded: false,
  subscribers: new Map(),
  lastSeen: new Map(),
  clampNoticed: new Set(),
};

// ------------------------------------------------------------ Outils

const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Fusion profonde : objets fusionnés, tableaux et valeurs simples remplacés. */
export function mergeDeep(target, patch) {
  const out = isObject(target) ? clone(target) : {};
  for (const [k, v] of Object.entries(isObject(patch) ? patch : {})) {
    if (v === undefined) continue;
    out[k] = isObject(v) && isObject(out[k]) ? mergeDeep(out[k], v) : clone(v);
  }
  return out;
}

function readPath(obj, path) {
  let cur = obj;
  for (const part of path.split(".")) {
    if (!isObject(cur) || !Object.hasOwn(cur, part)) return undefined;
    cur = cur[part];
  }
  return cur;
}

function pathPatch(path, value) {
  return path.split(".").reduceRight((acc, part) => ({ [part]: acc }), value);
}

/** Texte comparable : sans accents ni casse. */
function fold(text) {
  return String(text ?? "").normalize("NFD").replace(/\p{M}+/gu, "").toLowerCase();
}

function storage() {
  if (st.storage !== undefined) return st.storage;
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

function readLocal() {
  try {
    const raw = storage()?.getItem(LOCAL_STORAGE_KEY);
    const v = raw ? JSON.parse(raw) : {};
    return isObject(v) ? v : {};
  } catch {
    return {};
  }
}

// ------------------------------------------------------------ Branchements

export function configure({ vault, machine, estimator, storage: store } = {}) {
  if (vault !== undefined) st.vault = vault;
  if (machine !== undefined) st.machine = isObject(machine) ? { ...machine } : {};
  if (estimator !== undefined) st.estimator = typeof estimator === "function" ? estimator : null;
  if (store !== undefined) st.storage = store;
  notifyAll();
}

/** Chiffrement des préférences disponible (vault.js de la vague 2) ? */
function crypto() {
  const v = st.vault;
  return v && typeof v.encryptPrefs === "function" && typeof v.decryptPrefs === "function" ? v : null;
}

export function reset() {
  st.policy = null;
  st.policyRevision = null;
  st.policyEtag = null;
  st.prefs = null;
  st.own = null;
  st.prefsRevision = 0;
  st.prefsLoaded = false;
  st.clampNoticed.clear();
  notifyAll();
}

// ------------------------------------------------------------ Lecture serveur

export function loadPublic({ force = false } = {}) {
  if (st.public && !force) return Promise.resolve(st.public);
  if (st.publicPromise && !force) return st.publicPromise;
  st.publicPromise = apiFull("GET", "/settings/public")
    .then(({ data }) => {
      st.public = isObject(data) ? data : null;
      return st.public;
    })
    .catch((e) => {
      // Serveur 1.0 sans la route : aucune donnée publique ; panne : dernier état connu.
      if (e instanceof ApiError && e.status === 404) st.public = null;
      return st.public;
    })
    .finally(() => { st.publicPromise = null; });
  return st.publicPromise;
}

export const publicSettings = () => st.public;

/** Politique de l'organisation (A.4) ; serveur sans la route : politique vide. */
export async function loadPolicy(revision) {
  if (st.policy && revision !== undefined && revision !== null && revision === st.policyRevision) return st.policy;
  try {
    const res = await apiFull("GET", "/settings/policy", undefined, { ifNoneMatch: st.policy ? st.policyEtag : undefined });
    if (res.status !== 304 && isObject(res.data)) {
      st.policy = isObject(res.data.policy) ? res.data.policy : {};
      st.policyRevision = res.data.revision ?? null;
      st.policyEtag = res.etag;
    }
  } catch (e) {
    if (!(e instanceof ApiError) || e.status !== 404) throw e;
    st.policy = {};
  }
  notifyAll();
  return st.policy;
}

/**
 * Document de préférences ; absent sur le serveur : document par défaut.
 * `revision` (facultatif, annoncé par /sync : prefs_revision) évite une
 * requête inutile : 0 = aucun document enregistré, même révision que le
 * document en mémoire = déjà à jour.
 */
export async function loadPrefs(revision) {
  const v = crypto();
  const known = Number.isFinite(revision);
  if (v && known && st.prefsLoaded && st.prefs && revision === st.prefsRevision) return prefs();
  let doc = null;
  if (v && !(known && revision === 0)) {
    try {
      const { data } = await apiFull("GET", "/me/prefs");
      const own = mergeDeep({}, v.decryptPrefs(data.cipher));
      doc = { own, prefs: mergeDeep(DEFAULT_PREFS, own), revision: Number(data.revision) || 0 };
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 404) throw e;
    }
  }
  if (doc) {
    st.own = doc.own;
    st.prefs = doc.prefs;
    st.prefsRevision = doc.revision;
    mirrorDisplay();
  } else {
    // Aucun document (ou pas de chiffrement) : défauts, et les choix
    // d'affichage déjà faits sur cet appareil sont gardés (ils seront
    // synchronisés au premier enregistrement).
    st.own ??= localDisplay();
    st.prefs ??= mergeDeep(DEFAULT_PREFS, st.own);
    if (v) st.prefsRevision = 0;
  }
  st.prefsLoaded = true;
  notifyAll();
  return prefs();
}

/** Préférences d'affichage choisies sur cet appareil, en forme de document. */
function localDisplay() {
  const local = readLocal();
  let out = {};
  for (const key of MIRRORED) {
    if (local[key] !== undefined) out = mergeDeep(out, pathPatch(key, local[key]));
  }
  return out;
}

export const prefs = () => clone(st.prefs ?? DEFAULT_PREFS);

async function putPrefs(v, doc, revision) {
  const { data } = await apiFull("PUT", "/me/prefs", { cipher: v.encryptPrefs(doc) }, { ifMatch: String(revision), retry: false });
  return Number(data?.revision) || revision + 1;
}

export async function savePrefs(patch) {
  const v = crypto();
  // Seuls les choix explicites sont enregistrés : une valeur jamais choisie
  // suit la valeur proposée par l'organisation, même si elle change ensuite.
  const withPatch = () => mergeDeep(mergeDeep({ v: DEFAULT_PREFS.v }, st.own ?? {}), patch);
  let own = withPatch();
  if (v) {
    try {
      st.prefsRevision = await putPrefs(v, own, st.prefsRevision);
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 409) throw e;
      // Modifié ailleurs entre-temps : on repart du document du serveur.
      await loadPrefs();
      own = withPatch();
      st.prefsRevision = await putPrefs(v, own, st.prefsRevision);
    }
  }
  st.own = own;
  st.prefs = mergeDeep(DEFAULT_PREFS, own);
  st.prefsLoaded = true;
  mirrorDisplay();
  notifyAll();
  return prefs();
}

/** Apparence propre à cet appareil (case « Synchroniser » décochée) ? */
function displayIsLocal() {
  return readLocal()["prefs.sync"] === false;
}

/**
 * Recopie les préférences d'affichage sur l'appareil (écran de connexion),
 * sauf si cet appareil garde sa propre apparence.
 */
function mirrorDisplay() {
  if (!st.prefs || displayIsLocal()) return;
  for (const key of MIRRORED) {
    const value = readPath(st.prefs, key);
    if (value !== undefined) localOnly(key, value);
  }
}

// ------------------------------------------------------------ Cet appareil seulement

export function localOnly(key, value) {
  if (!LOCAL_KEYS.includes(key)) throw new RangeError(`localOnly(${key})`);
  if (value === undefined) return readLocal()[key];
  const all = readLocal();
  if (value === null) delete all[key];
  else all[key] = value;
  try {
    storage()?.setItem(LOCAL_STORAGE_KEY, JSON.stringify(all));
  } catch { /* stockage indisponible ou plein : réglage gardé pour cette page seulement */ }
  if (MIRRORED.includes(key)) notify(key);
  return value ?? undefined;
}

// ------------------------------------------------------------ Valeur effective

function registry(key) {
  return REGISTRY_DEFAULTS[key] ?? {};
}

function policyEntry(key) {
  const p = st.policy && Object.hasOwn(st.policy, key) ? st.policy[key] : null;
  return isObject(p) ? p : null;
}

/** « Jamais » permis pour cette clé ? */
function neverAllowed(key, pol) {
  if (!NEVER_ZERO.has(key)) return false;
  const allow = policyEntry("client.autolock_allow_never")?.value ?? registry("client.autolock_allow_never").value;
  if (allow === false) return false;
  if (pol?.mode === "enforced") return Number(pol.value) === 0;
  const max = pol?.max ?? null;
  return max === null || Number(max) >= AUTOLOCK_REGISTRY_MAX;
}

/** Rang de sûreté comparable : plus petit = plus sûr. */
function rank(key, value) {
  const dir = SAFER[key];
  if (typeof value === "boolean") return dir === "higher" ? (value ? 0 : 1) : value ? 1 : 0;
  const n = Number(value);
  if (NEVER_ZERO.has(key) && n === 0) return Number.POSITIVE_INFINITY;
  return dir === "higher" ? -n : n;
}

/** La plus sûre de deux valeurs (clé sans sens de sécurité : la première). */
function stricter(key, a, b) {
  if (!SAFER[key] || b === undefined || b === null) return a;
  return rank(key, b) < rank(key, a) ? b : a;
}

function bounded(key, value, pol) {
  const reg = registry(key);
  const min = pol?.min ?? reg.min ?? null;
  const max = pol?.max ?? reg.max ?? null;
  if (typeof value !== "number" || !Number.isFinite(value)) return { value, min, max, clamped: false };
  if (value === 0 && NEVER_ZERO.has(key)) {
    if (neverAllowed(key, pol)) return { value, min, max, clamped: false };
    const fallback = max ?? pol?.value ?? reg.value;
    return { value: fallback, min, max, clamped: true };
  }
  let v = value;
  if (min !== null && v < min) v = Number(min);
  if (max !== null && v > max) v = Number(max);
  return { value: v, min, max, clamped: v !== value };
}

function userValue(key) {
  const path = PREF_PATHS[key] ?? (key.startsWith("ui.") ? key : null);
  if (!path) return undefined;
  if (MIRRORED.includes(key) && displayIsLocal()) {
    const local = readLocal()[key];
    if (local !== undefined) return local;
  }
  const fromPrefs = st.own ? readPath(st.own, path) : undefined;
  if (fromPrefs !== undefined) return fromPrefs;
  return MIRRORED.includes(key) ? readLocal()[key] : undefined;
}

/**
 * Valeur effective (§4.1) :
 *   mode imposé : valeur de la politique ;
 *   sinon       : bornes(préférence ?? poste ?? politique ?? défaut) ;
 *   puis, si la clé a un sens de sécurité, la plus stricte de (résultat, poste).
 */
export function effective(key) {
  const pol = policyEntry(key);
  const reg = registry(key);
  const machine = st.machine[key];
  const mode = pol?.mode ?? (pol ? "enforced" : "free");
  if (pol && (pol.mode === "enforced" || (pol.mode === undefined && userValue(key) === undefined))) {
    const value = stricter(key, pol.value, machine);
    return { value, mode, min: pol.min ?? null, max: pol.max ?? null, source: value === pol.value ? "policy" : "machine", clamped: false };
  }
  const user = userValue(key);
  let source;
  let candidate;
  if (user !== undefined) { candidate = user; source = "user"; } else if (machine !== undefined) { candidate = machine; source = "machine"; } else if (pol) { candidate = pol.value; source = "policy"; } else {
    candidate = key.startsWith("ui.") ? readPath(DEFAULT_PREFS, key) : reg.value;
    source = "default";
  }
  const b = bounded(key, candidate, pol);
  let value = b.value;
  if (machine !== undefined && source !== "machine") {
    const strict = stricter(key, value, machine);
    if (strict !== value) { value = strict; source = "machine"; }
  }
  return { value, mode: pol ? mode : "free", min: b.min, max: b.max, source, clamped: b.clamped && source !== "machine" };
}

export function consumeClampNotice(key) {
  const e = effective(key);
  const mark = `${key}=${e.value}`;
  if (!e.clamped || st.clampNoticed.has(mark)) return false;
  st.clampNoticed.add(mark);
  return true;
}

export function optionsFor(key, candidates = []) {
  const pol = policyEntry(key);
  const reg = registry(key);
  const machine = st.machine[key];
  const min = pol?.min ?? reg.min ?? null;
  const max = pol?.max ?? reg.max ?? null;
  return candidates.map((value) => {
    let reason = null;
    let params;
    if (pol?.mode === "enforced") {
      if (value !== pol.value) reason = "enforced";
    } else if (NEVER_ZERO.has(key) && Number(value) === 0) {
      if (!neverAllowed(key, pol)) reason = "never_forbidden";
    } else if (typeof value === "number" && max !== null && value > max) {
      reason = "above_max";
      params = { max };
    } else if (typeof value === "number" && min !== null && value < min) {
      reason = "below_min";
      params = { min };
    }
    if (!reason && machine !== undefined && SAFER[key] && rank(key, value) > rank(key, machine)) {
      reason = "machine";
      params = { max: machine };
    }
    return { value, disabled: reason !== null, reason, params };
  });
}

// ------------------------------------------------------------ Mot de passe maître

function masterPolicy() {
  const mp = st.public?.master_password;
  return isObject(mp) ? { ...DEFAULT_MASTER, ...mp, banned_words: Array.isArray(mp.banned_words) ? mp.banned_words : [] } : { ...DEFAULT_MASTER };
}

/** Morceaux d'identité de 3 lettres ou plus : partie locale de l'adresse et mots du nom. */
function identityParts(email, name) {
  const local = String(email ?? "").split("@")[0];
  const parts = [local, ...local.split(/[._+-]+/), ...String(name ?? "").split(/[\s'’-]+/)];
  return [...new Set(parts.map(fold).filter((p) => p.length >= 3))];
}

function scoreOf(password) {
  if (!st.estimator) return null;
  try {
    const s = st.estimator(password);
    const n = Number(isObject(s) ? s.score : s);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

export function checkMasterPolicy(password, { email, name } = {}) {
  const pw = String(password ?? "");
  const mp = masterPolicy();
  const problems = [];
  if (!pw) return { ok: false, problems: [{ code: "empty", params: {} }] };
  if ([...pw].length < mp.min_length) problems.push({ code: "too_short", params: { min: mp.min_length } });
  const folded = fold(pw);
  if (mp.forbid_identity && identityParts(email, name).some((p) => folded.includes(p))) {
    problems.push({ code: "contains_identity", params: {} });
  }
  const banned = mp.banned_words.map(fold).find((w) => w.length >= 3 && folded.includes(w));
  if (banned) problems.push({ code: "banned_word", params: { word: banned } });
  const score = scoreOf(pw);
  if (score !== null && score < mp.min_score) problems.push({ code: "too_weak", params: { min_score: mp.min_score } });
  return { ok: problems.length === 0, problems };
}

// ------------------------------------------------------------ Abonnements

export function subscribe(key, fn) {
  if (typeof fn !== "function") return () => {};
  if (!st.subscribers.has(key)) st.subscribers.set(key, new Set());
  st.subscribers.get(key).add(fn);
  st.lastSeen.set(key, JSON.stringify(effective(key)));
  return () => st.subscribers.get(key)?.delete(fn);
}

function notify(key) {
  const fns = st.subscribers.get(key);
  if (!fns?.size) return;
  const e = effective(key);
  const sig = JSON.stringify(e);
  if (st.lastSeen.get(key) === sig) return;
  st.lastSeen.set(key, sig);
  for (const fn of [...fns]) {
    try {
      fn(e);
    } catch (err) {
      console.error(err);
    }
  }
}

function notifyAll() {
  for (const key of st.subscribers.keys()) notify(key);
}

/** Préférence d'une clé de politique (raccourci pour les écrans de préférences). */
export function prefPatch(key, value) {
  const path = PREF_PATHS[key] ?? (key.startsWith("ui.") ? key : null);
  if (!path) throw new RangeError(`prefPatch(${key})`);
  return pathPatch(path, value);
}
