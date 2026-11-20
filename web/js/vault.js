// Logique du coffre : tout chiffrement et déchiffrement se fait ici, dans le
// navigateur. Le serveur ne reçoit que des chiffrés.
//
// Ajouts de la vague 2 (contrat C4.4), l'API existante restant inchangée
// (interface web, extension, banc d'essai) :
//   encryptPrefs(doc) / decryptPrefs(cipher)   préférences chiffrées par la clé du
//       compte, AAD verrou:v1:prefs:<id> ; synchrones, exception si verrouillé ;
//   authProof(password)                        preuve du mot de passe maître (b64) ;
//   sync({ incremental, onProgress })          /sync?since=<seq> quand le serveur le
//       permet (position gardée en mémoire seulement) ;
//   createItem / updateItem / importItems      envoient key_version et refont un
//       envoi après un refus rekey_required (resynchronisation, une fois) ;
//   createShareLink(payload, minutes, vues, { itemId, collectionId })  lien avec
//       preuve de possession (op share_proof) quand le module la fournit ;
//   revokeShareLink(id), attachmentLimits()    limites lues dans la politique.
// Les éléments n'écrivent plus `favorite` : les favoris sont personnels.

import { call } from "./wasm.js";
import * as A from "./aad.js";
import { api, setToken, getBase } from "./api.js";
import { checkKdf, pinKdf, keyPinStatus, pinKey } from "./pins.js";
import { effective as policyValue } from "./settings-client.js";

export const state = {
  profile: null,
  userKey: null,
  privKey: null,
  collections: new Map(),
  items: new Map(),
  serverTime: 0,
  /** Révisions de la politique et des préférences annoncées par /sync (null si inconnues). */
  revisions: { policy: null, prefs: null },
};

export const isUnlocked = () => state.userKey !== null;

let deviceLabel = "Web";
export const setDeviceLabel = (l) => { deviceLabel = l; };

function deviceName() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Navigateur";
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : "";
  return `${deviceLabel} · ${browser}${os ? " sur " + os : ""}`;
}

const drop = (...keys) => keys.forEach((k) => { if (k) call("drop_key", { key: k }); });

/** Erreur propre au client (pas de réponse serveur) : `code` et `status` = 0. */
function clientError(code, message) {
  const e = new Error(message);
  e.code = code;
  e.status = 0;
  return e;
}

const keyMismatch = () => clientError("key_mismatch",
  "La clé publique fournie par le serveur ne correspond pas à votre clé privée. Connexion interrompue par sécurité.");

/** Notre clé publique, recalculée depuis la clé privée (jamais reprise du serveur). */
const myPublicKey = () => call("public_key", { key: state.privKey });

// ------------------------------------------------------------ Compte

export async function register({ email, name, password, inviteToken, ssoTicket, setupToken }) {
  const kdf = call("new_kdf");
  const mk = call("derive_master", { password, kdf });
  const userId = call("new_uuid");
  const userKey = call("generate_key");
  const recovery = call("generate_recovery");
  const rk = call("recovery_keys", { recovery: recovery.key });
  const kp = call("generate_keypair");
  const cid = call("new_uuid");
  const ck = call("generate_key");
  try {
    const res = await api("POST", "/auth/register", {
      user_id: userId,
      email,
      name,
      invite_token: inviteToken || null,
      sso_ticket: ssoTicket || null,
      // Jeton d'installation : exigé par le serveur pour le tout premier compte.
      setup_token: setupToken || null,
      auth_key: mk.auth_key,
      kdf,
      wrapped_user_key: call("wrap", { wrapping: mk.enc_key, key: userKey, aad: A.userKey() }),
      recovery_wrapped_user_key: call("wrap", { wrapping: rk.wrap_key, key: userKey, aad: A.recoveryUserKey() }),
      recovery_auth: rk.auth_key,
      public_key: kp.public_key,
      wrapped_private_key: call("wrap", { wrapping: userKey, key: kp.private_key, aad: A.privateKey(userId) }),
      personal_collection: {
        id: cid,
        enc_name: call("encrypt", { key: ck, plaintext: "Personnel", aad: A.collectionName(cid) }),
        sealed_key: call("seal", { public_key: kp.public_key, key: ck, context: A.collectionKey(cid, userId) }),
      },
    });
    setToken(res.token);
    state.profile = res.profile;
    state.userKey = userKey;
    state.privKey = kp.private_key;
    // Paramètres tirés par ce client : référence pour les connexions suivantes.
    pinKdf(email, kdf, { replace: true });
    return recovery.display;
  } catch (e) {
    drop(userKey, kp.private_key);
    throw e;
  } finally {
    drop(mk.enc_key, recovery.key, rk.wrap_key, ck);
  }
}

/** Première étape : renvoie `{ needTotp, pending }` si un code 2FA est demandé. */
export async function login({ email, password, ssoTicket, kdf }) {
  if (!kdf) ({ kdf } = await api("POST", "/auth/prelogin", { email }));
  // Paramètres plus faibles que ceux déjà vus sur cet appareil : refus avant Argon2.
  checkKdf(email, kdf);
  const mk = call("derive_master", { password, kdf });
  return finishLogin({ email, authKey: mk.auth_key, encKey: mk.enc_key, ssoTicket, kdf });
}

export async function finishLogin(pending, totp) {
  try {
    const res = await api("POST", "/auth/login", {
      email: pending.email, auth_key: pending.authKey, totp: totp || null, device: deviceName(), sso_ticket: pending.ssoTicket || null,
    });
    setToken(res.token);
    unlockWith(res.profile, pending.encKey);
    pinKdf(pending.email, pending.kdf);
    return { needTotp: false };
  } catch (e) {
    if (e.code === "totp_required" || e.code === "invalid_totp") {
      return { needTotp: true, pending, error: e.code === "invalid_totp" ? e.message : null };
    }
    drop(pending.encKey);
    throw e;
  }
}

function unlockWith(profile, encKey) {
  try {
    // Seul l'échec de ce premier déchiffrement signifie « mauvais mot de passe ».
    let userKey;
    try {
      userKey = call("unwrap", { wrapping: encKey, data: profile.wrapped_user_key, aad: A.userKey() });
    } catch {
      throw clientError("wrong_password", "Mot de passe maître incorrect.");
    }
    let privKey;
    try {
      privKey = call("unwrap", { wrapping: userKey, data: profile.wrapped_private_key, aad: A.privateKey(profile.id) });
    } catch (e) {
      drop(userKey);
      throw e;
    }
    if (call("public_key", { key: privKey }) !== profile.public_key) {
      drop(userKey, privKey);
      throw keyMismatch();
    }
    state.profile = profile;
    state.userKey = userKey;
    state.privKey = privKey;
  } finally {
    drop(encKey);
  }
}

/** Déverrouille avec la session déjà ouverte. */
export async function unlock(password) {
  const profile = await api("GET", "/me");
  checkKdf(profile.email, profile.kdf);
  const mk = call("derive_master", { password, kdf: profile.kdf });
  // Lève « wrong_password » ou « key_mismatch » : l'appelant lit le code, pas le texte.
  unlockWith(profile, mk.enc_key);
  pinKdf(profile.email, profile.kdf);
}

export function lock() {
  call("clear");
  state.userKey = null;
  state.privKey = null;
  state.collections = new Map();
  state.items = new Map();
  state.revisions = { policy: null, prefs: null };
  syncSeq = null;
}

export async function logout() {
  try { await api("POST", "/auth/logout"); } catch { /* session déjà close */ }
  setToken(null);
  lock();
  state.profile = null;
}

async function currentAuthKey(password) {
  const mk = call("derive_master", { password, kdf: state.profile.kdf });
  // Vérifie localement le mot de passe avant tout envoi.
  try {
    const k = call("unwrap", { wrapping: mk.enc_key, data: state.profile.wrapped_user_key, aad: A.userKey() });
    drop(k);
  } catch {
    throw clientError("wrong_password", "Mot de passe maître actuel incorrect.");
  } finally {
    drop(mk.enc_key);
  }
  return mk.auth_key;
}

/**
 * Change le mot de passe maître. `totp` : code de vérification ou code de
 * secours, exigé par le serveur quand la 2FA est active (401 totp_required).
 */
export async function changePassword(current, next, { totp } = {}) {
  const current_auth_key = await currentAuthKey(current);
  const kdf = call("new_kdf");
  const mk = call("derive_master", { password: next, kdf });
  try {
    await api("POST", "/me/password", {
      current_auth_key,
      auth_key: mk.auth_key,
      kdf,
      wrapped_user_key: call("wrap", { wrapping: mk.enc_key, key: state.userKey, aad: A.userKey() }),
      ...(totp ? { totp } : {}),
    });
  } finally {
    drop(mk.enc_key);
  }
  // Paramètres tirés par ce client : ils remplacent l'épinglage précédent.
  pinKdf(state.profile.email, kdf, { replace: true });
  state.profile = await api("GET", "/me");
}

/** Nouvelle clé de récupération (`totp` comme pour changePassword). */
export async function rotateRecovery(current, { totp } = {}) {
  const current_auth_key = await currentAuthKey(current);
  const rec = call("generate_recovery");
  const rk = call("recovery_keys", { recovery: rec.key });
  try {
    await api("POST", "/me/recovery", {
      current_auth_key,
      recovery_wrapped_user_key: call("wrap", { wrapping: rk.wrap_key, key: state.userKey, aad: A.recoveryUserKey() }),
      recovery_auth: rk.auth_key,
      ...(totp ? { totp } : {}),
    });
    return rec.display;
  } finally {
    drop(rec.key, rk.wrap_key);
  }
}

export async function recoverAccount(email, recoveryText, newPassword) {
  const rkey = call("parse_recovery", { recovery: recoveryText });
  const rk = call("recovery_keys", { recovery: rkey });
  let userKey = null;
  try {
    const start = await api("POST", "/auth/recover/start", { email, recovery_auth: rk.auth_key });
    userKey = call("unwrap", { wrapping: rk.wrap_key, data: start.recovery_wrapped_user_key, aad: A.recoveryUserKey() });
    const kdf = call("new_kdf");
    const mk = call("derive_master", { password: newPassword, kdf });
    try {
      await api("POST", "/auth/recover/finish", {
        recovery_token: start.recovery_token,
        auth_key: mk.auth_key,
        kdf,
        wrapped_user_key: call("wrap", { wrapping: mk.enc_key, key: userKey, aad: A.userKey() }),
      });
    } finally {
      drop(mk.enc_key);
    }
    pinKdf(email, kdf, { replace: true });
  } finally {
    drop(rkey, rk.wrap_key, userKey);
  }
}

// ------------------------------------------------------------ Synchronisation

/** Position renvoyée par le dernier /sync (mémoire seulement, jamais stockée). */
let syncSeq = null;
/** Déchiffrement par lots au-delà de ce nombre d'éléments, avec une pause d'affichage entre deux lots. */
const DECRYPT_BATCH = 500;
// À partir de 2 000 éléments (et non au-delà de 10 000) : aucune tâche de plus
// de 200 ms pour un grand coffre (mesure Q6-H4 : 426 ms d'un bloc à 10 000).
const BATCHED_FROM = 2_000;

// Repères de performance (outils de développement), actifs avec ?perf=1.
const PERF = typeof location !== "undefined" && typeof performance !== "undefined"
  && /[?&]perf=1(?:&|$)/.test(`${location.search}&${location.hash.split("?")[1] || ""}`);
function mark(name) {
  if (PERF) performance.mark(`locksy:${name}`);
}
function measure(name, start, end) {
  if (!PERF) return;
  try { performance.measure(`locksy:${name}`, `locksy:${start}`, `locksy:${end}`); } catch { /* repère absent */ }
}

/** Rend la main au navigateur pour qu'il affiche l'avancement (rien hors navigateur). */
function yieldFrame() {
  if (typeof requestAnimationFrame !== "function") return Promise.resolve();
  return new Promise((r) => {
    requestAnimationFrame(() => setTimeout(r, 0));
    // Onglet en arrière-plan : plus de rafraîchissement, le délai prend le relais.
    setTimeout(r, 50);
  });
}

function openCollection(c, uid) {
  let key = null;
  let name = "Coffre illisible";
  let error = null;
  try {
    key = call("open", { private_key: state.privKey, data: c.sealed_key, context: A.collectionKey(c.id, uid) });
    name = call("decrypt", { key, data: c.enc_name, aad: A.collectionName(c.id) });
  } catch (e) {
    error = e.message;
  }
  return { ...c, key, name, error };
}

function openItem(it, collections) {
  const col = collections.get(it.collection_id);
  let d = null;
  let error = null;
  try {
    d = JSON.parse(call("decrypt", { key: col.key, data: it.data, aad: A.item(it.collection_id, it.id) }));
  } catch {
    error = "Élément illisible ou altéré.";
  }
  return { ...it, data: d, error, data_ct: undefined };
}

/**
 * Synchronise le coffre. Avec `incremental` (défaut), demande seulement ce qui
 * a changé depuis la dernière position connue (/sync?since=) quand le serveur
 * en a donné une ; une réponse complète (`full`, ou serveur sans `seq`)
 * remplace tout. Les objets retirés (`removed`) sont oubliés. Au-delà de
 * 10 000 éléments, le déchiffrement se fait par lots de 500 et `onProgress`
 * reçoit { done, total } entre deux lots.
 */
export async function sync({ incremental = true, onProgress } = {}) {
  mark("sync:start");
  const since = incremental && syncSeq !== null ? `?since=${encodeURIComponent(syncSeq)}` : "";
  const data = await api("GET", `/sync${since}`);
  mark("sync:fetched");
  const uid = data.profile.id;
  const delta = since !== "" && data.full === false;
  const old = state.collections;
  const collections = delta ? new Map(old) : new Map();
  const replacedKeys = [];
  for (const c of data.collections) {
    const previous = collections.get(c.id);
    if (previous) replacedKeys.push(previous.key);
    collections.set(c.id, openCollection(c, uid));
  }
  const items = delta ? new Map(state.items) : new Map();
  if (delta) {
    const removed = data.removed || {};
    for (const id of removed.items || []) items.delete(id);
    for (const cid of removed.collections || []) {
      const c = collections.get(cid);
      if (c) replacedKeys.push(c.key);
      collections.delete(cid);
      for (const [id, it] of items) if (it.collection_id === cid) items.delete(id);
    }
  }
  const list = data.items || [];
  const batched = list.length >= BATCHED_FROM;
  for (let i = 0; i < list.length; i++) {
    if (batched && i > 0 && i % DECRYPT_BATCH === 0) {
      onProgress?.({ done: i, total: list.length });
      await yieldFrame();
    }
    items.set(list[i].id, openItem(list[i], collections));
  }
  if (batched) onProgress?.({ done: list.length, total: list.length });
  mark("sync:decrypted");
  measure("sync", "sync:start", "sync:decrypted");
  // Chaque ouverture crée une nouvelle poignée : les anciennes ne servent plus.
  if (delta) drop(...replacedKeys);
  else for (const c of old.values()) drop(c.key);
  state.profile = data.profile;
  state.collections = collections;
  state.items = items;
  state.serverTime = data.server_time;
  state.revisions = { policy: data.policy_revision ?? null, prefs: data.prefs_revision ?? null };
  syncSeq = Number.isFinite(data.seq) ? data.seq : null;
  return { full: !delta, seq: syncSeq };
}

export const now = () => Math.floor(Date.now() / 1000);

/**
 * Élément vide. Les favoris sont personnels (préférences chiffrées) : un
 * élément neuf ne porte plus `favorite`. `totp_fill` : l'extension remplit
 * aussi le code de vérification dans la page. `ssh.port` est une chaîne.
 */
export function emptyItem(kind = "login") {
  return {
    kind, name: "", tags: [], username: "", password: "", urls: [], totp: "", totp_fill: false, notes: "",
    fields: [], card: { holder: "", number: "", expiry: "", cvv: "", pin: "" },
    identity: { first_name: "", last_name: "", email: "", phone: "", address: "", company: "", document_number: "" },
    ssh: { host: "", username: "", port: "", password: "", private_key: "", public_key: "", passphrase: "" },
    password_history: [], password_changed_at: 0, expires_at: 0,
  };
}

function encryptItem(collectionId, itemId, data) {
  const col = state.collections.get(collectionId);
  // Coffre retiré ou clé illisible : même message qu'un objet introuvable.
  if (!col?.key) throw clientError("not_found", "Coffre indisponible.");
  return call("encrypt", { key: col.key, plaintext: JSON.stringify(data), aad: A.item(collectionId, itemId) });
}

/** Version de clé du coffre (absente avec un serveur qui ne la publie pas : rien n'est envoyé). */
function keyVersionOf(collectionId) {
  const v = state.collections.get(collectionId)?.key_version;
  return Number.isInteger(v) ? { key_version: v } : {};
}

const isRekey = (e) => e?.code === "rekey_required";

/**
 * Politique « mot de passe unique dans l'organisation » : poivre de l'organisation
 * (null si la politique est inactive), lu une fois par session.
 */
let pepperCache = null;
async function uniquePepper() {
  let on = false;
  try {
    on = policyValue("passwords.unique_across_users").value === true;
  } catch { /* registre absent : politique inactive */ }
  if (!on) return null;
  if (pepperCache === null) pepperCache = (await api("GET", "/passwords/pepper"))?.pepper || "";
  return pepperCache || null;
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

/**
 * Enregistre l'empreinte des mots de passe ({ id, data }) et renvoie les
 * identifiants dont le mot de passe est déjà utilisé par un autre compte.
 * Politique inactive : liste vide, rien n'est envoyé.
 */
async function claimUnique(entries, { dryRun = false } = {}) {
  const pepper = await uniquePepper();
  const withPassword = entries.filter((e) => e.data?.password);
  if (!pepper || !withPassword.length) return [];
  const body = [];
  for (const e of withPassword) body.push({ item_id: e.id, fp: await fingerprintOf(pepper, e.data.password) });
  const res = await api("POST", "/passwords/fingerprints", { entries: body, dry_run: dryRun || undefined });
  return res?.conflicts || [];
}

/** Empreinte d'un mot de passe : SHA-256(poivre de l'organisation, NUL, mot de passe). */
async function fingerprintOf(pepper, password) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${pepper}\u0000${password}`)));
}

/**
 * Ce mot de passe est-il déjà pris ? Oui s'il est déjà celui d'un élément du
 * coffre (comparaison en mémoire, sur le poste), ou, si la politique
 * « mots de passe uniques » est active, celui d'un autre compte (comparaison
 * d'empreintes par le serveur, sans rien enregistrer).
 */
export async function passwordTaken(password) {
  if (!password) return false;
  for (const i of state.items.values()) {
    if (i.data && !i.deleted_at && i.data.password === password) return true;
  }
  try {
    return (await claimUnique([{ id: call("new_uuid"), data: { password } }], { dryRun: true })).length > 0;
  } catch {
    return false; // serveur injoignable : la proposition n'est pas bloquée
  }
}

/** Erreur « mot de passe déjà utilisé par un collègue » (code stable pour l'interface). */
function duplicateError(count = 1) {
  const e = new Error(count > 1
    ? `${count} mots de passe sont déjà utilisés par des collègues. Choisissez-en d'autres.`
    : "Ce mot de passe est déjà utilisé par un collègue. Choisissez-en un autre.");
  e.code = "password_used_by_colleague";
  return e;
}

export async function createItem(collectionId, data) {
  const id = call("new_uuid");
  if ((await claimUnique([{ id, data }])).length) throw duplicateError();
  const send = () => api("POST", "/items", { id, collection_id: collectionId, data: encryptItem(collectionId, id, data), ...keyVersionOf(collectionId) });
  try {
    await send();
  } catch (e) {
    // Clé du coffre renouvelée entre-temps : on recharge, puis on chiffre avec la nouvelle (une fois).
    if (!isRekey(e)) throw e;
    await sync();
    await send();
  }
  return id;
}

/**
 * Enregistre l'élément (éventuellement déplacé vers `collectionId`). Refus
 * `rekey_required` : le coffre est resynchronisé, puis l'envoi est refait une
 * fois avec la nouvelle clé, si le contenu de l'élément n'a pas changé
 * entre-temps (sinon le refus est rendu à l'appelant, saisie intacte).
 */
export async function updateItem(item, data, collectionId = item.collection_id) {
  if (data?.password !== item.data?.password && (await claimUnique([{ id: item.id, data }])).length) throw duplicateError();
  const send = (revision) => api("PUT", `/items/${item.id}`, {
    collection_id: collectionId,
    data: encryptItem(collectionId, item.id, data),
    revision,
    ...keyVersionOf(collectionId),
  });
  try {
    return await send(item.revision);
  } catch (e) {
    if (!isRekey(e)) throw e;
    await sync();
    const fresh = state.items.get(item.id);
    // La rotation rechiffre sans changer le contenu : seule la révision avance.
    if (!fresh?.data || JSON.stringify(fresh.data) !== JSON.stringify(item.data)) throw e;
    return send(fresh.revision);
  }
}

/** Remplace le mot de passe en gardant l'ancien dans l'historique (20 derniers). */
export function applyPassword(data, newPassword) {
  if (newPassword === data.password) return data;
  const history = [...(data.password_history || [])];
  if (data.password) history.unshift({ password: data.password, changed_at: now() });
  return { ...data, password: newPassword, password_changed_at: now(), password_history: history.slice(0, 20) };
}

/**
 * Importe des éléments clairs dans un coffre, par lots de 500. Renvoie les
 * identifiants créés, dans l'ordre de `list` (favoris importés rangés
 * ensuite dans les préférences par l'appelant).
 */
export async function importItems(collectionId, list) {
  const created = [];
  for (let i = 0; i < list.length; i += 500) {
    const chunk = list.slice(i, i + 500);
    const ids = chunk.map(() => call("new_uuid"));
    const clashes = await claimUnique(chunk.map((data, n) => ({ id: ids[n], data })));
    if (clashes.length) throw duplicateError(clashes.length);
    const send = () => api("POST", "/items/batch", {
      items: chunk.map((data, n) => ({ id: ids[n], collection_id: collectionId, data: encryptItem(collectionId, ids[n], data), ...keyVersionOf(collectionId) })),
    });
    try {
      await send();
    } catch (e) {
      if (!isRekey(e)) throw e;
      await sync();
      await send();
    }
    created.push(...ids);
  }
  return created;
}

// ------------------------------------------------------------ Coffres partagés

export async function createCollection(name) {
  const id = call("new_uuid");
  const key = call("generate_key");
  try {
    await api("POST", "/collections", {
      id,
      enc_name: call("encrypt", { key, plaintext: name, aad: A.collectionName(id) }),
      sealed_key: call("seal", { public_key: myPublicKey(), key, context: A.collectionKey(id, state.profile.id) }),
    });
  } finally {
    drop(key);
  }
  return id;
}

export async function renameCollection(id, name) {
  const col = state.collections.get(id);
  await api("PUT", `/collections/${id}`, { enc_name: call("encrypt", { key: col.key, plaintext: name, aad: A.collectionName(id) }) });
}

export const fingerprint = (publicKey) => call("fingerprint", { public_key: publicKey });

/**
 * Ajoute un membre. L'interface fait confirmer son empreinte (keyPinStatus)
 * avant l'appel ; sa clé est épinglée après le succès.
 */
export async function addMember(collectionId, user, role) {
  const col = state.collections.get(collectionId);
  await api("POST", `/collections/${collectionId}/members`, {
    user_id: user.id,
    role,
    sealed_key: call("seal", { public_key: user.public_key, key: col.key, context: A.collectionKey(collectionId, user.id) }),
  });
  pinKey(user.id, user.public_key, user.email);
}

/**
 * Prépare un renouvellement de clé : destinataires restants, avec l'empreinte
 * de leur clé et son état par rapport à l'épinglage local (« new », « same »
 * ou « changed »). À faire confirmer avant rotateCollection.
 */
export async function planRotation(collectionId, removeUserIds = []) {
  const members = await api("GET", `/collections/${collectionId}/members`);
  const me = state.profile.id;
  const mine = myPublicKey();
  const remaining = members.filter((m) => !removeUserIds.includes(m.user_id));
  const self = remaining.find((m) => m.user_id === me);
  // Le serveur ne doit ni nous retirer de la liste ni substituer notre propre clé.
  if (!self || self.public_key !== mine || state.profile.public_key !== mine) throw keyMismatch();
  return {
    members: remaining.map((m) => ({
      user_id: m.user_id,
      name: m.name,
      email: m.email,
      role: m.role,
      public_key: m.public_key,
      fingerprint: fingerprint(m.public_key),
      pin: m.user_id === me ? "same" : keyPinStatus(m.user_id, m.public_key),
    })),
  };
}

/**
 * Retire des membres et renouvelle la clé : tout le contenu est rechiffré.
 * La nouvelle clé est scellée pour les membres du plan confirmé ; le serveur
 * répond 409 si la liste a changé entre-temps. Sans plan, il est calculé ici.
 */
export async function rotateCollection(collectionId, removeUserIds = [], plan = null) {
  const col = state.collections.get(collectionId);
  if (!col?.key) throw clientError("not_found", "Coffre indisponible.");
  const { members } = plan || await planRotation(collectionId, removeUserIds);
  const remaining = members.filter((m) => !removeUserIds.includes(m.user_id));
  const contents = [...state.items.values()].filter((i) => i.collection_id === collectionId);
  if (contents.some((i) => !i.data)) throw new Error("Un élément illisible empêche le renouvellement de la clé.");
  const key = call("generate_key");
  try {
    await api("POST", `/collections/${collectionId}/rotate`, {
      remove_user_ids: removeUserIds,
      enc_name: call("encrypt", { key, plaintext: col.name, aad: A.collectionName(collectionId) }),
      members: remaining.map((m) => ({
        user_id: m.user_id,
        sealed_key: call("seal", { public_key: m.public_key, key, context: A.collectionKey(collectionId, m.user_id) }),
      })),
      items: contents.map((i) => ({
        id: i.id,
        data: call("encrypt", { key, plaintext: JSON.stringify(i.data), aad: A.item(collectionId, i.id) }),
      })),
    });
  } finally {
    drop(key);
  }
  // Destinataires confirmés : leurs clés deviennent la référence locale.
  for (const m of remaining) if (m.user_id !== state.profile.id) pinKey(m.user_id, m.public_key, m.email);
}

// ------------------------------------------------------------ Partage par lien

/**
 * Vérificateur de la preuve de possession du lien (contrat C5) : hex de
 * SHA-256(SHA-256(texte du fragment)), calculé par le noyau. Module sans
 * l'opération (version précédente) : null, le lien est créé sans preuve.
 */
function shareVerifier(fragment) {
  try {
    const v = call("share_proof", { key: fragment })?.verifier;
    return typeof v === "string" && /^[0-9a-f]{64}$/.test(v) ? v : null;
  } catch {
    return null;
  }
}

/**
 * Crée un lien sécurisé. `payload` est chiffré tel quel : l'appelant n'y met
 * que ce que la personne a choisi d'envoyer. `itemId` / `collectionId`
 * rattachent le lien à l'élément (révocation automatique côté serveur).
 * Renvoie { id, url, expires_at, max_views, verified }.
 */
export async function createShareLink(payload, minutes, maxViews, { itemId, collectionId } = {}) {
  const key = call("generate_key");
  try {
    const data = call("encrypt", { key, plaintext: JSON.stringify(payload), aad: A.share() });
    const fragment = call("export_key", { key });
    const verifier = shareVerifier(fragment);
    const body = { data, expires_in_minutes: minutes, max_views: maxViews };
    if (verifier) body.verifier = verifier;
    if (itemId) body.item_id = itemId;
    if (collectionId) body.collection_id = collectionId;
    const res = await api("POST", "/shares", body);
    return { id: res.id, url: `${getBase()}/s/${res.id}#${fragment}`, expires_at: res.expires_at, max_views: maxViews, verified: !!verifier };
  } finally {
    drop(key);
  }
}

/** Révoque un lien (idempotent côté serveur). */
export async function revokeShareLink(id) {
  await api("DELETE", `/shares/${encodeURIComponent(id)}`);
}

// ------------------------------------------------------------ Préférences chiffrées

// Codes déjà traduits (errors.common.json) : verrouillé = il faut se reconnecter.
const locked = () => clientError("unauthorized", "Coffre verrouillé.");

/** Chiffre le document de préférences avec la clé du compte (AAD verrou:v1:prefs:<id>). */
export function encryptPrefs(doc) {
  if (!state.userKey || !state.profile) throw locked();
  return call("encrypt", { key: state.userKey, plaintext: JSON.stringify(doc), aad: A.prefs(state.profile.id) });
}

/** Déchiffre le document de préférences ; lève une erreur s'il n'est pas lié à ce compte. */
export function decryptPrefs(cipher) {
  if (!state.userKey || !state.profile) throw locked();
  const doc = JSON.parse(call("decrypt", { key: state.userKey, data: cipher, aad: A.prefs(state.profile.id) }));
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw clientError("unknown", "Préférences illisibles.");
  return doc;
}

/**
 * Preuve du mot de passe maître (b64 de l'auth_key, paramètres KDF du profil),
 * vérifiée localement avant tout envoi. Sert à la confirmation d'identité.
 */
export function authProof(password) {
  return currentAuthKey(password);
}

// ------------------------------------------------------------ Santé

export function healthReport() {
  const live = [...state.items.values()].filter((i) => i.data && !i.deleted_at);
  const logins = live.filter((i) => i.data.password);
  const counts = new Map();
  for (const i of logins) counts.set(i.data.password, (counts.get(i.data.password) || 0) + 1);
  const yearAgo = now() - 365 * 86400;
  const rows = logins.map((i) => {
    const s = call("strength", { password: i.data.password });
    const changed = i.data.password_changed_at || i.created_at;
    return {
      item: i,
      strength: s,
      weak: s.score <= 2,
      reused: counts.get(i.data.password) > 1,
      old: changed < yearAgo,
      expired: i.data.expires_at && i.data.expires_at < now(),
      no2fa: i.data.kind === "login" && (i.data.urls || []).length > 0 && !i.data.totp,
    };
  });
  const bad = rows.filter((r) => r.weak || r.reused || r.old || r.expired).length;
  const score = rows.length ? Math.round(100 * (rows.length - bad) / rows.length) : 100;
  return { rows, score, total: rows.length };
}

// ------------------------------------------------------------ Session de l'extension

/** Exporte les clés déverrouillées (gardées en mémoire par le navigateur, jamais sur disque). */
export function exportSession() {
  return {
    profile: state.profile,
    userKey: call("export_key", { key: state.userKey }),
    privKey: call("export_key", { key: state.privKey }),
  };
}

export function restoreSession(s) {
  state.profile = s.profile;
  state.userKey = call("import_key", { key: s.userKey });
  state.privKey = call("import_key", { key: s.privKey });
}

// ------------------------------------------------------------ Pièces jointes

/** Valeurs du registre quand la politique ne les donne pas (serveur ancien, extension). */
const ATTACHMENT_DEFAULTS = Object.freeze({ enabled: true, max_file_mib: 10, max_per_item: 20 });

/**
 * Limites des pièces jointes lues dans la politique de l'organisation
 * (attachment.*). Le serveur reste la barrière : ceci évite seulement de
 * chiffrer et d'envoyer un fichier qui sera refusé.
 */
export function attachmentLimits() {
  const read = (key, ok) => {
    try {
      const v = policyValue(`attachment.${key}`).value;
      return ok(v) ? v : ATTACHMENT_DEFAULTS[key];
    } catch {
      return ATTACHMENT_DEFAULTS[key];
    }
  };
  const maxFileMib = read("max_file_mib", (v) => Number.isFinite(v) && v > 0);
  return {
    enabled: read("enabled", (v) => typeof v === "boolean"),
    maxFileMib,
    maxFileBytes: maxFileMib * 1024 * 1024,
    maxPerItem: read("max_per_item", (v) => Number.isInteger(v) && v > 0),
  };
}

function bytesToB64url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Chiffre un fichier avec une clé aléatoire, l'envoie, puis l'ajoute à l'élément. */
export async function addAttachment(item, file) {
  // Mêmes refus que le serveur, avant de chiffrer ; les quotas restent vérifiés par lui seul.
  const lim = attachmentLimits();
  if (!lim.enabled) throw clientError("attachments_disabled", "Votre organisation a désactivé l'ajout de pièces jointes.");
  if (file.size > lim.maxFileBytes) throw clientError("attachment_too_large", `Fichier trop volumineux : ${lim.maxFileMib} Mo au plus.`);
  if ((item.data.attachments || []).length >= lim.maxPerItem) {
    throw clientError("attachment_limit", "Cet élément a atteint le nombre maximal de pièces jointes.");
  }
  const id = call("new_uuid");
  const key = call("generate_key");
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const data = call("encrypt_bytes", { key, data: bytesToB64url(bytes), aad: A.attachment(id) });
    bytes.fill(0);
    await api("PUT", `/items/${item.id}/attachments/${id}`, { data });
    const meta = { id, name: file.name.slice(0, 200), size: file.size, mime: file.type || "application/octet-stream", key: call("export_key", { key }) };
    try {
      await updateItem(item, { ...item.data, attachments: [...(item.data.attachments || []), meta] });
    } catch (e) {
      await api("DELETE", `/attachments/${id}`).catch(() => {});
      throw e;
    }
  } finally {
    drop(key);
  }
}

export async function downloadAttachment(att) {
  const { data } = await api("GET", `/attachments/${att.id}`);
  const key = call("import_key", { key: att.key });
  try {
    const b64 = call("decrypt_bytes", { key, data, aad: A.attachment(att.id) });
    return new Blob([b64urlToBytes(b64)], { type: att.mime || "application/octet-stream" });
  } finally {
    drop(key);
  }
}

/**
 * Supprime une pièce jointe : le fichier chiffré d'abord (un échec est
 * signalé et l'élément garde sa pièce jointe, rien ne reste en douce sur le
 * serveur ni dans le quota), puis la référence dans l'élément. Fichier déjà
 * absent (404) : seule la référence est retirée.
 */
export async function removeAttachment(item, att) {
  try {
    await api("DELETE", `/attachments/${att.id}`);
  } catch (e) {
    if (e?.status !== 404) throw e;
  }
  await updateItem(item, { ...item.data, attachments: (item.data.attachments || []).filter((a) => a.id !== att.id) });
}

export function formatSize(n) {
  if (n < 1024) return `${n} o`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} Ko`;
  return `${(n / 1024 / 1024).toFixed(1).replace(".", ",")} Mo`;
}
