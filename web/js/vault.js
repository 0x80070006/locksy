// Logique du coffre : tout chiffrement et déchiffrement se fait ici, dans le
// navigateur. Le serveur ne reçoit que des chiffrés.

import { call } from "./wasm.js";
import * as A from "./aad.js";
import { api, setToken, getBase } from "./api.js";

export const state = {
  profile: null,
  userKey: null,
  privKey: null,
  collections: new Map(),
  items: new Map(),
  serverTime: 0,
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

// ------------------------------------------------------------ Compte

export async function register({ email, name, password, inviteToken, ssoTicket }) {
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
  const mk = call("derive_master", { password, kdf });
  return finishLogin({ email, authKey: mk.auth_key, encKey: mk.enc_key, ssoTicket });
}

export async function finishLogin(pending, totp) {
  try {
    const res = await api("POST", "/auth/login", {
      email: pending.email, auth_key: pending.authKey, totp: totp || null, device: deviceName(), sso_ticket: pending.ssoTicket || null,
    });
    setToken(res.token);
    unlockWith(res.profile, pending.encKey);
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
    const userKey = call("unwrap", { wrapping: encKey, data: profile.wrapped_user_key, aad: A.userKey() });
    const privKey = call("unwrap", { wrapping: userKey, data: profile.wrapped_private_key, aad: A.privateKey(profile.id) });
    if (call("public_key", { key: privKey }) !== profile.public_key) {
      drop(userKey, privKey);
      throw new Error("La clé publique fournie par le serveur ne correspond pas à votre clé privée. Connexion interrompue par sécurité.");
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
  const mk = call("derive_master", { password, kdf: profile.kdf });
  try {
    unlockWith(profile, mk.enc_key);
  } catch (e) {
    if (String(e.message).includes("déchiffrement")) throw new Error("Mot de passe maître incorrect.");
    throw e;
  }
}

export function lock() {
  call("clear");
  state.userKey = null;
  state.privKey = null;
  state.collections = new Map();
  state.items = new Map();
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
    throw new Error("Mot de passe maître actuel incorrect.");
  } finally {
    drop(mk.enc_key);
  }
  return mk.auth_key;
}

export async function changePassword(current, next) {
  const current_auth_key = await currentAuthKey(current);
  const kdf = call("new_kdf");
  const mk = call("derive_master", { password: next, kdf });
  try {
    await api("POST", "/me/password", {
      current_auth_key,
      auth_key: mk.auth_key,
      kdf,
      wrapped_user_key: call("wrap", { wrapping: mk.enc_key, key: state.userKey, aad: A.userKey() }),
    });
  } finally {
    drop(mk.enc_key);
  }
  state.profile = await api("GET", "/me");
}

export async function rotateRecovery(current) {
  const current_auth_key = await currentAuthKey(current);
  const rec = call("generate_recovery");
  const rk = call("recovery_keys", { recovery: rec.key });
  try {
    await api("POST", "/me/recovery", {
      current_auth_key,
      recovery_wrapped_user_key: call("wrap", { wrapping: rk.wrap_key, key: state.userKey, aad: A.recoveryUserKey() }),
      recovery_auth: rk.auth_key,
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
  } finally {
    drop(rkey, rk.wrap_key, userKey);
  }
}

// ------------------------------------------------------------ Synchronisation

export async function sync() {
  const data = await api("GET", "/sync");
  const uid = data.profile.id;
  const old = state.collections;
  const collections = new Map();
  for (const c of data.collections) {
    let key = null;
    let name = "Coffre illisible";
    let error = null;
    try {
      key = call("open", { private_key: state.privKey, data: c.sealed_key, context: A.collectionKey(c.id, uid) });
      name = call("decrypt", { key, data: c.enc_name, aad: A.collectionName(c.id) });
    } catch (e) {
      error = e.message;
    }
    collections.set(c.id, { ...c, key, name, error });
  }
  const items = new Map();
  for (const it of data.items) {
    const col = collections.get(it.collection_id);
    let d = null;
    let error = null;
    try {
      d = JSON.parse(call("decrypt", { key: col.key, data: it.data, aad: A.item(it.collection_id, it.id) }));
    } catch (e) {
      error = "Élément illisible ou altéré.";
    }
    items.set(it.id, { ...it, data: d, error, data_ct: undefined });
  }
  for (const c of old.values()) drop(c.key);
  state.profile = data.profile;
  state.collections = collections;
  state.items = items;
  state.serverTime = data.server_time;
}

export const now = () => Math.floor(Date.now() / 1000);

export function emptyItem(kind = "login") {
  return {
    kind, name: "", favorite: false, tags: [], username: "", password: "", urls: [], totp: "", notes: "",
    fields: [], card: { holder: "", number: "", expiry: "", cvv: "", pin: "" },
    identity: { first_name: "", last_name: "", email: "", phone: "", address: "", company: "", document_number: "" },
    ssh: { private_key: "", public_key: "", passphrase: "" },
    password_history: [], password_changed_at: 0, expires_at: 0,
  };
}

function encryptItem(collectionId, itemId, data) {
  const col = state.collections.get(collectionId);
  if (!col?.key) throw new Error("Coffre indisponible.");
  return call("encrypt", { key: col.key, plaintext: JSON.stringify(data), aad: A.item(collectionId, itemId) });
}

export async function createItem(collectionId, data) {
  const id = call("new_uuid");
  await api("POST", "/items", { id, collection_id: collectionId, data: encryptItem(collectionId, id, data) });
  return id;
}

export async function updateItem(item, data, collectionId = item.collection_id) {
  const revision = await api("PUT", `/items/${item.id}`, {
    collection_id: collectionId,
    data: encryptItem(collectionId, item.id, data),
    revision: item.revision,
  });
  return revision;
}

/** Remplace le mot de passe en gardant l'ancien dans l'historique (20 derniers). */
export function applyPassword(data, newPassword) {
  if (newPassword === data.password) return data;
  const history = [...(data.password_history || [])];
  if (data.password) history.unshift({ password: data.password, changed_at: now() });
  return { ...data, password: newPassword, password_changed_at: now(), password_history: history.slice(0, 20) };
}

export async function importItems(collectionId, list) {
  for (let i = 0; i < list.length; i += 500) {
    const items = list.slice(i, i + 500).map((data) => {
      const id = call("new_uuid");
      return { id, collection_id: collectionId, data: encryptItem(collectionId, id, data) };
    });
    await api("POST", "/items/batch", { items });
  }
}

// ------------------------------------------------------------ Coffres partagés

export async function createCollection(name) {
  const id = call("new_uuid");
  const key = call("generate_key");
  try {
    await api("POST", "/collections", {
      id,
      enc_name: call("encrypt", { key, plaintext: name, aad: A.collectionName(id) }),
      sealed_key: call("seal", { public_key: state.profile.public_key, key, context: A.collectionKey(id, state.profile.id) }),
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

export async function addMember(collectionId, user, role) {
  const col = state.collections.get(collectionId);
  await api("POST", `/collections/${collectionId}/members`, {
    user_id: user.id,
    role,
    sealed_key: call("seal", { public_key: user.public_key, key: col.key, context: A.collectionKey(collectionId, user.id) }),
  });
}

/** Retire des membres et renouvelle la clé : tout le contenu est rechiffré. */
export async function rotateCollection(collectionId, removeUserIds = []) {
  const col = state.collections.get(collectionId);
  const members = await api("GET", `/collections/${collectionId}/members`);
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
}

// ------------------------------------------------------------ Partage par lien

export async function createShareLink(payload, minutes, maxViews) {
  const key = call("generate_key");
  try {
    const data = call("encrypt", { key, plaintext: JSON.stringify(payload), aad: A.share() });
    const res = await api("POST", "/shares", { data, expires_in_minutes: minutes, max_views: maxViews });
    return { url: `${getBase()}/s/${res.id}#${call("export_key", { key })}`, expires_at: res.expires_at };
  } finally {
    drop(key);
  }
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

export const MAX_ATTACHMENT = 10 * 1024 * 1024;

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
  if (file.size > MAX_ATTACHMENT) throw new Error("Fichier trop volumineux : 10 Mo au plus.");
  if ((item.data.attachments || []).length >= 20) throw new Error("20 pièces jointes au plus par élément.");
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

export async function removeAttachment(item, att) {
  await updateItem(item, { ...item.data, attachments: (item.data.attachments || []).filter((a) => a.id !== att.id) });
  await api("DELETE", `/attachments/${att.id}`).catch(() => {});
}

export function formatSize(n) {
  if (n < 1024) return `${n} o`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} Ko`;
  return `${(n / 1024 / 1024).toFixed(1).replace(".", ",")} Mo`;
}
