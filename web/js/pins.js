// Épinglage local (« trust on first use ») des paramètres de dérivation et des
// clés publiques. Module pur, partagé avec l'extension : aucun accès au DOM.
//
// - locksy.kdfpins : par adresse e-mail, les paramètres Argon2 les plus forts
//   déjà utilisés avec succès sur cet appareil. Un serveur compromis qui
//   annoncerait des paramètres plus faibles (pour accélérer une attaque par
//   dictionnaire sur la clé d'authentification) est refusé avant tout calcul.
// - locksy.keypins : par identifiant d'utilisateur, la dernière clé publique
//   vue. Un changement de clé est signalé avant de sceller une clé de coffre.
//
// Si le stockage est indisponible (navigation privée, stockage bloqué),
// l'épinglage est simplement inactif : rien ne casse.

const KDF_PINS = "locksy.kdfpins";
const KEY_PINS = "locksy.keypins";

let injected = null;

/** Remplace le stockage (tests). `null` revient au localStorage du navigateur. */
export function setPinStorage(s) {
  injected = s || null;
}

function storage() {
  if (injected) return injected;
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
}

function readMap(key) {
  try {
    const raw = storage()?.getItem(key);
    const v = raw ? JSON.parse(raw) : {};
    return v && typeof v === "object" && !Array.isArray(v) ? v : {};
  } catch {
    return {};
  }
}

function writeMap(key, map) {
  try {
    storage()?.setItem(key, JSON.stringify(map));
  } catch { /* stockage plein ou indisponible : épinglage inactif */ }
}

/** Adresse normalisée : minuscules, sans espaces. */
export const normEmail = (email) => String(email || "").replace(/\s+/g, "").toLowerCase();

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const mib = (kib) => (Number.isFinite(Number(kib)) ? Math.round(Number(kib) / 1024) : "?");

function clientError(code, message) {
  const e = new Error(message);
  e.code = code;
  e.status = 0;
  return e;
}

/**
 * Vérifie les paramètres annoncés par le serveur pour ce compte. Lève une
 * erreur « kdf_downgrade » s'ils sont plus faibles que ceux déjà épinglés.
 * À appeler AVANT toute dérivation Argon2.
 */
export function checkKdf(email, kdf) {
  const pin = readMap(KDF_PINS)[normEmail(email)];
  if (!pin || typeof pin !== "object") return;
  const k = kdf || {};
  if (k.alg !== "argon2id" || num(k.m_kib) < num(pin.m_kib) || num(k.t) < num(pin.t)) {
    throw clientError("kdf_downgrade",
      `Les paramètres de sécurité annoncés par le serveur pour ce compte (${mib(k.m_kib)} Mio, ${k.t ?? "?"} passes) `
      + `sont plus faibles que ceux déjà utilisés sur cet appareil (${mib(pin.m_kib)} Mio, ${num(pin.t)} passes). `
      + "Connexion bloquée par précaution : contactez votre administrateur.");
  }
}

/**
 * Mémorise les paramètres après une connexion réussie. On garde le maximum
 * vu, sauf `replace` : paramètres que ce client vient lui-même de choisir
 * (changement de mot de passe maître, récupération du compte).
 */
export function pinKdf(email, kdf, { replace = false } = {}) {
  const id = normEmail(email);
  if (!id || !kdf || kdf.alg !== "argon2id") return;
  const m = num(kdf.m_kib), t = num(kdf.t), p = num(kdf.p);
  if (m <= 0 || t <= 0) return;
  const pins = readMap(KDF_PINS);
  const old = !replace && pins[id] && typeof pins[id] === "object" ? pins[id] : { m_kib: 0, t: 0, p: 0 };
  pins[id] = { m_kib: Math.max(m, num(old.m_kib)), t: Math.max(t, num(old.t)), p: Math.max(p, num(old.p)) };
  writeMap(KDF_PINS, pins);
}

/** « new » (jamais vue), « same » (identique) ou « changed » (différente). */
export function keyPinStatus(userId, publicKey) {
  const pin = readMap(KEY_PINS)[String(userId)];
  if (!pin || typeof pin !== "object" || !pin.public_key) return "new";
  return pin.public_key === publicKey ? "same" : "changed";
}

/** Enregistre (ou remplace, après vérification) la clé publique d'une personne. */
export function pinKey(userId, publicKey, email) {
  if (!userId || !publicKey) return;
  const pins = readMap(KEY_PINS);
  pins[String(userId)] = { public_key: publicKey, email: String(email || ""), pinned_at: Math.floor(Date.now() / 1000) };
  writeMap(KEY_PINS, pins);
}
