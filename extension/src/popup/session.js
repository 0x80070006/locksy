// Session déverrouillée : ouverture du coffre, politique de l'organisation,
// échéance de verrouillage, verrouillage.
//
// chrome.storage.session.vault = { token, keys, expires, lockOnOsLock, server }.
// L'échéance n'est JAMAIS prolongée par la simple ouverture du popup, la
// recherche ou la synchronisation ; touch() la repousse seulement au
// déverrouillage, au remplissage, à une copie ou à un enregistrement. Le
// service worker (background.js) l'applique avec chrome.alarms, popup fermé.

import * as V from "../lib/vault.js";
import * as Settings from "../lib/settings-client.js";
import { setToken, getToken } from "../lib/api.js";
import { extensionRules, lockDeadline } from "../settings.js";
import { S, store, alarms, LOCK_ALARM } from "./context.js";

/** Règles effectives (politique de l'organisation, préférences, poste). */
export function computeRules() {
  S.rules = extensionRules(Settings.effective, S.managed.machine);
  return S.rules;
}

/**
 * Réglages de la version 1.0 gardés sur ce poste (verrouillage, presse-papiers) :
 * repris une fois dans les préférences synchronisées, puis oubliés.
 */
async function migrateLegacySettings() {
  const legacy = await store.get("local", "settings");
  if (!legacy || typeof legacy !== "object") return;
  const patch = {};
  if (Number.isInteger(legacy.autoLockMinutes) && legacy.autoLockMinutes > 0) patch.lock = { minutes: legacy.autoLockMinutes };
  if (Number.isInteger(legacy.clipboardSeconds) && legacy.clipboardSeconds > 0) patch.clipboard = { seconds: legacy.clipboardSeconds };
  if (Object.keys(patch).length) await Settings.savePrefs(patch);
  await store.del("local", "settings");
}

/** Politique et préférences : une panne n'empêche pas d'ouvrir le coffre (valeurs par défaut). */
async function loadPolicy() {
  await Promise.allSettled([Settings.loadPolicy(V.state.revisions?.policy ?? null), Settings.loadPrefs()]);
  await migrateLegacySettings().catch(() => { /* réessayé à la prochaine ouverture */ });
  computeRules();
}

/**
 * Synchronise le coffre (incrémental quand le serveur le permet, sinon
 * complet) et recharge la politique. Raccourcit l'échéance si la politique
 * l'a baissée ; ne la prolonge jamais.
 */
export async function openVault({ incremental = true } = {}) {
  const [synced] = await Promise.allSettled([V.sync({ incremental }), loadPolicy()]);
  if (synced.status === "rejected") throw synced.reason;
  await clampDeadline();
}

/** Raccourcit l'échéance si la politique ou les préférences l'ont baissée ; ne la prolonge jamais. */
export async function clampDeadline() {
  if (!V.isUnlocked() || S.expiresAt === 0) return;
  const latest = lockDeadline(S.rules.autolockMinutes);
  if (latest !== null && (S.expiresAt === null || S.expiresAt > latest)) await saveSession(latest);
}

async function saveSession(expires) {
  S.expiresAt = expires;
  await store.set("session", "vault", {
    token: getToken(), keys: V.exportSession(), expires, lockOnOsLock: S.rules.lockOnOsLock, server: S.server,
  });
  if (expires === null) await alarms.clear(LOCK_ALARM);
  else await alarms.create(LOCK_ALARM, { when: expires });
}

/** Repousse l'échéance de verrouillage (usage réel du coffre uniquement). */
export async function touch() {
  if (!V.isUnlocked()) return;
  await saveSession(lockDeadline((S.rules || computeRules()).autolockMinutes));
}

/** Reprend une session déverrouillée : false si elle est absente ou échue. */
export async function restore() {
  const s = await store.get("session", "vault");
  if (!s) return false;
  if (!(s.expires === null || s.expires > Date.now()) || (s.server && s.server !== S.server)) {
    await lock();
    return false;
  }
  S.expiresAt = s.expires;
  setToken(s.token);
  V.restoreSession(s.keys);
  return true;
}

/**
 * Verrouille : efface la session du navigateur et les clés en mémoire.
 * Avec revoke, la session est aussi fermée côté serveur (verrouillage manuel).
 */
export async function lock({ revoke = false } = {}) {
  const token = getToken();
  try {
    await store.del("session", "vault");
  } finally {
    await alarms.clear(LOCK_ALARM);
    forget();
  }
  // Effacement local d'abord (immédiat), puis fermeture de la session côté
  // serveur, au mieux : un serveur injoignable ne retarde pas le verrouillage.
  if (revoke && token && S.server) {
    fetch(`${S.server}/api/auth/logout`, {
      method: "POST", headers: { authorization: `Bearer ${token}` }, cache: "no-store", credentials: "omit", signal: AbortSignal.timeout(5000),
    }).catch(() => { /* session déjà close ou serveur injoignable */ });
  }
}

/** Oubli en mémoire (verrouillage décidé ici ou par le service worker). */
export function forget() {
  setToken(null);
  if (V.isUnlocked()) V.lock();
  Settings.reset();
  S.expiresAt = 0;
  computeRules();
}
