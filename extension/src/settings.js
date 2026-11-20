// Réglages de l'extension : politique du poste (chrome.storage.managed),
// adresse du serveur et règles de remplissage. Module pur (aucune API du
// navigateur), partagé par le popup et le service worker, testé par
// src/test/settings.test.js.
//
// Politique du poste (managed-schema.json) : MÊMES NOMS DE CLÉS que le serveur
// (server_url, client.*, extension.*), cahier §4.9 et contrat C4.7. Les noms
// de la version 1.0 (max_auto_lock_minutes, clipboard_seconds) restent lus.
// Valeur effective (cahier §4.1) : calculée par settings-client.effective(),
// qui reçoit la politique du poste comme niveau « machine » ; ce module
// ajoute la règle « la plus stricte gagne » aux clés extension.* que
// settings-client ne classe pas.

/** Clés de la politique du poste et leur forme. */
export const MANAGED_KEYS = Object.freeze({
  server_url: { type: "url" },
  "client.autolock_minutes": { type: "int", min: 1, max: 1440 },
  "client.clipboard_clear_seconds": { type: "int", min: 5, max: 600 },
  "client.lock_on_os_lock": { type: "bool" },
  "extension.http_fill": { type: "enum", values: ["warn", "block"] },
  "extension.allow_mismatch_fill": { type: "bool" },
  "extension.offer_save": { type: "bool" },
  "extension.autofill": { type: "bool" },
  "extension.copy_totp_after_fill": { type: "bool" },
  "extension.excluded_sites": { type: "domains" },
});

/** Noms de la version 1.0 (plafonds) -> clé actuelle. */
export const LEGACY_KEYS = Object.freeze({
  max_auto_lock_minutes: "client.autolock_minutes",
  clipboard_seconds: "client.clipboard_clear_seconds",
});

/** Valeurs du registre (crates/locksy-core/src/settings.rs) des clés extension.*. */
export const EXTENSION_DEFAULTS = Object.freeze({
  "extension.http_fill": "block",
  "extension.allow_mismatch_fill": false,
  "extension.offer_save": true,
  "extension.autofill": false,
  "extension.copy_totp_after_fill": true,
  "extension.excluded_sites": [],
});

/** chrome.alarms ne descend pas sous 30 s pour une extension publiée. */
export const ALARM_MIN_SECONDS = 30;

const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Origine d'un serveur Locksy acceptable : https, ou http sur la boucle locale
 * (développement). `allowHttp` (variante des tests seulement) accepte tout
 * http. Renvoie null pour toute autre valeur.
 */
export function normalizeServer(value, { allowHttp = false } = {}) {
  if (typeof value !== "string" || !value.trim()) return null;
  let u;
  try {
    u = new URL(value.trim());
  } catch {
    return null;
  }
  if (u.username || u.password) return null;
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && (loopback || allowHttp))) return null;
  return u.origin;
}

/**
 * Domaine d'une entrée de liste (« exemple.fr », « *.exemple.fr »,
 * « https://exemple.fr/chemin ») en minuscules, ou null si illisible.
 */
export function normalizeDomain(entry) {
  if (typeof entry !== "string") return null;
  let s = entry.trim().toLowerCase().replace(/^\*\./, "");
  if (!s) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) {
    try {
      s = new URL(s).hostname;
    } catch {
      return null;
    }
  }
  s = s.replace(/\/.*$/, "").replace(/:\d+$/, "").replace(/\.+$/, "");
  return /^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(s) ? s : null;
}

function readValue(spec, v) {
  switch (spec.type) {
    case "int": return Number.isInteger(v) ? clamp(v, spec.min, spec.max) : undefined;
    case "bool": return typeof v === "boolean" ? v : undefined;
    case "enum": return spec.values.includes(v) ? v : undefined;
    case "domains": {
      if (!Array.isArray(v)) return undefined;
      return [...new Set(v.map(normalizeDomain).filter(Boolean))];
    }
    default: return undefined;
  }
}

/**
 * Politique du poste lue dans chrome.storage.managed : { server, machine }.
 * `machine` ne garde que les valeurs valides (clé du serveur -> valeur) ; un
 * ancien nom et le nouveau donnés ensemble : la plus stricte gagne.
 */
export function readManaged(raw) {
  const m = isObject(raw) ? raw : {};
  const machine = {};
  for (const [key, spec] of Object.entries(MANAGED_KEYS)) {
    if (spec.type === "url") continue;
    const v = readValue(spec, m[key]);
    if (v !== undefined) machine[key] = v;
  }
  for (const [legacy, key] of Object.entries(LEGACY_KEYS)) {
    const spec = MANAGED_KEYS[key];
    // L'ancien plafond du presse-papiers interdisait « jamais » et descendait à 30 s.
    const v = readValue({ ...spec, min: legacy === "clipboard_seconds" ? ALARM_MIN_SECONDS : spec.min }, m[legacy]);
    if (v === undefined) continue;
    machine[key] = machine[key] === undefined ? v : Math.min(machine[key], v);
  }
  return { server: normalizeServer(m.server_url), machine };
}

/** Vrai si l'hôte est l'un des sites exclus ou l'un de leurs sous-domaines. */
export function siteExcluded(hostname, list) {
  const host = String(hostname || "").toLowerCase().replace(/\.+$/, "");
  if (!host || !Array.isArray(list)) return false;
  return list.some((d) => host === d || host.endsWith(`.${d}`));
}

/**
 * Règles effectives de l'extension.
 * @param {(key: string) => ({ value: any } | undefined)} effective  settings-client.effective
 * @param {object} machine  politique du poste (readManaged().machine)
 */
export function extensionRules(effective, machine = {}) {
  const value = (key, fallback) => {
    let v;
    try {
      v = effective(key)?.value;
    } catch {
      v = undefined;
    }
    return v === undefined || v === null ? fallback : v;
  };
  const http = value("extension.http_fill", EXTENSION_DEFAULTS["extension.http_fill"]);
  const lists = [value("extension.excluded_sites", []), machine["extension.excluded_sites"] || []];
  const minutes = Number(value("client.autolock_minutes", 10));
  const seconds = Number(value("client.clipboard_clear_seconds", 30));
  return {
    // Bloquer gagne : le poste ou l'organisation suffit.
    httpFill: http === "block" || machine["extension.http_fill"] === "block" ? "block" : "warn",
    allowMismatchFill: value("extension.allow_mismatch_fill", false) === true && machine["extension.allow_mismatch_fill"] !== false,
    excludedSites: [...new Set(lists.flat().map(normalizeDomain).filter(Boolean))].sort(),
    offerSave: value("extension.offer_save", true) !== false,
    autofill: value("extension.autofill", false) === true,
    copyTotpAfterFill: value("extension.copy_totp_after_fill", true) !== false,
    autolockMinutes: Number.isInteger(minutes) && minutes >= 0 ? minutes : 10,
    clipboardSeconds: Number.isInteger(seconds) && seconds > 0 ? seconds : 30,
    lockOnOsLock: value("client.lock_on_os_lock", true) !== false || machine["client.lock_on_os_lock"] === true,
  };
}

/** Échéance de verrouillage (ms) ; null = « jamais » (permis par la politique seulement). */
export function lockDeadline(minutes, now = Date.now()) {
  return Number.isInteger(minutes) && minutes > 0 ? now + minutes * 60_000 : null;
}

/**
 * Échéance raccourcie par le plafond du poste (service worker, popup fermé) :
 * jamais prolongée. Renvoie la nouvelle échéance, ou null si rien ne change.
 */
export function shortenedDeadline(expires, machine, now = Date.now()) {
  const cap = machine?.["client.autolock_minutes"];
  if (!Number.isInteger(cap) || cap <= 0) return null;
  const latest = now + cap * 60_000;
  return expires === null || expires === undefined || expires > latest ? latest : null;
}

/**
 * Effacement du presse-papiers par le service worker : minuterie si le délai
 * est sous le minimum de chrome.alarms (le service worker vit encore 30 s
 * après le message), alarme dans tous les cas (reprise si le service worker
 * a été arrêté).
 */
export function clipboardPlan(seconds, now = Date.now()) {
  const s = Number.isInteger(seconds) && seconds > 0 ? seconds : 0;
  if (!s) return null;
  return { timerMs: s < ALARM_MIN_SECONDS ? s * 1000 : null, alarmAt: now + s * 1000 };
}
