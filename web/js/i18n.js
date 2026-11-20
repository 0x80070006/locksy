// Textes et formats de l'interface : catalogue, pluriels, dates, nombres,
// tailles et messages d'erreur.
//
// Le catalogue est généré par tools/gen-i18n.mjs depuis design/i18n/fr/*.json
// et importé de façon synchrone (aucun chargement réseau). Les fonctions
// renvoient du texte brut, à poser par textContent (via h()) : jamais de HTML.
// Le module ne touche pas au DOM : il s'importe aussi sous Node (tests, outils).
//
// La construction de l'extension copie ce module et le dossier ./i18n/
// (extension/build.mjs, contrat C4.7) : les modules partagés peuvent l'importer.

import catalog from "./i18n/fr.js";

const DEFAULT_LOCALE = "fr-FR";
const PARAM_RE = /\{([a-z0-9_]+)\}/g;
const UNRESOLVED_RE = /\{[a-z0-9_]+\}/;
const NO_VALUE = "—";

/** Repli par statut HTTP quand le code d'erreur n'a pas de texte. */
const STATUS_FALLBACK = Object.freeze({
  400: "errors.bad_request",
  408: "errors.timeout",
  413: "errors.payload_too_large",
  422: "errors.bad_request",
  502: "errors.server_busy",
  503: "errors.server_busy",
  504: "errors.timeout",
});

const settings = { locale: DEFAULT_LOCALE, timeZone: undefined, dev: defaultDev() };
const reported = new Set();
const formatters = new Map();
let missingHook = null;

/** Mode développement par défaut : page servie depuis localhost ou 127.0.0.1. */
function defaultDev() {
  try {
    const host = globalThis.location?.hostname;
    return host === "localhost" || host === "127.0.0.1";
  } catch {
    return false;
  }
}

/**
 * Règle la langue des formats, le fuseau horaire des dates et le mode
 * développement. Un fuseau inconnu est ignoré (fuseau du système).
 */
export function configure({ locale, timeZone, dev } = {}) {
  if (locale !== undefined) settings.locale = locale || DEFAULT_LOCALE;
  if (timeZone !== undefined) {
    let tz = timeZone || undefined;
    if (tz) {
      try {
        new Intl.DateTimeFormat(settings.locale, { timeZone: tz });
      } catch {
        if (settings.dev) console.error(`i18n : fuseau horaire inconnu « ${tz} », fuseau du système utilisé.`);
        tz = undefined;
      }
    }
    settings.timeZone = tz;
  }
  if (dev !== undefined) settings.dev = !!dev;
  formatters.clear();
}

/** Appelée à chaque clé absente (réservé aux tests) ; null pour retirer. */
export function onMissing(fn) {
  missingHook = typeof fn === "function" ? fn : null;
}

function reportMissing(key) {
  missingHook?.(key);
  if (settings.dev && !reported.has(key)) {
    reported.add(key);
    console.error(`i18n : clé absente du catalogue : ${key}`);
  }
}

const lookup = (key) => (typeof key === "string" && Object.hasOwn(catalog, key) ? catalog[key] : undefined);

/** Remplace chaque {nom} par params.nom ; un paramètre absent laisse {nom}. */
function interpolate(text, params) {
  if (!params) return text;
  return text.replace(PARAM_RE, (whole, name) => (
    Object.hasOwn(params, name) && params[name] != null ? String(params[name]) : whole
  ));
}

function pluralForm(value, n) {
  const category = formatter("plural", () => new Intl.PluralRules(settings.locale)).select(Number(n));
  return value[category] ?? value.other;
}

/** Vrai si la clé existe dans le catalogue. */
export function has(key) {
  return lookup(key) !== undefined;
}

/**
 * Texte d'une clé, paramètres {nom} remplacés. Clé absente : renvoie la clé
 * (et le signale une fois dans la console en mode développement).
 */
export function t(key, params) {
  const value = lookup(key);
  if (value === undefined) {
    reportMissing(key);
    return String(key);
  }
  if (typeof value === "string") return interpolate(value, params);
  if (Array.isArray(value)) return value.join(", ");
  if (params && typeof params.n === "number") return plural(key, params.n, params);
  return interpolate(value.other, params);
}

/** Liste d'une clé « .synonyms » (tableau vide si elle est absente). */
export function tList(key) {
  const value = lookup(key);
  if (Array.isArray(value)) return [...value];
  return typeof value === "string" ? [value] : [];
}

/**
 * Texte au pluriel : la forme suit Intl.PluralRules (en français, 0 et 1
 * prennent « one ») ; {n} reçoit le nombre formaté (« 1 204 »).
 */
export function plural(key, n, params) {
  const value = lookup(key);
  if (value === undefined) {
    reportMissing(key);
    return String(key);
  }
  const all = { ...params, n: fmtNumber(n) };
  if (typeof value === "string") return interpolate(value, all);
  if (Array.isArray(value)) return value.join(", ");
  return interpolate(pluralForm(value, n), all);
}

// ------------------------------------------------------------------ Nombres

function formatter(id, make) {
  const cacheKey = `${id}|${settings.locale}|${settings.timeZone ?? ""}`;
  let f = formatters.get(cacheKey);
  if (!f) {
    f = make();
    formatters.set(cacheKey, f);
  }
  return f;
}

const numberFormat = (digits) => formatter(`number:${digits}`, () => new Intl.NumberFormat(settings.locale, {
  maximumFractionDigits: digits,
}));

/** Nombre groupé à la française : 1204 -> « 1 204 » (espace fine insécable). */
export function fmtNumber(n, { maxDecimals = 3 } = {}) {
  const v = Number(n);
  if (!Number.isFinite(v)) return String(n);
  return numberFormat(maxDecimals).format(v);
}

const BYTE_UNITS = ["common.unit.kb", "common.unit.mb", "common.unit.gb", "common.unit.tb"];

/** Taille en base 1024 : « 512 octets », « 12 Ko », « 3,4 Mo » (une décimale sous 10). */
export function fmtBytes(n) {
  const bytes = Math.max(0, Number(n) || 0);
  if (bytes < 1024) return plural("common.unit.bytes", Math.round(bytes));
  let value = bytes / 1024;
  let unit = 0;
  for (;;) {
    const digits = value < 10 ? 1 : 0;
    const rounded = Number(value.toFixed(digits));
    if (rounded >= 1024 && unit < BYTE_UNITS.length - 1) {
      value /= 1024;
      unit += 1;
      continue;
    }
    return t(BYTE_UNITS[unit], { n: numberFormat(digits).format(rounded) });
  }
}

// ------------------------------------------------------------------ Dates

/** Date depuis un horodatage Unix en secondes ou un objet Date ; null si absent. */
function toDate(ts) {
  if (ts instanceof Date) return Number.isNaN(ts.getTime()) ? null : ts;
  if (ts === null || ts === undefined || ts === "" || ts === 0) return null;
  const s = Number(ts);
  return Number.isFinite(s) ? new Date(s * 1000) : null;
}

const dateParts = (date, id, options) => {
  const f = formatter(`date:${id}`, () => new Intl.DateTimeFormat(settings.locale, {
    ...options,
    timeZone: settings.timeZone,
  }));
  const out = {};
  for (const p of f.formatToParts(date)) out[p.type] = p.value;
  return out;
};

const PARTS_SHORT = { day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", hourCycle: "h23" };
const PARTS_LONG = { ...PARTS_SHORT, weekday: "long", month: "long" };

/** Typographie française : « 1er » pour le premier jour du mois. */
const dayLabel = (day) => (Number(day) === 1 && settings.locale.startsWith("fr") ? "1er" : String(Number(day)));

const timeLabel = (p) => t("common.time.hm", { h: String(Number(p.hour) % 24), mm: String(p.minute).padStart(2, "0") });

/**
 * Date en heure locale (ou dans le fuseau de configure()).
 *   "datetime" : « 18 nov. à 14 h 20 », année ajoutée hors de l'année en cours ;
 *   "date"     : « 18 nov. 2026 » ;
 *   "time"     : « 14 h 20 », « 9 h 05 » ;
 *   "long"     : « mercredi 18 novembre 2026 à 14 h 20 ».
 * `now` (secondes Unix) sert à décider si l'année est affichée.
 */
export function fmtDate(ts, style = "datetime", now = Date.now() / 1000) {
  const date = toDate(ts);
  if (!date) return NO_VALUE;
  if (style === "long") {
    const p = dateParts(date, "long", PARTS_LONG);
    const day = `${p.weekday} ${dayLabel(p.day)} ${p.month} ${p.year}`;
    return t("common.time.at", { date: day, time: timeLabel(p) });
  }
  const p = dateParts(date, "short", PARTS_SHORT);
  if (style === "time") return timeLabel(p);
  if (style === "date") return `${dayLabel(p.day)} ${p.month} ${p.year}`;
  const nowDate = toDate(now) ?? new Date();
  const sameYear = dateParts(nowDate, "short", PARTS_SHORT).year === p.year;
  const day = sameYear ? `${dayLabel(p.day)} ${p.month}` : `${dayLabel(p.day)} ${p.month} ${p.year}`;
  return t("common.time.at", { date: day, time: timeLabel(p) });
}

/**
 * Durée relative : « à l'instant », « il y a 5 min », « il y a 2 h »,
 * « il y a 3 jours » (jusqu'à 30 jours), puis la date. Futur : « dans 5 min »…
 */
export function relTime(ts, now = Date.now() / 1000) {
  const date = toDate(ts);
  if (!date) return NO_VALUE;
  const diff = Number(now) - date.getTime() / 1000;
  const past = diff >= 0;
  const abs = Math.abs(diff);
  if (abs < 45) return t(past ? "common.time.just_now" : "common.time.in_a_moment");
  if (abs < 3600) return plural(past ? "common.time.minutes_ago" : "common.time.in_minutes", Math.max(1, Math.floor(abs / 60)));
  if (abs < 86400) return plural(past ? "common.time.hours_ago" : "common.time.in_hours", Math.floor(abs / 3600));
  const days = Math.floor(abs / 86400);
  if (days <= 30) return plural(past ? "common.time.days_ago" : "common.time.in_days", days);
  return fmtDate(date, "date", now);
}

// ------------------------------------------------------------------ Erreurs

/** Paramètres d'un message d'erreur : params, bornes et délai d'attente. */
function errorParams(e) {
  const out = {};
  for (const k of ["min", "max", "key"]) if (e[k] !== undefined && e[k] !== null) out[k] = e[k];
  Object.assign(out, e.params && typeof e.params === "object" ? e.params : {});
  const retry = e.retryAfter ?? e.retry_after ?? out.retry_after;
  if (retry !== undefined && retry !== null && retry !== "") {
    out.retry_after = Number.isFinite(Number(retry)) ? fmtNumber(Math.ceil(Number(retry))) : retry;
  }
  return out;
}

/**
 * Message à afficher pour une erreur ({code, message, status, fields?,
 * retryAfter|retry_after?, params?}). Ordre : texte du code, repli par
 * statut, message reçu, message générique. Un texte dont un paramètre reste
 * sans valeur (ex. « {retry_after} ») est sauté au profit du suivant.
 */
export function errorText(err) {
  if (typeof err === "string") return err.trim() || t("errors.unknown");
  const e = err && typeof err === "object" ? err : {};
  const code = typeof e.code === "string" ? e.code : "";
  const params = errorParams(e);
  const candidates = [];
  if (code) {
    if (has(`errors.${code}`)) candidates.push(`errors.${code}`);
    else reportMissing(`errors.${code}`);
  }
  if (STATUS_FALLBACK[e.status]) candidates.push(STATUS_FALLBACK[e.status]);
  for (const key of candidates) {
    const text = t(key, params);
    if (!UNRESOLVED_RE.test(text)) return text;
  }
  // Le message reçu n'est repris que pour une erreur de l'API ou du client
  // (code ou statut connus) : jamais le texte brut d'une exception JavaScript.
  const fromApi = code !== "" || (Number.isInteger(e.status) && e.status > 0);
  const message = typeof e.message === "string" ? e.message.trim() : "";
  if (fromApi && message) return message;
  return t("errors.unknown");
}

/** Message d'une erreur de champ ({code, ...params}) : clé errors.field.<code>. */
export function fieldErrorText(fieldError) {
  const { code, ...params } = fieldError && typeof fieldError === "object" ? fieldError : {};
  const key = `errors.field.${code}`;
  if (typeof code === "string" && has(key)) {
    // Nombres à la française (« 7,84 », espace fine pour les milliers).
    const shown = Object.fromEntries(Object.entries(params).map(([k, v]) => [k, typeof v === "number" ? fmtNumber(v, { maxDecimals: 2 }) : v]));
    return t(key, shown);
  }
  reportMissing(key);
  return t("errors.invalid_input");
}
