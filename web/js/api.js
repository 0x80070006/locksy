// Client HTTP de l'API Locksy (contrat C4.1 de la vague 2).
//
// Exports :
//   api(method, path, body?, opts?)      -> corps JSON (null pour 204), comme avant ;
//   apiFull(method, path, body?, opts?)  -> { data, etag, status, headers } ;
//     opts = { ifMatch, ifNoneMatch, reauth, signal, retry = true }
//       ifMatch     -> en-tête If-Match: "<valeur>" (révision attendue) ;
//       ifNoneMatch -> en-tête If-None-Match (304 : data = null, status = 304) ;
//       reauth      -> en-tête X-Locksy-Reauth (jeton « rt1.… » ou preuve historique) ;
//       retry=false -> aucun nouvel essai automatique.
//   ApiError { status, code, message, fields?, retryAfter?, params? } : erreur
//     typée ; `params` reprend les champs supplémentaires du corps (max, reason…).
//   withReauth(action, fn, { title, message, objectName }) : confirmation de
//     l'identité (mot de passe maître, puis code de vérification si demandé),
//     échange contre un jeton d'usage unique (POST /auth/reauth), puis
//     fn({ reauth: jeton }). Renvoie le résultat de fn, ou undefined si la
//     personne annule (fn n'est alors pas appelée). L'interface est branchée
//     par setReauthUi() (app.js) : ce module n'importe ni composant ni vue,
//     car il est partagé avec l'extension.
//   Inchangés : setToken, hasToken, getToken, onSessionExpired, setBase,
//     getBase, download, saveBlob ; jeton de session dans sessionStorage
//     « locksy.session ».
//
// Fin de session : une réponse 401 « unauthorized » (session close ou
// périmée) ou 403 « account_disabled » / « account_expired » (compte désactivé
// ou arrivé à échéance pendant la session) vide le jeton et appelle
// onSessionExpired(err). Les autres refus (totp_required, invalid_totp,
// reauth_required…) laissent la session intacte.
//
// Nouvel essai poli : une réponse 503 « server_busy » (le serveur n'a rien
// traité) est réessayée quelle que soit la méthode ; une requête GET ou HEAD
// l'est aussi sur 502, 503, 504 ou panne réseau. Au plus 2 nouveaux essais ;
// délai = Retry-After borné à 10 s, sinon 1 s puis 3 s.
//
// Messages : ce module est partagé avec l'extension, qui n'embarque pas le
// catalogue (règle D5 : i18n.js hors des modules partagés). ApiError.message
// garde donc le texte du serveur, ou un texte de repli ci-dessous ; à
// l'affichage, errorText() le remplace par la traduction de errors.<code>
// (chaque code levé ici a la sienne : tools/test/i18n.test.mjs le vérifie).

const TOKEN_KEY = "locksy.session";
const MAX_RETRIES = 2;
const MAX_RETRY_DELAY_MS = 10_000;
const DEFAULT_DELAYS_MS = [1000, 3000];
const IDEMPOTENT = new Set(["GET", "HEAD"]);
/** Interface de confirmation d'identité non branchée (erreur de programmation). */
const REAUTH_UNAVAILABLE = "La confirmation d'identité n'est pas disponible sur cette page. Rechargez la page puis recommencez.";
/** Champs du corps d'erreur déjà rangés ailleurs dans ApiError. */
const KNOWN_ERROR_FIELDS = new Set(["error", "message", "fields", "retry_after"]);

let token = safeGet(TOKEN_KEY);
let onExpired = null;
// Adresse du serveur : vide pour l'interface web (même origine), renseignée par l'extension.
let base = "";
let sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let reauthUi = null;

export const setBase = (b) => { base = String(b || "").replace(/\/+$/, ""); };
export const getBase = () => base || location.origin;

function safeGet(k) {
  try { return sessionStorage.getItem(k); } catch { return null; }
}

export class ApiError extends Error {
  constructor(status, code, message, { fields, retryAfter, params } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    if (fields !== undefined) this.fields = fields;
    if (retryAfter !== undefined) this.retryAfter = retryAfter;
    if (params !== undefined) this.params = params;
  }
}

export function setToken(t) {
  token = t;
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* stockage indisponible : la session reste en mémoire */ }
}

export const hasToken = () => !!token;
export const getToken = () => token;
export const onSessionExpired = (fn) => { onExpired = fn; };

/** Remplace l'attente entre deux essais (tests). `null` revient au minuteur. */
export function setRetrySleep(fn) {
  sleep = typeof fn === "function" ? fn : (ms) => new Promise((resolve) => setTimeout(resolve, ms));
}

/** Délai Retry-After en secondes (nombre ou date HTTP), ou undefined. */
export function parseRetryAfter(raw, now = Date.now()) {
  if (raw === null || raw === undefined || raw === "") return undefined;
  const s = String(raw).trim();
  if (/^\d+$/.test(s)) return Number(s);
  const at = Date.parse(s);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - now) / 1000));
}

/** Délai avant le nouvel essai n° `attempt` (0, 1…) en millisecondes. */
export function retryDelay(attempt, retryAfter) {
  if (Number.isFinite(retryAfter)) return Math.min(Math.max(0, retryAfter) * 1000, MAX_RETRY_DELAY_MS);
  return DEFAULT_DELAYS_MS[Math.min(attempt, DEFAULT_DELAYS_MS.length - 1)];
}

/** Codes qui mettent fin à la session : [statut, code]. */
const SESSION_ENDED = Object.freeze([[401, "unauthorized"], [403, "account_disabled"], [403, "account_expired"]]);

/** Session refusée par le serveur : jeton vidé, fin de session signalée. */
function endSessionOn(err) {
  if (!token || !SESSION_ENDED.some(([status, code]) => err.status === status && err.code === code)) return;
  setToken(null);
  onExpired?.(err);
}

/** Vrai si la réponse (ou la panne réseau, status 0) mérite un nouvel essai. */
function retryable(method, status, code) {
  if (status === 503 && code === "server_busy") return true;
  return IDEMPOTENT.has(method) && (status === 0 || status === 502 || status === 503 || status === 504);
}

/** Erreur typée depuis une réponse non réussie. */
function errorFrom(res, data) {
  const params = {};
  for (const [k, v] of Object.entries(data && typeof data === "object" ? data : {})) {
    if (!KNOWN_ERROR_FIELDS.has(k)) params[k] = v;
  }
  const retryAfter = parseRetryAfter(res.headers.get("retry-after")) ?? (Number.isFinite(data?.retry_after) ? data.retry_after : undefined);
  return new ApiError(res.status, data?.error || "error", data?.message || fallbackMessage(res.status), {
    fields: data?.fields,
    retryAfter,
    params: Object.keys(params).length ? params : undefined,
  });
}

/** Une seule tentative : réponse brute, ou ApiError « network ». */
async function send(method, path, body, opts) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token) headers.authorization = `Bearer ${token}`;
  if (opts.ifMatch !== undefined && opts.ifMatch !== null) headers["if-match"] = `"${String(opts.ifMatch).replace(/"/g, "")}"`;
  if (opts.ifNoneMatch) headers["if-none-match"] = opts.ifNoneMatch;
  if (opts.reauth) headers["x-locksy-reauth"] = opts.reauth;
  try {
    return await fetch(`${base}/api${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "omit",
      signal: opts.signal,
    });
  } catch (e) {
    if (e?.name === "AbortError") throw e;
    throw new ApiError(0, "network", "Serveur injoignable. Vérifiez votre connexion puis réessayez.");
  }
}

/** Requête complète : { data, etag, status, headers }. Lève une ApiError. */
export async function apiFull(method, path, body, opts = {}) {
  const verb = String(method || "GET").toUpperCase();
  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await send(verb, path, body, opts);
    } catch (e) {
      if (opts.retry !== false && attempt < MAX_RETRIES && e instanceof ApiError && retryable(verb, 0, e.code)) {
        await sleep(retryDelay(attempt));
        continue;
      }
      throw e;
    }
    const etag = res.headers.get("etag");
    if (res.status === 204 || res.status === 304) return { data: null, etag, status: res.status, headers: res.headers };
    const data = await res.json().catch(() => ({}));
    if (res.ok) return { data, etag, status: res.status, headers: res.headers };
    const err = errorFrom(res, data);
    if (opts.retry !== false && attempt < MAX_RETRIES && retryable(verb, res.status, err.code)) {
      await sleep(retryDelay(attempt, err.retryAfter));
      continue;
    }
    endSessionOn(err);
    throw err;
  }
}

/** Corps JSON de la réponse (null pour 204) : forme historique, toujours servie. */
export async function api(method, path, body, opts) {
  return (await apiFull(method, path, body, opts)).data;
}

/** Message d'une réponse d'erreur sans corps JSON (délai dépassé, proxy…). */
function fallbackMessage(status) {
  if (status === 408 || status === 504) return "Le serveur a mis trop de temps à répondre. Réessayez.";
  if (status === 502 || status === 503) return "Le serveur est très sollicité. Réessayez dans quelques secondes.";
  // Limite de taille d'un proxy ou du serveur (le quota renvoie, lui, un message précis).
  if (status === 413) return "Envoi trop volumineux pour le serveur. Choisissez un fichier plus petit puis réessayez.";
  // Requête mal formée rejetée avant le code métier (serveur d'une autre version ?).
  if (status === 400 || status === 422) return "Le serveur n'a pas pu traiter la demande. Rechargez la page ; si le problème persiste, contactez votre administrateur.";
  return "Le serveur a refusé l'opération. Réessayez ; si le problème persiste, contactez votre administrateur.";
}

/** Code et message de repli d'un téléchargement refusé sans corps JSON. */
const DOWNLOAD_CODES = Object.freeze({ 401: "unauthorized", 403: "forbidden", 404: "not_found" });

function downloadMessage(status) {
  if (status === 401) return "Votre session a expiré. Reconnectez-vous puis recommencez.";
  if (status === 403) return "Vous n'avez pas le droit de télécharger ce fichier. Demandez-le à votre administrateur.";
  if (status === 404) return "Fichier introuvable : il a peut-être été supprimé. Rechargez la page.";
  if ([408, 413, 502, 503, 504].includes(status)) return fallbackMessage(status);
  return "Téléchargement impossible. Réessayez ; si le problème persiste, contactez votre administrateur.";
}

export async function download(path, filename) {
  const headers = {};
  // Pas de « Bearer null » : l'en-tête n'est posé qu'avec une session.
  if (token) headers.authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(`${base}/api${path}`, { headers, cache: "no-store", credentials: "omit" });
  } catch {
    throw new ApiError(0, "network", "Serveur injoignable. Vérifiez votre connexion puis réessayez.");
  }
  if (!res.ok) {
    let code = DOWNLOAD_CODES[res.status] || "download";
    let message = downloadMessage(res.status);
    if ((res.headers.get("content-type") || "").includes("application/json")) {
      const data = await res.json().catch(() => ({}));
      code = data.error || code;
      message = data.message || message;
    }
    const err = new ApiError(res.status, code, message, { retryAfter: parseRetryAfter(res.headers.get("retry-after")) });
    endSessionOn(err);
    throw err;
  }
  saveBlob(await res.blob(), filename);
}

export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// ------------------------------------------------------------ Réauthentification

/**
 * Branche l'interface de réauthentification (app.js) :
 * {
 *   proof(password) -> Promise<string>      preuve b64 (auth_key) du mot de passe maître ;
 *   ask({ action, title, message, objectName, exchange }) -> Promise<string|null>
 *     affiche la confirmation ; exchange(password, totp?) renvoie le jeton ou
 *     lève l'ApiError à afficher (totp_required : demander le code, puis
 *     rappeler exchange(null, code), la preuve déjà dérivée est réutilisée) ;
 *     résout le jeton obtenu, ou null si la personne annule.
 * }
 */
export function setReauthUi(ui) {
  reauthUi = ui && typeof ui.ask === "function" && typeof ui.proof === "function" ? ui : null;
}

/**
 * Échange la preuve du mot de passe maître (et le code de vérification) contre
 * un jeton de réauthentification. Serveur sans POST /auth/reauth (404) : la
 * preuve historique (b64 de l'auth_key) est renvoyée telle quelle ; elle ne vaut
 * que pour l'action « settings ».
 */
export async function exchangeReauth(action, authKey, totp) {
  try {
    const res = await api("POST", "/auth/reauth", { action, auth_key: authKey, totp: totp || undefined }, { retry: false });
    return res.token;
  } catch (e) {
    if (e instanceof ApiError && e.status === 404 && e.code === "not_found") return authKey;
    throw e;
  }
}

export async function withReauth(action, fn, { title, message, objectName } = {}) {
  if (!reauthUi) throw new ApiError(0, "unknown", REAUTH_UNAVAILABLE);
  const ui = reauthUi;
  // La preuve dérivée (Argon2, environ 1 s) est gardée le temps de la
  // confirmation : le second appel, avec le code de vérification, passe
  // password = null pour la réutiliser.
  let authKey = null;
  const exchange = async (password, totp) => {
    if (password !== null && password !== undefined) authKey = await ui.proof(password);
    if (!authKey) throw new ApiError(0, "unknown", REAUTH_UNAVAILABLE);
    return exchangeReauth(action, authKey, totp);
  };
  let reauth;
  try {
    reauth = await ui.ask({ action, title, message, objectName, exchange });
  } finally {
    authKey = null;
  }
  if (!reauth) return undefined;
  return fn({ reauth });
}
