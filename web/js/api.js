// Client HTTP de l'API Locksy.

const TOKEN_KEY = "locksy.session";
let token = safeGet(TOKEN_KEY);
let onExpired = null;
// Adresse du serveur : vide pour l'interface web (même origine), renseignée par l'extension.
let base = "";
export const setBase = (b) => { base = String(b || "").replace(/\/+$/, ""); };
export const getBase = () => base || location.origin;

function safeGet(k) {
  try { return sessionStorage.getItem(k); } catch { return null; }
}

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
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

export async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token) headers.authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(`${base}/api${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "omit",
    });
  } catch {
    throw new ApiError(0, "network", "Serveur injoignable. Vérifiez votre connexion.");
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new ApiError(res.status, data.error || "error", data.message || `Erreur ${res.status}`);
    if (res.status === 401 && data.error === "unauthorized" && token) {
      setToken(null);
      onExpired?.(err);
    }
    throw err;
  }
  return data;
}

export async function download(path, filename) {
  const res = await fetch(`${base}/api${path}`, { headers: { authorization: `Bearer ${token}` }, cache: "no-store" });
  if (!res.ok) throw new ApiError(res.status, "download", "Téléchargement impossible.");
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
