// Préférences locales à ce navigateur (aucune donnée sensible).
const KEY = "locksy.prefs";

function read() {
  try { return JSON.parse(localStorage.getItem(KEY) || "{}"); } catch { return {}; }
}

export const prefs = {
  get(k, fallback) {
    const v = read()[k];
    return v === undefined ? fallback : v;
  },
  set(k, v) {
    const all = read();
    all[k] = v;
    try { localStorage.setItem(KEY, JSON.stringify(all)); } catch { /* stockage indisponible */ }
  },
};

let clipTimer = null;
/** Copie puis efface le presse-papiers après le délai choisi. */
export async function copySecret(text, label = "Copié") {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return false;
  }
  const secs = Number(prefs.get("clipboardSeconds", 30));
  clearTimeout(clipTimer);
  if (secs > 0) {
    clipTimer = setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), secs * 1000);
  }
  return `${label}${secs > 0 ? ` · effacé dans ${secs} s` : ""}`;
}
