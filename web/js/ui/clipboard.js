// Presse-papiers des secrets : écriture, effacement à l'échéance et
// effacement immédiat au verrouillage. Module sans DOM ni texte affiché
// (testé sous Node) ; secret.js s'en sert pour copySecret.
//
// Règles :
// - on n'efface que ce que nous avons copié : si le navigateur laisse lire le
//   presse-papiers sans rien demander (permission « clipboard-read » déjà
//   accordée), on vérifie que le contenu est encore le secret ; sinon on
//   efface sans condition, sans jamais déclencher de demande d'autorisation ;
// - une copie faite ensuite dans la page (Ctrl+C) remplace notre valeur : on
//   n'y touche plus ;
// - un document sans le focus ne peut pas écrire dans le presse-papiers : le
//   secret reste alors en attente et on réessaie au retour du focus.

/** Accès réel au presse-papiers (remplaçable dans les tests). */
const browserClipboard = {
  async permission() {
    // Firefox et Safari lèvent une exception pour « clipboard-read ».
    const status = await navigator.permissions.query({ name: "clipboard-read" });
    return status.state;
  },
  read: () => navigator.clipboard.readText(),
  write: (text) => navigator.clipboard.writeText(text),
};

let clip = browserClipboard;
/** Remplace l'accès au presse-papiers (tests). `null` revient au navigateur. */
export function setClipboardBackend(b) { clip = b || browserClipboard; }

// Copies faites ailleurs dans la page depuis notre dernière écriture.
let pageCopies = 0;
let copyListener = false;
function watchCopies() {
  if (copyListener || typeof document === "undefined") return;
  copyListener = true;
  try { document.addEventListener("copy", () => { pageCopies += 1; }); } catch { /* contexte sans DOM */ }
}

/**
 * Décision d'effacement, sans état : renvoie
 * - « none » : rien en attente ;
 * - « wait » : échéance pas encore atteinte ;
 * - « changed » : le presse-papiers contient autre chose, on n'y touche pas ;
 * - « cleared » : effacé ;
 * - « retry » : écriture refusée (document sans focus), à retenter.
 * `pending` = { text, due, copies? } ; `copies` : nombre de copies de la page
 * au moment de l'écriture (une copie de l'utilisateur depuis vaut « changed »).
 */
export async function decideClear(pending, now, cb) {
  if (!pending) return "none";
  if (now < pending.due) return "wait";
  if (pending.copies !== undefined && pending.copies !== pageCopies) return "changed";
  let state = "unknown";
  try { state = await cb.permission(); } catch { state = "unsupported"; }
  if (state === "granted") {
    let current = null;
    try { current = await cb.read(); } catch { current = null; }
    if (typeof current === "string" && current !== pending.text) return "changed";
  }
  try {
    await cb.write("");
    return "cleared";
  } catch {
    return "retry";
  }
}

let pending = null; // { text, due, copies } : dernier secret copié, pas encore effacé
let clipTimer = null;
let running = null;

function tryClear() {
  if (running) return running;
  running = (async () => {
    const p = pending;
    const r = await decideClear(p, Date.now(), clip);
    // Un nouveau secret copié entre-temps garde sa propre échéance.
    if (pending === p && (r === "cleared" || r === "changed")) pending = null;
    return r;
  })().finally(() => { running = null; });
  return running;
}

/**
 * Écrit `text` dans le presse-papiers ; avec `seconds` > 0, il sera effacé à
 * l'échéance (s'il y est encore). Renvoie false si le navigateur refuse.
 */
export async function writeSecret(text, seconds) {
  try {
    await clip.write(String(text ?? ""));
  } catch {
    return false;
  }
  watchCopies();
  clearTimeout(clipTimer);
  const secs = Number(seconds);
  if (Number.isFinite(secs) && secs > 0) {
    pending = { text: String(text ?? ""), due: Date.now() + secs * 1000, copies: pageCopies };
    clipTimer = setTimeout(tryClear, secs * 1000);
  } else {
    pending = null; // valeur non secrète : rien à effacer
  }
  return true;
}

/** Efface tout de suite le dernier secret copié (verrouillage, déconnexion). */
export async function clearClipboardNow() {
  if (!pending) return;
  clearTimeout(clipTimer);
  pending.due = 0;
  try {
    // Un essai déjà en cours a pu voir l'ancienne échéance : on recommence.
    if (await tryClear() === "wait") await tryClear();
  } catch { /* nouvel essai au retour du focus */ }
}

// Nouvel essai quand la page retrouve le focus (écriture refusée auparavant).
if (typeof window !== "undefined") {
  try {
    const retry = () => { if (pending && Date.now() >= pending.due) tryClear(); };
    window.addEventListener("focus", retry);
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") retry(); });
  } catch { /* contexte sans DOM */ }
}
