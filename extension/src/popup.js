// Extension Locksy : déverrouillage, comptes du site, remplissage, copie et
// enregistrement. Même noyau cryptographique que l'interface web
// (WebAssembly), mêmes composants (lib/ui), mêmes textes (lib/i18n) et même
// politique (lib/settings-client) : le serveur ne reçoit que des chiffrés.
//
// Écrans : popup/login.js (accès), popup/list.js (principal), popup/save.js
// (enregistrement), popup/generate.js, popup/prefs.js. Démarrage ici :
// politique du poste (chrome.storage.managed, lue AVANT chrome.storage.local),
// serveur, autorisation de l'extension par l'organisation, session.

import { t, setIconBase, setClipboardPolicy } from "./lib/ui/index.js";
import { loadCrypto } from "./lib/wasm.js";
import { setBase, onSessionExpired } from "./lib/api.js";
import * as V from "./lib/vault.js";
import * as Settings from "./lib/settings-client.js";
import { TEST } from "./lib/build-flags.js";
import { webPage } from "./match.js";
import { normalizeServer, readManaged } from "./settings.js";
import { S, ext, store, registerScreens, go, fatal, showError, perfMark, perfMarkAfterPaint } from "./popup/context.js";
import { computeRules, restore, openVault, lock, forget } from "./popup/session.js";
import { renderSetup, renderGrant, renderBlocked, renderLogin, hasHostPermission } from "./popup/login.js";
import { renderMain } from "./popup/list.js";
import { renderSave } from "./popup/save.js";
import { renderGenerate } from "./popup/generate.js";
import { renderPrefs } from "./popup/prefs.js";
import { renderOffline } from "./popup/offline.js";

registerScreens({
  boot: () => boot().catch(fatal),
  setup: renderSetup,
  login: (o) => renderLogin(o).catch(showError),
  main: renderMain,
  save: () => renderSave().catch(showError),
  generate: renderGenerate,
  prefs: renderPrefs,
});

let listening = false;

/** Onglet visé : l'onglet actif ; la variante des tests peut en désigner un (?tab=<id>). */
async function targetTab() {
  const forced = TEST ? Number(new URLSearchParams(location.search).get("tab")) : 0;
  if (forced) return ext.tabs.get(forced).catch(() => null);
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

/**
 * Extension autorisée par l'organisation (GET /extension/allowed) ? Un serveur
 * qui ne connaît pas la route (404) ou injoignable : comportement d'avant
 * (le serveur reste la barrière, à la connexion d'entreprise notamment).
 */
async function allowedByOrganisation() {
  const id = ext.runtime?.id;
  if (!id) return true;
  try {
    const r = await fetch(`${S.server}/api/extension/allowed?id=${encodeURIComponent(id)}`, {
      cache: "no-store", credentials: "omit", signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return true;
    return (await r.json())?.allowed !== false;
  } catch {
    return true;
  }
}

async function boot() {
  perfMark("boot");
  if (!ext) return fatal(t("extension.unsupported"));
  if (!listening) {
    listening = true;
    ext.runtime?.onMessage?.addListener((msg) => {
      // Verrouillage décidé par le service worker (échéance, session Windows verrouillée).
      if (msg?.type === "locksy:locked" && V.isUnlocked()) {
        forget();
        go("login", { info: t("extension.session.locked") });
      }
    });
    // Jeton refusé par le serveur (session révoquée ou expirée) : on verrouille.
    onSessionExpired(() => {
      lock().finally(() => go("login", { error: t("extension.session.expired") }));
    });
  }
  setIconBase("lib/sprite.svg");
  // Effacement des copies faites popup ouvert : délai effectif
  // (client.clipboard_clear_seconds borné par l'organisation et le poste).
  setClipboardPolicy({ clearSeconds: () => S.rules?.clipboardSeconds ?? 30 });
  // Tout ce qui ne dépend de rien part en même temps : module
  // cryptographique, onglet visé, politique du poste, serveur choisi.
  const cryptoReady = loadCrypto("lib/locksy.wasm");
  let managed = {};
  const [tab, stored] = await Promise.all([
    targetTab(),
    store.get("local", "server"),
    // Politique du poste d'abord, puis le choix de l'utilisateur.
    Promise.resolve(ext.storage.managed?.get(null)).then((m) => { managed = m || {}; }, () => { /* aucune politique */ }),
  ]);
  S.tab = tab;
  S.page = webPage(S.tab?.url);
  S.managed = readManaged(managed);
  Settings.configure({ vault: V, machine: S.managed.machine });
  computeRules();
  await cryptoReady;
  perfMark("crypto");
  V.setDeviceLabel(t("extension.device"));

  if (S.managed.server) {
    // Serveur imposé : on oublie une session ouverte sur un autre serveur.
    if (stored !== S.managed.server) {
      await lock();
      await store.set("local", "server", S.managed.server);
    }
    S.server = S.managed.server;
    if (!(await hasHostPermission(S.server))) return renderGrant();
  } else {
    S.server = normalizeServer(stored, { allowHttp: TEST });
    if (!S.server) return renderSetup();
  }
  setBase(S.server);

  // Vérification de l'organisation et ouverture du coffre en parallèle ;
  // rien n'est affiché avant la réponse de l'organisation.
  const allowed = allowedByOrganisation();
  const restored = await restore();
  perfMark("restored");
  const opened = restored ? openVault().then(() => null, (e) => e) : null;
  if (!(await allowed)) {
    await opened;
    await lock({ revoke: true });
    return renderBlocked();
  }
  if (!restored) return renderLogin();
  const failure = await opened;
  perfMark("synced");
  if (failure) {
    // 401 : déjà traité par onSessionExpired.
    if (failure.status !== 401) renderOffline(failure, () => go("boot"));
    return;
  }
  renderMain();
  perfMark("rendered");
  perfMarkAfterPaint("painted");
}

boot().catch(fatal);
