// Service worker de l'extension : verrouillage réel et effacement du presse-papiers.
//
// Le popup ne vit que tant qu'il est ouvert : c'est donc ici, avec chrome.alarms,
// que l'échéance de verrouillage est appliquée, même popup fermé.
//  - « locksy-autolock » : efface storage.session.vault (jeton + clés exportées) ;
//    l'échéance est posée par le popup selon client.autolock_minutes effectif ;
//  - verrouillage de la session du système (chrome.idle « locked ») : idem,
//    selon client.lock_on_os_lock effectif (mémorisé dans la session) ou le poste ;
//  - démarrage du navigateur : idem (défense, storage.session est déjà vide) ;
//  - politique du poste modifiée : l'échéance est raccourcie, jamais prolongée ;
//  - « locksy-clipboard » et message « locksy:clipboard » : efface le
//    presse-papiers via un document offscreen, après client.clipboard_clear_seconds.
// Dépendances : settings.js (pur) et le catalogue des textes (lib/i18n.js), sans DOM.

import { t } from "./lib/i18n.js";
import { readManaged, shortenedDeadline, clipboardPlan } from "./settings.js";

const LOCK_ALARM = "locksy-autolock";
const CLIP_ALARM = "locksy-clipboard";
const OFFSCREEN = "offscreen.html";

async function managedPolicy() {
  try {
    return readManaged(await chrome.storage.managed.get(null));
  } catch {
    return readManaged({});
  }
}

/** Serveur en usage : celui du poste, sinon celui choisi par l'utilisateur. */
async function serverUrl() {
  const { server } = await managedPolicy();
  if (server) return server;
  const local = await chrome.storage.local.get("server").catch(() => ({}));
  return typeof local.server === "string" ? local.server : null;
}

// ------------------------------------------------------------------ Verrouillage

/** Efface la session déverrouillée et prévient le popup s'il est ouvert. */
async function wipeVault(reason) {
  const { vault } = await chrome.storage.session.get("vault").catch(() => ({}));
  try {
    await chrome.storage.session.remove("vault");
  } finally {
    await chrome.alarms.clear(LOCK_ALARM).catch(() => {});
    chrome.runtime.sendMessage({ type: "locksy:locked", reason }).catch(() => { /* popup fermé */ });
  }
  // Le jeton est oublié localement ; on ferme aussi la session côté serveur, au mieux.
  if (vault?.token) {
    const server = await serverUrl();
    if (server) {
      fetch(`${server}/api/auth/logout`, {
        method: "POST", headers: { authorization: `Bearer ${vault.token}` }, cache: "no-store", credentials: "omit", signal: AbortSignal.timeout(5000),
      }).catch(() => { /* serveur injoignable : la session expirera côté serveur */ });
    }
  }
  // Un secret copié peu avant reste sinon dans le presse-papiers jusqu'à son échéance.
  if (await chrome.alarms.get(CLIP_ALARM).catch(() => null)) await clearClipboard().catch(() => {});
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === LOCK_ALARM) wipeVault("timeout");
  else if (alarm.name === CLIP_ALARM) clearClipboard().catch(() => {});
});

chrome.idle.onStateChanged.addListener(async (state) => {
  if (state !== "locked") return;
  const { vault } = await chrome.storage.session.get("vault").catch(() => ({}));
  if (!vault) return;
  const { machine } = await managedPolicy();
  if (vault.lockOnOsLock !== false || machine["client.lock_on_os_lock"] === true) await wipeVault("os-lock");
});

chrome.runtime.onStartup.addListener(() => { wipeVault("startup"); });

// La politique du poste peut baisser le délai maximal pendant qu'une session
// est ouverte : on raccourcit l'échéance, sans jamais la prolonger. Un autre
// serveur imposé ferme la session.
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "managed") return;
  const { vault } = await chrome.storage.session.get("vault").catch(() => ({}));
  if (!vault) return;
  const { server, machine } = await managedPolicy();
  if (server && vault.server && server !== vault.server) return wipeVault("policy");
  const next = shortenedDeadline(vault.expires, machine);
  if (next !== null) {
    await chrome.storage.session.set({ vault: { ...vault, expires: next } });
    await chrome.alarms.create(LOCK_ALARM, { when: next });
  }
});

// ------------------------------------------------------------------ Presse-papiers
// Sans la permission clipboardRead, on ne peut pas vérifier que le presse-papiers
// contient encore le secret : l'effacement est inconditionnel. Seule la dernière
// copie faite par Locksy est concernée : l'alarme du même nom et la minuterie
// sont remplacées à chaque copie.

let clipTimer = 0;

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== "locksy:clipboard") return false;
  const plan = clipboardPlan(msg.seconds);
  clearTimeout(clipTimer);
  if (!plan) {
    chrome.alarms.clear(CLIP_ALARM).catch(() => {}).finally(() => sendResponse({ ok: true }));
    return true;
  }
  if (plan.timerMs !== null) clipTimer = setTimeout(() => { clearClipboard().catch(() => {}); }, plan.timerMs);
  chrome.alarms.create(CLIP_ALARM, { when: plan.alarmAt }).catch(() => {}).finally(() => sendResponse({ ok: true }));
  return true;
});

let creating = null;

async function ensureOffscreen() {
  const url = chrome.runtime.getURL(OFFSCREEN);
  const existing = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"], documentUrls: [url] });
  if (existing.length) return;
  creating ??= chrome.offscreen.createDocument({
    url: OFFSCREEN,
    reasons: ["CLIPBOARD"],
    justification: t("extension.offscreen.justification"),
  }).finally(() => { creating = null; });
  await creating;
}

async function clearClipboard() {
  clearTimeout(clipTimer);
  await chrome.alarms.clear(CLIP_ALARM).catch(() => {});
  await ensureOffscreen();
  try {
    const message = { type: "locksy:clear-clipboard", target: "offscreen" };
    try {
      await chrome.runtime.sendMessage(message);
    } catch {
      // Document tout juste créé et pas encore à l'écoute : un second essai.
      await new Promise((r) => setTimeout(r, 200));
      await chrome.runtime.sendMessage(message);
    }
  } finally {
    await chrome.offscreen.closeDocument().catch(() => {});
  }
}
