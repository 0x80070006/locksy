// Préférences de l'extension : délai de verrouillage, effacement du
// presse-papiers, proposition d'enregistrement, copie du code après le
// remplissage. Ce sont les préférences synchronisées du compte (/me/prefs,
// chiffrées), bornées par la politique de l'organisation et celle du poste ;
// chaque contrôle limité porte sa mention (policyHint). Sans coffre ouvert,
// seuls le serveur et l'identifiant de l'extension sont affichés.

import { h, t, durationSelect, formatDuration, toggle, policyHint, policyText, announce } from "../lib/ui/index.js";
import * as V from "../lib/vault.js";
import * as Settings from "../lib/settings-client.js";
import { S, ext, go, screen, showError, action } from "./context.js";
import { computeRules, clampDeadline } from "./session.js";

const LOCK_PRESETS = [1, 5, 10, 15, 30, 60, 240];
const CLIPBOARD_PRESETS = [10, 20, 30, 60, 120];

/** Enregistre une préférence ; message d'état ou erreur (le contrôle est alors rétabli par un nouveau rendu). */
async function savePref(key, value, back) {
  try {
    await Settings.savePrefs(Settings.prefPatch(key, value));
    computeRules();
    await clampDeadline();
    announce(t("extension.prefs.saved"));
  } catch (e) {
    renderPrefs(back);
    showError(e);
  }
}

/**
 * Sélecteur de durée borné par la politique : imposé par l'organisation,
 * seule la valeur imposée reste possible ; plafond du poste, il devient le maximum.
 */
function duration(key, label, unit, presets, back) {
  const e = Settings.effective(key);
  const fmt = (v) => formatDuration(v, unit, { never: true });
  const enforced = e.mode === "enforced";
  const machine = e.source === "machine";
  const allowNever = unit === "minutes" && !enforced && !machine && !Settings.optionsFor(key, [0])[0].disabled;
  return durationSelect({
    label, unit, presets, value: e.value, allowNever,
    min: enforced ? e.value : e.min ?? undefined,
    max: enforced || machine ? e.value : e.max ?? undefined,
    disabledReason: policyText(e, fmt) || undefined,
    onChange: (v) => savePref(key, v, back),
  });
}

function preference(key, label, help, back) {
  const e = Settings.effective(key);
  const fixed = e.mode === "enforced" || e.source === "machine";
  return h("div", {},
    toggle({ label, help, checked: e.value !== false, disabled: fixed, reason: fixed ? policyText(e) : undefined, onChange: (on) => savePref(key, on, back) }),
    policyHint({ policy: e }));
}

export function renderPrefs(back = () => go("main")) {
  const unlocked = V.isUnlocked();
  const version = ext.runtime?.getManifest?.().version || "";
  const id = ext.runtime?.id || "";
  const imposed = S.managed.server !== null;
  screen({ title: t("extension.prefs.title"), back, session: unlocked },
    unlocked ? [
      duration("client.autolock_minutes", t("extension.prefs.lock_after"), "minutes", LOCK_PRESETS, back),
      h("p", { class: "c-field__help" }, t("extension.prefs.lock_help")),
      duration("client.clipboard_clear_seconds", t("extension.prefs.clipboard_after"), "seconds", CLIPBOARD_PRESETS, back),
      preference("extension.offer_save", t("extension.prefs.offer_save"), t("extension.prefs.offer_save_help"), back),
      preference("extension.autofill", t("extension.prefs.autofill"), t("extension.prefs.autofill_help"), back),
      preference("extension.copy_totp_after_fill", t("extension.prefs.copy_code"), t("extension.prefs.copy_code_help"), back),
      h("p", { class: "u-muted" }, t("extension.prefs.synced")),
    ] : h("p", { class: "u-muted" }, t("extension.prefs.locked")),
    h("section", { class: "l-stack x-about", "aria-labelledby": "x-about-titre" },
      h("h3", { id: "x-about-titre" }, t("extension.prefs.about")),
      h("p", {}, t("extension.prefs.server"), " ", h("span", { class: "x-site" }, S.server || t("extension.prefs.no_server"))),
      imposed ? h("p", { class: "c-policy-hint" }, t("ui.policy.machine")) : unlocked ? null
        : action({ label: t("extension.prefs.change_server"), onClick: () => go("setup") }),
      h("p", {}, t("extension.prefs.version", { version })),
      id ? h("p", {}, t("extension.prefs.id"), " ", h("span", { class: "u-mono" }, id)) : null));
}
