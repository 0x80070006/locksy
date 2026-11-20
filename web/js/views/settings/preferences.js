// Paramètres › Préférences (cahier §3.3.8 et §4.9) : apparence, verrouillage,
// copie, nouveaux éléments, générateur, partage, extension, raccourcis.
//
// Chaque préférence est enregistrée dès qu'elle change, dans le document de
// préférences chiffré (settings-client.savePrefs) : elle suit la personne sur
// ses appareils. Une préférence bornée par l'organisation affiche la mention
// de la politique (policyHint) ; les options hors bornes restent visibles et
// désactivées ; une préférence hors bornes est ramenée dans les bornes et
// signalée une fois. Chaque section a « Rétablir les valeurs recommandées ».
//
// « Synchroniser mes préférences sur mes appareils » (case décochée) : sur cet
// appareil, l'apparence est gardée localement (localOnly) au lieu d'être
// enregistrée dans le compte ; les autres préférences restent liées au compte.
// La case n'apparaît que si settings-client sait lire l'apparence locale en
// priorité (clé « prefs.sync » admise par localOnly) : sans cela, un choix
// local serait aussitôt masqué par celui du compte.

import {
  t, plural, h, clear, uid, button, field, selectInput, toggle, durationSelect, formatDuration,
  policyHint, policyText, alertCard, notify, keepFocus, errorText, fmtNumber,
} from "../../ui/index.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";

const DISPLAY_KEYS = Object.freeze(["ui.theme", "ui.contrast", "ui.text_scale", "ui.density"]);
const SYNC_KEY = "prefs.sync";
const LOCK_PRESETS = [1, 5, 10, 15, 30, 60, 240, 480, 1440, 0];
const CLIPBOARD_PRESETS = [10, 15, 30, 60, 120, 300, 600];
const SHARE_PRESETS = [60, 240, 1440, 4320, 10080, 43200];
const VIEW_PRESETS = [1, 2, 3, 5, 10, 25, 50, 100];

/** Clés bornées dont une préférence hors bornes est ramenée et signalée. */
const CLAMPED = Object.freeze({
  "client.autolock_minutes": "minutes",
  "client.clipboard_clear_seconds": "seconds",
  "share.default_expiry_minutes": "minutes",
  "share.default_views": "count",
  "generator.length": "chars",
});

/** Plafonds du registre : un plafond égal à celui-ci ne vient pas de l'organisation. */
const REGISTRY_MAX = Object.freeze({
  "client.autolock_minutes": 1440,
  "client.clipboard_clear_seconds": 600,
  "share.default_expiry_minutes": 43_200,
  "share.default_views": 100,
});

/** Plafond à mentionner (« Limité à … par votre organisation »), ou null. */
const orgMax = (key, max) => (max !== null && max !== undefined && max < (REGISTRY_MAX[key] ?? Infinity) ? max : null);

/** Choix « ne pas synchroniser l'apparence » possible avec ce settings-client ? */
export function syncChoiceSupported(settings = S) {
  return Array.isArray(settings.LOCAL_KEYS) && settings.LOCAL_KEYS.includes(SYNC_KEY);
}

/** Synchronisation de l'apparence sur cet appareil (réglage local, non sensible). */
export function syncEnabled(settings = S) {
  if (!syncChoiceSupported(settings)) return true;
  try {
    return settings.localOnly(SYNC_KEY) !== false;
  } catch {
    return true; // stockage local indisponible : préférences du compte
  }
}

/** Enregistre le choix ; faux si le stockage local l'a refusé. */
function setSync(settings, on) {
  try {
    settings.localOnly(SYNC_KEY, on ? null : false);
    return true;
  } catch {
    return false;
  }
}

/** Lecture d'un chemin du document de préférences (« lock.minutes »). */
function readPath(doc, path) {
  return path.split(".").reduce((cur, part) => (cur && typeof cur === "object" ? cur[part] : undefined), doc);
}

function pathPatch(path, value) {
  return path.split(".").reduceRight((acc, part) => ({ [part]: acc }), value);
}

/** Texte d'une valeur bornée (« 30 minutes », « 14 caractères »). */
function boundText(kind, value) {
  if (kind === "minutes" || kind === "seconds") return formatDuration(value, kind);
  if (kind === "chars") return plural("settings_user.prefs.chars", value);
  return fmtNumber(value);
}

export async function render(container, ctx) {
  const settings = ctx.settings || S;
  let disposed = false;
  const unsubscribe = [];
  /** Messages « valeur ramenée dans les bornes », par clé. */
  const clampMessages = new Map();

  /**
   * Enregistrements en file : deux choix rapprochés ne partent pas en même
   * temps avec la même révision (sinon 409 et rechargement du document).
   */
  let pending = Promise.resolve();

  /** Enregistre une modification ; échec : message et retour à l'état réel. */
  function save(patch, redraw) {
    const run = pending.then(async () => {
      try {
        await settings.savePrefs(patch);
        notify({ text: t("settings_user.prefs.saved"), tone: "ok" });
      } catch (e) {
        notify({ text: t("settings_user.prefs.save_failed", { reason: errorText(e) }), tone: "danger" });
        redraw?.();
      }
    });
    pending = run;
    return run;
  }

  /** Préférence d'une clé de politique ou d'affichage. */
  function savePref(key, value, redraw) {
    clampMessages.delete(key);
    if (DISPLAY_KEYS.includes(key) && !syncEnabled(settings)) {
      settings.localOnly(key, value);
      notify({ text: t("settings_user.prefs.saved_local"), tone: "ok" });
      return Promise.resolve();
    }
    return save(settings.prefPatch(key, value), redraw);
  }

  /** Préférence sans clé de politique (chemin du document). */
  const savePath = (path, value, redraw) => save(pathPatch(path, value), redraw);

  // ---------------------------------------------------------- Contrôles

  function selectPref({ label, key, path, options, help }) {
    const current = key ? settings.effective(key).value : readPath(settings.prefs(), path);
    const select = selectInput({ value: current ?? options[0].value, options });
    const el = field({ label, input: select, help });
    select.addEventListener("change", () => {
      const raw = select.value;
      const opt = options.find((o) => String(o.value) === raw);
      const value = opt ? opt.value : raw;
      if (key) savePref(key, value, redrawAll);
      else savePath(path, value === "" ? null : value, redrawAll);
    });
    return el;
  }

  function togglePref({ label, key, path, help }) {
    const eff = key ? settings.effective(key) : { value: readPath(settings.prefs(), path), mode: "free" };
    const locked = eff.mode === "enforced" || eff.source === "machine";
    const hint = key ? policyHint({ policy: eff }) : null;
    const el = toggle({
      label, help, checked: eff.value === true, disabled: locked, reason: locked ? policyText(eff) : undefined,
      onChange: (on) => (key ? savePref(key, on, redrawAll) : savePath(path, on, redrawAll)),
    });
    if (hint) el.append(hint);
    return el;
  }

  function durationPref({ label, key, unit, presets, maxFrom }) {
    const eff = settings.effective(key);
    const locked = eff.mode === "enforced" || eff.source === "machine";
    let max = eff.max ?? null;
    if (maxFrom) {
      const cap = Number(settings.effective(maxFrom).value);
      if (Number.isFinite(cap) && cap > 0) max = max === null ? cap : Math.min(max, cap);
    }
    const allowNever = key === "client.autolock_minutes" && !settings.optionsFor(key, [0])[0].disabled;
    const reason = policyText({ ...eff, max: orgMax(key, max) }, (v) => formatDuration(v, unit));
    return durationSelect({
      label, unit, presets, allowNever,
      value: eff.value,
      min: locked ? eff.value : eff.min ?? undefined,
      max: locked ? eff.value : max ?? undefined,
      disabledReason: reason || undefined,
      onChange: (v) => savePref(key, v, redrawAll),
    });
  }

  function countPref({ label, key, presets, maxFrom }) {
    const eff = settings.effective(key);
    const locked = eff.mode === "enforced" || eff.source === "machine";
    let max = eff.max ?? null;
    const cap = maxFrom ? Number(settings.effective(maxFrom).value) : NaN;
    if (Number.isFinite(cap) && cap > 0) max = max === null ? cap : Math.min(max, cap);
    const min = eff.min ?? 1;
    const reason = policyText({ ...eff, max: orgMax(key, max) });
    const values = [...new Set([...presets, eff.value])].sort((a, b) => a - b);
    const options = values.map((v) => {
      const out = locked ? v !== eff.value : v < min || (max !== null && v > max);
      return { value: v, label: out ? t("settings_user.prefs.unavailable", { label: fmtNumber(v) }) : fmtNumber(v), disabled: out, title: out ? reason || undefined : undefined };
    });
    const select = selectInput({ value: eff.value, options });
    const el = field({ label, input: select });
    if (reason) {
      const hint = h("p", { class: "c-policy-hint", id: uid("politique") }, h("span", {}, reason));
      el.querySelector(".c-field__error").before(hint);
      select.setAttribute("aria-describedby", [select.getAttribute("aria-describedby"), hint.id].filter(Boolean).join(" "));
    }
    select.addEventListener("change", () => savePref(key, Number(select.value), redrawAll));
    return el;
  }

  function lengthPref() {
    const eff = settings.effective("generator.length");
    const floor = Number(settings.effective("generator.min_length").value) || 8;
    const min = Math.max(eff.min ?? 8, floor);
    const max = eff.max ?? 128;
    const input = h("input", { type: "number", class: "c-input", inputmode: "numeric", min, max, step: 1, value: String(eff.value) });
    const el = field({
      label: t("settings_user.prefs.generator_length"), input,
      help: min > 8 ? plural("tools.generator.min_imposed", min) : t("settings_user.prefs.between", { min: fmtNumber(min), max: fmtNumber(max) }),
    });
    input.addEventListener("change", () => {
      const n = Number(input.value);
      if (!Number.isInteger(n) || n < min || n > max) {
        input.value = String(eff.value);
        notify({ text: t("settings_user.prefs.between", { min: fmtNumber(min), max: fmtNumber(max) }), tone: "warn" });
        return;
      }
      savePref("generator.length", n, redrawAll);
    });
    return el;
  }

  /** Section avec titre, contrôles et « Rétablir les valeurs recommandées ». */
  function section(titleKey, controls, resetPatch, notices = []) {
    const id = uid("section");
    return h("section", { class: "c-card", "aria-labelledby": id },
      h("h2", { id }, t(titleKey)),
      notices.map((text) => alertCard({ tone: "info", text })),
      controls,
      resetPatch ? h("div", { class: "l-cluster" }, button({
        label: t("settings_user.prefs.reset"), icon: "restore", variant: "quiet",
        onClick: async () => {
          const patch = resetPatch();
          if (patch.local) {
            for (const key of DISPLAY_KEYS) settings.localOnly(key, null);
            delete patch.local;
          }
          await save(patch, redrawAll);
          await redrawAll();
        },
      })) : null);
  }

  /**
   * Préférences ramenées dans les bornes : la valeur corrigée est enregistrée
   * et le message reste affiché pendant la visite de la page (les sections
   * sont redessinées après l'enregistrement), jusqu'à un nouveau choix.
   */
  function clampNotices(keys) {
    const out = [];
    for (const key of keys) {
      const eff = settings.effective(key);
      if (eff.clamped && !clampMessages.has(key)) {
        settings.consumeClampNotice(key); // la coquille ne le signale plus une seconde fois
        clampMessages.set(key, t("settings_user.prefs.clamped", { value: boundText(CLAMPED[key], eff.value) }));
        const patch = settings.prefPatch(key, eff.value);
        pending = pending.then(() => settings.savePrefs(patch).catch(() => { /* la valeur effective reste bornée */ }));
      }
      if (clampMessages.has(key)) out.push(clampMessages.get(key));
    }
    return out;
  }

  const D = S.DEFAULT_PREFS;
  const defaultsOf = (part) => JSON.parse(JSON.stringify(D[part]));

  function draw() {
    if (disposed) return;
    const writable = [...V.state.collections.values()].filter((c) => c.personal || ["manager", "editor"].includes(c.role));
    const shareOn = settings.effective("share.enabled").value !== false;
    let syncCard = null;
    if (syncChoiceSupported(settings)) {
      const syncBox = h("input", { type: "checkbox", checked: syncEnabled(settings), id: uid("sync") });
      syncBox.addEventListener("change", () => {
        if (!setSync(settings, syncBox.checked)) {
          syncBox.checked = !syncBox.checked;
          notify({ text: t("settings_user.prefs.sync_failed"), tone: "danger" });
          return;
        }
        notify({ text: t(syncBox.checked ? "settings_user.prefs.sync_on" : "settings_user.prefs.sync_off"), tone: "ok" });
        redrawAll();
      });
      const syncHelp = uid("sync-aide");
      syncBox.setAttribute("aria-describedby", syncHelp);
      syncCard = h("div", { class: "c-card" },
        h("label", { class: "l-cluster" }, syncBox, h("strong", {}, t("settings_user.prefs.sync"))),
        h("p", { class: "u-muted", id: syncHelp }, t("settings_user.prefs.sync_help")));
    }

    clear(container,
      syncCard,

      section("settings_user.prefs.appearance", [
        selectPref({ label: t("settings_user.prefs.theme"), key: "ui.theme", options: ["system", "light", "dark"].map((v) => ({ value: v, label: t(`settings_user.prefs.theme_${v}`) })) }),
        selectPref({ label: t("settings_user.prefs.contrast"), key: "ui.contrast", options: ["system", "normal", "more"].map((v) => ({ value: v, label: t(`settings_user.prefs.contrast_${v}`) })) }),
        selectPref({
          label: t("settings_user.prefs.text_scale"), key: "ui.text_scale",
          options: [[100, "normal"], [112.5, "large"], [125, "larger"]].map(([v, n]) => ({ value: v, label: t(`settings_user.prefs.text_scale_${n}`) })),
        }),
        selectPref({ label: t("settings_user.prefs.density"), key: "ui.density", options: ["comfortable", "compact"].map((v) => ({ value: v, label: t(`settings_user.prefs.density_${v}`) })) }),
      ], () => ({ local: true, ui: { theme: D.ui.theme, contrast: D.ui.contrast, text_scale: D.ui.text_scale, density: D.ui.density } })),

      section("settings_user.prefs.locking", [
        durationPref({ label: t("settings_user.prefs.lock_after"), key: "client.autolock_minutes", unit: "minutes", presets: LOCK_PRESETS }),
        togglePref({ label: t("settings_user.prefs.lock_on_hide"), key: "client.lock_on_hide", help: t("settings_user.prefs.lock_on_hide_help") }),
      ], () => ({ lock: defaultsOf("lock") }), clampNotices(["client.autolock_minutes"])),

      section("settings_user.prefs.copy", [
        durationPref({ label: t("settings_user.prefs.clipboard_after"), key: "client.clipboard_clear_seconds", unit: "seconds", presets: CLIPBOARD_PRESETS }),
        togglePref({ label: t("settings_user.prefs.click_to_copy"), path: "ui.click_to_copy", help: t("settings_user.prefs.click_to_copy_help") }),
      ], () => ({ clipboard: defaultsOf("clipboard"), ui: { click_to_copy: D.ui.click_to_copy } }), clampNotices(["client.clipboard_clear_seconds"])),

      section("settings_user.prefs.new_items", [
        selectPref({
          label: t("settings_user.prefs.default_collection"), path: "ui.default_collection",
          options: [{ value: "", label: t("settings_user.prefs.default_collection_auto") },
            ...writable.map((c) => ({ value: c.id, label: c.personal ? t("common.glossary.personal_vault") : c.name }))],
        }),
      ], () => ({ ui: { default_collection: null } })),

      section("settings_user.prefs.generator", [
        selectPref({
          label: t("settings_user.prefs.generator_style"), path: "generator.style",
          options: [{ value: "random", label: t("tools.generator.style_random") }, { value: "words", label: t("tools.generator.style_words") }],
        }),
        lengthPref(),
      ], () => ({ generator: defaultsOf("generator") }), clampNotices(["generator.length"])),

      section("settings_user.prefs.sharing", shareOn ? [
        durationPref({ label: t("settings_user.prefs.share_expiry"), key: "share.default_expiry_minutes", unit: "minutes", presets: SHARE_PRESETS, maxFrom: "share.max_expiry_minutes" }),
        countPref({ label: t("settings_user.prefs.share_views"), key: "share.default_views", presets: VIEW_PRESETS, maxFrom: "share.max_views" }),
      ] : [alertCard({ tone: "info", text: t("settings_user.prefs.share_disabled") })],
      shareOn ? () => ({ share: defaultsOf("share") }) : null,
      shareOn ? clampNotices(["share.default_expiry_minutes", "share.default_views"]) : []),

      section("settings_user.prefs.extension", [
        togglePref({ label: t("settings_user.prefs.offer_save"), key: "extension.offer_save" }),
        togglePref({ label: t("settings_user.prefs.copy_totp"), key: "extension.copy_totp_after_fill" }),
      ], () => ({ extension: defaultsOf("extension") })),

      section("settings_user.prefs.shortcuts", [
        togglePref({ label: t("settings_user.prefs.single_key"), key: "client.single_key_shortcuts", help: t("settings_user.prefs.single_key_help") }),
      ], () => ({ shortcuts: defaultsOf("shortcuts") })));
  }

  const redrawAll = () => keepFocus(container, draw);
  draw();
  // Politique rechargée (révision changée) : bornes et mentions à jour.
  for (const key of ["client.autolock_minutes", "client.clipboard_clear_seconds", "share.default_expiry_minutes", "generator.length"]) {
    unsubscribe.push(settings.subscribe(key, () => { if (!disposed && !container.contains(document.activeElement)) redrawAll(); }));
  }
  return {
    dispose() {
      disposed = true;
      for (const off of unsubscribe) off();
    },
    isDirty: () => false,
  };
}

