// Générateur de mots de passe (cahier §3.3.6) : panneau ouvert depuis la
// barre du haut, l'éditeur ou l'extension, et page #/generateur (mobile,
// accès direct).
//
// Exports (contrat C4.5) :
//   openGeneratorPanel({ anchor, onUse, initial }) -> { el, close() }
//     onUse(valeur) : bouton « Utiliser » (éditeur), le panneau se ferme ;
//     initial : options de départ ({ style, length… }) prioritaires sur les
//     préférences, sans les modifier.
//   generatorBounds(settings?) -> bornes appliquées (politique generator.*)
//   render(ctx) -> { dispose(), isDirty() } : page #/generateur.
//
// Règles : la valeur n'est jamais dans une région annoncée (aucun aria-live,
// règle A2) ; une annonce différée la décrit sans la dire (« Nouveau mot de
// passe : 20 caractères, très solide ») ; bornes de l'organisation appliquées
// (curseur borné, mention du minimum) ; réglages gardés dans les préférences
// synchronisées ; aucun historique des valeurs générées.

import {
  t, plural, h, clear, uid, button, panel, field, segmented, selectInput, notify, announce, copySecret,
  formatSecret, strengthMeter, updateStrength, strengthLevel, strengthLabel, policyText, alertCard, icon,
} from "../../ui/index.js";
import { call } from "../../wasm.js";
import * as S from "../../settings-client.js";

const LENGTH_FLOOR = 8;
const LENGTH_CEIL = 128;
const WORDS_FLOOR = 3;
const WORDS_CEIL = 12;
const SAVE_DELAY_MS = 800;
const ANNOUNCE_DELAY_MS = 500;
const SEPARATORS = Object.freeze([["-", "dash"], [".", "dot"], ["_", "underscore"], [" ", "space"]]);

const num = (v, fallback) => (Number.isFinite(Number(v)) && v !== null && v !== "" ? Number(v) : fallback);
const clamp = (v, min, max) => Math.min(max, Math.max(min, Math.round(v)));

/**
 * Bornes de l'organisation : longueur (generator.length bornée, au moins
 * generator.min_length), nombre de mots (generator.min_words), types de
 * caractères exigés (generator.require_classes), « éviter les caractères
 * ambigus » imposé ou non.
 */
export function generatorBounds(settings = S) {
  const len = settings.effective("generator.length");
  const minLength = num(settings.effective("generator.min_length").value, LENGTH_FLOOR);
  const minWords = num(settings.effective("generator.min_words").value, WORDS_FLOOR);
  const classes = num(settings.effective("generator.require_classes").value, 1);
  const ambiguous = settings.effective("generator.avoid_ambiguous");
  const lengthMin = clamp(Math.max(num(len.min, LENGTH_FLOOR), minLength), LENGTH_FLOOR, LENGTH_CEIL);
  return {
    lengthMin,
    lengthMax: clamp(Math.max(num(len.max, LENGTH_CEIL), lengthMin), lengthMin, LENGTH_CEIL),
    lengthImposed: lengthMin > LENGTH_FLOOR,
    wordsMin: clamp(minWords, WORDS_FLOOR, WORDS_CEIL),
    requireClasses: clamp(classes, 1, 4),
    ambiguousEnforced: ambiguous.mode === "enforced" || ambiguous.source === "machine",
    ambiguousValue: ambiguous.value !== false,
    ambiguousHint: policyText(ambiguous),
  };
}

/** Options de départ : préférences, puis `initial`, ramenées dans les bornes. */
function startOptions(settings, bounds, initial) {
  const g = { ...S.DEFAULT_PREFS.generator, ...(settings.prefs?.().generator || {}), ...(initial || {}) };
  const opts = {
    style: g.style === "words" ? "words" : "random",
    length: num(g.length, 20),
    digits: g.digits !== false,
    symbols: g.symbols !== false,
    avoid_ambiguous: bounds.ambiguousEnforced ? bounds.ambiguousValue : g.avoid_ambiguous !== false,
    words: num(g.words, 5),
    separator: SEPARATORS.some(([v]) => v === g.separator) ? g.separator : "-",
    capitalize: g.capitalize !== false,
    number: g.number !== false,
  };
  const notices = [];
  const length = clamp(opts.length, bounds.lengthMin, bounds.lengthMax);
  if (length > opts.length) notices.push(t("tools.generator.clamped_min", { n: length }));
  else if (length < opts.length) notices.push(t("tools.generator.clamped_max", { n: length }));
  const words = clamp(opts.words, bounds.wordsMin, WORDS_CEIL);
  if (words !== opts.words) notices.push(t("tools.generator.clamped_words", { n: words }));
  opts.length = length;
  opts.words = words;
  // Types exigés : minuscules et majuscules toujours présentes, puis chiffres et symboles.
  if (2 + opts.digits + opts.symbols < bounds.requireClasses) {
    opts.digits = true;
    if (2 + opts.digits + opts.symbols < bounds.requireClasses) opts.symbols = true;
  }
  return { opts, notices, adjusted: notices.length > 0 && !initial };
}

/** Une valeur et son évaluation par le noyau. */
function produce(opts) {
  const g = opts.style === "words"
    ? call("generate_passphrase", { options: { words: opts.words, separator: opts.separator, capitalize: opts.capitalize, include_number: opts.number } })
    : call("generate_password", {
      options: { length: opts.length, lower: true, upper: true, digits: opts.digits, symbols: opts.symbols, avoid_ambiguous: opts.avoid_ambiguous },
    });
  let score = 4;
  let issues = [];
  try {
    const s = call("strength", { password: g.value });
    score = s.score;
    issues = s.warnings || [];
  } catch { /* évaluation indisponible : la valeur reste utilisable */ }
  return { value: g.value, level: strengthLevel(score, issues), score, issues };
}

/** Case à cocher simple, désactivable avec une raison visible. */
function checkbox({ label, checked, onChange, disabled, reason }) {
  const reasonId = reason ? uid("gen-raison") : undefined;
  const input = h("input", { type: "checkbox", checked, disabled: !!disabled, "aria-describedby": reasonId });
  input.addEventListener("change", () => onChange(input.checked));
  return h("label", {}, input, h("strong", {}, label),
    reason ? h("span", { class: "u-muted", id: reasonId }, reason) : null);
}

/**
 * Corps du générateur (panneau ou page). Renvoie { el, focusTarget, dispose }.
 */
function generatorBody({ settings = S, initial, onUse, onClose }) {
  const bounds = generatorBounds(settings);
  const start = startOptions(settings, bounds, initial);
  const opts = start.opts;
  let current = null;
  let saveTimer = 0;
  let saveFailed = false;
  let disposed = false;

  const valueEl = h("div", { class: "c-card u-mono" });
  const meter = strengthMeter({ score: null });
  const notices = h("div", { class: "l-stack", "data-gap": "2" },
    start.notices.map((text) => alertCard({ tone: "info", text })));
  const optionsEl = h("div", { class: "l-stack", "data-gap": "4" });

  const save = () => {
    clearTimeout(saveTimer);
    if (initial) return; // options ponctuelles (éditeur) : préférences inchangées
    saveTimer = setTimeout(async () => {
      try {
        await settings.savePrefs({ generator: { ...opts } });
        saveFailed = false;
      } catch {
        if (!saveFailed && !disposed) notify({ text: t("tools.generator.save_failed"), tone: "danger" });
        saveFailed = true;
      }
    }, SAVE_DELAY_MS);
  };

  const regenerate = ({ say = true } = {}) => {
    try {
      current = produce(opts);
    } catch (e) {
      clear(valueEl, h("span", { class: "u-muted" }, t("tools.generator.unavailable")));
      current = null;
      return e;
    }
    clear(valueEl, h("span", { class: "u-sr-only" }, t("tools.generator.value_label")), formatSecret(current.value));
    updateStrength(meter, { score: current.score, issues: current.issues });
    if (say) {
      const level = strengthLabel(current.level).toLocaleLowerCase("fr-FR");
      const key = opts.style === "words" ? "tools.generator.announce_passphrase" : "tools.generator.announce_password";
      announce(t(key, { n: opts.style === "words" ? opts.words : opts.length, level }), { delay: ANNOUNCE_DELAY_MS });
    }
    return null;
  };

  const changed = () => {
    regenerate();
    save();
  };

  /** Curseur borné avec sa valeur écrite et la mention de la politique. */
  function slider({ label, value, min, max, unitKey, hint, onInput }) {
    const shown = h("span", { "aria-hidden": "true" }, plural(unitKey, value));
    const input = h("input", { type: "range", min, max, step: 1, value: String(value), "aria-valuetext": plural(unitKey, value) });
    input.addEventListener("input", () => {
      const n = Number(input.value);
      shown.textContent = plural(unitKey, n);
      input.setAttribute("aria-valuetext", plural(unitKey, n));
      onInput(n);
    });
    const el = field({ label, input, suffix: shown });
    if (hint) {
      const hintId = uid("gen-mention");
      el.querySelector(".c-field__error").before(h("p", { class: "c-policy-hint", id: hintId }, icon("lock", { size: "sm" }), h("span", {}, hint)));
      input.setAttribute("aria-describedby", [input.getAttribute("aria-describedby"), hintId].filter(Boolean).join(" "));
    }
    return el;
  }

  function drawOptions() {
    const classes = (key) => {
      const others = 2 + opts.digits + opts.symbols - (opts[key] ? 1 : 0);
      return opts[key] && others < bounds.requireClasses;
    };
    const style = segmented({
      label: t("tools.generator.style"),
      value: opts.style,
      options: [{ value: "random", label: t("tools.generator.style_random") }, { value: "words", label: t("tools.generator.style_words") }],
      onChange: (v) => {
        opts.style = v;
        drawOptions();
        changed();
      },
    });
    let detail;
    if (opts.style === "words") {
      const sep = selectInput({
        value: opts.separator,
        options: SEPARATORS.map(([value, name]) => ({ value, label: t(`tools.generator.separator_${name}`) })),
      });
      sep.addEventListener("change", () => {
        opts.separator = sep.value;
        changed();
      });
      detail = [
        slider({
          label: t("tools.generator.words"), value: opts.words, min: bounds.wordsMin, max: WORDS_CEIL, unitKey: "tools.generator.words_value",
          hint: bounds.wordsMin > WORDS_FLOOR ? plural("tools.generator.min_words_imposed", bounds.wordsMin) : null,
          onInput: (n) => { opts.words = n; changed(); },
        }),
        field({ label: t("tools.generator.separator"), input: sep }),
        h("fieldset", { class: "c-radio-cards" }, h("legend", {}, t("tools.generator.options")),
          checkbox({ label: t("tools.generator.capitalize"), checked: opts.capitalize, onChange: (v) => { opts.capitalize = v; changed(); } }),
          checkbox({ label: t("tools.generator.number"), checked: opts.number, onChange: (v) => { opts.number = v; changed(); } })),
      ];
    } else {
      const required = plural("tools.generator.classes_required", bounds.requireClasses);
      detail = [
        slider({
          label: t("tools.generator.length"), value: opts.length, min: bounds.lengthMin, max: bounds.lengthMax, unitKey: "tools.generator.length_value",
          hint: bounds.lengthImposed ? plural("tools.generator.min_imposed", bounds.lengthMin) : null,
          onInput: (n) => { opts.length = n; changed(); },
        }),
        h("fieldset", { class: "c-radio-cards" }, h("legend", {}, t("tools.generator.characters")),
          checkbox({
            label: t("tools.generator.digits"), checked: opts.digits, disabled: classes("digits"), reason: classes("digits") ? required : null,
            onChange: (v) => { opts.digits = v; drawOptions(); changed(); },
          }),
          checkbox({
            label: t("tools.generator.symbols"), checked: opts.symbols, disabled: classes("symbols"), reason: classes("symbols") ? required : null,
            onChange: (v) => { opts.symbols = v; drawOptions(); changed(); },
          }),
          checkbox({
            label: t("tools.generator.avoid_ambiguous"), checked: opts.avoid_ambiguous, disabled: bounds.ambiguousEnforced, reason: bounds.ambiguousEnforced ? bounds.ambiguousHint : null,
            onChange: (v) => { opts.avoid_ambiguous = v; changed(); },
          })),
      ];
    }
    // Le focus reste sur le contrôle actif quand le bloc est redessiné.
    const active = document.activeElement;
    const inBlock = active && optionsEl.contains(active) ? active.closest("fieldset, .c-field") : null;
    const index = inBlock ? [...optionsEl.querySelectorAll("fieldset, .c-field")].indexOf(inBlock) : -1;
    clear(optionsEl, style, detail);
    if (index >= 0) {
      const again = optionsEl.querySelectorAll("fieldset, .c-field")[index]?.querySelector("input:checked, input:not([type=radio]), select");
      again?.focus();
    }
  }

  const copyBtn = button({
    label: t("tools.generator.copy"), icon: "copy", variant: onUse ? "secondary" : "primary",
    onClick: () => (current ? copySecret(current.value, { kind: "password" }) : undefined),
  });
  const actions = [
    copyBtn,
    button({ label: t("tools.generator.another"), icon: "refresh", onClick: () => { regenerate(); } }),
    onUse ? button({
      label: t("tools.generator.use"), icon: "check", variant: "primary",
      onClick: () => {
        if (!current) return;
        onUse(current.value);
        onClose?.();
      },
    }) : null,
  ];

  drawOptions();
  const failed = regenerate({ say: false });
  if (start.adjusted) save();

  const el = failed
    ? alertCard({ tone: "danger", text: t("tools.generator.unavailable") })
    : h("div", { class: "l-stack", "data-gap": "4" },
      notices,
      valueEl,
      meter,
      h("div", { class: "l-cluster" }, actions),
      optionsEl,
      initial ? null : h("p", { class: "u-muted" }, t("tools.generator.synced")));

  return {
    el,
    focusTarget: () => copyBtn,
    dispose() {
      disposed = true;
      // Enregistre tout de suite un réglage en attente.
      if (saveTimer && !initial) {
        clearTimeout(saveTimer);
        settings.savePrefs({ generator: { ...opts } }).catch(() => {});
      }
      current = null;
    },
  };
}

/**
 * Panneau « Générer un mot de passe ». anchor : élément qui reçoit le focus
 * à la fermeture (à défaut, l'élément actif à l'ouverture).
 */
export function openGeneratorPanel({ anchor, onUse, initial, settings } = {}) {
  if (anchor && typeof anchor.focus === "function" && anchor !== document.activeElement) anchor.focus();
  let handle = null;
  const body = generatorBody({ settings, initial, onUse, onClose: () => handle?.close() });
  handle = panel({
    title: t("tools.generator.panel_title"),
    body: body.el,
    onClose: () => body.dispose(),
    initialFocus: body.focusTarget,
  });
  return handle;
}

/** Page #/generateur. */
export async function render(ctx) {
  const body = generatorBody({ settings: ctx.settings || S });
  clear(ctx.root, h("div", { class: "l-stack", "data-gap": "5" },
    h("h1", { tabindex: "-1" }, t("tools.generator.title")),
    h("p", { class: "u-muted" }, t("tools.generator.intro")),
    body.el));
  return { dispose: () => body.dispose(), isDirty: () => false };
}
