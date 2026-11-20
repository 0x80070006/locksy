// Réglage généré depuis le registre (cahier §4.8, annexes A.1 et A.2) : le
// contrôle est choisi d'après kind.type ; badges « Modifié », « Imposé »,
// « Fixé par l'hébergeur », « Réservé aux propriétaires », « Avancé » ;
// « Rétablir (défaut : …) » ; sélecteur de mode (Libres / Par défaut /
// Imposé) avec l'aperçu de ce que verront les utilisateurs ; erreur à côté.
// Les libellés viennent de settings.<clé>.label|help|unit (catalogue du lot
// L4), avec repli sur la clé. La clé technique n'est affichée que dans
// « Détails techniques ».

import { fieldErrorText, fmtNumber, has, t } from "../i18n.js";
import { clear, h, icon, uid } from "./core.js";
import { badge } from "./badges.js";
import { button } from "./button.js";
import { checkboxGroup, segmented, toggle } from "./choice.js";
import { chipsInput } from "./chips.js";
import { durationSelect, formatDuration } from "./duration.js";
import { describe, field, fieldInput, selectInput, textArea, textInput } from "./field.js";
import { keepFocus } from "./focus.js";
import { passwordField } from "./password.js";
import { policyHint } from "./policy-hint.js";
import { technicalDetails } from "./tech.js";

const DURATION_UNITS = new Set(["seconds", "minutes", "hours", "days"]);
const MODES = ["free", "default", "enforced"];
const ROLES = ["user", "admin", "owner"];
const LIST_TYPES = new Set(["cidrs", "domains", "emails", "words"]);

// Surfaces et textes sur l'accent, copiés de design/tokens.json (color.light.surface,
// color.dark.surface, on-accent clair et sombre) : mêmes seuils que le serveur (accent_ok).
const SURFACES = Object.freeze({ light: "#ffffff", dark: "#121922" });
const ON_ACCENT = Object.freeze(["#ffffff", "#0b1a17"]);

/** Texte du catalogue, ou repli (autre clé, ou texte donné) si la clé est absente. */
const tr = (key, fallbackKey, params) => (has(key) ? t(key, params) : fallbackKey ? t(fallbackKey, params) : null);

/** Libellé d'un réglage : settings.<clé>.label, sinon la clé. */
export function settingLabel(key) {
  return has(`settings.${key}.label`) ? t(`settings.${key}.label`) : String(key);
}

const enumLabel = (key, v) => (has(`settings.${key}.value.${v}`) ? t(`settings.${key}.value.${v}`) : String(v));
const modeLabel = (m) => tr(`settings.mode.${m}`, `ui.setting.mode.${m}`);
const kindOf = (def) => (def?.kind && typeof def.kind === "object" ? def.kind : { type: String(def?.kind || "text").toLowerCase() });

/** Défaut du schéma : { value, mode?, min?, max? } (A.1) ou valeur nue. */
function defaultOf(def) {
  const d = def?.default;
  return d && typeof d === "object" && !Array.isArray(d) && "value" in d ? d : { value: d };
}

function unitText(def, n) {
  const kind = kindOf(def);
  if (has(`settings.${def?.key}.unit`)) {
    // Unité seule (« caractères », « Mio ») ou gabarit avec {n} (« {n} jours »).
    const unit = t(`settings.${def.key}.unit`, { n: fmtNumber(n) });
    return unit.includes(fmtNumber(n)) ? unit : `${fmtNumber(n)} ${unit}`;
  }
  if (kind.unit && has(`ui.unit.${kind.unit}`)) return t(`ui.unit.${kind.unit}`, { n: fmtNumber(n) });
  return fmtNumber(n);
}

/** Valeur lisible d'un réglage (récapitulatifs, « défaut : … »). */
export function formatSettingValue(def, v) {
  if (v === null || v === undefined) return t("ui.value.none");
  if (typeof v === "object" && !Array.isArray(v) && "value" in v) {
    const parts = [formatSettingValue(def, v.value)];
    if (v.mode) parts.push(modeLabel(v.mode));
    if (v.mode === "default" && v.max !== null && v.max !== undefined) parts.push(t("ui.setting.at_most", { max: formatSettingValue(def, v.max) }));
    return parts.join(" · ");
  }
  if (v === "***") return t("ui.value.secret");
  const kind = kindOf(def);
  if (typeof v === "boolean") return v ? t("common.state.enabled") : t("common.state.disabled");
  if (Array.isArray(v)) {
    if (!v.length) return t("ui.value.empty_list");
    return v.map((x) => (kind.type === "roles" ? t(`ui.role.${x}`) : String(x))).join(", ");
  }
  if (typeof v === "number") {
    if (kind.type === "int" && DURATION_UNITS.has(kind.unit)) return formatDuration(v, kind.unit, { never: v === 0 && Number(kind.min) === 0 });
    return def ? unitText(def, v) : fmtNumber(v);
  }
  if (kind.type === "enum") return enumLabel(def.key, v);
  if (typeof v === "object") return v.has_image ? t("ui.setting.image.custom") : t("ui.setting.image.default");
  return String(v);
}

// ------------------------------------------------------------------ Validation des listes

const DOMAIN_RE = /^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const IPV4 = "(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}";
const CIDR4_RE = new RegExp(`^${IPV4}(?:/(?:3[0-2]|[12]?\\d))?$`);
const CIDR6_RE = /^[0-9a-f:]{2,39}(?:\/(?:12[0-8]|1[01]\d|\d?\d))?$/i;

function itemProblem(type, value) {
  const bad = (code) => (has(`errors.field.${code}`) ? fieldErrorText({ code, value }) : t("ui.setting.invalid_item", { value }));
  if (type === "domains" && !DOMAIN_RE.test(value)) return bad("invalid_domain");
  if (type === "emails" && !EMAIL_RE.test(value)) return bad("invalid_email");
  if (type === "cidrs" && !(CIDR4_RE.test(value) || (value.includes(":") && CIDR6_RE.test(value)))) return bad("invalid_cidr");
  if (type === "words" && !/^\S{1,64}$/u.test(value)) return bad("invalid_word");
  return null;
}

// ------------------------------------------------------------------ Contraste

function luminance(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(hex).trim());
  if (!m) return null;
  const n = parseInt(m[1], 16);
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * lin(((n >> 16) & 255) / 255) + 0.7152 * lin(((n >> 8) & 255) / 255) + 0.0722 * lin((n & 255) / 255);
}

/** Rapport de contraste WCAG entre deux couleurs #rrggbb (null si illisible). */
export function contrastRatio(a, b) {
  const la = luminance(a);
  const lb = luminance(b);
  if (la === null || lb === null) return null;
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** Contrôle de la couleur d'accent : texte 4,5:1 et surface 3:1, en clair et en sombre. */
export function accentCheck(hex) {
  const text = Math.max(...ON_ACCENT.map((c) => contrastRatio(hex, c) ?? 0));
  const light = contrastRatio(hex, SURFACES.light) ?? 0;
  const dark = contrastRatio(hex, SURFACES.dark) ?? 0;
  return { light, dark, text, ok: text >= 4.5 && light >= 3 && dark >= 3 };
}

/** Nuance conforme la plus proche (pas de 2 % vers le noir ou le blanc), ou null. */
export function closestAccent(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(hex).trim());
  if (!m) return null;
  const n = parseInt(m[1], 16);
  const rgb = [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  const mix = (to, k) => `#${rgb.map((c) => Math.round(c + (to - c) * k).toString(16).padStart(2, "0")).join("")}`;
  for (let k = 0.02; k <= 1; k += 0.02) {
    for (const to of [0, 255]) {
      const candidate = mix(to, k);
      if (accentCheck(candidate).ok) return candidate;
    }
  }
  return null;
}

const ratio = (r) => fmtNumber(Math.floor(r * 100) / 100, { maxDecimals: 2 });

// ------------------------------------------------------------------ Composant

/**
 * settingField({ def, value, mode, min, max, source, lockedBy, canEdit = true, hasSecret, error, onChange })
 *   -> { el, update(props), destroy() }
 * def : entrée du schéma (A.1) ; value, mode, min, max, source, lockedBy
 * (« locked_by »), hasSecret : entrée de GET /admin/settings (A.2).
 * onChange(changement) : valeur nue, { value, mode, min, max } pour une clé à
 * modes, ou null pour « Rétablir » (forme du PATCH).
 */
export function settingField(initial) {
  let p = { canEdit: true, ...initial };
  const el = h("div", { class: "c-setting", "data-key": p.def.key });

  const def = () => p.def;
  const kind = () => kindOf(p.def);
  const dflt = () => defaultOf(p.def);
  const cur = () => ({ value: p.value, mode: p.mode ?? dflt().mode, min: p.min ?? dflt().min, max: p.max ?? dflt().max });
  const isModified = () => {
    const c = cur();
    const d = dflt();
    return JSON.stringify(c.value) !== JSON.stringify(d.value) || (def().modes && (c.mode !== d.mode || c.max !== d.max));
  };
  const readOnly = () => !p.canEdit || p.source === "host_locked";
  const readOnlyReason = () => (p.source === "host_locked" ? t("ui.setting.host_locked_reason") : t("ui.setting.owner_only_reason"));

  const emit = (patch, { repaint = false } = {}) => {
    Object.assign(p, patch);
    if (kind().type === "secret" && "value" in patch) p.hasSecret = true;
    const c = cur();
    p.onChange?.(def().modes ? { value: c.value, mode: c.mode, min: c.min ?? null, max: c.max ?? null } : c.value);
    if (repaint) paint();
    else paintBadges();
  };

  const badges = h("div", { class: "c-setting__badges" });
  function paintBadges() {
    clear(badges,
      isModified() ? badge({ tone: "info", label: tr("settings.badge.modified", "ui.setting.badge.modified") }) : null,
      cur().mode === "enforced" ? badge({ tone: "warn", icon: "lock", label: tr("settings.badge.enforced", "ui.setting.badge.enforced") }) : null,
      p.source === "host_locked" ? badge({ tone: "neutral", icon: "server", label: tr("settings.badge.host_locked", "ui.setting.badge.host_locked"), title: p.lockedBy }) : null,
      def().owner_only ? badge({ tone: "neutral", icon: "shield", label: tr("settings.badge.owner_only", "ui.setting.badge.owner_only") }) : null,
      def().advanced ? badge({ tone: "neutral", label: tr("settings.badge.advanced", "ui.setting.badge.advanced") }) : null);
    resetBtn.hidden = !isModified() || readOnly();
  }

  const resetBtn = h("button", { type: "button", class: "c-setting__reset" });
  resetBtn.addEventListener("click", () => {
    const d = dflt();
    Object.assign(p, { value: d.value, mode: d.mode, min: d.min, max: d.max });
    p.onChange?.(null);
    keepFocus(el, paint);
  });

  function control(label, help) {
    const k = kind();
    const c = cur();
    const set = (value) => emit({ value });
    switch (k.type) {
      case "bool":
        return toggle({ label, help, checked: !!c.value, onChange: set });
      case "int": {
        if (DURATION_UNITS.has(k.unit)) {
          return durationSelect({ label, help, value: c.value, presets: def().presets || [], min: k.min, max: k.max, unit: k.unit, allowNever: Number(k.min) === 0, onChange: set });
        }
        const input = textInput({ type: "number", inputmode: "numeric", value: c.value, min: k.min, max: k.max, step: 1 });
        input.addEventListener("change", () => set(Number(input.value)));
        return field({
          label, input, suffix: has(`ui.unit_short.${k.unit}`) ? t(`ui.unit_short.${k.unit}`) : undefined,
          help: [help, t("ui.setting.between", { min: fmtNumber(k.min), max: fmtNumber(k.max) })].filter(Boolean).join(" "),
        });
      }
      case "enum": {
        const options = (k.values || []).map((v) => ({ value: v, label: enumLabel(def().key, v) }));
        if (options.length <= 4) return segmented({ label, help, options, value: c.value, onChange: set });
        const input = selectInput({ options, value: c.value });
        input.addEventListener("change", () => set(input.value));
        return field({ label, help, input });
      }
      case "roles":
        return checkboxGroup({ legend: label, help, options: ROLES.map((r) => ({ value: r, label: t(`ui.role.${r}`) })), values: c.value || [], onChange: set });
      case "secret":
        return secretControl(label, help);
      case "image":
        return imageControl(label, help);
      case "color":
        return colorControl(label, help);
      default:
        if (LIST_TYPES.has(k.type)) {
          return chipsInput({
            label, help, values: c.value || [], max: k.max, onChange: set,
            validate: (v) => itemProblem(k.type, v),
            placeholderKey: `ui.setting.placeholder.${k.type}`,
          });
        }
        return textControl(label, help, k);
    }
  }

  function textControl(label, help, k) {
    const type = k.type === "url" ? "url" : k.type === "email" ? "email" : "text";
    const input = k.multiline
      ? textArea({ value: cur().value ?? "", maxlength: k.max_len })
      : textInput({ type, value: cur().value ?? "", maxlength: k.max_len, inputmode: type === "url" ? "url" : undefined });
    input.addEventListener("change", () => emit({ value: input.value }));
    const f = field({ label, help, input, count: !!k.max_len });
    if (k.type === "url") {
      const test = h("a", { href: "#", target: "_blank", rel: "noopener noreferrer", class: "c-button c-button--quiet" },
        icon("external"), t("ui.setting.test_link"));
      const refresh = () => {
        const ok = /^https?:\/\/\S+$/i.test(input.value.trim());
        test.hidden = !ok;
        if (ok) test.href = input.value.trim();
      };
      input.addEventListener("input", refresh);
      refresh();
      f.append(test);
    }
    return f;
  }

  function secretControl(label, help) {
    const status = h("p", { class: "c-setting__value" }, p.hasSecret ? t("ui.setting.secret.set") : t("ui.setting.secret.unset"));
    const box = h("div", { class: "l-stack", "data-gap": "2" });
    const replace = button({
      label: p.hasSecret ? t("ui.setting.secret.replace") : t("ui.setting.secret.define"), icon: "key",
      onClick: () => {
        const pw = passwordField({ label: t("ui.setting.secret.new_label"), help, autocomplete: "new-password" });
        fieldInput(pw).addEventListener("change", (e) => emit({ value: e.target.value }));
        replace.hidden = true;
        box.append(pw);
        fieldInput(pw).focus();
      },
    });
    box.append(h("span", { class: "c-field__label" }, label), status, replace);
    return box;
  }

  function imageControl(label, help) {
    const k = kind();
    const value = cur().value;
    const src = typeof value === "string" ? value : value?.url;
    const preview = src ? h("img", { src, alt: t("ui.setting.image.preview"), class: "c-avatar", "data-size": "lg" }) : null;
    const input = h("input", { type: "file", accept: "image/png,image/webp", class: "c-input" });
    const f = field({ label, help, input });
    input.addEventListener("change", () => {
      const file = input.files?.[0];
      if (!file) return;
      if (k.max_bytes && file.size > k.max_bytes) {
        showError({ code: "image_too_large", max: Math.round(k.max_bytes / 1024) });
        return;
      }
      const reader = new FileReader();
      reader.addEventListener("load", () => emit({ value: String(reader.result) }, { repaint: true }));
      reader.readAsDataURL(file);
    });
    const reset = src ? button({ label: t("ui.setting.image.reset"), variant: "quiet", onClick: () => emit({ value: null }, { repaint: true }) }) : null;
    return h("div", { class: "l-stack", "data-gap": "2" }, f, preview, reset);
  }

  function colorControl(label, help) {
    const value = String(cur().value || "");
    const picker = h("input", { type: "color", value: /^#[0-9a-f]{6}$/i.test(value) ? value : "#0d6b64", "aria-label": t("ui.setting.color.picker", { label }) });
    const input = textInput({ value, maxlength: 7, spellcheck: false });
    const control = h("div", { class: "c-field__control" }, input, picker);
    const f = field({ label, help, input, control });
    const swatch = h("span", { class: "c-avatar", "aria-hidden": "true" }, t("ui.setting.color.sample"));
    const report = h("p", { class: "c-field__help", id: uid("contraste") });
    const fix = button({ label: t("ui.setting.color.use_fix"), variant: "quiet" });
    describe(input, [report.id]);
    const show = (hex) => {
      const r = accentCheck(hex);
      swatch.style.setProperty("--tile", /^#[0-9a-f]{6}$/i.test(hex) ? hex : "");
      report.textContent = t(r.ok ? "ui.setting.color.ok" : "ui.setting.color.low", { light: ratio(r.light), dark: ratio(r.dark), text: ratio(r.text) });
      const better = r.ok ? null : closestAccent(hex);
      fix.hidden = !better;
      fix.dataset.value = better || "";
    };
    const choose = (hex) => {
      input.value = hex;
      if (/^#[0-9a-f]{6}$/i.test(hex)) picker.value = hex;
      show(hex);
      emit({ value: hex });
    };
    input.addEventListener("change", () => choose(input.value.trim()));
    picker.addEventListener("input", () => choose(picker.value));
    fix.addEventListener("click", () => fix.dataset.value && choose(fix.dataset.value));
    show(value);
    return h("div", { class: "l-stack", "data-gap": "2" }, f, h("div", { class: "l-cluster" }, swatch, report), fix);
  }

  function modeControl() {
    const c = cur();
    const k = kind();
    const box = h("div", { class: "c-setting__mode l-stack", "data-gap": "2" },
      segmented({
        label: t("ui.setting.mode_legend"),
        options: MODES.map((m) => ({ value: m, label: modeLabel(m) })),
        value: c.mode,
        onChange: (mode) => emit({ mode }, { repaint: true }),
      }));
    if (c.mode === "default" && k.type === "int") {
      const label = t("ui.setting.max_label");
      const onChange = (max) => emit({ max }, { repaint: false });
      box.append(DURATION_UNITS.has(k.unit)
        ? durationSelect({ label, value: c.max ?? k.max, presets: def().presets || [], min: k.min, max: k.max, unit: k.unit, onChange })
        : field({ label, input: numberInput(c.max ?? k.max, k, onChange) }));
    }
    const fmt = (v) => formatSettingValue(def(), v);
    const hint = policyHint({ policy: { value: c.value, mode: c.mode, max: c.max }, format: fmt });
    box.append(h("p", { class: "c-field__help" }, hint ? [t("ui.setting.preview"), " ", hint] : t("ui.setting.preview_free")));
    return box;
  }

  function numberInput(value, k, onChange) {
    const input = textInput({ type: "number", inputmode: "numeric", value, min: k.min, max: k.max, step: 1 });
    input.addEventListener("change", () => onChange(Number(input.value)));
    return input;
  }

  function showError(err) {
    const box = el.querySelector(":scope > .c-field__error");
    const target = el.querySelector("input:not([type=color]), select, textarea, [role=switch]");
    const text = !err ? "" : typeof err === "string" ? err : has(`errors.field.${err.code}`) ? fieldErrorText(err) : t("errors.invalid_input");
    box.hidden = !text;
    box.lastElementChild.textContent = text;
    if (!target) return;
    if (text) {
      target.setAttribute("aria-invalid", "true");
      describe(target, [box.id]);
    } else {
      target.removeAttribute("aria-invalid");
      describe(target, [], [box.id]);
    }
  }

  function paint() {
    const label = settingLabel(def().key);
    const help = has(`settings.${def().key}.help`) ? t(`settings.${def().key}.help`) : undefined;
    const head = h("div", { class: "c-setting__head" });
    let body;
    if (readOnly()) {
      head.append(h("p", { class: "c-field__label" }, label));
      body = [
        h("p", { class: "c-setting__value" }, formatSettingValue(def(), def().modes ? cur() : cur().value)),
        h("p", { class: "c-policy-hint" }, icon("lock", { size: "sm" }), h("span", {}, readOnlyReason())),
      ];
    } else {
      const ctl = control(label, help);
      const ownLabel = ctl.querySelector(":scope > .c-field__label, :scope .c-field > .c-field__label");
      const legend = ctl.querySelector("legend");
      if (ownLabel && !legend) head.append(ownLabel);
      else {
        legend?.classList.add("u-sr-only");
        head.append(h("span", { class: "c-field__label", "aria-hidden": "true" }, label));
      }
      const focusTarget = ctl.querySelector("input, select, textarea, button");
      if (focusTarget) focusTarget.dataset.focusKey = `reglage:${def().key}`;
      body = [ctl, def().modes ? modeControl() : null];
    }
    head.append(badges);
    resetBtn.textContent = t("ui.setting.reset", { value: formatSettingValue(def(), dflt().value) });
    clear(el, head, body, resetBtn,
      h("p", { class: "c-field__error", id: uid("reglage-erreur"), hidden: true }, icon("error", { size: "sm" }), h("span", {})),
      technicalDetails({ body: p.lockedBy ? `${def().key} · ${p.lockedBy}` : def().key }));
    paintBadges();
    if (p.error) showError(p.error);
  }

  paint();
  return {
    el,
    update(next = {}) {
      p = { ...p, ...next };
      keepFocus(el, paint);
    },
    destroy() {
      el.remove();
    },
  };
}
