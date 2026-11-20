// Réglages de l'organisation (cahier §3.4.6, §4.6 à §4.8, annexes A.1 à A.3).
//
// L'écran est GÉNÉRÉ depuis GET /admin/settings/schema : sections et ordre du
// registre, réglages avancés repliés, recherche (libellés, aides, synonymes,
// clés techniques), filtre « Modifiés seulement », un settingField par clé
// (badges, « Rétablir », modes Libres / Par défaut / Imposé), profils de
// sécurité. Enregistrement : barre collante -> POST /validate -> récapitulatif
// (abaissements, impact, motif) -> confirmation d'identité si demandée ->
// PATCH If-Match -> « Révision N · Annuler ». Conflit 409 : « Voir ses
// changements » / « Recharger en gardant les miens ».
//
// La saisie (brouillon) vit dans ce module : elle est conservée quand on
// change de section ; quitter les sections avec des modifications passe par
// la garde du routeur (Enregistrer / Abandonner / Rester).
//
// Repli R11 : sans /schema (serveur plus ancien), les 5 réglages historiques
// (GET / PUT /admin/settings, ancien format).
//
// Exports pour les autres écrans : loadSettings, settingsStore, defOf,
// currentValue, settingsNav, openRecap, openSettingPanel.

import {
  t, plural, has, tList, h, clear, icon, button, notify, announce, errorText, relTime,
  settingField, settingLabel, diffList, saveBar, searchBox, segmented, toggle, sideNav,
  dialog, panel, field, textInput, alertCard, emptyState, errorState, skeleton, keepFocus,
  dirtyGuard, normalize, focusSafely,
} from "../../ui/index.js";
import { api, apiFull } from "../../api.js";
import { isOwner, reauthThen, routeMissing, withStepUp } from "./shell.js";
import { applyAccent } from "../../accent.js";

/** Regroupement des sections du registre dans la navigation (intertitres). */
const SECTION_GROUPS = Object.freeze([
  { key: "admin.settings.group.security", sections: ["login", "sessions", "passwords"] },
  { key: "admin.settings.group.vaults", sections: ["sharing", "retention"] },
  { key: "admin.settings.group.clients", sections: ["clients"] },
  { key: "admin.settings.group.org", sections: ["identity", "branding", "mail"] },
  { key: "admin.settings.group.advanced", sections: ["advanced"] },
]);

/** Pages des réglages qui ne sont pas des sections du registre. */
const EXTRA_PAGES = Object.freeze([
  { id: "historique", key: "admin.settings.nav.history", icon: "history" },
  { id: "transfert", key: "admin.settings.nav.transfer", icon: "download" },
  { id: "systeme", key: "admin.settings.nav.system", icon: "server" },
]);

const PROFILES = Object.freeze(["standard", "reinforced", "strict"]);
const SEARCH_MIN = 2;
const VALIDATE_DELAY_MS = 300;

/** Réglages historiques (serveur sans registre) : clé du registre <-> champ à plat. */
const LEGACY = Object.freeze([
  { key: "twofa.required", field: "require_2fa", kind: { type: "bool" }, default: false, section: "login" },
  { key: "session.idle_minutes", field: "session_idle_minutes", kind: { type: "int", min: 5, max: 1440, unit: "minutes" }, default: 60, section: "sessions", presets: [5, 10, 15, 30, 60, 120, 240, 480, 1440] },
  { key: "session.max_hours", field: "session_max_hours", kind: { type: "int", min: 1, max: 720, unit: "hours" }, default: 12, section: "sessions", presets: [1, 4, 8, 12, 24, 72, 168, 720] },
  { key: "retention.audit_days", field: "audit_retention_days", kind: { type: "int", min: 30, max: 3650, unit: "days" }, default: 365, section: "retention", presets: [30, 90, 180, 365, 730, 1095, 1825, 3650] },
  { key: "retention.trash_days", field: "trash_retention_days", kind: { type: "int", min: 1, max: 365, unit: "days" }, default: 30, section: "retention", presets: [1, 3, 7, 14, 30, 60, 90, 180, 365] },
]);

// ------------------------------------------------------------------ État du module

/** Réglages chargés et saisie en cours (partagés par les écrans de réglages). */
export const settingsStore = {
  schema: null,
  values: null,
  revision: null,
  legacy: false,
  defs: new Map(),
  draft: new Map(),
  errors: new Map(),
  query: "",
  onlyModified: false,
  focusKeys: null,
};

const S = settingsStore;

export const defOf = (key) => S.defs.get(key);
const entryOf = (key) => S.values?.values?.[key] || {};
/** Valeur enregistrée d'un réglage, sinon son défaut (undefined si la clé est inconnue). */
export const currentValue = (key) => entryOf(key).value ?? defaultOf(defOf(key)).value;
const sectionLabel = (id) => (has(`settings.section.${id}.label`) ? t(`settings.section.${id}.label`) : t("admin.settings.section_other"));

/** Défaut du schéma : { value, mode?, min?, max? }. */
function defaultOf(def) {
  const d = def?.default;
  return d && typeof d === "object" && !Array.isArray(d) && "value" in d ? d : { value: d };
}

/** Révision d'une réponse (champ revision, sinon ETag « "r42" »). */
function revisionOf(res) {
  if (Number.isFinite(res?.data?.revision)) return res.data.revision;
  const m = /r(\d+)/.exec(res?.etag || "");
  return m ? Number(m[1]) : null;
}

const ifMatch = () => (S.revision === null || S.revision === undefined ? undefined : `r${S.revision}`);

/**
 * Charge le schéma et les valeurs (repli sur les 5 réglages historiques si
 * /schema n'existe pas). `force` : recharge même si déjà chargé.
 */
export async function loadSettings({ force = false } = {}) {
  if (S.values && !force) return S;
  let schema = null;
  try {
    schema = await api("GET", "/admin/settings/schema");
  } catch (e) {
    if (!routeMissing(e)) throw e;
  }
  const res = await apiFull("GET", "/admin/settings");
  S.legacy = !schema;
  S.schema = schema || legacySchema();
  S.values = schema ? res.data : legacyValues(res.data);
  S.revision = schema ? revisionOf(res) : null;
  S.defs = new Map(S.schema.settings.map((d) => [d.key, d]));
  for (const key of [...S.draft.keys()]) if (!S.defs.has(key)) S.draft.delete(key);
  return S;
}

function legacySchema() {
  return {
    sections: [...new Set(LEGACY.map((l) => l.section))],
    settings: LEGACY.map((l, i) => ({ key: l.key, kind: l.kind, default: l.default, section: l.section, order: i, presets: l.presets || [] })),
    profiles: {},
  };
}

function legacyValues(flat = {}) {
  const values = {};
  for (const l of LEGACY) {
    if (flat[l.field] === undefined || flat[l.field] === null) continue;
    values[l.key] = { value: flat[l.field], default: l.default, source: "org" };
  }
  return { values, legacy: flat };
}

// ------------------------------------------------------------------ Brouillon

/** Forme canonique d'une valeur (comparaisons). */
function canon(def, c) {
  if (c === null) return null;
  if (!def?.modes) return c;
  const o = c && typeof c === "object" && "value" in c ? c : { value: c };
  return { value: o.value ?? null, mode: o.mode ?? null, max: o.max ?? null };
}

/** Valeur enregistrée sous la forme du PATCH. */
function storedChange(key) {
  const def = defOf(key);
  const e = entryOf(key);
  if (def?.modes) return { value: e.value, mode: e.mode ?? defaultOf(def).mode ?? null, min: e.min ?? null, max: e.max ?? null };
  return e.value;
}

const same = (def, a, b) => JSON.stringify(canon(def, a)) === JSON.stringify(canon(def, b));

/** Vrai si la valeur enregistrée est celle par défaut. */
function storedIsDefault(key) {
  const def = defOf(key);
  if (def?.kind?.type === "secret") return !entryOf(key).has_secret;
  const d = defaultOf(def);
  return same(def, storedChange(key), def?.modes ? { value: d.value, mode: d.mode, max: d.max } : d.value);
}

/** Valeur affichée (brouillon, sinon valeur enregistrée), forme { value, mode, min, max }. */
function shownValue(key) {
  const def = defOf(key);
  const d = defaultOf(def);
  if (S.draft.has(key)) {
    const c = S.draft.get(key);
    if (c === null) return { value: d.value, mode: d.mode, min: d.min, max: d.max, reset: true };
    if (def?.modes) return { value: c.value, mode: c.mode, min: c.min, max: c.max };
    return { value: c };
  }
  const e = entryOf(key);
  return { value: e.value, mode: e.mode ?? undefined, min: e.min ?? undefined, max: e.max ?? undefined };
}

/** Vrai si le réglage diffère de son défaut (en tenant compte du brouillon). */
function isModified(key) {
  if (S.draft.has(key)) return S.draft.get(key) !== null;
  return !storedIsDefault(key);
}

function setDraft(key, change) {
  const def = defOf(key);
  if (change === null) {
    if (storedIsDefault(key)) S.draft.delete(key);
    else S.draft.set(key, null);
  } else if (def?.kind?.type !== "secret" && same(def, change, storedChange(key))) {
    S.draft.delete(key);
  } else {
    S.draft.set(key, change);
  }
  S.errors.delete(key);
}

/** Erreurs de champ { clé: { code, … } } (validation, 422, refus par clé). */
function applyErrors(fields = {}) {
  for (const [key, err] of Object.entries(fields || {})) S.errors.set(key, err && typeof err === "object" ? err : { code: String(err) });
}

/** Erreurs d'une réponse de refus (403 owner_only, 409 host_locked / test_required, 422). */
function errorsFromRejection(e) {
  if (e?.fields) return e.fields;
  const keys = e?.params?.keys || (e?.params?.key ? [e.params.key] : []);
  return Object.fromEntries(keys.map((k) => [k, { code: e.code }]));
}

// ------------------------------------------------------------------ Recherche

function searchText(def) {
  const key = def.key;
  return normalize([
    settingLabel(key),
    has(`settings.${key}.help`) ? t(`settings.${key}.help`) : "",
    ...(def.synonyms || []),
    ...tList(`settings.${key}.synonyms`),
    key,
  ].join(" "));
}

function matches(def) {
  if (S.focusKeys && !S.focusKeys.includes(def.key)) return false;
  if (S.onlyModified && !isModified(def.key)) return false;
  if (S.query.length >= SEARCH_MIN && !searchText(def).includes(S.query)) return false;
  return true;
}

const filtering = () => S.query.length >= SEARCH_MIN || S.onlyModified || !!S.focusKeys;

// ------------------------------------------------------------------ Impact et récapitulatif

/** Lignes d'impact d'une validation (« 5 personnes devront… », lien vers la liste filtrée). */
function impactLines(validation) {
  const lines = (validation?.impact || []).map((i) => {
    const key = has(`admin.settings.impact.${i.key}`) ? `admin.settings.impact.${i.key}` : "admin.settings.impact.generic";
    return h("li", {},
      plural(key, Number(i.affected_users) || 0, { admins: Number(i.affected_admins) || 0, label: settingLabel(i.key) }),
      i.link ? [" ", h("a", { href: i.link }, t("admin.settings.impact.see_list"))] : null);
  });
  const warnings = (validation?.warnings || []).map((w) => h("li", {},
    `${settingLabel(w.key)} : `, has(`settings.warning.${w.code}`) ? t(`settings.warning.${w.code}`, w.params || {}) : t("admin.settings.warning_generic")));
  return [...lines, ...warnings];
}

/**
 * Récapitulatif d'une écriture validée (enregistrement, profil, import,
 * retour à une version) : différences, abaissements, impact, motif, puis
 * écriture par send(reason, { reauth }) avec confirmation d'identité si la
 * validation l'exige. Résout true si l'écriture a eu lieu.
 */
export function openRecap({ validation, title, confirmLabel, send, onSaved, onRejected }) {
  return new Promise((resolve) => {
    let saved = false;
    const diff = (validation.diff || []).map((d) => ({ key: d.key, def: defOf(d.key), old: d.old, new: d.new, lowered: !!d.lowered }));
    const lowered = diff.some((d) => d.lowered) || validation.requires_reauth;
    const impact = impactLines(validation);
    const reason = textInput({ maxlength: 500, autocomplete: "off" });
    const problem = h("div", { hidden: true });
    const body = h("div", { class: "l-stack", "data-gap": "3" },
      diff.length ? diffList({ changes: diff }) : h("p", {}, t("admin.settings.recap.nothing")),
      impact.length ? h("div", { class: "c-alert", "data-tone": "info" }, icon("info"), h("ul", { class: "l-stack", "data-gap": "1" }, impact)) : null,
      lowered ? alertCard({ tone: "warn", text: t("admin.settings.recap.lowered_notice") }) : null,
      field({ label: t("admin.settings.recap.reason"), help: t("admin.settings.recap.reason_help"), optional: true, input: reason }),
      problem);
    dialog({
      title,
      body,
      size: "lg",
      actions: [
        { label: t("admin.settings.recap.back"), value: "cancel" },
        {
          label: confirmLabel || t("common.action.save"), variant: "primary", busyLabel: t("common.state.saving"),
          disabled: !diff.length,
          onClick: async () => {
            const why = reason.value.trim() || undefined;
            try {
              const run = (opts) => send(why, opts);
              const res = validation.requires_reauth
                ? await reauthThen("settings", run, { title: t("admin.settings.reauth_title"), message: t("admin.settings.reauth_message") })
                : await withStepUp("settings", run, { title: t("admin.settings.reauth_title"), message: t("admin.settings.reauth_message") });
              if (res === undefined) return false;
              saved = true;
              await onSaved?.(res, validation);
              return true;
            } catch (e) {
              if (onRejected && (await onRejected(e))) return true;
              clear(problem, alertCard({ tone: "danger", text: errorText(e) }));
              problem.hidden = false;
              announce(errorText(e), { assertive: true });
              return false;
            }
          },
        },
      ],
      onClose: () => resolve(saved),
    });
  });
}

// ------------------------------------------------------------------ Écran

let current = null;

export async function renderPage(ctx, container, route) {
  const section = route.section || "login";
  const head = h("div", { class: "l-stack", "data-gap": "3" }, h("h1", { tabindex: "-1" }, t("admin.settings.title")));
  const body = h("div", {}, skeleton({ lines: 6 }));
  clear(container, head, body);
  try {
    await loadSettings({ force: S.draft.size === 0 });
  } catch (e) {
    clear(body, errorState({ error: e, onRetry: () => renderPage(ctx, container, route) }));
    return { dispose() {}, isDirty: () => false };
  }
  current = { ctx, container, head, body, section, subnav: route.subnav || null, fields: new Map() };
  const view = current;
  const bar = saveBar({ count: S.draft.size, onReset: () => resetAll(view), onSave: () => review(view) });
  view.bar = bar;
  const guard = dirtyGuard(() => S.draft.size > 0, { unload: true });
  paintHead(view);
  paintBody(view);
  return {
    dispose() {
      guard.destroy();
      if (!inSettingsSections(location.hash)) {
        S.draft.clear();
        S.errors.clear();
        S.focusKeys = null;
        S.query = "";
        S.onlyModified = false;
      }
      if (current === view) current = null;
    },
    isDirty: () => S.draft.size > 0 && !inSettingsSections(location.hash),
    save: () => review(view),
  };
}

/** Vrai si l'adresse est une section des réglages générés (la saisie y est conservée). */
function inSettingsSections(hash) {
  const m = /^#\/admin\/reglages\/([^/?]+)/.exec(String(hash || ""));
  return !!m && !EXTRA_PAGES.some((p) => p.id === m[1]);
}

function paintHead(view) {
  const search = searchBox({
    label: t("admin.settings.search_label"), placeholderKey: "admin.settings.search_placeholder", value: S.query, shortcut: "",
    onInput: (norm) => {
      S.query = norm;
      paintBody(view);
    },
  });
  const onlyModified = toggle({
    label: t("admin.settings.only_modified"), checked: S.onlyModified,
    onChange: (on) => {
      S.onlyModified = on;
      paintBody(view);
    },
  });
  const parts = [search, S.legacy ? null : onlyModified];
  if (!S.legacy && Object.keys(S.schema.profiles || {}).length) {
    const prof = S.values.profile || {};
    const deviations = prof.deviations || [];
    parts.push(h("div", { class: "l-cluster" },
      segmented({
        label: t("admin.settings.profile.legend"),
        options: PROFILES.filter((p) => S.schema.profiles[p]).map((p) => ({ value: p, label: t(`settings.profile.${p}.label`) })),
        value: prof.closest,
        onChange: (p) => chooseProfile(view, p),
      }),
      deviations.length ? button({
        label: plural("admin.settings.profile.deviations", deviations.length), variant: "quiet", icon: "chevron-right",
        onClick: () => {
          S.focusKeys = S.focusKeys ? null : deviations;
          paintBody(view);
        },
      }) : null));
  }
  clear(view.head, h("h1", { tabindex: "-1" }, t("admin.settings.title")), h("div", { class: "l-cluster" }, parts));
}

const navFor = (view) => settingsNav(filtering() ? null : view.section);

/**
 * Navigation des réglages : sections du registre (avec le nombre de
 * modifications en attente), puis Historique, Importer / exporter, Système.
 * Sans registre (serveur plus ancien) : les trois pages seulement.
 */
export function settingsNav(current) {
  const counts = {};
  for (const key of S.draft.keys()) {
    const sec = defOf(key)?.section;
    counts[sec] = (counts[sec] || 0) + 1;
  }
  const groupedSections = (all) => {
    const used = new Set();
    const groups = SECTION_GROUPS.map((g) => {
      const list = g.sections.filter((s) => all.includes(s));
      list.forEach((s) => used.add(s));
      return { label: t(g.key), sections: list };
    }).filter((g) => g.sections.length);
    const rest = all.filter((s) => !used.has(s));
    if (rest.length) groups.push({ label: t("admin.settings.group.other"), sections: rest });
    return groups;
  };
  const sections = S.schema ? S.schema.sections.filter((s) => S.schema.settings.some((d) => d.section === s)) : [];
  return sideNav({
    label: t("admin.settings.nav.label"),
    current,
    items: [
      ...groupedSections(sections).flatMap((g) => [
        { group: g.label },
        ...g.sections.map((s) => ({
          id: s, href: `#/admin/reglages/${s}`, label: sectionLabel(s),
          badge: counts[s] ? { tone: "info", label: plural("admin.settings.nav.pending", counts[s]) } : undefined,
        })),
      ]),
      { group: t("admin.settings.nav.more") },
      ...EXTRA_PAGES.map((p) => ({ id: p.id, href: `#/admin/reglages/${p.id}`, icon: p.icon, label: t(p.key) })),
    ],
  });
}

function paintBody(view) {
  keepFocus(view.body, () => {
    view.fields = new Map();
    const content = h("div", { class: "l-stack", "data-gap": "4" });
    if (S.legacy) content.append(alertCard({ tone: "info", text: t("admin.settings.legacy_notice") }));
    if (S.focusKeys) content.append(focusBanner(view));
    if (filtering()) content.append(...filteredView(view));
    else content.append(...sectionView(view, view.section));
    if (view.subnav) clear(view.subnav, navFor(view));
    clear(view.body, content, view.bar.el);
    view.bar.update({ count: S.draft.size });
  });
}

function focusBanner(view) {
  const closest = S.values.profile?.closest;
  return alertCard({
    tone: "info",
    text: plural("admin.settings.profile.deviation_text", S.focusKeys.length, { name: closest ? t(`settings.profile.${closest}.label`) : "" }),
    action: closest ? { label: t("admin.settings.profile.back_to", { name: t(`settings.profile.${closest}.label`) }), onClick: () => chooseProfile(view, closest) } : null,
  });
}

function sectionView(view, section) {
  const defs = S.schema.settings.filter((d) => d.section === section).sort((a, b) => a.order - b.order);
  if (!defs.length) {
    return [emptyState({ icon: "settings", title: t("admin.settings.unknown_section"), actions: [{ label: t("admin.settings.back_to_first"), href: "#/admin/reglages/login" }] })];
  }
  const basic = defs.filter((d) => !d.advanced);
  const advanced = defs.filter((d) => d.advanced);
  const out = [h("h2", {}, sectionLabel(section))];
  if (has(`settings.section.${section}.help`)) out.push(h("p", { class: "u-muted" }, t(`settings.section.${section}.help`)));
  out.push(h("div", {}, basic.map((d) => fieldFor(view, d))));
  if (advanced.length) {
    const open = advanced.some((d) => S.draft.has(d.key) || S.errors.has(d.key));
    out.push(h("details", { class: "c-card", open },
      h("summary", {}, plural("admin.settings.advanced", advanced.length)),
      h("p", { class: "u-muted" }, t("admin.settings.advanced_help")),
      advanced.map((d) => fieldFor(view, d))));
  }
  if (section === "identity") {
    out.push(h("p", {}, h("a", { class: "c-button", href: "#/admin/connexion" }, icon("building"), t("admin.settings.identity_link"))));
  }
  if (section === "clients") {
    const slot = h("section", { class: "l-stack", "data-gap": "3", "aria-label": t("admin.deploy.title") });
    out.push(slot);
    import("./deploy-snippets.js")
      .then((m) => m.renderDeploySnippets(slot, { values: S.values, defs: S.defs }))
      .catch(() => slot.remove());
  }
  return out;
}

function filteredView(view) {
  const groups = [];
  for (const section of S.schema.sections) {
    const defs = S.schema.settings.filter((d) => d.section === section && matches(d)).sort((a, b) => a.order - b.order);
    if (defs.length) groups.push(h("section", { class: "l-stack", "data-gap": "1" }, h("h2", {}, sectionLabel(section)), defs.map((d) => fieldFor(view, d))));
  }
  if (groups.length) return [h("p", { class: "u-muted" }, plural("admin.settings.results", groups.reduce((n, g) => n + g.querySelectorAll(".c-setting").length, 0))), ...groups];
  return [emptyState({
    icon: "search",
    title: S.query ? t("admin.settings.no_result", { q: S.query }) : t("admin.settings.no_modified"),
    actions: [{ label: t("admin.settings.clear_filters"), variant: "secondary", onClick: () => { S.query = ""; S.onlyModified = false; S.focusKeys = null; paintHead(view); paintBody(view); } }],
  })];
}

function fieldFor(view, def) {
  const key = def.key;
  const e = entryOf(key);
  const v = shownValue(key);
  const comp = settingField({
    def,
    value: v.value,
    mode: v.mode,
    min: v.min,
    max: v.max,
    source: e.source,
    lockedBy: e.locked_by,
    hasSecret: e.has_secret || (S.draft.has(key) && S.draft.get(key) !== null && def.kind?.type === "secret"),
    canEdit: !def.owner_only || isOwner(view.ctx),
    error: S.errors.get(key),
    onChange: (change) => {
      setDraft(key, change);
      view.bar.update({ count: S.draft.size });
      if (!filtering()) refreshNavBadges(view);
    },
  });
  view.fields.set(key, comp);
  return comp.el;
}

/** Recalcule la navigation (pastilles « N à enregistrer ») sans toucher aux champs. */
function refreshNavBadges(view) {
  if (view.subnav) clear(view.subnav, navFor(view));
}

function resetAll(view) {
  S.draft.clear();
  S.errors.clear();
  paintBody(view);
  announce(t("admin.settings.reset_done"));
}

// ------------------------------------------------------------------ Enregistrement

/** « Vérifier et enregistrer » : validation, récapitulatif, écriture. Résout true si enregistré. */
async function review(view) {
  if (!S.draft.size) return true;
  if (S.legacy) return saveLegacy(view);
  const changes = Object.fromEntries(S.draft);
  let validation;
  try {
    validation = await api("POST", "/admin/settings/validate", { changes });
  } catch (e) {
    notify({ text: errorText(e), tone: "danger" });
    return false;
  }
  if (!validation.ok) {
    showErrors(view, validation.errors);
    return false;
  }
  return openRecap({
    validation,
    title: plural("admin.settings.recap.title", S.draft.size),
    confirmLabel: t("common.action.save"),
    send: (reason, opts) => apiFull("PATCH", "/admin/settings", { changes, reason }, { ifMatch: ifMatch(), ...opts }),
    onSaved: (res) => afterSave(view, res, validation),
    onRejected: (e) => handleRejection(view, e),
  });
}

/** Erreurs de champ affichées à côté des réglages (et la section du premier). */
function showErrors(view, fields) {
  applyErrors(fields);
  const keys = Object.keys(fields || {});
  const first = keys.map(defOf).find(Boolean);
  if (first && !filtering() && first.section !== view.section) {
    view.section = first.section;
    history.replaceState(history.state, "", `#/admin/reglages/${first.section}`);
  }
  paintBody(view);
  const text = plural("admin.settings.errors_count", keys.length);
  notify({ text, tone: "danger" });
  const target = first && view.fields.get(first.key)?.el.querySelector("[aria-invalid=true], input, select, button");
  focusSafely(target);
}

/** Refus de l'écriture : renvoie true si l'erreur est traitée ici (fenêtre fermée). */
async function handleRejection(view, e) {
  if (e?.code === "settings_conflict") {
    setTimeout(() => conflictDialog(view, e), 0);
    return true;
  }
  if (["invalid_settings", "owner_only", "host_locked", "test_required"].includes(e?.code)) {
    setTimeout(() => showErrors(view, errorsFromRejection(e)), 0);
    return true;
  }
  return false;
}

async function afterSave(view, res, validation) {
  const revision = res?.data?.revision ?? revisionOf(res);
  S.draft.clear();
  S.errors.clear();
  try {
    await loadSettings({ force: true });
    // Couleur de l'organisation : visible tout de suite, sans recharger la page.
    applyAccent(document.documentElement, S.values?.values?.["branding.accent_color"]?.value);
  } catch { /* l'écran garde les valeurs affichées ; un nouvel affichage les rechargera */ }
  paintHead(view);
  paintBody(view);
  notify({
    text: t("admin.settings.saved", { revision }),
    tone: "ok",
    action: { label: t("common.action.undo"), run: () => undoRevision(view, validation), doneText: t("admin.settings.undone") },
  });
}

/** Annule une révision : les anciennes valeurs reviennent (nouvelle révision). */
async function undoRevision(view, validation) {
  const changes = {};
  for (const d of validation.diff || []) {
    const type = defOf(d.key)?.kind?.type;
    if (type === "secret" || type === "image") continue;
    changes[d.key] = d.old;
  }
  if (!Object.keys(changes).length) return;
  const send = (opts) => apiFull("PATCH", "/admin/settings", { changes, reason: t("admin.settings.undo_reason") }, { ifMatch: ifMatch(), ...opts });
  await withStepUp("settings", send, { title: t("admin.settings.reauth_title"), message: t("admin.settings.reauth_message") });
  await loadSettings({ force: true });
  if (current === view) {
    paintHead(view);
    paintBody(view);
  }
}

/** Conflit 409 : quelqu'un a enregistré entre-temps ; la saisie est conservée. */
function conflictDialog(view, e) {
  const by = e.params?.by || t("admin.settings.conflict.someone");
  const at = e.params?.at;
  dialog({
    title: t("admin.settings.conflict.title"),
    description: at ? t("admin.settings.conflict.text_at", { by, when: relTime(at) }) : t("admin.settings.conflict.text", { by }),
    body: h("p", {}, t("admin.settings.conflict.keep")),
    actions: [
      { label: t("admin.settings.conflict.see"), value: "see", onClick: () => { setTimeout(() => theirChanges(view), 0); } },
      { label: t("admin.settings.conflict.reload"), variant: "primary", value: "reload", onClick: () => { setTimeout(() => reloadKeeping(view), 0); } },
    ],
  });
}

/** Changements enregistrés par les autres depuis la révision chargée. */
async function theirChanges(view) {
  const since = S.revision ?? 0;
  const list = h("div", { class: "l-stack", "data-gap": "3" }, skeleton({ lines: 3 }));
  dialog({
    title: t("admin.settings.conflict.their_title"),
    body: list,
    size: "lg",
    actions: [
      { label: t("common.action.close"), value: "close" },
      { label: t("admin.settings.conflict.reload"), variant: "primary", value: "reload", onClick: () => { setTimeout(() => reloadKeeping(view), 0); } },
    ],
  });
  try {
    const page = await api("GET", "/admin/settings/history?per_page=20");
    const newer = (page.revisions || []).filter((r) => r.revision > since);
    clear(list, newer.length
      ? newer.map((r) => h("section", { class: "l-stack", "data-gap": "2" },
        h("h3", {}, t("admin.history.entry", { revision: r.revision, by: r.by || r.email || "", when: relTime(r.at) })),
        diffList({ changes: (r.changes || []).map((c) => ({ ...c, def: defOf(c.key) })) })))
      : h("p", {}, t("admin.settings.conflict.no_detail")));
  } catch (err) {
    clear(list, alertCard({ tone: "danger", text: errorText(err) }));
  }
}

/** Recharge les valeurs de la nouvelle révision, garde la saisie et la revalide. */
async function reloadKeeping(view) {
  try {
    await loadSettings({ force: true });
  } catch (e) {
    notify({ text: errorText(e), tone: "danger" });
    return;
  }
  for (const [key, change] of [...S.draft]) setDraft(key, change);
  paintHead(view);
  paintBody(view);
  if (S.draft.size) await review(view);
}

/** Serveur sans registre : PUT /admin/settings avec les champs historiques. */
async function saveLegacy(view) {
  const body = {};
  for (const [key, change] of S.draft) {
    const l = LEGACY.find((x) => x.key === key);
    if (l) body[l.field] = change === null ? l.default : change;
  }
  try {
    await api("PUT", "/admin/settings", body);
  } catch (e) {
    notify({ text: errorText(e), tone: "danger" });
    return false;
  }
  S.draft.clear();
  await loadSettings({ force: true }).catch(() => {});
  paintBody(view);
  notify({ text: t("admin.settings.saved_legacy"), tone: "ok" });
  return true;
}

// ------------------------------------------------------------------ Profils

async function chooseProfile(view, profile) {
  const name = t(`settings.profile.${profile}.label`);
  let validation;
  try {
    validation = await api("POST", "/admin/settings/profile", { profile, dry_run: true });
  } catch (e) {
    notify({ text: errorText(e), tone: "danger" });
    paintHead(view);
    return;
  }
  if (!validation.ok) {
    const ownerOnly = Object.values(validation.errors || {}).some((x) => x?.code === "owner_only");
    paintHead(view);
    // Réglages refusés : signalés sous chaque champ (même rendu qu'un enregistrement).
    if (ownerOnly) notify({ text: t("admin.settings.profile.owner_only"), tone: "danger" });
    else showErrors(view, validation.errors);
    return;
  }
  if (!(validation.diff || []).length) {
    notify({ text: t("admin.settings.profile.already", { name }), tone: "info" });
    paintHead(view);
    return;
  }
  const saved = await openRecap({
    validation,
    title: plural("admin.settings.profile.recap_title", validation.diff.length, { name }),
    confirmLabel: t("admin.settings.profile.apply", { name }),
    send: (reason, opts) => apiFull("POST", "/admin/settings/profile", { profile, dry_run: false, reason }, { ifMatch: ifMatch(), ...opts }),
    onSaved: async (res) => {
      S.focusKeys = null;
      await afterSave(view, res, validation);
    },
    onRejected: (e) => handleRejection(view, e),
  });
  if (!saved) paintHead(view);
}

// ------------------------------------------------------------------ Réglage en contexte

/**
 * Panneau « réglage en contexte » (Accueil, Journal) : mêmes settingField,
 * impact affiché avant d'enregistrer, même PATCH If-Match.
 * openSettingPanel(ctx, keys, { title, intro, onSaved }) -> Promise<boolean>
 */
export async function openSettingPanel(ctx, keys, { title, intro, onSaved } = {}) {
  try {
    await loadSettings({ force: true });
  } catch (e) {
    notify({ text: errorText(e), tone: "danger" });
    return false;
  }
  const local = new Map();
  const impact = h("div", { class: "l-stack", "data-gap": "2" });
  const known = keys.filter((k) => defOf(k));
  let timer = 0;
  let lastValidation = null;

  const revalidate = () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      if (!local.size || S.legacy) {
        clear(impact);
        lastValidation = null;
        return;
      }
      try {
        lastValidation = await api("POST", "/admin/settings/validate", { changes: Object.fromEntries(local) });
        const lines = lastValidation.ok ? impactLines(lastValidation) : [];
        clear(impact,
          lines.length ? h("div", { class: "c-alert", "data-tone": "info" }, icon("info"), h("ul", { class: "l-stack", "data-gap": "1" }, lines)) : null,
          !lastValidation.ok ? alertCard({ tone: "danger", text: plural("admin.settings.errors_count", Object.keys(lastValidation.errors || {}).length) }) : null);
      } catch (e) {
        clear(impact, alertCard({ tone: "danger", text: errorText(e) }));
      }
    }, VALIDATE_DELAY_MS);
  };

  const comps = known.map((key) => {
    const def = defOf(key);
    const e = entryOf(key);
    return settingField({
      def, value: e.value, mode: e.mode ?? undefined, min: e.min ?? undefined, max: e.max ?? undefined,
      source: e.source, lockedBy: e.locked_by, hasSecret: e.has_secret,
      canEdit: !def.owner_only || isOwner(ctx),
      onChange: (change) => {
        if (change === null ? storedIsDefault(key) : same(def, change, storedChange(key))) local.delete(key);
        else local.set(key, change);
        revalidate();
      },
    });
  });
  const problem = h("div");

  return new Promise((resolve) => {
    let saved = false;
    panel({
      title: title || t("admin.settings.panel_title"),
      body: h("div", { class: "l-stack", "data-gap": "3" },
        intro ? h("p", {}, intro) : null,
        comps.length ? comps.map((c) => c.el) : h("p", {}, t("admin.settings.panel_unavailable")),
        impact, problem,
        h("p", {}, h("a", { href: `#/admin/reglages/${defOf(known[0])?.section || "login"}` }, t("admin.settings.panel_all")))),
      dirty: () => local.size > 0,
      actions: [
        { label: t("common.action.cancel"), cancel: true },
        {
          label: t("common.action.save"), variant: "primary", busyLabel: t("common.state.saving"),
          onClick: async () => {
            if (!local.size) return true;
            const changes = Object.fromEntries(local);
            try {
              if (S.legacy) {
                const body = {};
                for (const [k, c] of local) {
                  const l = LEGACY.find((x) => x.key === k);
                  if (l) body[l.field] = c === null ? l.default : c;
                }
                await api("PUT", "/admin/settings", body);
              } else {
                const send = (opts) => apiFull("PATCH", "/admin/settings", { changes }, { ifMatch: ifMatch(), ...opts });
                const texts = { title: t("admin.settings.reauth_title"), message: t("admin.settings.reauth_message") };
                const res = lastValidation?.requires_reauth ? await reauthThen("settings", send, texts) : await withStepUp("settings", send, texts);
                if (res === undefined) return false;
              }
            } catch (e) {
              const fields = errorsFromRejection(e);
              for (const c of comps) {
                const err = fields[c.el.dataset.key];
                if (err) c.update({ error: err });
              }
              clear(problem, alertCard({ tone: "danger", text: errorText(e) }));
              return false;
            }
            saved = true;
            local.clear();
            await loadSettings({ force: true }).catch(() => {});
            notify({ text: t("admin.settings.saved_short"), tone: "ok" });
            await onSaved?.();
            return true;
          },
        },
      ],
      onClose: () => {
        clearTimeout(timer);
        resolve(saved);
      },
    });
  });
}
