// Journal (cahier §3.4.8, audit 02 §5.6 et annexe A) : une phrase par
// événement (« Hugo Martin : connexion refusée (Chrome sur Windows) »),
// gravité en badge ET en texte, filtres dans l'adresse (période, personne,
// type, gravité, recherche), détail en panneau latéral avec « Détails
// techniques » (code d'événement, identifiants, adresse IP complète), export
// CSV avec les mêmes filtres, sous-section « Transfert vers le SIEM ».
//
// Libellés : audit.event.<action> (design/i18n/fr/audit.json) ; une action
// inconnue devient « Événement technique » (code dans « Détails techniques »).
// Serveur plus ancien (sans gravité ni curseur) : gravité calculée ici avec
// la même table que le serveur (admin_api::SEVERITY_RULES), pages par décalage.
//
// Exports : renderPage, eventText, eventSentence, severityOf, severityBadge,
// loadNames.

import {
  t, plural, has, h, clear, button, badge, dataTable, filterBar, searchBox, panel, notify,
  fmtDate, relTime, errorText, technicalDetails, skeleton, errorState, statusCard, field, textInput,
} from "../../ui/index.js";
import { api, download } from "../../api.js";
import { setQuery } from "./shell.js";

const PAGE_SIZE = 50;
const DAY = 86400;

/**
 * Gravités pour un serveur qui ne les renvoie pas encore : même table que
 * admin_api::SEVERITY_RULES ([action ou préfixe « x. », gravité]) ; les deux
 * règles qui dépendent du motif de l'événement sont dans motiveSeverity().
 */
const SEVERITY_RULES = Object.freeze([
  ["settings.lowered", "critical"], ["admin.user_role", "critical"], ["audit.verify_failed", "critical"],
  ["ldap.sync_refused", "critical"], ["sso.discovery_blocked", "critical"],
  ["login.failed", "warning"], ["login.locked", "warning"], ["login.refused", "warning"], ["ldap.login_failed", "warning"],
  ["recovery.", "warning"], ["2fa.recovery_code_used", "warning"], ["admin.user_disabled", "warning"],
  ["admin.user_deleted", "warning"], ["admin.2fa_reset", "warning"], ["admin.user_offboarded", "warning"],
  ["admin.sessions_revoked", "warning"], ["admin.shares_revoked", "warning"],
  ["mail.failed", "warning"], ["sso.denied", "warning"],
]);

/** Règles de admin_api::SEVERITY_RULES qui dépendent du motif (details). */
function motiveSeverity(action, details) {
  if (action === "2fa.disabled" && details === "imposée") return "critical";
  if (action === "share.ended" && details === "revoked_admin") return "warning";
  return null;
}

const SEVERITY_TONE = Object.freeze({ info: "info", warning: "warn", critical: "danger" });
const SEVERITY_ICON = Object.freeze({ info: "info", warning: "warn", critical: "error" });

/** Familles d'événements du filtre « Type » (préfixe d'action). */
const TYPES = Object.freeze(["login", "2fa", "recovery", "session", "item", "collection", "share", "attachment",
  "admin", "settings", "sso", "ldap", "scim", "directory", "mail", "audit"]);
const PERIODS = Object.freeze(["tout", "jour", "7j", "30j", "dates"]);
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const LEVELS = Object.freeze(["info", "warning", "critical"]);

/** Gravité d'un événement : celle du serveur, sinon la table locale. */
export function severityOf(entry) {
  if (LEVELS.includes(entry?.severity)) return entry.severity;
  const action = String(entry?.action || "");
  const byMotive = motiveSeverity(action, String(entry?.details || ""));
  if (byMotive) return byMotive;
  for (const [rule, level] of SEVERITY_RULES) {
    if (rule.endsWith(".") ? action.startsWith(rule) : action === rule) return level;
  }
  return "info";
}

/** Badge de gravité (icône + texte, jamais la seule couleur). */
export function severityBadge(level) {
  const l = LEVELS.includes(level) ? level : "info";
  return badge({ tone: SEVERITY_TONE[l], icon: SEVERITY_ICON[l], label: t(`audit.severity.${l}`) });
}

/** Libellé d'une action (« connexion refusée »), ou « Événement technique ». */
export function eventText(action) {
  return has(`audit.event.${action}`) ? t(`audit.event.${action}`) : t("audit.event_unknown");
}

/** « Chrome sur Windows » depuis l'agent utilisateur (texte vide si inconnu). */
function deviceText(ua = "") {
  const s = String(ua);
  if (!s) return "";
  if (/locksy-desktop|Locksy\/.*Windows/i.test(s)) return t("audit.device.desktop");
  if (/locksy-server/i.test(s)) return t("audit.device.server");
  const browser = /Edg\//.test(s) ? "edge" : /Firefox\//.test(s) ? "firefox" : /Chrome\//.test(s) ? "chrome" : /Safari\//.test(s) ? "safari" : null;
  const os = /Windows/.test(s) ? "windows" : /Android/.test(s) ? "android" : /iPhone|iPad|iOS/.test(s) ? "ios"
    : /Mac OS X|Macintosh/.test(s) ? "macos" : /Linux/.test(s) ? "linux" : null;
  if (browser && os) return t("audit.device.browser_on_os", { browser: t(`audit.device.browser.${browser}`), os: t(`audit.device.os.${os}`) });
  if (browser) return t(`audit.device.browser.${browser}`);
  return t("audit.device.other");
}

let names = null;

/** Noms des comptes (id -> nom) pour écrire « Hugo Martin » plutôt que l'adresse. */
export async function loadNames() {
  if (names) return names;
  try {
    const list = await api("GET", "/admin/users");
    names = new Map((Array.isArray(list) ? list : []).map((u) => [u.id, u.name || u.email]));
  } catch {
    names = new Map();
  }
  return names;
}

/** Auteur d'un événement : nom, sinon adresse, sinon « Locksy » (action automatique). */
function who(entry) {
  return (entry.user_id && names?.get(entry.user_id)) || entry.email || t("audit.who.system");
}

/** Phrase d'un événement : « Hugo Martin : connexion refusée (Chrome sur Windows) ». */
export function eventSentence(entry, { withDevice = true } = {}) {
  const device = withDevice ? deviceText(entry.user_agent) : "";
  const text = t("audit.sentence", { who: who(entry), what: eventText(entry.action) });
  return device ? t("audit.sentence_device", { sentence: text, device }) : text;
}

// ------------------------------------------------------------------ Filtres

function readFilters(query) {
  const q = query || new URLSearchParams();
  return {
    periode: PERIODS.includes(q.get("periode")) ? q.get("periode") : "tout",
    type: TYPES.includes(q.get("type")) ? q.get("type") : "",
    gravite: LEVELS.includes(q.get("gravite")) ? q.get("gravite") : "",
    personne: q.get("personne") || "",
    q: q.get("q") || "",
    du: DATE_RE.test(q.get("du") || "") ? q.get("du") : "",
    au: DATE_RE.test(q.get("au") || "") ? q.get("au") : "",
  };
}

/** Paramètres de l'API (journal et export CSV) pour des filtres. */
function auditParams(f, now = Math.floor(Date.now() / 1000)) {
  const p = new URLSearchParams();
  if (f.q) p.set("q", f.q);
  if (f.type) {
    p.set("type", `${f.type}.`);
    p.set("action", f.type);
  }
  if (f.gravite) p.set("severity", f.gravite);
  if (f.personne) p.set("actor", f.personne);
  if (f.periode === "dates") {
    const from = dayStart(f.du);
    const to = dayStart(f.au);
    if (from !== null) p.set("from", String(from));
    if (to !== null) p.set("to", String(to + DAY - 1));
    return p;
  }
  const today = new Date(now * 1000);
  today.setHours(0, 0, 0, 0);
  const midnight = Math.floor(today.getTime() / 1000);
  const start = { jour: midnight, "7j": now - 7 * DAY, "30j": now - 30 * DAY }[f.periode];
  if (start) p.set("from", String(start));
  return p;
}

/** Début d'une journée locale (AAAA-MM-JJ) en horodatage Unix, ou null. */
function dayStart(value) {
  if (!DATE_RE.test(value || "")) return null;
  const d = new Date(`${value}T00:00:00`);
  return Number.isNaN(d.getTime()) ? null : Math.floor(d.getTime() / 1000);
}

// ------------------------------------------------------------------ Écran

export async function renderPage(ctx, container) {
  let filters = readFilters(ctx.query);
  let entries = [];
  let cursor = null;
  let total = 0;
  let disposed = false;

  const result = h("div", { class: "l-stack", "data-gap": "3" }, skeleton({ lines: 6 }));
  const table = dataTable({
    caption: t("audit.table.caption"),
    columns: [
      { key: "event", label: t("audit.table.event"), render: (e) => eventSentence(e) },
      { key: "severity", label: t("audit.table.severity"), render: (e) => severityBadge(severityOf(e)) },
      { key: "at", label: t("audit.table.date"), render: (e) => h("span", { class: "u-nowrap", title: fmtDate(e.at, "long") }, fmtDate(e.at)) },
    ],
    rows: [],
    rowKey: (e) => e.id,
    rowLabel: (e) => eventSentence(e, { withDevice: false }),
    onRowOpen: (e) => openDetail(e, (actor) => {
      filters.personne = actor;
      person.value = actor;
      sync();
      load();
    }),
    empty: t("audit.empty"),
  });
  const counter = h("p", { class: "u-muted" });
  const more = h("div", {});

  const sync = () => setQuery(ctx, {
    periode: filters.periode === "tout" ? null : filters.periode,
    type: filters.type || null, gravite: filters.gravite || null, personne: filters.personne || null, q: filters.q || null,
    du: filters.periode === "dates" ? filters.du || null : null, au: filters.periode === "dates" ? filters.au || null : null,
  });

  const load = async ({ append = false } = {}) => {
    const p = auditParams(filters);
    p.set("limit", String(PAGE_SIZE));
    // Page suivante : curseur du serveur, sinon décalage (serveur plus ancien).
    if (append && cursor !== null) p.set("before_id", String(cursor));
    else if (append) p.set("offset", String(entries.length));
    try {
      await loadNames();
      const page = await api("GET", `/admin/audit?${p}`);
      if (disposed) return;
      let rows = page.entries || [];
      // Serveur sans filtre de gravité : filtrage ici.
      if (filters.gravite && rows.some((e) => !e.severity)) rows = rows.filter((e) => severityOf(e) === filters.gravite);
      entries = append ? [...entries, ...rows] : rows;
      cursor = page.next_cursor ?? null;
      total = Number(page.total) || entries.length;
      table.update({ rows: entries, loading: false });
      counter.textContent = plural("audit.count", total);
      const hasMore = page.next_cursor != null || (page.next_cursor === undefined && entries.length < total && rows.length === PAGE_SIZE);
      clear(more, hasMore ? button({ label: t("audit.more"), icon: "chevron-down", onClick: () => load({ append: true }) }) : null);
      clear(result, counter, table.el, more);
    } catch (e) {
      if (!disposed) clear(result, errorState({ error: e, onRetry: () => load() }));
    }
  };

  const filtersBar = filterBar({
    label: t("audit.filters.label"),
    filters: [
      { key: "periode", label: t("audit.filters.period"), options: PERIODS.map((v) => ({ value: v, label: t(`audit.period.${v}`) })) },
      { key: "type", label: t("audit.filters.type"), options: [{ value: "", label: t("audit.type.all") }, ...TYPES.map((v) => ({ value: v, label: t(`audit.type.${v}`) }))] },
      { key: "gravite", label: t("audit.filters.severity"), options: [{ value: "", label: t("audit.severity.all") }, ...LEVELS.map((v) => ({ value: v, label: t(`audit.severity.${v}`) }))] },
    ],
    values: filters,
    syncUrl: false,
    onChange: (v) => {
      filters = { ...filters, ...v };
      dates.hidden = filters.periode !== "dates";
      sync();
      load();
    },
  });
  const dateInput = (name) => {
    const input = textInput({ type: "date", value: filters[name] });
    input.addEventListener("change", () => {
      filters[name] = input.value;
      sync();
      load();
    });
    return input;
  };
  const dates = h("div", { class: "l-cluster", hidden: filters.periode !== "dates" },
    field({ label: t("audit.filters.from"), input: dateInput("du") }),
    field({ label: t("audit.filters.to"), input: dateInput("au") }));
  const search = searchBox({
    label: t("audit.search_label"), placeholderKey: "audit.search_placeholder", value: filters.q, shortcut: "", delay: 300,
    onInput: (_n, raw) => {
      filters.q = raw.trim();
      sync();
      load();
    },
  });
  const person = textInput({ type: "search", value: filters.personne, autocomplete: "off" });
  person.addEventListener("change", () => {
    filters.personne = person.value.trim();
    sync();
    load();
  });

  const exportBtn = button({
    label: t("audit.export"), icon: "download", busyLabel: t("audit.exporting"),
    onClick: async () => {
      try {
        await download(`/admin/audit.csv?${auditParams(filters)}`, `locksy-journal-${new Date().toISOString().slice(0, 10)}.csv`);
        notify({ text: t("audit.exported"), tone: "ok" });
      } catch (e) {
        notify({ text: errorText(e), tone: "danger" });
      }
    },
  });

  const siem = h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "journal-siem" });

  clear(container,
    h("div", { class: "l-cluster", "data-justify": "between" }, h("h1", { tabindex: "-1" }, t("audit.title")), exportBtn),
    h("p", { class: "u-muted" }, t("audit.intro")),
    h("div", { class: "l-cluster" }, search, field({ label: t("audit.filters.person"), help: t("audit.filters.person_help"), input: person })),
    filtersBar.el,
    dates,
    result,
    siem);
  renderSiem(ctx, siem);
  await load();
  return {
    dispose() {
      disposed = true;
    },
    isDirty: () => false,
  };
}

/** Panneau de détail d'un événement ; onPerson(acteur) filtre le journal sur son auteur. */
function openDetail(e, onPerson) {
  const level = severityOf(e);
  const device = deviceText(e.user_agent);
  const row = (label, value) => (value ? [h("dt", {}, h("strong", {}, label)), h("dd", {}, value)] : []);
  panel({
    title: eventText(e.action),
    body: h("div", { class: "l-stack", "data-gap": "3" },
      h("p", {}, eventSentence(e)),
      h("dl", { class: "l-stack", "data-gap": "1" },
        row(t("audit.detail.when"), `${fmtDate(e.at, "long")} (${relTime(e.at)})`),
        row(t("audit.detail.who"), who(e)),
        row(t("audit.detail.severity"), severityBadge(level)),
        row(t("audit.detail.device"), device)),
      technicalDetails({
        body: h("dl", {},
          row(t("audit.detail.code"), e.action),
          row(t("audit.detail.target"), e.target),
          row(t("audit.detail.details"), e.details),
          row(t("audit.detail.account"), e.user_id),
          row(t("audit.detail.email"), e.email),
          row(t("audit.detail.ip"), e.ip),
          row(t("audit.detail.agent"), e.user_agent),
          row(t("audit.detail.id"), String(e.id))),
      })),
    actions: [
      e.email || e.user_id ? { label: t("audit.detail.same_person"), icon: "filter", onClick: () => onPerson?.(e.email || e.user_id) } : null,
      { label: t("common.action.close"), cancel: true },
    ],
  });
}

/** Sous-section « Transfert vers le SIEM » : état et réglages audit.syslog.* en contexte. */
async function renderSiem(ctx, container) {
  const paint = async () => {
    let url = "";
    let format = "";
    try {
      const { loadSettings, settingsStore } = await import("./settings.js");
      await loadSettings({ force: true });
      url = settingsStore.values?.values?.["audit.syslog.url"]?.value || "";
      format = settingsStore.values?.values?.["audit.syslog.format"]?.value || "";
    } catch {
      /* réglages illisibles : l'état reste « non configuré » */
    }
    const configure = {
      label: url ? t("audit.siem.change") : t("audit.siem.configure"),
      onClick: async () => {
        const { openSettingPanel } = await import("./settings.js");
        if (await openSettingPanel(ctx, ["audit.syslog.url", "audit.syslog.format", "audit.csv_separator"], { title: t("audit.siem.title"), intro: t("audit.siem.intro") })) paint();
      },
    };
    clear(container,
      h("h2", { id: "journal-siem" }, t("audit.siem.title")),
      h("p", { class: "u-muted" }, t("audit.siem.intro")),
      statusCard({
        tone: url ? "ok" : "neutral",
        title: url ? t("audit.siem.on") : t("audit.siem.off"),
        detail: url ? t("audit.siem.on_detail", { format: has(`settings.audit.syslog.format.value.${format}`) ? t(`settings.audit.syslog.format.value.${format}`) : format }) : t("audit.siem.off_detail"),
        action: configure,
      }),
      url ? technicalDetails({ body: url }) : null);
  };
  clear(container, skeleton({ lines: 2 }));
  await paint();
}

