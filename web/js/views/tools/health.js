// Bilan de sécurité (cahier §3.3.7) : score sur 100, mots de passe à
// corriger (faibles, réutilisés, anciens, à renouveler) et action
// « Corriger » : l'éditeur s'ouvre avec un nouveau mot de passe déjà généré
// (#/element/:id/modifier?regenerer=1) et le site s'ouvre dans un nouvel
// onglet ; « Enregistrer » termine (3 clics depuis la navigation).
//
// L'analyse se fait dans le navigateur, sur les éléments déchiffrés : le
// serveur n'en sait rien. Les catégories suivent la jauge de force
// (strengthMeter) : un mot de passe est « faible » sous le seuil
// health.weak_below_score, et il est affiché avec le même mot que la jauge.
//
// Exports : computeHealth(items, opts) (aussi pour le compteur de la barre
// latérale), render(ctx).

import {
  t, plural, h, clear, icon, button, badge, statCard, statusCard, emptyState, dataTable, itemAvatar,
  strengthLevel, strengthLabel, issueText, fmtNumber,
} from "../../ui/index.js";
import { call } from "../../wasm.js";
import { api } from "../../api.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";

const DAY = 86400;

/** Estimation du noyau ; null si le module manque. */
function wasmEstimate(password) {
  try {
    const r = call("strength", { password });
    return { score: r.score, issues: r.warnings || [] };
  } catch {
    return null;
  }
}

const num = (v, fallback) => (Number.isFinite(Number(v)) && v !== null && v !== "" ? Number(v) : fallback);

/** Seuils de l'organisation (health.*), avec les valeurs du registre à défaut. */
export function healthThresholds(settings = S) {
  return {
    weakBelow: Math.min(4, Math.max(1, num(settings.effective("health.weak_below_score").value, 3))),
    maxAgeDays: Math.max(1, num(settings.effective("health.max_password_age_days").value, 365)),
  };
}

/**
 * Analyse des éléments déchiffrés (hors corbeille, mot de passe renseigné).
 * Renvoie { score, total, rows, toFix, noTotp } ; chaque ligne :
 * { item, level, weak, reusedWith, old, ageDays, expired, problems }.
 */
export function computeHealth(items, { weakBelow = 3, maxAgeDays = 365, now = Date.now() / 1000, estimate = wasmEstimate } = {}) {
  const live = [...items].filter((i) => i?.data && !i.deleted_at);
  const logins = live.filter((i) => i.data.password);
  const counts = new Map();
  for (const i of logins) counts.set(i.data.password, (counts.get(i.data.password) || 0) + 1);
  const rows = logins.map((item) => {
    const s = estimate(item.data.password) || { score: 4, issues: [] };
    const level = strengthLevel(s.score, s.issues);
    const changed = item.data.password_changed_at || item.created_at || now;
    const ageDays = Math.max(0, Math.floor((now - changed) / DAY));
    const row = {
      item,
      level,
      weak: level < weakBelow,
      reusedWith: (counts.get(item.data.password) || 1) - 1,
      old: ageDays > maxAgeDays,
      ageDays,
      expired: !!item.data.expires_at && item.data.expires_at < now,
    };
    row.problems = row.weak || row.reusedWith > 0 || row.old || row.expired;
    return row;
  });
  const toFix = rows.filter((r) => r.problems)
    .sort((a, b) => a.level - b.level || b.reusedWith - a.reusedWith || String(a.item.data.name).localeCompare(String(b.item.data.name), "fr"));
  const noTotp = live.filter((i) => i.data.kind === "login" && (i.data.urls || []).some(Boolean) && !i.data.totp);
  const score = rows.length ? Math.round((100 * (rows.length - toFix.length)) / rows.length) : 100;
  return { score, total: rows.length, rows, toFix, noTotp };
}

/** Nom d'application d'un élément : domaine de sa première adresse web, sinon son nom. */
export function appName(data) {
  const url = webUrl(data);
  if (url) return new URL(url).hostname.replace(/^www[.]/, "");
  return String(data?.name || "").trim() || "—";
}

/**
 * Part des mots de passe uniques (jamais utilisés ailleurs dans le coffre),
 * globalement et par application (regroupement par domaine).
 * Renvoie { percent, apps: [{ app, accounts, unique, percent }] } ; les
 * applications les moins uniques d'abord.
 */
export function uniqueness(rows) {
  const apps = new Map();
  for (const r of rows) {
    const key = appName(r.item.data);
    const a = apps.get(key) || { app: key, accounts: 0, unique: 0 };
    a.accounts += 1;
    if (r.reusedWith === 0) a.unique += 1;
    apps.set(key, a);
  }
  const list = [...apps.values()].map((a) => ({ ...a, percent: Math.round((100 * a.unique) / a.accounts) }))
    .sort((a, b) => a.percent - b.percent || b.accounts - a.accounts || a.app.localeCompare(b.app, "fr"));
  const unique = rows.filter((r) => r.reusedWith === 0).length;
  return { percent: rows.length ? Math.round((100 * unique) / rows.length) : 100, apps: list };
}

/** Tonalité d'une part « bonne » (0 à 100) : vert, orange ou rouge. */
export function gradePct(p) {
  return p >= 85 ? "ok" : p >= 60 ? "warn" : "danger";
}

/** Tonalité d'un nombre de problèmes rapporté au total. */
export function gradeCount(n, total) {
  if (!n) return "ok";
  return total && n / total <= 0.1 ? "warn" : "danger";
}

/** Couleur de la jauge pour un score de 0 à 100 (rouge -> orange -> vert). */
export function scoreColor(score) {
  const hue = Math.round(Math.max(0, Math.min(100, score)) * 1.3);
  return `hsl(${hue} 72% 45%)`;
}

/**
 * Jauge demi-cercle du score (SVG construit ici, sans donnée de l'utilisateur).
 * Le dégradé suit l'arc de gauche (rouge) à droite (vert) ; l'arc plein s'arrête au score.
 */
function scoreGauge(score, label) {
  const v = Math.max(0, Math.min(100, Math.round(score)));
  const len = Math.PI * 80;
  const wrap = h("div", { class: "c-gauge", role: "img", "aria-label": label });
  wrap.innerHTML = `<svg viewBox="0 0 200 116" aria-hidden="true">
  <defs><linearGradient id="jauge-degrade" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="#dc2626"/><stop offset="0.5" stop-color="#f59e0b"/><stop offset="1" stop-color="#16a34a"/>
  </linearGradient></defs>
  <path d="M20 100 A80 80 0 0 1 180 100" fill="none" class="c-gauge__track" stroke-width="16" stroke-linecap="round"/>
  <path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="url(#jauge-degrade)" stroke-width="16" stroke-linecap="round"
    stroke-dasharray="${(len * v) / 100} ${len}"/>
</svg>`;
  const value = h("strong", { class: "c-gauge__value" }, String(v));
  value.style.color = scoreColor(v);
  wrap.append(value, h("span", { class: "c-gauge__max" }, "/ 100"));
  return wrap;
}

/** Âge lisible : « 2 ans », « 8 mois ». */
function ageText(days) {
  if (days >= 365) return plural("tools.health.age_years", Math.floor(days / 365));
  return plural("tools.health.age_months", Math.max(1, Math.floor(days / 30)));
}

/** Première adresse web (http ou https) de l'élément, ou null. */
export function webUrl(data) {
  for (const raw of data?.urls || []) {
    const text = String(raw || "").trim();
    if (!text) continue;
    try {
      const u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(text) ? text : `https://${text}`);
      if (u.protocol === "https:" || u.protocol === "http:") return u.href;
    } catch { /* adresse illisible : suivante */ }
  }
  return null;
}

/** Badges des problèmes d'une ligne (le mot de la jauge pour la force). */
function problemBadges(row) {
  const out = [];
  if (row.weak) out.push(badge({ tone: row.level <= 1 ? "danger" : "warn", icon: row.level <= 1 ? "error" : "warn", label: strengthLabel(row.level) }));
  if (row.reusedWith > 0) out.push(badge({ tone: "warn", label: issueText({ code: "reused", n: row.reusedWith }) }));
  if (row.old) out.push(badge({ tone: "warn", label: issueText({ code: "old", params: { age: ageText(row.ageDays) } }) }));
  if (row.expired) out.push(badge({ tone: "warn", label: t("tools.health.issue_expired") }));
  return out;
}

/** Navigation vers une route (« /element/… ») par le routeur, ou par l'adresse. */
function go(ctx, path) {
  if (typeof ctx.navigate === "function") ctx.navigate(path);
  else location.hash = `#${path}`;
}

/** « Corriger » : ouvre le site (nouvel onglet, sans référent) puis l'éditeur. */
function fix(ctx, item) {
  const url = webUrl(item.data);
  if (url) window.open(url, "_blank", "noopener,noreferrer");
  go(ctx, `/element/${encodeURIComponent(item.id)}/modifier?regenerer=1`);
}

/** Prénom affiché dans la salutation : premier mot du nom du compte. */
function firstName() {
  return String(V.state.profile?.name || "").trim().split(" ")[0] || "";
}

export async function render(ctx, { dashboard = false } = {}) {
  const settings = ctx.settings || S;
  const report = computeHealth(V.state.items.values(), healthThresholds(settings));
  ctx.shell?.setSidebarCounts?.({ health: report.toFix.length });

  const who = dashboard ? firstName() : "";
  const heading = h("div", { class: "l-cluster", "data-justify": "between" },
    h("h1", { tabindex: "-1" }, dashboard ? (who ? t("tools.home.hello", { name: who }) : t("tools.home.hello_anon")) : t("tools.health.title")),
    report.total && !dashboard ? h("p", { class: "c-badge", "data-tone": report.score >= 85 ? "ok" : report.score >= 60 ? "warn" : "danger" },
      t("tools.health.score", { score: fmtNumber(report.score) })) : null);
  const intro = h("p", { class: "u-muted" }, t(dashboard ? "tools.home.intro" : "tools.health.intro"));
  const content = h("div", { class: "l-stack", "data-gap": "5" });
  clear(ctx.root, h("div", { class: "l-stack", "data-gap": "5" }, heading, intro, content));

  const emptyCard = () => emptyState({
    icon: "health", title: t("tools.health.empty_title"), text: t("tools.health.empty_text"),
    actions: [{ label: t("tools.health.empty_action"), href: "#/nouveau/login", variant: "primary" }],
  });
  // Bilan seul : rien à montrer sans mot de passe. Accueil : les tuiles restent affichées (à zéro).
  if (!report.total && !dashboard) {
    content.append(emptyState({
      icon: "health", title: t("tools.health.empty_title"), text: t("tools.health.empty_text"),
      actions: [{ label: t("tools.health.empty_action"), href: "#/nouveau/login", variant: "primary" }],
    }));
    return { dispose() {}, isDirty: () => false };
  }

  const th = healthThresholds(settings);
  const minLength = Math.max(1, num(settings.effective("generator.min_length").value, 12));
  const uniq = uniqueness(report.rows);
  const pct = (n) => (report.total ? Math.round((100 * n) / report.total) : 0);
  const compliant = (r) => !r.weak && String(r.item.data.password).length >= minLength;
  const months = report.total ? Math.round(report.rows.reduce((n, r) => n + r.ageDays, 0) / report.total / 30) : 0;
  const tags = new Map();
  for (const r of report.rows) for (const tag of r.item.data.tags || []) tags.set(tag, (tags.get(tag) || 0) + 1);
  const categories = [...tags].map(([name, n]) => ({ name, n })).sort((x, y) => y.n - x.n || x.name.localeCompare(y.name, "fr"));

  // Tuiles : chacune ouvre son détail sous les tuiles (filtre), si elle en a un.
  const strong = report.rows.filter((r) => !r.weak);
  const tiles = [
    { id: "tofix", value: t("common.glossary.security_score", { score: fmtNumber(report.score) }), label: plural("tools.health.to_fix", report.toFix.length), rows: report.toFix },
    { id: "all", value: report.total, label: t("tools.health.stat_all"), rows: report.rows },
    { id: "strong", value: t("tools.health.percent", { n: fmtNumber(pct(strong.length)) }), label: t("tools.health.stat_strong"), rows: strong },
    { id: "weak", value: report.total - strong.length, label: t("tools.health.stat_weak"), rows: report.rows.filter((r) => r.weak) },
    { id: "reused", value: report.rows.filter((r) => r.reusedWith > 0).length, label: t("tools.health.stat_reused"), rows: report.rows.filter((r) => r.reusedWith > 0) },
    { id: "unique", value: t("tools.health.percent", { n: fmtNumber(uniq.percent) }), label: t("tools.health.stat_unique"), apps: uniq.apps },
    { id: "age", value: plural("tools.health.age_months", months), label: t("tools.health.stat_age"), rows: [...report.rows].sort((x, y) => y.ageDays - x.ageDays) },
    { id: "old", value: report.rows.filter((r) => r.old).length, label: plural("tools.health.stat_old", th.maxAgeDays), rows: report.rows.filter((r) => r.old) },
    { id: "categories", value: categories.length, label: t("tools.health.stat_categories"), categories },
    { id: "policy", value: t("tools.health.percent", { n: fmtNumber(pct(report.rows.filter(compliant).length)) }), label: t("tools.health.stat_policy"), rows: report.rows.filter((r) => !compliant(r)), policy: true },
  ];

  const nWeak = report.total - strong.length;
  const nReused = report.rows.filter((r) => r.reusedWith > 0).length;
  const nOld = report.rows.filter((r) => r.old).length;
  const pStrong = pct(strong.length);
  const pPolicy = pct(report.rows.filter(compliant).length);
  const LOOK = {
    all: { icon: "key", hue: "#2563eb", tone: "info" },
    strong: { icon: "shield", hue: "#16a34a", tone: report.total ? gradePct(pStrong) : "neutral", bar: pStrong },
    weak: { icon: "warn", hue: "#dc2626", tone: report.total ? gradeCount(nWeak, report.total) : "neutral" },
    reused: { icon: "copy", hue: "#ea580c", tone: report.total ? gradeCount(nReused, report.total) : "neutral" },
    unique: { icon: "star", hue: "#7c3aed", tone: report.total ? gradePct(uniq.percent) : "neutral", bar: uniq.percent },
    age: { icon: "clock", hue: "#0891b2", tone: !report.total ? "neutral" : months <= 6 ? "ok" : months <= 12 ? "warn" : "danger" },
    old: { icon: "history", hue: "#d97706", tone: report.total ? gradeCount(nOld, report.total) : "neutral" },
    categories: { icon: "folder", hue: "#db2777", tone: "neutral" },
    policy: { icon: "check", hue: "#0d9488", tone: report.total ? gradePct(pPolicy) : "neutral", bar: pPolicy },
  };

  const detail = h("section", { class: "l-stack", "data-gap": "3", "aria-live": "polite" });
  let active = report.toFix.length ? "tofix" : "all";
  const tileEls = new Map();

  const rowsTable = (tile) => dataTable({
    caption: tile.label,
    rows: tile.rows,
    rowKey: (r) => r.item.id,
    rowLabel: (r) => r.item.data.name,
    columns: [
      { key: "name", label: t("tools.health.col_item"), render: (r) => h("span", { class: "l-cluster" }, itemAvatar({ item: r.item.data }), h("strong", {}, r.item.data.name)) },
      { key: "app", label: t("tools.health.col_app"), render: (r) => appName(r.item.data) },
      { key: "force", label: t("tools.health.col_strength"), render: (r) => strengthLabel(r.level) },
      { key: "age", label: t("tools.health.col_age"), render: (r) => ageText(r.ageDays) },
      { key: "problems", label: t("tools.health.col_problems"), render: (r) => h("span", { class: "l-cluster" }, problemBadges(r)) },
      {
        key: "action", label: t("tools.health.col_action"),
        render: (r) => button({
          label: t("common.glossary.fix"), icon: "edit",
          attrs: { "aria-label": t("tools.health.fix_named", { name: r.item.data.name }), "data-focus-key": `corriger:${r.item.id}` },
          onClick: () => fix(ctx, r.item),
        }),
      },
    ],
  }).el;

  const appsTable = (tile) => dataTable({
    caption: tile.label,
    rows: tile.apps,
    rowKey: (a) => a.app,
    rowLabel: (a) => a.app,
    columns: [
      { key: "app", label: t("tools.health.col_app"), render: (a) => h("strong", {}, a.app) },
      { key: "accounts", label: t("tools.health.col_accounts"), render: (a) => String(a.accounts) },
      {
        key: "unique", label: t("tools.health.col_unique"),
        render: (a) => h("span", { class: "l-cluster" },
          h("meter", { min: 0, max: 100, low: 99, high: 100, optimum: 100, value: a.percent, "aria-label": t("tools.health.unique_named", { app: a.app, n: fmtNumber(a.percent) }) }),
          h("span", {}, t("tools.health.percent", { n: fmtNumber(a.percent) }))),
      },
    ],
  }).el;

  const categoriesTable = (tile) => dataTable({
    caption: tile.label,
    rows: tile.categories,
    rowKey: (c) => c.name,
    rowLabel: (c) => c.name,
    columns: [
      { key: "name", label: t("tools.health.col_category"), render: (c) => h("strong", {}, c.name) },
      { key: "n", label: t("tools.health.col_accounts"), render: (c) => String(c.n) },
    ],
  }).el;

  const paint = () => {
    if (!report.total) {
      clear(detail, emptyCard());
      return;
    }
    const tile = tiles.find((x) => x.id === active);
    for (const [id, el] of tileEls) if (el.tagName === "BUTTON") el.setAttribute("aria-pressed", String(id === active));
    const empty = tile.rows && !tile.rows.length;
    const body = tile.apps ? appsTable(tile) : tile.categories ? categoriesTable(tile) : rowsTable(tile);
    clear(detail, h("h2", {}, tile.label),
      tile.id === "unique" ? h("p", { class: "u-muted" }, t("tools.health.apps_help")) : null,
      tile.policy ? h("p", { class: "u-muted" }, plural("tools.health.policy_help", minLength)) : null,
      empty ? statusCard({ tone: "ok", title: t("tools.health.all_good"), detail: plural("tools.health.analyzed", report.total) }) : body);
  };

  const select = (id) => () => { active = id; paint(); };
  const tileFor = (tile) => {
    const look = LOOK[tile.id];
    const has = tile.rows ? tile.rows.length > 0 : tile.apps ? tile.apps.length > 0 : tile.categories.length > 0;
    const click = report.total && has;
    const icn = h("span", { class: "c-stat__icon" }, icon(look.icon));
    icn.style.setProperty("--hue", look.hue);
    const bar = typeof look.bar === "number" ? h("span", { class: "c-stat__bar" }, h("span", {})) : null;
    if (bar) bar.firstChild.style.inlineSize = `${Math.max(0, Math.min(100, look.bar))}%`;
    const el = h(click ? "button" : "div", {
      class: "c-stat c-stat--metric", "data-tone": look.tone,
      ...(click ? { type: "button", "aria-pressed": "false", onclick: select(tile.id) } : {}),
    },
    h("span", { class: "c-stat__head" }, icn, h("span", { class: "c-stat__label" }, tile.label)),
    h("span", { class: "c-stat__value" }, typeof tile.value === "number" ? fmtNumber(tile.value) : tile.value),
    bar);
    tileEls.set(tile.id, el);
    return el;
  };
  const scoreTile = tiles.find((x) => x.id === "tofix");
  const scoreLabel = t("tools.health.score", { score: fmtNumber(report.score) });
  const hero = h(report.total ? "button" : "div", {
    class: "c-stat c-stat--hero", "data-tone": report.total ? gradePct(report.score) : "neutral",
    ...(report.total ? { type: "button", "aria-pressed": "false", onclick: select("tofix") } : {}),
  },
  h("span", { class: "c-stat__label" }, t("tools.health.stat_score")),
  scoreGauge(report.total ? report.score : 0, scoreLabel),
  h("span", { class: "c-stat__hint" }, report.total ? plural("tools.health.to_fix", report.toFix.length) : t("tools.health.empty_title")));
  tileEls.set("tofix", hero);
  content.append(h("div", { class: "c-dash" }, hero, h("div", { class: "c-dash__tiles" }, tiles.filter((x) => x.id !== "tofix").map(tileFor))), detail);
  paint();

  if (report.noTotp.length) {
    content.append(h("details", { class: "c-card" },
      h("summary", {}, plural("tools.health.no_totp", report.noTotp.length)),
      h("p", { class: "u-muted" }, t("tools.health.no_totp_help")),
      h("ul", { class: "l-stack", "data-gap": "2" }, report.noTotp.map((i) => h("li", {},
        h("a", { href: `#/element/${encodeURIComponent(i.id)}` }, i.data.name))))));
  }

  // Liens sécurisés actifs : compteur indicatif, la page Liens envoyés fait foi.
  const links = h("div", {});
  content.append(links);
  api("GET", "/shares").then((list) => {
    const n = Array.isArray(list) ? list.length : 0;
    if (!n || !links.isConnected) return;
    links.append(h("details", { class: "c-card" },
      h("summary", {}, plural("tools.health.active_links", n)),
      h("p", { class: "u-muted" }, t("tools.health.active_links_help")),
      h("a", { href: "#/liens" }, t("tools.health.active_links_open"))));
  }).catch(() => { /* compteur facultatif : la page Liens envoyés affiche l'erreur */ });

  return { dispose() {}, isDirty: () => false };
}
