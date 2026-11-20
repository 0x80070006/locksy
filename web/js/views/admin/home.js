// Administration › Accueil (cahier §3.4.2) :
//   - « Mise en service · N étapes sur 7 » : progression DÉDUITE de l'état réel
//     (GET /admin/stats, champ setup), prochaine étape et son action ;
//   - « À traiter » : une alerte par sujet, chacune avec UNE action (liste
//     filtrée des personnes, ou réglage en contexte dans un panneau : même
//     settingField, impact de /validate, même PATCH If-Match) ;
//   - « En chiffres » : cartes cliquables vers la liste filtrée ; taux de double
//     authentification calculé sur les comptes ACTIFS, avec numérateur et
//     dénominateur ;
//   - « État du service » et « Activité récente ».
// Repli : serveur dont /admin/stats ne porte que les champs historiques
// (pas de mise en service, alertes réduites à ce qui se calcule).

import {
  t, plural, h, clear, icon, button, statCard, statusCard, skeleton, errorState, relTime, fmtNumber, fmtDate,
  settingLabel, has,
} from "../../ui/index.js";
import { api } from "../../api.js";
import { me } from "./shell.js";

/** Étapes de mise en service, dans l'ordre d'affichage ; `optional` : ne bloque pas. */
const SETUP_STEPS = Object.freeze([
  { id: "twofa_self", href: "#/parametres/compte" },
  { id: "second_owner", href: "#/admin/personnes?role=admin" },
  { id: "login_method_chosen", href: "#/admin/connexion" },
  { id: "profile_chosen", href: "#/admin/reglages/login" },
  { id: "invites_sent", invite: true },
  { id: "extension_seen", href: "#/admin/reglages/clients" },
  { id: "siem_configured", href: "#/admin/journal", optional: true },
]);

const DAY = 86400;
/** Masquage de la mise en service pour la durée de la session (aucun stockage local). */
let setupHidden = false;

export async function renderPage(ctx, container) {
  let disposed = false;
  const body = h("div", { class: "l-stack", "data-gap": "5" }, skeleton({ lines: 8 }));
  clear(container, h("h1", { tabindex: "-1" }, t("admin.home.title")), body);

  const load = async () => {
    let stats;
    try {
      stats = await api("GET", "/admin/stats");
    } catch (e) {
      if (!disposed) clear(body, errorState({ error: e, onRetry: load }));
      return;
    }
    const since = Math.floor(Date.now() / 1000) - 7 * DAY;
    const [settings, events, lowered, health] = await Promise.all([
      api("GET", "/admin/settings").catch(() => null),
      api("GET", "/admin/audit?limit=8").catch(() => null),
      api("GET", `/admin/audit?action=settings.lowered&type=settings.lowered&from=${since}&limit=5`).catch(() => null),
      ctx.health ? Promise.resolve(ctx.health) : api("GET", "/health").catch(() => null),
    ]);
    if (disposed) return;
    const reload = () => load();
    clear(body,
      setupCard(ctx, stats, reload),
      todoSection(ctx, stats, settings, lowered, reload),
      figures(stats),
      serviceSection(stats, health),
      await recentActivity(events));
  };
  await load();
  return {
    dispose() {
      disposed = true;
    },
    isDirty: () => false,
  };
}

// ------------------------------------------------------------------ Mise en service

function setupCard(ctx, stats, reload) {
  const setup = stats.setup;
  if (!setup || setupHidden) return null;
  const required = SETUP_STEPS.filter((s) => !s.optional);
  const done = required.filter((s) => setup[s.id]).length;
  const next = SETUP_STEPS.find((s) => !setup[s.id]);
  if (!next) return null;
  const section = h("section", { class: "c-card l-stack", "data-gap": "3", "aria-labelledby": "accueil-mise-en-service" });
  const action = next.invite
    ? button({ label: t("admin.home.setup.action.invites_sent"), variant: "primary", icon: "plus", onClick: () => invite(ctx, reload) })
    : h("a", { class: "c-button c-button--primary", href: next.href }, t(`admin.home.setup.action.${next.id}`));
  clear(section,
    h("div", { class: "l-cluster", "data-justify": "between" },
      h("h2", { id: "accueil-mise-en-service" }, t("admin.home.setup.title", { done, total: required.length })),
      button({ label: t("admin.home.setup.hide"), variant: "quiet", onClick: () => { setupHidden = true; section.remove(); } })),
    h("ul", { class: "l-grid" }, SETUP_STEPS.map((s) => h("li", { class: "l-cluster" },
      icon(setup[s.id] ? "check" : "clock", { size: "sm" }),
      h("span", { class: "u-sr-only" }, setup[s.id] ? t("admin.home.setup.done") : t("admin.home.setup.todo")),
      h("span", {}, t(`admin.home.setup.step.${s.id}`)),
      s.optional ? h("span", { class: "u-muted" }, t("admin.home.setup.optional")) : null))),
    h("div", { class: "l-cluster", "data-justify": "between" },
      h("p", {}, t("admin.home.setup.next", { step: t(`admin.home.setup.step.${next.id}`) })),
      action));
  return section;
}

async function invite(ctx, reload) {
  const { openInviteDialog } = await import("./invite.js");
  await openInviteDialog(ctx, { onDone: reload });
}

// ------------------------------------------------------------------ À traiter

/** Alerte avec une ou plusieurs actions (liens ou boutons). */
function todo(tone, text, actions) {
  return h("li", { class: "c-alert", "data-tone": tone },
    icon(tone === "danger" ? "error" : tone === "warn" ? "warn" : "info"),
    h("div", { class: "l-cluster", "data-justify": "between" },
      h("p", {}, text),
      h("div", { class: "l-cluster" }, actions.filter(Boolean).map((a) => (a.href
        ? h("a", { class: "c-button", href: a.href }, a.label)
        : button({ label: a.label, onClick: a.onClick }))))));
}

/** Réglage en contexte (panneau), puis rechargement de l'Accueil s'il a été enregistré. */
function settingAction(ctx, label, keys, reload, intro) {
  return {
    label,
    onClick: async () => {
      const { openSettingPanel } = await import("./settings.js");
      if (await openSettingPanel(ctx, keys, { title: label, intro })) await reload();
    },
  };
}

function todoSection(ctx, s, settings, lowered, reload) {
  const items = [];
  const self = me(ctx).id;
  for (const e of (lowered?.entries || []).filter((x) => x.action === "settings.lowered" && x.user_id !== self).slice(0, 1)) {
    items.push(todo("danger", t("admin.home.todo.lowered", { who: e.email || t("audit.who.system"), when: relTime(e.at) }),
      [{ label: t("admin.home.todo.see_history"), href: "#/admin/reglages/historique" }]));
  }
  if (Number(s.admins_without_2fa) > 0) {
    items.push(todo("warn", plural("admin.home.todo.admins_without_2fa", s.admins_without_2fa),
      [{ label: t("admin.home.todo.see"), href: "#/admin/personnes?role=admin&2fa=non&etat=actif" }]));
  }
  const active = Number(s.active_users) || 0;
  const with2fa = Number(s.active_with_2fa ?? s.users_with_2fa) || 0;
  const twofaRequired = settings?.values?.["twofa.required"]?.value === true;
  if (active > with2fa && !twofaRequired) {
    items.push(todo("warn", plural("admin.home.todo.without_2fa", active - with2fa),
      [settingAction(ctx, t("admin.home.todo.require_2fa"), ["twofa.required", "twofa.required_roles", "twofa.grace_days"], reload, t("admin.home.todo.require_2fa_intro"))]));
  }
  if (Number(s.expired_invites) > 0) {
    items.push(todo("warn", plural("admin.home.todo.expired_invites", s.expired_invites),
      [{ label: t("admin.home.todo.see"), href: "#/admin/personnes?etat=invitation_expiree" }]));
  }
  if (Number(s.owners) === 1) {
    items.push(todo("warn", t("admin.home.todo.single_owner"),
      [{ label: t("admin.home.todo.name_owner"), href: "#/admin/personnes?role=admin" }]));
  }
  if (Number(s.inactive_users) > 0) {
    const days = settings?.values?.["users.inactive_alert_days"]?.value ?? 90;
    items.push(todo("info", plural("admin.home.todo.inactive", s.inactive_users, { days }),
      [{ label: t("admin.home.todo.see"), href: "#/admin/personnes?etat=inactif" },
        settingAction(ctx, t("admin.home.todo.change_threshold"), ["users.inactive_alert_days", "users.disable_after_inactive_days"], reload)]));
  }
  if (Number(s.pending_deprovision) > 0) {
    items.push(todo("info", plural("admin.home.todo.pending_deprovision", s.pending_deprovision),
      [{ label: t("admin.home.todo.see"), href: "#/admin/personnes?etat=suppression_programmee" }]));
  }
  for (const w of settings?.warnings || []) {
    const text = has(`settings.warning.${w.code}`) ? t(`settings.warning.${w.code}`, w.params || {}) : t("admin.settings.warning_generic");
    items.push(todo(w.code === "read_error" ? "danger" : "info", t("admin.home.todo.setting_warning", { label: settingLabel(w.key), text }),
      [settingAction(ctx, t("admin.home.todo.change_setting"), [w.key], reload)]));
  }
  return h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "accueil-a-traiter" },
    h("h2", { id: "accueil-a-traiter" }, t("admin.home.todo.title")),
    items.length
      ? h("ul", { class: "l-stack", "data-gap": "2" }, items)
      : h("p", { class: "l-cluster" }, icon("check"), t("admin.home.todo.none")));
}

// ------------------------------------------------------------------ En chiffres

function figures(s) {
  const active = Number(s.active_users) || 0;
  const with2fa = Math.min(active, Number(s.active_with_2fa ?? s.users_with_2fa) || 0);
  const pct = active ? Math.round((100 * with2fa) / active) : 0;
  const cards = [
    statCard({ value: active, label: plural("admin.home.figures.active", active), href: "#/admin/personnes?etat=actif" }),
    statCard({
      value: t("admin.home.figures.percent", { pct: fmtNumber(pct) }),
      label: t("admin.home.figures.twofa", { n: fmtNumber(with2fa), total: fmtNumber(active) }),
      href: "#/admin/personnes?etat=actif&2fa=non",
      tone: pct >= 90 ? "ok" : pct >= 50 ? "warn" : "danger",
    }),
    s.inactive_users !== undefined
      ? statCard({ value: Number(s.inactive_users) || 0, label: plural("admin.home.figures.inactive", Number(s.inactive_users) || 0), href: "#/admin/personnes?etat=inactif" })
      : null,
    s.pending_invites !== undefined
      ? statCard({ value: Number(s.pending_invites) || 0, label: plural("admin.home.figures.invites", Number(s.pending_invites) || 0), href: "#/admin/personnes?etat=invite" })
      : null,
    statCard({ value: Number(s.active_share_links ?? s.active_shares) || 0, label: plural("admin.home.figures.links", Number(s.active_share_links ?? s.active_shares) || 0) }),
    s.failed_logins_24h !== undefined
      ? statCard({ value: Number(s.failed_logins_24h) || 0, label: plural("admin.home.figures.failed_logins", Number(s.failed_logins_24h) || 0), href: "#/admin/journal?type=login&periode=jour" })
      : null,
  ];
  return h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "accueil-chiffres" },
    h("h2", { id: "accueil-chiffres" }, t("admin.home.figures.title")),
    h("div", { class: "l-grid" }, cards));
}

// ------------------------------------------------------------------ État du service

function serviceSection(s, health) {
  const sync = s.last_ldap_sync;
  const cards = [
    statusCard({ tone: health ? "ok" : "neutral", title: health?.version ? t("admin.home.service.server", { version: health.version }) : t("admin.home.service.server_unknown"), action: { label: t("admin.home.service.details"), href: "#/admin/reglages/systeme" } }),
    s.last_backup_at
      ? statusCard({ tone: Date.now() / 1000 - s.last_backup_at > 2 * DAY ? "warn" : "ok", title: t("admin.home.service.backup", { when: relTime(s.last_backup_at) }) })
      : null,
    sync
      ? statusCard({
        tone: sync.ok ? "ok" : "danger",
        title: sync.ok ? plural("admin.home.service.ldap_ok", Number(sync.found) || 0, { when: relTime(sync.at) }) : t("admin.home.service.ldap_failed", { when: relTime(sync.at) }),
        action: { label: t("admin.home.service.see"), href: "#/admin/connexion" },
      })
      : null,
    s.scim_last_used_at ? statusCard({ tone: "ok", title: t("admin.home.service.scim", { when: relTime(s.scim_last_used_at) }) }) : null,
    s.setup
      ? statusCard({
        tone: s.setup.siem_configured ? "ok" : "neutral",
        title: s.setup.siem_configured ? t("admin.home.service.siem_on") : t("admin.home.service.siem_off"),
        action: s.setup.siem_configured ? null : { label: t("admin.home.service.configure"), href: "#/admin/journal" },
      })
      : null,
  ];
  return h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "accueil-service" },
    h("h2", { id: "accueil-service" }, t("admin.home.service.title")),
    h("div", { class: "l-grid" }, cards));
}

// ------------------------------------------------------------------ Activité récente

async function recentActivity(page) {
  const { eventSentence, severityBadge, severityOf, loadNames } = await import("./journal.js");
  await loadNames();
  const entries = page?.entries || [];
  return h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "accueil-activite" },
    h("div", { class: "l-cluster", "data-justify": "between" },
      h("h2", { id: "accueil-activite" }, t("admin.home.activity.title")),
      h("a", { href: "#/admin/journal" }, t("admin.home.activity.all"))),
    entries.length
      ? h("ul", { class: "l-stack", "data-gap": "2" }, entries.map((e) => h("li", { class: "l-cluster" },
        h("span", { class: "u-muted u-nowrap", title: fmtDate(e.at, "long") }, relTime(e.at)),
        h("span", {}, eventSentence(e)),
        severityOf(e) !== "info" ? severityBadge(severityOf(e)) : null)))
      : h("p", { class: "u-muted" }, page ? t("audit.empty") : t("admin.home.activity.unavailable")));
}
