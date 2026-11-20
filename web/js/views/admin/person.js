// Fiche d'une personne, en panneau latéral (cahier §3.4.4, contrat C1.1) :
// adresse, origine, état, rôle avec « Changer le rôle… », double
// authentification ; onglets Sessions (avec « Fermer »), Coffres
// (métadonnées seulement : le nom d'un coffre est chiffré, l'administration
// ne le lit jamais ; badge « Seul gestionnaire »), Activité, Sécurité ;
// « Déconnecter partout », « Réinitialiser la double authentification »,
// « Départ de l'entreprise… » ; menu ⋯ : Modifier, Désactiver / Réactiver,
// Révoquer ses liens sécurisés, Supprimer, Rapport d'accès (CSV).
// Invitations : panneau court (renvoyer, copier le lien, révoquer).
//
// Exports : openPerson, openInvite, userMenuItems, inviteMenuItems (menus ⋯
// de la liste), statusText, originText.
// Repli : serveur sans GET /admin/users/:id -> fiche réduite depuis la liste.

import {
  t, plural, has, h, clear, button, menuButton, panel, tabs, dialog, confirm, notify, badge, field, textInput,
  alertCard, skeleton, errorText, relTime, fmtDate, fmtNumber, copySecret,
} from "../../ui/index.js";
import { api, download } from "../../api.js";
import {
  dateInputToTs, dateOrNone, go, isOwner, me, personName, reauthThen, roleLabel, routeMissing, tsToDateInput, withStepUp,
} from "./shell.js";
import { openRoleDialog } from "./role-dialog.js";

/** Origine d'un compte : « Active Directory », « Invitation »… */
export const originText = (origin) => (has(`admin.people.origin.${origin}`) ? t(`admin.people.origin.${origin}`) : t("admin.people.origin.local"));

/** État d'une ligne (compte ou invitation), en clair. */
export function statusText(row) {
  const s = row?.status || "active";
  if (s === "invited") return t("admin.people.status.invited_until", { when: relTime(row.expires_at) });
  if (s === "pending_deprovision" && row.deprovision_at) return t("admin.people.status.pending_deprovision_at", { date: fmtDate(row.deprovision_at, "date") });
  if (s === "expired" && row.access_until) return t("admin.people.status.expired_at", { date: fmtDate(row.access_until, "date") });
  return has(`admin.people.status.${s}`) ? t(`admin.people.status.${s}`) : t("admin.people.status.active");
}

const isSelf = (ctx, row) => row?.is_self === true || row?.id === me(ctx).id;
/** Un administrateur non propriétaire ne gère pas un propriétaire. */
const canManage = (ctx, row) => !isSelf(ctx, row) && (isOwner(ctx) || row?.role !== "owner");

// ------------------------------------------------------------------ Actions unitaires

const personActions = {
  /** Ferme toutes les sessions d'une personne. */
  async revokeSessions(row) {
    await api("POST", `/admin/users/${encodeURIComponent(row.id)}/revoke-sessions`);
    notify({ text: t("admin.person.sessions_closed", { name: personName(row) }), tone: "ok" });
    return true;
  },

  /** Désactive (confirmation de niveau 1) ou réactive un compte. */
  async setDisabled(row, disabled) {
    if (disabled) {
      const ok = await confirm({
        level: 1, title: t("admin.person.disable_title", { name: personName(row) }),
        message: t("admin.person.disable_text"), confirmLabel: t("admin.person.disable"), danger: true,
      });
      if (!ok.confirmed) return false;
    }
    await api("PUT", `/admin/users/${encodeURIComponent(row.id)}`, { disabled });
    notify({ text: t(disabled ? "admin.person.disabled_done" : "admin.person.enabled_done", { name: personName(row) }), tone: "ok" });
    return true;
  },

  /** Réinitialise la double authentification (niveau 2, jeton « admin.reset_2fa » si demandé). */
  async reset2fa(row) {
    const ok = await confirm({
      level: 2, title: t("admin.person.reset_2fa_title", { name: personName(row) }),
      message: t("admin.person.reset_2fa_text"), impact: t("admin.person.reset_2fa_impact"),
      confirmLabel: t("admin.person.reset_2fa"),
    });
    if (!ok.confirmed) return false;
    const res = await withStepUp("admin.reset_2fa",
      (opts) => api("POST", `/admin/users/${encodeURIComponent(row.id)}/reset-2fa`, undefined, { ...opts, retry: false }),
      { title: t("admin.person.reset_2fa_title", { name: personName(row) }) });
    if (res === undefined) return false;
    notify({ text: t("admin.person.reset_2fa_done", { name: personName(row) }), tone: "ok" });
    return true;
  },

  /** Supprime un compte (niveau 3 : nom de la personne et mot de passe maître). */
  async remove(row) {
    const res = await reauthThen("admin.delete_user",
      (opts) => api("DELETE", `/admin/users/${encodeURIComponent(row.id)}`, undefined, { ...opts, retry: false }).then(() => true),
      {
        title: t("admin.person.delete_title", { name: personName(row) }),
        message: t("admin.person.delete_text"),
        objectName: personName(row),
        confirmLabel: t("admin.person.delete"),
        danger: true,
      });
    if (!res) return false;
    notify({ text: t("admin.person.deleted", { name: personName(row) }), tone: "ok" });
    return true;
  },

  /** Révoque tous les liens sécurisés créés par la personne (niveau 1). */
  async revokeShares(row) {
    const ok = await confirm({
      level: 1, title: t("admin.person.revoke_shares_title", { name: personName(row) }),
      message: t("admin.person.revoke_shares_text"), confirmLabel: t("admin.person.revoke_shares"), danger: true,
    });
    if (!ok.confirmed) return false;
    try {
      const res = await api("POST", "/admin/shares/revoke", { owner_id: row.id }, { retry: false });
      notify({ text: plural("admin.person.shares_revoked", Number(res?.revoked) || 0, { name: personName(row) }), tone: "ok" });
    } catch (e) {
      if (!routeMissing(e)) throw e;
      notify({ text: t("admin.person.revoke_shares_unavailable"), tone: "info" });
      return false;
    }
    return true;
  },

  /** Rapport d'accès (CSV, identifiants de coffre seulement). */
  async accessReport(row) {
    await download(`/admin/users/${encodeURIComponent(row.id)}/access-report.csv`, `locksy-rapport-acces-${new Date().toISOString().slice(0, 10)}.csv`);
    notify({ text: t("admin.person.report_done"), tone: "ok" });
    return false;
  },

  /** Ferme une session précise. */
  async closeSession(row, session) {
    await api("DELETE", `/admin/users/${encodeURIComponent(row.id)}/sessions/${encodeURIComponent(session.id)}`);
    notify({ text: t("admin.person.session_closed"), tone: "ok" });
    return true;
  },

  /** Renvoie une invitation : nouveau lien, l'ancien ne vaut plus. */
  async resendInvite(row) {
    const res = await api("POST", `/admin/invites/${encodeURIComponent(row.id)}/resend`);
    if (res?.mailed) notify({ text: t("admin.invite.resent_mailed", { email: row.email }), tone: "ok" });
    else showLink(row.email, res?.link);
    return true;
  },

  /** Révoque une invitation (niveau 1). */
  async revokeInvite(row) {
    const ok = await confirm({
      level: 1, title: t("admin.invite.revoke_title"), message: t("admin.invite.revoke_text", { email: row.email }),
      confirmLabel: t("admin.invite.revoke"), danger: true,
    });
    if (!ok.confirmed) return false;
    await api("DELETE", `/admin/invites/${encodeURIComponent(row.id)}`);
    notify({ text: t("admin.invite.revoked", { email: row.email }), tone: "ok" });
    return true;
  },
};

/** Lien d'une invitation à transmettre à la main (envoi par e-mail désactivé). */
function showLink(email, link) {
  if (!link) return;
  const box = textInput({ value: link, readonly: true, spellcheck: false });
  dialog({
    title: t("admin.invite.link_title"),
    description: t("admin.invite.link_text", { email }),
    body: h("div", { class: "l-stack", "data-gap": "2" },
      field({ label: t("admin.invite.link_label"), input: box }),
      button({ label: t("common.action.copy"), icon: "copy", onClick: () => copySecret(link, { kind: "text" }) })),
    actions: [{ label: t("common.action.close"), variant: "primary", value: "close" }],
  });
}

/**
 * Exécute une action unitaire avec message d'erreur ; `after` est appelée si
 * l'action a changé quelque chose.
 */
async function run(action, after) {
  try {
    if (await action()) await after?.();
  } catch (e) {
    notify({ text: errorText(e), tone: "danger" });
  }
}

/** Actions rapides d'un compte (menu ⋯ de la liste). */
export function userMenuItems(ctx, row, { onChange, onOpen } = {}) {
  const manage = canManage(ctx, row);
  const reason = isSelf(ctx, row) ? t("admin.person.self_reason") : t("admin.person.owner_reason");
  return [
    { label: t("admin.person.open"), icon: "user", onSelect: () => onOpen?.(row) },
    { label: t("admin.person.change_role"), icon: "users", disabled: !manage, reason, onSelect: () => openRoleDialog(ctx, [row], { onDone: onChange }) },
    { label: t("admin.person.revoke_sessions"), icon: "logout", disabled: !manage, reason, onSelect: () => run(() => personActions.revokeSessions(row), onChange) },
    row.status === "disabled"
      ? { label: t("admin.person.enable"), icon: "unlock", disabled: !manage, reason, onSelect: () => run(() => personActions.setDisabled(row, false), onChange) }
      : { label: t("admin.person.disable"), icon: "lock", disabled: !manage, reason, danger: true, onSelect: () => run(() => personActions.setDisabled(row, true), onChange) },
    "separator",
    { label: t("admin.person.offboard"), icon: "logout", disabled: !manage, reason, onSelect: () => go(ctx, `/admin/personnes/${encodeURIComponent(row.id)}/depart`) },
  ];
}

/** Actions rapides d'une invitation. */
export function inviteMenuItems(ctx, row, { onChange } = {}) {
  return [
    { label: t("admin.invite.resend"), icon: "mail", onSelect: () => run(() => personActions.resendInvite(row), onChange) },
    { label: t("admin.invite.revoke"), icon: "trash", danger: true, onSelect: () => run(() => personActions.revokeInvite(row), onChange) },
  ];
}

// ------------------------------------------------------------------ Fiche d'un compte

/**
 * Ouvre la fiche d'un compte dans un panneau.
 * row : ligne de la liste (A.6) ; onChange() après une modification ; onClose().
 */
export function openPerson(ctx, row, { onChange, onClose } = {}) {
  const body = h("div", { class: "l-stack", "data-gap": "4" }, skeleton({ lines: 6 }));
  let detail = { ...row, sessions: null, collections: null, recent_events: null };
  let changed = false;
  const pnl = panel({
    title: personName(row),
    body,
    actions: [{ label: t("common.action.close"), cancel: true }],
    onClose: () => onClose?.(changed),
  });

  const refresh = async () => {
    changed = true;
    await onChange?.();
    await load();
  };

  const load = async () => {
    try {
      detail = await api("GET", `/admin/users/${encodeURIComponent(row.id)}`);
    } catch (e) {
      if (!routeMissing(e)) {
        clear(body, alertCard({ tone: "danger", text: errorText(e), action: { label: t("common.action.retry"), onClick: load } }));
        return;
      }
      detail = { ...row, sessions: null, collections: null, recent_events: null };
    }
    paint();
  };

  function paint() {
    const manage = canManage(ctx, detail);
    const reason = isSelf(ctx, detail) ? t("admin.person.self_reason") : t("admin.person.owner_reason");
    const sessions = detail.sessions;
    const collections = detail.collections;
    const events = detail.recent_events;
    const tabList = [
      { id: "sessions", label: sessions ? t("admin.person.tab.sessions_n", { n: sessions.length }) : t("admin.person.tab.sessions"), render: (p) => paintSessions(p, sessions, manage) },
      { id: "coffres", label: collections ? t("admin.person.tab.vaults_n", { n: collections.length }) : t("admin.person.tab.vaults"), render: (p) => paintCollections(p, collections) },
      { id: "activite", label: t("admin.person.tab.activity"), render: (p) => paintEvents(p, events) },
      { id: "securite", label: t("admin.person.tab.security"), render: (p) => paintSecurity(p, manage) },
    ];
    const more = menuButton({
      label: t("admin.person.more", { name: personName(detail) }), iconOnly: true,
      items: () => [
        { label: t("admin.person.edit"), icon: "edit", disabled: !manage && !isSelf(ctx, detail), reason, onSelect: () => editPerson(ctx, detail, refresh) },
        detail.status === "disabled"
          ? { label: t("admin.person.enable"), icon: "unlock", disabled: !manage, reason, onSelect: () => run(() => personActions.setDisabled(detail, false), refresh) }
          : { label: t("admin.person.disable"), icon: "lock", disabled: !manage, reason, onSelect: () => run(() => personActions.setDisabled(detail, true), refresh) },
        { label: t("admin.person.revoke_shares"), icon: "link", disabled: !manage, reason, onSelect: () => run(() => personActions.revokeShares(detail), refresh) },
        { label: t("admin.person.report"), icon: "download", onSelect: () => run(() => personActions.accessReport(detail)) },
        "separator",
        { label: t("admin.person.delete"), icon: "trash", danger: true, disabled: !manage, reason, onSelect: () => run(() => personActions.remove(detail), async () => { changed = true; await onChange?.(); pnl.close(); }) },
      ],
    });
    clear(body,
      h("p", {}, detail.email, " · ", originText(detail.origin), " · ", statusText(detail)),
      detail.access_until ? h("p", { class: "u-muted" }, t("admin.person.access_until", { date: fmtDate(detail.access_until, "date") })) : null,
      h("div", { class: "l-cluster" },
        h("span", {}, t("admin.person.role_line", { role: roleLabel(detail.role) })),
        button({ label: t("admin.person.change_role"), icon: "users", disabled: !manage, reason, onClick: () => openRoleDialog(ctx, [detail], { onDone: refresh }) })),
      h("p", {}, t(detail.twofa ?? detail.totp_enabled ? "admin.person.twofa_on" : "admin.person.twofa_off")),
      tabs({ label: t("admin.person.tabs_label"), tabs: tabList }).el,
      h("div", { class: "l-cluster" },
        button({ label: t("admin.person.revoke_sessions"), icon: "logout", disabled: !manage, reason, onClick: () => run(() => personActions.revokeSessions(detail), refresh) }),
        (detail.twofa ?? detail.totp_enabled) ? button({ label: t("admin.person.reset_2fa"), icon: "key", disabled: !manage, reason, onClick: () => run(() => personActions.reset2fa(detail), refresh) }) : null),
      h("div", { class: "l-cluster", "data-justify": "between" },
        manage ? h("a", { class: "c-button", href: `#/admin/personnes/${encodeURIComponent(detail.id)}/depart` }, t("admin.person.offboard")) : h("span"),
        more));
  }

  function paintSessions(p, sessions, manage) {
    if (!sessions) return clear(p, h("p", { class: "u-muted" }, t("admin.person.unavailable")));
    if (!sessions.length) return clear(p, h("p", { class: "u-muted" }, t("admin.person.no_session")));
    return clear(p, h("ul", { class: "l-stack", "data-gap": "2" }, sessions.map((s) => h("li", { class: "l-cluster", "data-justify": "between" },
      h("span", {}, t("admin.person.session_line", { device: s.device || t("admin.person.device_unknown"), when: relTime(s.last_seen_at) })),
      s.current ? badge({ tone: "info", label: t("admin.person.session_current") })
        : button({
          label: t("admin.person.close_session"), disabled: !manage,
          attrs: { "aria-label": t("admin.person.close_session_named", { device: s.device || t("admin.person.device_unknown") }) },
          onClick: () => run(() => personActions.closeSession(detail, s), refresh),
        })))));
  }

  function paintCollections(p, collections) {
    if (!collections) return clear(p, h("p", { class: "u-muted" }, t("admin.person.unavailable")));
    if (!collections.length) return clear(p, h("p", { class: "u-muted" }, t("admin.person.no_vault")));
    return clear(p,
      h("p", { class: "u-muted" }, t("admin.person.vaults_note")),
      h("ul", { class: "l-stack", "data-gap": "2" }, collections.map((c) => h("li", { class: "c-card l-stack", "data-gap": "1" },
        h("strong", {}, c.personal ? t("common.glossary.personal_vault") : t("admin.person.vault_shared", { role: t(`admin.person.vault_role.${["manager", "editor", "reader"].includes(c.role) ? c.role : "reader"}`) })),
        h("span", {}, plural("admin.person.vault_members", Number(c.members_count) || 0), " · ", plural("admin.person.vault_items", Number(c.items_count) || 0)),
        h("span", { class: "l-cluster" },
          c.sole_manager && !c.personal ? badge({ tone: "warn", icon: "warn", label: t("admin.person.sole_manager") }) : null,
          c.rotation_suggested_at ? badge({ tone: "info", label: t("admin.person.rotation_suggested") }) : null)))));
  }

  function paintEvents(p, events) {
    if (!events) return clear(p, h("p", { class: "u-muted" }, t("admin.person.unavailable")));
    if (!events.length) return clear(p, h("p", { class: "u-muted" }, t("audit.empty")));
    clear(p, skeleton({ lines: 3 }));
    return import("./journal.js").then(({ eventText, severityBadge }) => clear(p,
      h("ul", { class: "l-stack", "data-gap": "2" }, events.map((e) => h("li", { class: "l-cluster" },
        h("span", { class: "u-muted u-nowrap", title: fmtDate(e.at, "long") }, relTime(e.at)),
        h("span", {}, eventText(e.action)),
        e.severity && e.severity !== "info" ? severityBadge(e.severity) : null))),
      h("a", { href: `#/admin/journal?personne=${encodeURIComponent(detail.email || "")}` }, t("admin.person.all_events"))));
  }

  function paintSecurity(p, manage) {
    const on = detail.twofa ?? detail.totp_enabled;
    clear(p, h("ul", { class: "l-stack", "data-gap": "2" },
      h("li", {}, t(on ? "admin.person.twofa_on" : "admin.person.twofa_off")),
      on && detail.recovery_codes_remaining !== undefined && detail.recovery_codes_remaining !== null
        ? h("li", {}, plural("admin.person.recovery_codes", Number(detail.recovery_codes_remaining) || 0)) : null,
      h("li", {}, t("admin.person.created", { date: fmtDate(detail.created_at, "date") })),
      h("li", {}, detail.last_seen_at ? t("admin.person.last_seen", { when: relTime(detail.last_seen_at) }) : t("admin.person.never_seen")),
      h("li", {}, t("admin.person.access_until_line", { date: dateOrNone(detail.access_until) }))),
    on ? button({ label: t("admin.person.reset_2fa"), icon: "key", disabled: !manage, onClick: () => run(() => personActions.reset2fa(detail), refresh) }) : null);
  }

  load();
  return pnl;
}

/** « Modifier » : nom, adresse, date de fin d'accès (PATCH /admin/users/:id). */
function editPerson(ctx, row, after) {
  const name = textInput({ value: row.name || "", maxlength: 120, autocomplete: "off" });
  const email = textInput({ type: "email", value: row.email || "", autocomplete: "off" });
  const until = textInput({ type: "date", value: tsToDateInput(row.access_until) });
  const problem = h("div");
  const initial = JSON.stringify([name.value, email.value, until.value]);
  dialog({
    title: t("admin.person.edit_title", { name: personName(row) }),
    body: h("div", { class: "l-stack", "data-gap": "3" },
      field({ label: t("admin.person.field.name"), input: name }),
      field({ label: t("admin.person.field.email"), help: t("admin.person.field.email_help"), input: email }),
      field({ label: t("admin.person.field.until"), help: t("admin.person.field.until_help"), optional: true, input: until }),
      problem),
    dirty: () => JSON.stringify([name.value, email.value, until.value]) !== initial,
    actions: [
      { label: t("common.action.cancel"), cancel: true, value: "cancel" },
      {
        label: t("common.action.save"), variant: "primary", busyLabel: t("common.state.saving"),
        onClick: async () => {
          const patch = {};
          if (name.value.trim() !== (row.name || "")) patch.name = name.value.trim();
          if (email.value.trim() !== (row.email || "")) patch.email = email.value.trim();
          if (until.value !== tsToDateInput(row.access_until)) patch.access_until = dateInputToTs(until.value);
          if (!Object.keys(patch).length) return true;
          try {
            await api("PATCH", `/admin/users/${encodeURIComponent(row.id)}`, patch);
          } catch (e) {
            clear(problem, alertCard({ tone: "danger", text: routeMissing(e) ? t("admin.person.edit_unavailable") : errorText(e) }));
            return false;
          }
          notify({ text: t("admin.person.edited", { name: patch.name || personName(row) }), tone: "ok" });
          await after?.();
          return true;
        },
      },
    ],
  });
}

// ------------------------------------------------------------------ Invitation

/** Panneau d'une invitation en attente ou expirée. */
export function openInvite(ctx, row, { onChange, onClose } = {}) {
  let changed = false;
  const after = async () => {
    changed = true;
    await onChange?.();
    pnl.close();
  };
  const pnl = panel({
    title: row.email,
    body: h("div", { class: "l-stack", "data-gap": "3" },
      h("p", {}, statusText(row)),
      h("ul", { class: "l-stack", "data-gap": "1" },
        h("li", {}, t("admin.person.role_line", { role: roleLabel(row.role) })),
        h("li", {}, t("admin.invite.sent_line", { n: fmtNumber(Number(row.sent_count) || 1), when: relTime(row.last_sent_at || row.created_at) })),
        row.access_until ? h("li", {}, t("admin.person.access_until", { date: fmtDate(row.access_until, "date") })) : null),
      h("div", { class: "l-cluster" },
        button({ label: t("admin.invite.resend"), icon: "mail", onClick: () => run(() => personActions.resendInvite(row), after) }),
        button({ label: t("admin.invite.revoke"), icon: "trash", variant: "danger", onClick: () => run(() => personActions.revokeInvite(row), after) }))),
    actions: [{ label: t("common.action.close"), cancel: true }],
    onClose: () => onClose?.(changed),
  });
  return pnl;
}
