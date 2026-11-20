// Administration › Personnes (cahier §3.4.3, annexe A.6 et A.7) : comptes,
// invitations et comptes de l'annuaire dans une seule liste. Aucun bouton
// d'action dans les lignes : la ligne ouvre la fiche (panneau, adresse
// #/admin/personnes/:id), « ⋯ » donne les actions rapides. Recherche,
// filtres (état, rôle, double authentification, origine), tri et page dans
// l'adresse ; pagination par le serveur (GET /admin/people) ; actions de
// masse avec rapport « 3 effectuées, 1 ignorée : … » ; « Inviter des
// personnes » ; « Exporter (CSV) ».
// Repli R11 : serveur sans /admin/people -> /admin/users + /admin/invites,
// filtrés, triés et paginés ici ; actions de masse personne par personne.

import {
  t, plural, h, clear, button, menuButton, dataTable, filterBar, searchBox, notify, alertCard, emptyState, errorState,
  relTime, fmtDate, errorText, confirm, badge,
} from "../../ui/index.js";
import { api, saveBlob } from "../../api.js";
import { csvBlob, datedName, me, personName, roleLabel, roleRank, routeMissing, setQuery, withStepUp } from "./shell.js";
import { inviteMenuItems, openInvite, openPerson, originText, statusText, userMenuItems } from "./person.js";
import { openRoleDialog, skipReason } from "./role-dialog.js";

const PER_PAGE = 25;
const DAY = 86400;
const ETATS = Object.freeze(["", "actif", "desactive", "invite", "invitation_expiree", "expire", "inactif", "suppression_programmee"]);
const ROLES = Object.freeze(["", "owner", "admin", "user"]);
const TWOFA = Object.freeze(["", "oui", "non"]);
const ORIGINES = Object.freeze(["", "local", "sso", "ldap", "scim", "invite"]);
const SORTS = Object.freeze({ nom: "nom", role: "role", derniere_connexion: "derniere_connexion" });
/** État de la liste -> statut calculé par le serveur (filtrage du repli). */
const ETAT_STATUS = Object.freeze({
  actif: ["active", "inactive"], desactive: ["disabled"], invite: ["invited"], invitation_expiree: ["invite_expired"],
  expire: ["expired"], inactif: ["inactive"], suppression_programmee: ["pending_deprovision"],
});

const pick = (list, v) => (list.includes(v) ? v : "");

/** Filtres de l'adresse (#/admin/personnes?etat=actif&2fa=non&tri=nom&page=2). */
function readQuery(query) {
  const q = query || new URLSearchParams();
  const tri = q.get("tri") || "";
  const key = tri.replace(/^-/, "");
  return {
    q: q.get("q") || "",
    etat: pick(ETATS, q.get("etat") || ""),
    role: pick(ROLES, q.get("role") || ""),
    "2fa": pick(TWOFA, q.get("2fa") || ""),
    origine: pick(ORIGINES, q.get("origine") || ""),
    tri: SORTS[key] ? tri : "",
    page: Math.max(1, Number.parseInt(q.get("page") || "1", 10) || 1),
  };
}

/** Paramètres de GET /admin/people. */
function apiQuery(f, page = f.page, perPage = PER_PAGE) {
  const p = new URLSearchParams();
  for (const k of ["q", "etat", "role", "2fa", "origine", "tri"]) if (f[k]) p.set(k, f[k]);
  p.set("page", String(page));
  p.set("par_page", String(perPage));
  return p;
}

// ------------------------------------------------------------------ Repli

/** Lignes A.6 depuis les routes historiques (comptes et invitations non utilisées). */
async function legacyRows(ctx) {
  const now = Math.floor(Date.now() / 1000);
  const [users, invites] = await Promise.all([
    api("GET", "/admin/users"),
    api("GET", "/admin/invites").catch(() => []),
  ]);
  const self = me(ctx).id;
  const rows = (Array.isArray(users) ? users : []).map((u) => ({
    kind: "user", id: u.id, name: u.name, email: u.email, role: u.role,
    status: u.disabled ? "disabled" : (u.last_login_at || u.created_at) < now - 90 * DAY ? "inactive" : "active",
    twofa: !!u.totp_enabled, origin: "local", last_seen_at: u.last_login_at ?? null, created_at: u.created_at, is_self: u.id === self,
  }));
  for (const i of Array.isArray(invites) ? invites : []) {
    if (i.used_at) continue;
    rows.push({
      kind: "invite", id: i.id, email: i.email, role: i.role, status: i.expires_at < now ? "invite_expired" : "invited",
      expires_at: i.expires_at, created_at: i.created_at, sent_count: 1, origin: "invite",
    });
  }
  return rows;
}

/** Filtre, tri et page côté navigateur (repli). */
function legacyPage(all, f, page = f.page, perPage = PER_PAGE) {
  const needle = f.q.trim().toLowerCase();
  let rows = all.filter((r) => {
    if (needle && !`${r.name || ""} ${r.email}`.toLowerCase().includes(needle)) return false;
    if (f.etat && !(ETAT_STATUS[f.etat] || []).includes(r.status)) return false;
    if (f.role && r.role !== f.role) return false;
    if (f["2fa"] && (r.kind !== "user" || r.twofa !== (f["2fa"] === "oui"))) return false;
    if (f.origine && r.origin !== f.origine) return false;
    return true;
  });
  const key = f.tri.replace(/^-/, "") || "nom";
  const dir = f.tri.startsWith("-") ? -1 : 1;
  const val = (r) => (key === "role" ? roleRank(r.role) : key === "derniere_connexion" ? r.last_seen_at || 0 : personName(r).toLowerCase());
  rows = rows.sort((a, b) => (val(a) < val(b) ? -dir : val(a) > val(b) ? dir : String(a.id).localeCompare(String(b.id))));
  return { total: rows.length, page, per_page: perPage, rows: rows.slice((page - 1) * perPage, page * perPage) };
}

// ------------------------------------------------------------------ Écran

export async function renderPage(ctx, container, route) {
  let f = readQuery(ctx.query);
  let legacy = null;
  let rows = [];
  let total = 0;
  let disposed = false;
  let openedId = route.id || null;

  const title = h("h1", { tabindex: "-1" }, t("admin.people.title"));
  const report = h("div", { class: "l-stack", "data-gap": "2" });
  const result = h("div", { class: "l-stack", "data-gap": "3" });

  const sync = () => setQuery(ctx, {
    q: f.q || null, etat: f.etat || null, role: f.role || null, "2fa": f["2fa"] || null, origine: f.origine || null,
    tri: f.tri || null, page: f.page > 1 ? f.page : null,
  });

  const table = dataTable({
    caption: t("admin.people.caption"),
    columns: [
      { key: "nom", label: t("admin.people.col.person"), sortable: true, render: personCell },
      { key: "role", label: t("admin.people.col.role"), sortable: true, render: (r) => (r.kind === "invite" ? t("admin.people.invited_role", { role: roleLabel(r.role) }) : roleLabel(r.role)) },
      { key: "2fa", label: t("admin.people.col.twofa"), render: (r) => (r.kind === "invite" ? t("admin.value.dash") : t(r.twofa ? "admin.people.twofa_on" : "admin.people.twofa_off")) },
      { key: "derniere_connexion", label: t("admin.people.col.last_seen"), sortable: true, render: lastSeenCell },
      {
        key: "actions", label: t("admin.people.col.actions"),
        render: (r) => menuButton({
          label: t("admin.people.row_actions", { name: personName(r) }), iconOnly: true, variant: "quiet",
          items: () => (r.kind === "invite"
            ? inviteMenuItems(ctx, r, { onChange: reload })
            : userMenuItems(ctx, r, { onChange: reload, onOpen: open })),
        }),
      },
    ],
    rows: [],
    rowKey: (r) => `${r.kind}:${r.id}`,
    rowLabel: personName,
    selectable: true,
    onRowOpen: (r) => open(r),
    loading: true,
    pageSize: PER_PAGE,
    onPage: (page) => {
      f.page = page;
      sync();
      load();
    },
    onSort: ({ key, dir }) => {
      f.tri = `${dir === "descending" ? "-" : ""}${key}`;
      f.page = 1;
      sync();
      load();
    },
    empty: emptyState({
      icon: "users", title: t("admin.people.empty"), level: 3,
      actions: [{ label: t("ui.filters.clear"), variant: "secondary", onClick: () => clearFilters() }],
    }),
    bulkActions: [
      { label: t("admin.people.bulk.revoke_sessions"), icon: "logout", onClick: (sel) => bulk("revoke_sessions", sel) },
      { label: t("admin.people.bulk.disable"), icon: "lock", danger: true, onClick: (sel) => bulk("disable", sel) },
      { label: t("admin.people.bulk.enable"), icon: "unlock", onClick: (sel) => bulk("enable", sel) },
      { label: t("admin.people.bulk.reset_2fa"), icon: "key", onClick: (sel) => bulk("reset_2fa", sel) },
      { label: t("admin.people.bulk.set_role"), icon: "users", onClick: (sel) => bulkRole(sel) },
    ],
  });

  function personCell(r) {
    const self = r.kind === "user" && (r.is_self || r.id === me(ctx).id);
    return h("span", { class: "l-stack", "data-gap": "1" },
      h("strong", {}, r.kind === "invite" ? r.email : personName(r), self ? ` ${t("admin.people.you")}` : ""),
      h("span", { class: "u-muted" }, r.kind === "invite" ? originText("invite") : `${r.email} · ${originText(r.origin)}`));
  }

  function lastSeenCell(r) {
    if (r.kind === "invite") return statusText(r);
    if (r.status && !["active", "inactive"].includes(r.status)) return badge({ tone: r.status === "disabled" ? "neutral" : "warn", label: statusText(r) });
    const seen = r.last_seen_at ? h("span", { title: fmtDate(r.last_seen_at, "long") }, relTime(r.last_seen_at)) : t("admin.people.never");
    return r.status === "inactive" ? h("span", { class: "l-cluster" }, seen, badge({ tone: "warn", label: t("admin.people.status.inactive") })) : seen;
  }

  const filters = filterBar({
    label: t("admin.people.filters"),
    filters: [
      { key: "etat", label: t("admin.people.filter.state"), options: ETATS.map((v) => ({ value: v, label: t(`admin.people.etat.${v || "tous"}`) })) },
      { key: "role", label: t("admin.people.filter.role"), options: ROLES.map((v) => ({ value: v, label: v ? roleLabel(v) : t("admin.people.filter.all_roles") })) },
      { key: "2fa", label: t("admin.people.filter.twofa"), options: TWOFA.map((v) => ({ value: v, label: t(`admin.people.twofa_filter.${v || "toutes"}`) })) },
      { key: "origine", label: t("admin.people.filter.origin"), options: ORIGINES.map((v) => ({ value: v, label: v ? originText(v) : t("admin.people.filter.all_origins") })) },
    ],
    values: f,
    syncUrl: false,
    onChange: (v) => {
      f = { ...f, ...v, page: 1 };
      sync();
      load();
    },
  });

  const search = searchBox({
    label: t("admin.people.search"), placeholderKey: "admin.people.search_placeholder", value: f.q, shortcut: "", delay: 250,
    onInput: (_n, raw) => {
      f.q = raw.trim();
      f.page = 1;
      sync();
      load();
    },
  });

  function clearFilters() {
    f = { ...f, etat: "", role: "", "2fa": "", origine: "", q: "", page: 1 };
    filters.update({ values: f });
    const input = search.querySelector("input");
    if (input) input.value = "";
    sync();
    load();
  }

  clear(container,
    h("div", { class: "l-cluster", "data-justify": "between" },
      title,
      h("div", { class: "l-cluster" },
        button({ label: t("admin.people.export"), icon: "download", busyLabel: t("admin.people.exporting"), onClick: exportCsv }),
        button({ label: t("admin.people.invite"), icon: "plus", variant: "primary", onClick: invite }))),
    search,
    filters.el,
    report,
    result);
  clear(result, table.el);

  async function fetchPage(page = f.page, perPage = PER_PAGE) {
    if (!legacy) {
      try {
        return await api("GET", `/admin/people?${apiQuery(f, page, perPage)}`);
      } catch (e) {
        if (!routeMissing(e)) throw e;
        legacy = await legacyRows(ctx);
      }
    }
    return legacyPage(legacy, f, page, perPage);
  }

  async function load() {
    table.update({ loading: true });
    try {
      const res = await fetchPage();
      if (disposed) return;
      rows = res.rows || [];
      total = Number(res.total) || 0;
      const sortKey = f.tri.replace(/^-/, "");
      table.update({
        rows, total, page: Number(res.page) || f.page, loading: false,
        sort: sortKey ? { key: sortKey, dir: f.tri.startsWith("-") ? "descending" : "ascending" } : undefined,
      });
      title.textContent = t("admin.people.title_count", { n: total });
      clear(result, table.el);
      if (openedId) {
        const id = openedId;
        openedId = null;
        openById(id);
      }
    } catch (e) {
      if (!disposed) clear(result, errorState({ error: e, onRetry: load }));
    }
  }

  async function reload() {
    legacy = null;
    await load();
  }

  /** Ouvre la fiche (ou l'invitation) ; l'adresse suit sans recharger la liste. */
  function open(r) {
    if (!r) return;
    const base = location.hash.replace(/^#\/admin\/personnes(\/[^?]*)?/, "#/admin/personnes");
    const query = base.includes("?") ? base.slice(base.indexOf("?")) : "";
    history.replaceState(history.state, "", `#/admin/personnes/${encodeURIComponent(r.id)}${query}`);
    const onClose = () => {
      if (disposed) return;
      history.replaceState(history.state, "", `#/admin/personnes${query}`);
    };
    if (r.kind === "invite") openInvite(ctx, r, { onChange: reload, onClose });
    else openPerson(ctx, r, { onChange: reload, onClose });
  }

  /** Lien direct vers une fiche : ligne de la page, sinon fiche chargée par son identifiant. */
  function openById(id) {
    const row = rows.find((r) => String(r.id) === id) || (legacy || []).find((r) => String(r.id) === id) || { kind: "user", id, email: "", name: "" };
    open(row);
  }

  // ---------------------------------------------------------------- Actions de masse

  /** Rapport d'une action de masse, gardé à l'écran jusqu'à la suivante. */
  function showReport(res, selection) {
    const name = (id) => personName(selection.find((r) => r.id === id) || { email: id });
    const skipped = res.skipped || [];
    const done = (res.done || []).length;
    const lines = skipped.map((s) => t("admin.people.bulk.skipped_line", { name: name(s.id), reason: t(`admin.people.skip_reason.${s.reason}`) }));
    clear(report, alertCard({
      tone: skipped.length ? "warn" : "ok",
      title: skipped.length ? t("admin.people.bulk.report_mixed", { done: plural("admin.people.bulk.done", done), skipped: plural("admin.people.bulk.skipped", skipped.length) }) : plural("admin.people.bulk.done", done),
      text: lines.length ? lines.join(" ; ") : null,
    }));
    notify({ text: skipped.length ? t("admin.people.bulk.report_short", { done, skipped: skipped.length }) : plural("admin.people.bulk.done", done), tone: skipped.length ? "warn" : "ok" });
  }

  /** Sépare comptes et invitations (une invitation n'est pas un compte). */
  const split = (selection) => ({
    users: selection.filter((r) => r.kind !== "invite"),
    invites: selection.filter((r) => r.kind === "invite").map((r) => ({ id: r.id, reason: "invite" })),
  });

  async function bulk(action, selection) {
    const { users, invites } = split(selection);
    if (action !== "enable") {
      const ok = await confirm({
        level: action === "reset_2fa" ? 2 : 1,
        title: plural(`admin.people.bulk.confirm.${action}`, users.length),
        message: t(`admin.people.bulk.confirm_text.${action}`),
        impact: action === "reset_2fa" ? t("admin.person.reset_2fa_impact") : undefined,
        confirmLabel: t(`admin.people.bulk.${action}`),
        danger: action === "disable",
      });
      if (!ok.confirmed) return;
    }
    try {
      const res = users.length ? await runBulk(action, users) : { done: [], skipped: [] };
      if (res === undefined) return;
      res.skipped = [...(res.skipped || []), ...invites];
      showReport(res, selection);
      await reload();
    } catch (e) {
      notify({ text: errorText(e), tone: "danger" });
    }
  }

  async function runBulk(action, users) {
    const ids = users.map((r) => r.id);
    try {
      return await withStepUp("admin.bulk",
        (opts) => api("POST", "/admin/users/bulk", { ids, action }, { ...opts, retry: false }),
        { title: t(`admin.people.bulk.${action}`) });
    } catch (e) {
      if (!routeMissing(e)) throw e;
    }
    const out = { done: [], skipped: [] };
    for (const r of users) {
      try {
        if (action === "revoke_sessions") await api("POST", `/admin/users/${encodeURIComponent(r.id)}/revoke-sessions`);
        else if (action === "reset_2fa") await api("POST", `/admin/users/${encodeURIComponent(r.id)}/reset-2fa`);
        else await api("PUT", `/admin/users/${encodeURIComponent(r.id)}`, { disabled: action === "disable" });
        out.done.push(r.id);
      } catch (err) {
        out.skipped.push({ id: r.id, reason: skipReason(err) });
      }
    }
    return out;
  }

  async function bulkRole(selection) {
    const { users, invites } = split(selection);
    if (!users.length) return;
    await openRoleDialog(ctx, users, {
      onDone: async (res) => {
        res.skipped = [...(res.skipped || []), ...invites];
        showReport(res, selection);
        await reload();
      },
    });
  }

  // ---------------------------------------------------------------- Inviter, exporter

  async function invite() {
    const { openInviteDialog } = await import("./invite.js");
    await openInviteDialog(ctx, { onDone: reload });
  }

  async function exportCsv() {
    try {
      const all = [];
      for (let page = 1; page <= 200; page++) {
        const res = await fetchPage(page, 100);
        all.push(...(res.rows || []));
        if (all.length >= (Number(res.total) || 0) || !(res.rows || []).length) break;
      }
      const head = ["name", "email", "role", "state", "twofa", "origin", "last_seen", "created"].map((k) => t(`admin.people.csv.${k}`));
      const lines = all.map((r) => [
        r.kind === "invite" ? "" : r.name || "", r.email, roleLabel(r.role), statusText(r),
        r.kind === "invite" ? "" : t(r.twofa ? "admin.people.twofa_on" : "admin.people.twofa_off"),
        originText(r.origin), r.last_seen_at ? fmtDate(r.last_seen_at, "long") : "", r.created_at ? fmtDate(r.created_at, "long") : "",
      ]);
      saveBlob(csvBlob([head, ...lines]), datedName("personnes", "csv"));
      notify({ text: plural("admin.people.exported", all.length), tone: "ok" });
    } catch (e) {
      notify({ text: errorText(e), tone: "danger" });
    }
  }

  await load();
  return {
    dispose() {
      disposed = true;
    },
    isDirty: () => false,
  };
}
