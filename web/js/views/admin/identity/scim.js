// Création automatique des comptes (SCIM) : adresse de base à déclarer dans
// l'annuaire, jeton (affiché une seule fois), régénération avec confirmation
// d'identité, révocation confirmée avec gestion d'erreur, expiration et liste
// des comptes créés par l'annuaire.

import { api, withReauth } from "../../../api.js";
import {
  alertCard, badge, button, clear, confirm, copySecret, dataTable, field, fmtDate, h, notify, plural, relTime, t,
  textInput,
} from "../../../ui/index.js";
import { backLink, copyField, getOrNull, nowSecs, pageHeader, relatedSettings, resultArea } from "./common.js";
import { loadIdentityStatus } from "./status-cards.js";

/** Jeton tout juste créé : affiché une fois, avec « Copier ». */
function tokenReveal(token) {
  const input = textInput({ value: token, readonly: true, spellcheck: false });
  input.classList.add("u-mono");
  const copy = button({
    label: t("common.action.copy"), icon: "copy", attrs: { "aria-label": t("identity.scim.token.copy") },
    onClick: () => copySecret(token, { kind: "secret" }),
  });
  return h("div", { class: "l-stack", "data-gap": "2" },
    alertCard({ tone: "warn", text: t("identity.scim.token.once") }),
    field({ label: t("identity.scim.token.label"), input, control: h("div", { class: "c-field__control" }, input, copy) }));
}

/** Lignes d'état du jeton : création, expiration, dernière utilisation. */
function tokenLines(s) {
  if (!s.token_set) return [h("p", {}, h("strong", {}, t("identity.scim.state.none")))];
  const expired = Number(s.token_expires_at) > 0 && s.token_expires_at <= nowSecs();
  return [
    h("p", {}, h("strong", {}, t(expired ? "identity.scim.state.expired" : "identity.scim.state.active"))),
    s.token_created_at ? h("p", {}, t("identity.scim.created_at", { date: fmtDate(s.token_created_at, "date") })) : null,
    h("p", {}, s.token_expires_at
      ? t(expired ? "identity.scim.ttl.expired" : "identity.scim.ttl.date", { date: fmtDate(s.token_expires_at, "date") })
      : t("identity.scim.ttl.none")),
    h("p", {}, s.last_used_at ? t("identity.scim.detail.used", { when: relTime(s.last_used_at) }) : t("identity.scim.detail.never_used")),
  ];
}

/** Tableau des comptes créés par l'annuaire (GET /admin/directory). */
function directoryTable(rows) {
  const state = (d) => {
    if (!d.active) return badge({ tone: "neutral", label: t("identity.scim.dir.disabled") });
    if (!d.registered) return badge({ tone: "info", label: t("identity.scim.dir.pending") });
    return badge({ tone: "ok", label: t("identity.scim.dir.active") });
  };
  return dataTable({
    caption: plural("identity.scim.dir.caption", rows.length),
    columns: [
      { key: "display_name", label: t("identity.scim.dir.col.person"), render: (d) => h("span", { class: "l-stack", "data-gap": "1" }, h("strong", {}, d.display_name || d.email), h("span", { class: "u-muted" }, d.email)) },
      { key: "active", label: t("identity.scim.dir.col.state"), render: state },
      { key: "updated_at", label: t("identity.scim.dir.col.updated"), render: (d) => relTime(d.updated_at) },
    ],
    rows,
    rowKey: (d) => d.id,
    rowLabel: (d) => d.display_name || d.email,
    pageSize: 100,
    empty: t("identity.scim.dir.empty"),
  }).el;
}

/** Page « Création automatique des comptes (SCIM) ». */
export async function scimPage(container) {
  const [status, directory] = await Promise.all([loadIdentityStatus(), getOrNull("/admin/directory")]);
  let s = status.scim || {};
  const rows = Array.isArray(directory) ? directory : [];
  const card = h("section", { class: "c-card l-stack", "data-gap": "3", "aria-labelledby": "scim-jeton" });
  const reveal = h("div", {});
  const area = resultArea();

  const refresh = async () => {
    try {
      s = (await loadIdentityStatus()).scim || {};
    } catch {
      /* état affiché inchangé : l'action, elle, a réussi et l'a dit */
    }
    render();
  };

  /** Crée (premier jeton) ou régénère le jeton, puis l'affiche une fois. */
  const issue = async (opts) => {
    const r = await api("POST", "/admin/scim/token", undefined, opts);
    clear(reveal, tokenReveal(r.token));
    notify({ text: t(s.token_set ? "identity.scim.regenerated" : "identity.scim.created"), tone: "ok" });
    await refresh();
  };

  const create = button({
    label: t("identity.scim.create"), variant: "primary", icon: "key", busyLabel: t("identity.scim.creating"),
    onClick: async () => {
      area.clear();
      try {
        await issue();
      } catch (e) {
        area.error(e);
      }
    },
  });
  const regenerate = button({
    label: t("identity.scim.regenerate"), icon: "refresh", busyLabel: t("identity.scim.creating"),
    onClick: async () => {
      area.clear();
      try {
        await withReauth("scim.token", (opts) => issue(opts), {
          title: t("identity.scim.regenerate.title"), message: t("identity.scim.regenerate.message"),
        });
      } catch (e) {
        area.error(e);
      }
    },
  });
  const revoke = button({
    label: t("identity.scim.revoke"), variant: "danger", icon: "close", busyLabel: t("identity.scim.revoking"),
    onClick: async () => {
      const active = rows.filter((d) => d.active).length;
      const { confirmed } = await confirm({
        level: 2,
        title: t("identity.scim.revoke.title"),
        message: t("identity.scim.revoke.message"),
        impact: plural("identity.scim.revoke.impact", active),
        confirmLabel: t("identity.scim.revoke"),
        danger: true,
      });
      if (!confirmed) return;
      area.clear();
      try {
        await api("DELETE", "/admin/scim/token");
      } catch (e) {
        // Le jeton reste en place : l'erreur est dite à côté de lui.
        area.error(e, { title: t("identity.scim.revoke.failed") });
        return;
      }
      clear(reveal);
      notify({ text: t("identity.scim.revoked"), tone: "ok" });
      await refresh();
    },
  });

  function render() {
    clear(card,
      h("h2", { id: "scim-jeton" }, t("identity.scim.token.title")),
      ...tokenLines(s),
      h("div", { class: "l-cluster" }, ...(s.token_set ? [regenerate, revoke] : [create])),
      area.el,
      reveal);
  }
  render();

  clear(container,
    backLink(),
    ...pageHeader("identity.scim.title", "identity.scim.intro"),
    status.partial ? alertCard({ tone: "info", text: t("identity.partial") }) : null,
    copyField({
      label: t("identity.scim.base_url.label"), help: t("identity.scim.base_url.help"),
      value: s.base_url || "", copyLabel: t("identity.scim.base_url.copy"),
    }),
    card,
    h("p", { class: "u-muted" }, t("identity.scim.groups_note")),
    Array.isArray(directory) ? directoryTable(rows) : null,
    relatedSettings(["scim.token_ttl_days", "directory.deprovision", "directory.delete_after_days"], "scim-reglages"));
  return {};
}

