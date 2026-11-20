// Fiche d'un élément (cahier §3.3.2) : une ligne par information avec un
// bouton « Copier » libellé, force du mot de passe sur une seule échelle avec
// ses défauts cliquables (correctif P0 01-1), code de vérification, favori
// personnel, audience, droits insuffisants expliqués, pièces jointes,
// historique, liens sécurisés actifs, actions avec gestion d'erreur.
//
// renderDetail({ item, env, heading, mobile }) -> { el, destroy() }
//   env : { reload(), navigate(path, opts), shell } fourni par l'écran du coffre ;
//   heading : niveau du titre (1 sur #/element/:id) ; mobile : barre d'action fixe.

import {
  t, plural, fmtDate, relTime, fmtBytes, h, icon, button, iconButton, setPressed, menuButton, secretRow, totpCode,
  strengthMeter, issueChip, audienceLine, itemAvatar, technicalDetails, dialog, confirm, notify, badge, setDisabled,
} from "../../ui/index.js";
import { api, saveBlob } from "../../api.js";
import { call } from "../../wasm.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";
import {
  kindLabel, roleLabel, collectionOf, collectionLabel, canWrite, favorites, safeUrl, primarySecret, errorNotice, offline,
} from "./common.js";
import * as A from "./actions.js";

const YEAR = 365 * 86400;

/** Problèmes du mot de passe : avertissements du noyau, réutilisation, ancienneté, adresse non chiffrée. */
export function passwordIssues(item) {
  const d = item.data;
  const issues = [];
  let score = null;
  if (d.password) {
    try {
      const s = call("strength", { password: d.password });
      score = s.score;
      for (const w of s.warnings || []) issues.push({ text: w, fix: "weak" });
      if (s.score <= 2 && !(s.warnings || []).length) issues.push({ issue: { code: "weak" }, fix: "weak" });
    } catch { /* module absent : pas de jauge */ }
    const reused = [...V.state.items.values()].filter((o) => o.id !== item.id && !o.deleted_at && o.data?.password === d.password).length;
    if (reused) issues.push({ issue: { code: "reused", n: reused }, fix: "report" });
    const changed = d.password_changed_at || item.created_at;
    if (changed && changed < V.now() - YEAR) {
      issues.push({ issue: { code: "old", params: { age: plural("vault.detail.age_years", Math.floor((V.now() - changed) / YEAR)) } }, fix: "weak" });
    }
  }
  if ((d.urls || []).some((u) => /^http:\/\//i.test(String(u).trim()))) issues.push({ issue: { code: "http" }, fix: "report" });
  return { score, issues };
}

function lines(rows) {
  const list = rows.filter(Boolean);
  return list.length ? h("div", { class: "c-card" }, list) : null;
}

function plain(label, value, { kind = "text", copyLabelKey, mono } = {}) {
  if (value === undefined || value === null || String(value) === "") return null;
  return secretRow({ label, value: String(value), kind, masked: false, mono, copyLabelKey });
}

function secret(label, value, { mono = true, copyLabelKey } = {}) {
  if (!value) return null;
  return secretRow({ label, value: String(value), kind: "secret", masked: true, mono, copyLabelKey });
}

export function renderDetail({ item, env, heading = 2, mobile = false }) {
  const d = item.data;
  const col = collectionOf(item.collection_id);
  const writable = canWrite(item.collection_id);
  const trashed = !!item.deleted_at;
  const clickToCopy = S.prefs().ui?.click_to_copy === true;
  const cleanups = [];
  const id = encodeURIComponent(item.id);

  // ---------------------------------------------------------- En-tête
  const fav = favorites().has(item.id);
  const star = iconButton({
    icon: fav ? "star-filled" : "star",
    label: t(fav ? "vault.detail.favorite_remove" : "vault.detail.favorite_add"),
    pressed: fav,
    onClick: async () => {
      const now = await A.toggleFavorite(item);
      setPressed(star, now);
      star.replaceChildren(icon(now ? "star-filled" : "star"));
      const label = t(now ? "vault.detail.favorite_remove" : "vault.detail.favorite_add");
      star.setAttribute("aria-label", label);
      star.title = label;
      env.countsChanged?.();
    },
  });
  const more = trashed ? null : menuButton({
    label: t("common.action.more_actions"), icon: "more", iconOnly: true, variant: "quiet",
    items: [
      { label: t("vault.detail.duplicate"), icon: "copy", disabled: !writable, reason: writable ? undefined : t("vault.detail.read_only"),
        onSelect: () => env.navigate(`/nouveau/${encodeURIComponent(d.kind)}?copie=${id}`) },
      { label: t("vault.detail.move"), icon: "folder", disabled: !writable, reason: writable ? undefined : t("vault.detail.read_only"),
        onSelect: () => A.moveDialog(item, env) },
      { label: t("common.action.move_to_trash"), icon: "trash", danger: true, disabled: !writable, reason: writable ? undefined : t("vault.detail.read_only"),
        onSelect: () => A.moveToTrash(item, env).then((ok) => { if (ok) env.navigate(env.listPath(), { replace: true }); }) },
      "separator",
      { label: t("common.glossary.technical_details"), icon: "info", onSelect: () => technicalDialog(item) },
    ],
  });
  const Title = `h${heading}`;
  const head = h("header", { class: "l-stack", "data-gap": "2" },
    mobile ? h("a", { href: `#${env.listPath()}`, class: "c-button c-button--quiet" }, icon("arrow-left"), t("vault.detail.back")) : null,
    h("div", { class: "l-cluster", "data-justify": "between" },
      h("div", { class: "l-cluster" }, itemAvatar({ item: d, size: "lg" }), h(Title, { tabindex: "-1" }, d.name || t("vault.list.untitled"))),
      h("div", { class: "l-cluster" }, trashed ? null : star, more)),
    h("p", { class: "u-muted" }, t("vault.detail.kind_in", { kind: kindLabel(d.kind), vault: collectionLabel(col) })),
    audienceLine({ collection: { name: collectionLabel(col), personal: col?.personal }, members: col?.member_count || 0 }));

  // ---------------------------------------------------------- Avertissements
  const notices = [];
  if (trashed) notices.push(trashNotice(item));
  if (d.expires_at && d.expires_at < V.now()) {
    notices.push(h("div", { class: "c-alert", "data-tone": "warn" }, icon("clock"), h("p", {}, t("vault.detail.expired", { date: fmtDate(d.expires_at, "date") }))));
  }
  if (!writable && !trashed) {
    notices.push(h("p", { class: "c-policy-hint" }, icon("info", { size: "sm" }), t("vault.detail.read_only_role", { role: roleLabel(col?.role).toLowerCase() })));
  }

  // ---------------------------------------------------------- Lignes
  const totps = [];
  const rows = [];
  const pwRow = (label, value) => {
    if (!value) return null;
    const row = secretRow({ label, value, kind: "password", masked: true, mono: true, clickToCopy });
    if (label !== t("common.glossary.password") || d.kind !== "login") return row;
    const { score, issues } = passwordIssues(item);
    const chips = issues.map((x) => issueChip({
      issue: x.issue || x.text,
      href: x.fix === "weak" && writable && !trashed ? `#/element/${id}/modifier?regenerer=1` : "#/bilan",
    }));
    return h("div", {}, row, h("div", { class: "l-cluster" },
      score === null ? null : strengthMeter({ score, issues: issues.map((x) => x.issue || x.text) }), chips));
  };
  if (d.kind === "login") {
    rows.push(plain(t("common.glossary.username"), d.username, { kind: "username" }));
    rows.push(pwRow(t("common.glossary.password"), d.password));
    if (d.totp) {
      const code = totpCode({ config: d.totp });
      totps.push(code);
      rows.push(h("div", { class: "c-secret-row" }, h("div", { class: "c-field__label" }, t("common.glossary.verification_code")), code.el));
    }
    for (const u of d.urls || []) rows.push(siteRow(u));
  } else if (d.kind === "card") {
    rows.push(plain(t("vault.field.card_holder"), d.card?.holder));
    rows.push(secret(t("vault.field.card_number"), d.card?.number, { copyLabelKey: "vault.detail.copy_number" }));
    rows.push(plain(t("vault.field.card_expiry"), d.card?.expiry));
    rows.push(secret(t("vault.field.card_cvv"), d.card?.cvv, { copyLabelKey: "vault.detail.copy_cvv" }));
    rows.push(secret(t("vault.field.card_pin"), d.card?.pin, { copyLabelKey: "vault.detail.copy_pin" }));
  } else if (d.kind === "identity") {
    const i = d.identity || {};
    rows.push(plain(t("vault.field.first_name"), i.first_name), plain(t("vault.field.last_name"), i.last_name),
      plain(t("vault.field.email"), i.email), plain(t("vault.field.phone"), i.phone), plain(t("vault.field.company"), i.company),
      plain(t("vault.field.address"), i.address), secret(t("vault.field.document_number"), i.document_number, { mono: false }));
  } else if (d.kind === "ssh") {
    const s = d.ssh || {};
    rows.push(plain(t("vault.field.ssh_host"), s.host, { mono: true }), plain(t("common.glossary.username"), s.username, { kind: "username" }),
      plain(t("vault.field.ssh_port"), s.port, { mono: true }), pwRow(t("vault.field.ssh_password"), s.password),
      plain(t("vault.field.ssh_public_key"), s.public_key, { mono: true }),
      secret(t("vault.field.ssh_private_key"), s.private_key, { copyLabelKey: "vault.detail.copy_private_key" }),
      secret(t("vault.field.ssh_passphrase"), s.passphrase, { copyLabelKey: "vault.detail.copy_passphrase" }));
  }
  for (const f of d.fields || []) {
    rows.push(f.hidden ? secret(f.label || t("vault.field.custom"), f.value) : plain(f.label || t("vault.field.custom"), f.value));
  }
  if (d.notes) {
    rows.push(h("div", { class: "c-secret-row" }, h("div", { class: "c-field__label" }, t("vault.field.notes")),
      h("p", { class: "c-secret-row__value" }, d.notes)));
  }
  const tags = (d.tags || []).length ? h("p", { class: "l-cluster" }, d.tags.map((tag) => badge({ label: tag }))) : null;

  // ---------------------------------------------------------- Volets
  const attachments = attachmentsSection(item, env, { writable: writable && !trashed });
  const history = (d.password_history || []).length
    ? h("details", { class: "c-card" },
      h("summary", {}, t("vault.detail.history", { n: d.password_history.length })),
      d.password_history.map((p) => secretRow({ label: t("vault.detail.replaced_on", { date: fmtDate(p.changed_at) }), value: p.password, kind: "password", masked: true, mono: true })))
    : null;
  const links = h("p", { hidden: true });
  if (!trashed) activeLinks(item).then((n) => {
    if (!n) return;
    links.replaceChildren(h("a", { href: "#/liens" }, icon("link", { size: "sm" }), " ", plural("vault.detail.active_links", n)));
    links.hidden = false;
  });

  // ---------------------------------------------------------- Actions
  const actions = h("div", { class: "l-actionbar" });
  const paintActions = (isMobile) => {
    actions.replaceChildren(...(trashed ? trashActions(item, env, writable) : itemActions(item, env, writable, isMobile)));
  };
  paintActions(mobile);

  const meta = h("p", { class: "u-muted" }, t("vault.detail.meta", { created: relTime(item.created_at), updated: relTime(item.updated_at) }),
    d.password_changed_at ? ` · ${t("vault.detail.password_changed", { when: relTime(d.password_changed_at) })}` : "");

  const el = h("article", { class: "c-panel__body" },
    head, notices, lines(rows), tags, attachments, history, links, actions, meta);

  return {
    el,
    setMobile: paintActions,
    destroy() {
      for (const c of totps) c.destroy();
      while (cleanups.length) cleanups.pop()();
    },
  };
}

function siteRow(url) {
  const safe = safeUrl(url);
  const open = safe ? h("a", { class: "c-button c-button--quiet c-button--icon", href: safe, target: "_blank", rel: "noopener noreferrer", "aria-label": t("vault.detail.open_site"), title: t("vault.detail.open_site") }, icon("external")) : null;
  const row = secretRow({ label: t("vault.field.site"), value: url, kind: "text", masked: false, copyLabelKey: "vault.detail.copy_site" });
  if (open) row.querySelector(".c-secret-row__actions").prepend(open);
  return row;
}

function itemActions(item, env, writable, isMobile) {
  const id = encodeURIComponent(item.id);
  const edit = button({ label: t("common.action.edit"), icon: "edit", variant: isMobile ? "secondary" : "primary", onClick: () => env.navigate(`/element/${id}/modifier`) });
  if (!writable) setDisabled(edit, true, t("vault.detail.read_only_role", { role: roleLabel(collectionOf(item.collection_id)?.role).toLowerCase() }));
  else if (offline()) setDisabled(edit, true, t("vault.offline_reason"));
  const share = button({ label: t("common.action.share"), icon: "share", onClick: () => env.openShare(item) });
  const out = [];
  if (isMobile && primarySecret(item.data)) {
    out.push(button({ label: t("ui.secret.copy_password"), icon: "copy", variant: "primary", onClick: () => A.copyPrimary(item) }));
  }
  out.push(edit, share);
  return out;
}

function trashActions(item, env, writable) {
  const reason = writable ? undefined : t("vault.detail.read_only_role", { role: roleLabel(collectionOf(item.collection_id)?.role).toLowerCase() });
  return [
    button({ label: t("common.action.restore"), icon: "restore", variant: "primary", disabled: !writable, reason,
      onClick: () => A.restore(item, env) }),
    button({ label: t("common.action.delete_forever"), icon: "trash", variant: "danger", disabled: !writable, reason,
      onClick: async () => { if (await A.purge(item, env)) env.navigate("/corbeille", { replace: true }); } }),
  ];
}

/** Date de purge : celle du serveur, sinon suppression + délai de l'organisation (30 jours par défaut). */
export function purgeAt(item) {
  if (Number.isFinite(item.purge_at)) return item.purge_at;
  const days = Number(S.effective("retention.trash_days")?.value) || 30;
  return (item.deleted_at || 0) + days * 86400;
}

function trashNotice(item) {
  return h("div", { class: "c-alert", "data-tone": "warn" }, icon("trash"),
    h("p", {}, t("vault.trash.notice", { when: relTime(purgeAt(item)) })));
}

/** Liens sécurisés actifs de l'élément (serveur : item_id ; sinon correspondance des préférences). */
async function activeLinks(item) {
  try {
    const list = await api("GET", "/shares");
    const map = S.prefs().links || {};
    return (list || []).filter((s) => s.item_id === item.id || map[s.id]?.item_id === item.id).length;
  } catch {
    return 0;
  }
}

function attachmentsSection(item, env, { writable }) {
  const d = item.data;
  const list = d.attachments || [];
  const lim = V.attachmentLimits();
  if (!list.length && !(writable && lim.enabled)) return null;
  const input = h("input", { type: "file", hidden: true });
  input.addEventListener("change", async () => {
    const file = input.files[0];
    input.value = "";
    if (!file) return;
    try {
      await V.addAttachment(item, file);
    } catch (e) {
      errorNotice(e);
      return;
    }
    notify({ text: t("vault.attachments.added", { name: file.name }), tone: "ok" });
    await env.reload();
  });
  const addBtn = writable && lim.enabled
    ? button({ label: t("vault.attachments.add"), icon: "plus", onClick: () => input.click(), disabled: offline(), reason: offline() ? t("vault.offline_reason") : undefined })
    : null;
  const rows = list.map((a) => h("div", { class: "c-secret-row" },
    h("div", { class: "c-field__label" }, icon("attachment", { size: "sm" }), " ", a.name),
    h("div", { class: "c-secret-row__actions" },
      button({ label: t("common.action.download"), icon: "download", variant: "quiet",
        onClick: async () => {
          try { saveBlob(await V.downloadAttachment(a), a.name); } catch (e) { errorNotice(e); }
        } }),
      writable ? iconButton({ icon: "trash", label: t("vault.attachments.remove", { name: a.name }), onClick: () => removeAttachment(item, a, env) }) : null),
    h("div", { class: "c-secret-row__value u-muted" }, fmtBytes(a.size))));
  return h("details", { class: "c-card", open: list.length > 0 },
    h("summary", {}, t("vault.attachments.title", { n: list.length })),
    rows,
    addBtn ? h("div", { class: "l-cluster" }, addBtn, input,
      h("span", { class: "u-muted" }, t("vault.attachments.limit", { mib: lim.maxFileMib }))) : null);
}

async function removeAttachment(item, att, env) {
  const { confirmed } = await confirm({
    level: 1,
    title: t("vault.attachments.remove_title"),
    message: t("vault.attachments.remove_text"),
    objectName: att.name,
    confirmLabel: t("common.action.delete_forever"),
    danger: true,
  });
  if (!confirmed) return;
  try {
    await V.removeAttachment(item, att);
  } catch (e) {
    errorNotice(e);
    return;
  }
  notify({ text: t("vault.attachments.removed", { name: att.name }), tone: "ok" });
  await env.reload();
}

function technicalDialog(item) {
  const col = collectionOf(item.collection_id);
  const row = (k, v) => [h("dt", {}, k), h("dd", { class: "u-mono" }, String(v ?? "—"))];
  dialog({
    title: t("common.glossary.technical_details"),
    body: technicalDetails({
      body: h("dl", { class: "c-hotkeys" },
        row(t("vault.tech.item_id"), item.id), row(t("vault.tech.vault_id"), item.collection_id),
        row(t("vault.tech.revision"), item.revision), row(t("vault.tech.key_version"), col?.key_version),
        row(t("vault.tech.created"), fmtDate(item.created_at)), row(t("vault.tech.updated"), fmtDate(item.updated_at))),
    }),
    actions: [{ label: t("common.action.close"), variant: "primary" }],
  });
}
