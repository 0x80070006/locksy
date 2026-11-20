// Réglages › Système (cahier §3.4.6, contrats C1.5 et C1.6) :
//   - service : version du serveur, version de la base et du registre des
//     réglages, état de la base, dernière sauvegarde, avertissements de lecture ;
//   - e-mails : état de l'envoi, « Envoyer un e-mail de test » (résultat lisible
//     selon le code d'échec), envois en échec avec « Renvoyer » ;
//   - journal : « Vérifier le journal » (chaînage des événements) ;
//   - quotas : pièces jointes (réglages en contexte) et plafonds de l'hébergeur ;
//   - configuration de l'hébergeur (propriétaires), secrets masqués, avec la
//     source de chaque valeur. Les noms de variables sont techniques : ils sont
//     marqués data-technical.
// Chaque bloc se replie proprement si la route manque (serveur plus ancien).

import {
  t, plural, has, h, clear, button, notify, errorText, relTime, fmtDate, fmtNumber, statusCard, alertCard,
  field, textInput, dataTable, skeleton, technicalDetails, settingLabel,
} from "../../ui/index.js";
import { api } from "../../api.js";
import { isOwner, me, routeMissing } from "./shell.js";
import { loadSettings, settingsStore, settingsNav, defOf, currentValue, openSettingPanel } from "./settings.js";

const MAIL_KEYS = Object.freeze(["mail.enabled", "mail.smtp.host", "mail.smtp.port", "mail.smtp.security", "mail.smtp.username", "mail.smtp.password", "mail.from"]);
const QUOTA_KEYS = Object.freeze(["attachment.max_file_mib", "attachment.quota_user_mib", "attachment.quota_total_mib"]);
/** Quotas pour lesquels 0 veut dire « sans limite ». */
const UNLIMITED_AT_ZERO = Object.freeze(["attachment.quota_user_mib", "attachment.quota_total_mib"]);

const valueOf = currentValue;

/** « 10 Mio », ou « Illimité » pour un quota à 0. */
function quotaText(key) {
  const v = Number(valueOf(key));
  if (!Number.isFinite(v)) return t("admin.value.none");
  if (v === 0 && UNLIMITED_AT_ZERO.includes(key)) return t("admin.system.quotas.unlimited");
  return t("ui.unit.mib", { n: fmtNumber(v) });
}

export async function renderPage(ctx, container, route) {
  let disposed = false;
  try {
    await loadSettings({ force: true });
  } catch {
    /* blocs dépendants des réglages affichés en mode dégradé */
  }
  if (route.subnav) clear(route.subnav, settingsNav("systeme"));

  const service = h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "systeme-service" });
  const mail = h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "systeme-mail" });
  const journal = h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "systeme-journal" });
  const quotas = h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "systeme-quotas" });
  const host = h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "systeme-hebergeur" });
  clear(container,
    h("h1", { tabindex: "-1" }, t("admin.system.title")),
    h("p", { class: "u-muted" }, t("admin.system.intro")),
    service, mail, journal, quotas, isOwner(ctx) ? host : null);

  const live = () => !disposed;
  await Promise.all([
    paintService(service, live),
    paintMail(ctx, mail, live),
    paintJournal(journal),
    paintQuotas(ctx, quotas),
    isOwner(ctx) ? paintHost(host, live) : null,
  ]);
  return {
    dispose() {
      disposed = true;
    },
    isDirty: () => false,
  };
}

// ------------------------------------------------------------------ Service

async function paintService(section, live) {
  clear(section, h("h2", { id: "systeme-service" }, t("admin.system.service.title")), skeleton({ lines: 3 }));
  const [ready, stats] = await Promise.all([
    api("GET", "/ready").catch((e) => ({ error: e })),
    api("GET", "/admin/stats").catch(() => ({})),
  ]);
  if (!live()) return;
  const values = settingsStore.values || {};
  const warnings = values.warnings || [];
  const cards = [
    ready.error
      ? statusCard({ tone: "danger", title: t("admin.system.service.db_down"), detail: errorText(ready.error) })
      : statusCard({
        tone: "ok",
        title: t("admin.system.service.server", { version: ready.version || "" }),
        detail: t("admin.system.service.schema", { db: ready.schema_version ?? "", settings: values.schema_version ?? "" }),
      }),
    statusCard({
      tone: stats.last_backup_at ? "ok" : "neutral",
      title: stats.last_backup_at ? t("admin.system.service.backup", { when: relTime(stats.last_backup_at) }) : t("admin.system.service.backup_unknown"),
      detail: t("admin.system.service.backup_help"),
    }),
    values.revision !== undefined && values.revision !== null
      ? statusCard({
        tone: "info",
        title: t("admin.system.service.revision", { revision: values.revision }),
        detail: values.last_change?.at ? t("admin.system.service.last_change", { by: values.last_change.by || "", when: relTime(values.last_change.at) }) : null,
        action: { label: t("admin.system.service.history"), href: "#/admin/reglages/historique" },
      })
      : null,
  ];
  clear(section,
    h("h2", { id: "systeme-service" }, t("admin.system.service.title")),
    h("div", { class: "l-grid" }, cards),
    warnings.length ? h("div", { class: "l-stack", "data-gap": "2" }, warnings.map((w) => alertCard({
      tone: w.code === "read_error" ? "danger" : "warn",
      text: `${settingLabel(w.key)} : ${has(`settings.warning.${w.code}`) ? t(`settings.warning.${w.code}`, w.params || {}) : t("admin.settings.warning_generic")}`,
      action: defOf(w.key) ? { label: t("admin.system.fix"), href: `#/admin/reglages/${defOf(w.key).section}` } : null,
    }))) : null);
}

// ------------------------------------------------------------------ E-mails

async function paintMail(ctx, section, live) {
  const enabled = valueOf("mail.enabled") === true;
  const hostName = valueOf("mail.smtp.host") || "";
  const result = h("div", { class: "l-stack", "data-gap": "2" });
  const queue = h("div", { class: "l-stack", "data-gap": "2" });
  const to = textInput({ type: "email", value: me(ctx).email || "", autocomplete: "off" });
  const send = button({
    label: t("admin.system.mail.test"), icon: "mail", busyLabel: t("admin.system.mail.sending"),
    onClick: async () => {
      const address = to.value.trim();
      try {
        await api("POST", "/admin/mail/test", address ? { to: address } : {}, { retry: false });
        clear(result, alertCard({ tone: "ok", text: t("admin.system.mail.sent", { to: address || me(ctx).email || "" }) }));
        notify({ text: t("admin.system.mail.sent_short"), tone: "ok" });
      } catch (e) {
        clear(result, mailError(e));
      }
    },
  });
  clear(section,
    h("h2", { id: "systeme-mail" }, t("admin.system.mail.title")),
    statusCard({
      tone: enabled ? "ok" : "neutral",
      title: enabled ? t("admin.system.mail.on", { host: hostName || t("admin.system.mail.no_host") }) : t("admin.system.mail.off"),
      detail: enabled ? null : t("admin.system.mail.off_detail"),
      action: { label: t("admin.system.mail.configure"), onClick: () => openSettingPanel(ctx, MAIL_KEYS, { title: t("admin.system.mail.title") }).then((saved) => { if (saved && live()) paintMail(ctx, section, live); }) },
    }),
    field({ label: t("admin.system.mail.to"), help: t("admin.system.mail.to_help"), input: to }),
    h("div", { class: "l-cluster" }, send),
    result,
    h("h3", {}, t("admin.system.mail.queue_title")),
    queue);
  await paintQueue(queue, live);
}

/** Échec d'un e-mail de test, expliqué selon le code stable du serveur. */
function mailError(e) {
  const code = e?.params?.error_code;
  const detail = code && has(`mail.error_code.${code}`) ? t(`mail.error_code.${code}`) : null;
  if (routeMissing(e)) return alertCard({ tone: "info", text: t("admin.system.mail.unavailable") });
  return alertCard({
    tone: "danger",
    title: errorText(e),
    text: detail,
  });
}

async function paintQueue(container, live) {
  clear(container, skeleton({ lines: 2 }));
  let rows;
  try {
    rows = await api("GET", "/admin/mail/queue?status=failed");
  } catch (e) {
    if (!live()) return;
    clear(container, routeMissing(e)
      ? h("p", { class: "u-muted" }, t("admin.system.mail.queue_unavailable"))
      : alertCard({ tone: "danger", text: errorText(e), action: { label: t("common.action.retry"), onClick: () => paintQueue(container, live) } }));
    return;
  }
  if (!live()) return;
  if (!Array.isArray(rows) || !rows.length) {
    clear(container, h("p", { class: "u-muted" }, t("admin.system.mail.queue_empty")));
    return;
  }
  const table = dataTable({
    caption: plural("admin.system.mail.queue_caption", rows.length),
    columns: [
      { key: "kind", label: t("admin.system.mail.col_kind"), render: (r) => (has(`mail.kind.${r.kind}`) ? t(`mail.kind.${r.kind}`) : t("admin.system.mail.kind_other")) },
      { key: "to", label: t("admin.system.mail.col_to"), render: (r) => r.to_email },
      { key: "error", label: t("admin.system.mail.col_error"), render: (r) => (r.last_error_code && has(`mail.error_code.${r.last_error_code}`) ? t(`mail.error_code.${r.last_error_code}`) : t("admin.system.mail.error_other")) },
      { key: "attempts", label: t("admin.system.mail.col_attempts"), numeric: true, render: (r) => fmtNumber(Number(r.attempts) || 0) },
      { key: "at", label: t("admin.system.mail.col_date"), render: (r) => h("span", { class: "u-nowrap", title: fmtDate(r.updated_at, "long") }, relTime(r.updated_at)) },
      {
        key: "retry", label: t("admin.system.mail.col_action"),
        render: (r) => button({
          label: t("admin.system.mail.retry"), icon: "refresh", busyLabel: t("admin.system.mail.retrying"),
          attrs: { "aria-label": t("admin.system.mail.retry_named", { to: r.to_email }) },
          onClick: async () => {
            try {
              await api("POST", `/admin/mail/queue/${encodeURIComponent(r.id)}/retry`);
              notify({ text: t("admin.system.mail.retried"), tone: "ok" });
              await paintQueue(container, live);
            } catch (e) {
              notify({ text: errorText(e), tone: "danger" });
            }
          },
        }),
      },
    ],
    rows,
    rowKey: (r) => r.id,
  });
  clear(container, table.el);
}

// ------------------------------------------------------------------ Journal

async function paintJournal(section) {
  const result = h("div", { class: "l-stack", "data-gap": "2" });
  clear(section,
    h("h2", { id: "systeme-journal" }, t("admin.system.audit.title")),
    h("p", {}, t("admin.system.audit.intro")),
    h("div", { class: "l-cluster" },
      button({
        label: t("admin.system.audit.verify"), icon: "shield", busyLabel: t("admin.system.audit.verifying"),
        onClick: async () => {
          try {
            const r = await api("GET", "/admin/audit/verify", undefined, { retry: false });
            clear(result, verifyReport(r));
          } catch (e) {
            clear(result, routeMissing(e)
              ? alertCard({ tone: "info", text: t("admin.system.audit.unavailable") })
              : alertCard({ tone: "danger", text: errorText(e) }));
          }
        },
      })),
    result);
}

/** Résultat d'une vérification du chaînage (contrat C1.6). */
function verifyReport(r) {
  const breaks = r.breaks || [];
  const notes = [];
  if (r.unchained_before) notes.push(h("p", { class: "u-muted" }, t("admin.system.audit.unchained", { id: fmtNumber(r.unchained_before) })));
  const details = technicalDetails({
    body: h("ul", {},
      h("li", {}, t("admin.system.audit.range", { first: r.first_id ?? "", last: r.last_id ?? "" })),
      breaks.map((b) => h("li", {}, t("admin.system.audit.break_line", {
        id: b.id, kind: has(`admin.system.audit.break.${b.kind}`) ? t(`admin.system.audit.break.${b.kind}`) : b.kind,
      })))),
  });
  if (r.ok) {
    return h("div", { class: "l-stack", "data-gap": "2" },
      alertCard({
        tone: "ok",
        title: t("admin.system.audit.ok"),
        text: t("admin.system.audit.ok_detail", { checked: fmtNumber(r.checked || 0), anchors: fmtNumber(r.anchors || 0), when: fmtDate(r.verified_at || Date.now() / 1000) }),
      }),
      ...notes, details);
  }
  return h("div", { class: "l-stack", "data-gap": "2" },
    alertCard({ tone: "danger", title: t("admin.system.audit.broken"), text: plural("admin.system.audit.broken_detail", breaks.length) }),
    ...notes, details);
}

// ------------------------------------------------------------------ Quotas

async function paintQuotas(ctx, section) {
  const lines = QUOTA_KEYS.filter((k) => defOf(k)).map((k) => h("li", {},
    h("strong", {}, settingLabel(k)), " : ", quotaText(k)));
  clear(section,
    h("h2", { id: "systeme-quotas" }, t("admin.system.quotas.title")),
    h("p", {}, t("admin.system.quotas.intro")),
    lines.length ? h("ul", { class: "l-stack", "data-gap": "1" }, lines) : h("p", { class: "u-muted" }, t("admin.system.quotas.unavailable")),
    lines.length ? h("div", { class: "l-cluster" }, button({
      label: t("admin.system.quotas.change"), icon: "settings",
      onClick: async () => {
        if (await openSettingPanel(ctx, QUOTA_KEYS, { title: t("admin.system.quotas.title") })) paintQuotas(ctx, section);
      },
    })) : null);
}

// ------------------------------------------------------------------ Hébergeur

const SOURCE_KEYS = Object.freeze({ env: "admin.system.host.source.env", file: "admin.system.host.source.file", default: "admin.system.host.source.default" });

async function paintHost(section, live) {
  clear(section, h("h2", { id: "systeme-hebergeur" }, t("admin.system.host.title")), skeleton({ lines: 3 }));
  let cfg;
  try {
    cfg = await api("GET", "/admin/config/effective");
  } catch (e) {
    if (!live()) return;
    clear(section, h("h2", { id: "systeme-hebergeur" }, t("admin.system.host.title")),
      routeMissing(e) ? h("p", { class: "u-muted" }, t("admin.system.host.unavailable")) : alertCard({ tone: "danger", text: errorText(e) }));
    return;
  }
  if (!live()) return;
  const vars = cfg.vars || [];
  const rate = cfg.rate_limits || {};
  const table = dataTable({
    caption: t("admin.system.host.caption"),
    columns: [
      { key: "name", label: t("admin.system.host.col_name"), render: (v) => h("code", { class: "u-mono" }, v.name) },
      { key: "value", label: t("admin.system.host.col_value"), render: (v) => (v.secret ? t("ui.value.secret") : h("code", { class: "u-mono" }, String(v.value ?? ""))) },
      { key: "source", label: t("admin.system.host.col_source"), render: (v) => t(SOURCE_KEYS[v.source] || "admin.system.host.source.other") },
    ],
    rows: vars,
    rowKey: (v) => v.name,
  });
  const limits = ["login_ip", "prelogin_ip", "register_ip", "recover_ip", "share_open_ip", "invite_ip"]
    .filter((k) => rate[k] !== undefined)
    .map((k) => h("li", {}, t(`admin.system.host.rate.${k}`, { n: fmtNumber(Number(rate[k]) || 0) })));
  clear(section,
    h("h2", { id: "systeme-hebergeur" }, t("admin.system.host.title")),
    h("p", {}, t("admin.system.host.intro")),
    h("div", { "data-technical": "" }, table.el),
    limits.length ? h("h3", {}, t("admin.system.host.rate_title")) : null,
    limits.length ? h("ul", { class: "l-stack", "data-gap": "1" }, limits) : null,
    rate.factor !== undefined ? h("p", { class: "u-muted" }, t("admin.system.host.factor", { factor: fmtNumber(Number(rate.factor) || 1) })) : null);
}
