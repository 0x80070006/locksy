// Paramètres › Appareils et sessions (cahier §3.3.8) : sessions ouvertes
// (appareil, adresse, dernière activité), « Fermer » une session ou toutes
// les autres, et lien vers « Mon activité ».
//
// La session de cet appareil n'a pas de bouton « Fermer » : on la quitte par
// « Se déconnecter » (menu du compte).

import {
  t, plural, h, clear, button, badge, notify, dataTable, emptyState, errorState, withLoading, keepFocus, confirm,
  fmtDate, relTime, errorText,
} from "../../ui/index.js";
import { api } from "../../api.js";
import { deviceText } from "./activity.js";

/** Libellé lisible d'une session (navigateur et système, sinon le nom envoyé à la connexion). */
export function sessionLabel(s) {
  return s.device ? deviceText(s.device) : t("settings_user.devices.unknown_device");
}

export async function render(container) {
  let disposed = false;
  const body = h("div", { class: "l-stack", "data-gap": "4" });
  clear(container,
    h("section", { class: "c-card l-stack", "data-gap": "4", "aria-labelledby": "titre-sessions" },
      h("h2", { id: "titre-sessions" }, t("settings_user.devices.heading")),
      h("p", { class: "u-muted" }, t("settings_user.devices.help")),
      body),
    h("section", { class: "c-card l-stack", "data-gap": "2", "aria-labelledby": "titre-activite" },
      h("h2", { id: "titre-activite" }, t("settings_user.activity.title")),
      h("p", { class: "u-muted" }, t("settings_user.devices.activity_help")),
      h("p", {}, h("a", { href: "#/parametres/activite" }, t("settings_user.devices.activity_link")))));

  async function close(session) {
    try {
      await api("DELETE", `/me/sessions/${encodeURIComponent(session.id)}`);
    } catch (e) {
      notify({ text: t("settings_user.devices.close_failed", { reason: errorText(e) }), tone: "danger" });
      return;
    }
    notify({ text: t("settings_user.devices.closed"), tone: "ok" });
    await keepFocus(body, load);
  }

  async function closeOthers(others) {
    const { confirmed } = await confirm({
      level: 1,
      title: t("settings_user.devices.close_others_title"),
      message: plural("settings_user.devices.close_others_message", others.length),
      confirmLabel: t("settings_user.devices.close_others"),
      danger: true,
    });
    if (!confirmed) return;
    let failed = null;
    let done = 0;
    for (const s of others) {
      try {
        await api("DELETE", `/me/sessions/${encodeURIComponent(s.id)}`);
        done += 1;
      } catch (e) {
        failed = e;
        break;
      }
    }
    if (failed) notify({ text: t("settings_user.devices.close_others_failed", { done, reason: errorText(failed) }), tone: "danger" });
    else notify({ text: plural("settings_user.devices.closed_others", done), tone: "ok" });
    await keepFocus(body, load);
  }

  async function load() {
    let list;
    try {
      list = await withLoading(body, api("GET", "/me/sessions"));
    } catch (e) {
      if (!disposed) clear(body, errorState({ error: e, title: t("settings_user.devices.load_failed"), onRetry: load }));
      return;
    }
    if (disposed) return;
    const rows = Array.isArray(list) ? list : [];
    if (!rows.length) {
      clear(body, emptyState({ icon: "user", title: t("settings_user.devices.empty") }));
      return;
    }
    const others = rows.filter((s) => !s.current);
    const table = dataTable({
      caption: plural("settings_user.devices.caption", rows.length),
      rows,
      rowKey: (s) => s.id,
      rowLabel: sessionLabel,
      columns: [
        {
          key: "device", label: t("settings_user.devices.col_device"),
          render: (s) => h("span", { class: "l-cluster" }, h("strong", {}, sessionLabel(s)),
            s.current ? badge({ tone: "ok", icon: "check", label: t("settings_user.devices.this_device") }) : null),
        },
        { key: "ip", label: t("settings_user.devices.col_ip"), render: (s) => h("span", { class: "u-mono" }, s.ip || t("settings_user.devices.no_ip")) },
        {
          key: "seen", label: t("settings_user.devices.col_seen"),
          render: (s) => h("span", { title: fmtDate(s.last_seen_at) }, relTime(s.last_seen_at)),
        },
        { key: "since", label: t("settings_user.devices.col_since"), render: (s) => fmtDate(s.created_at, "date") },
        {
          key: "action", label: t("settings_user.devices.col_action"),
          render: (s) => (s.current
            ? h("span", { class: "u-muted" }, t("settings_user.devices.current_hint"))
            : button({
              label: t("settings_user.devices.close"), busyLabel: t("settings_user.devices.closing"),
              attrs: { "aria-label": t("settings_user.devices.close_named", { device: sessionLabel(s) }), "data-focus-key": `fermer:${s.id}` },
              onClick: () => close(s),
            })),
        },
      ],
    });
    clear(body, table.el,
      others.length > 1 ? h("div", { class: "l-cluster" }, button({
        label: t("settings_user.devices.close_others"), variant: "danger", attrs: { "data-focus-key": "fermer-autres" },
        onClick: () => closeOthers(others),
      })) : null);
  }

  await load();
  return { dispose() { disposed = true; }, isDirty: () => false };
}
