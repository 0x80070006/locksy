// Paramètres › Mon activité (cahier §3.3.8) : les 200 derniers événements du
// compte (GET /me/audit), en phrases françaises : « Connexion à votre
// compte », « Chrome sur Windows ». Jamais d'identifiant technique (UUID) ni
// de code d'action à l'écran : une action inconnue de ce catalogue prend le
// libellé du journal d'administration (audit.event.<action>) s'il existe,
// sinon une phrase générique.
//
// Exports : eventText(entry), deviceText(texte), render(conteneur, ctx).

import {
  t, has, h, clear, dataTable, emptyState, errorState, withLoading, fmtDate, relTime, plural,
} from "../../ui/index.js";
import { api } from "../../api.js";

const PAGE_SIZE = 50;

/** Motifs de fin d'un lien (share.ended) dont le libellé existe (tools.links.reason.<motif>). */
const LINK_REASONS = new Set(["revoked", "revoked_admin", "expired", "exhausted", "item_deleted", "access_lost", "owner_disabled", "rotated"]);

/** Navigateurs et systèmes reconnus dans une chaîne d'agent (ordre significatif). */
const BROWSERS = Object.freeze([[/Edg(e|A|iOS)?\//, "edge"], [/OPR\/|Opera/, "opera"], [/Firefox\/|FxiOS/, "firefox"],
  [/Chrome\/|CriOS/, "chrome"], [/Safari\//, "safari"], [/locksy/i, "locksy"]]);
const SYSTEMS = Object.freeze([[/Windows/, "windows"], [/iPhone|iPad|iOS/, "ios"], [/Mac OS|Macintosh/, "macos"],
  [/Android/, "android"], [/CrOS/, "chromeos"], [/Linux/, "linux"]]);

const pick = (table, text) => table.find(([re]) => re.test(text))?.[1] ?? null;

/**
 * Appareil lisible : une chaîne d'agent brute (« Mozilla/5.0 … ») devient
 * « Chrome sur Windows » ; un nom déjà lisible (« Web · Firefox sur Linux »,
 * donné par le client à la connexion) est gardé tel quel.
 */
export function deviceText(raw) {
  const text = String(raw ?? "").trim();
  if (!text) return t("settings_user.devices.unknown_device");
  if (!/Mozilla\/|AppleWebKit|\b[A-Za-z]+\/\d/.test(text)) return text;
  const browser = pick(BROWSERS, text);
  const os = pick(SYSTEMS, text);
  const b = browser ? t(`settings_user.activity.browser.${browser}`) : t("settings_user.activity.browser.other");
  return os ? t("settings_user.activity.device", { browser: b, os: t(`settings_user.activity.os.${os}`) }) : b;
}

/** Phrase d'un événement du journal personnel (sans identifiant ni code). */
export function eventText(entry) {
  const action = String(entry?.action ?? "");
  if (action === "share.ended" && LINK_REASONS.has(entry.details)) {
    return t("settings_user.activity.share_ended_reason", { reason: t(`tools.links.reason.${entry.details}`) });
  }
  const own = `settings_user.activity.event.${action}`;
  if (/^[a-z0-9_]+(\.[a-z0-9_-]+)+$/.test(action)) {
    if (has(own)) return t(own);
    if (has(`audit.event.${action}`)) return t(`audit.event.${action}`);
  }
  return t("settings_user.activity.event_other");
}

export async function render(container) {
  let disposed = false;
  const body = h("div", { class: "l-stack", "data-gap": "4" });
  clear(container, h("section", { class: "c-card l-stack", "data-gap": "4", "aria-labelledby": "titre-mon-activite" },
    h("h2", { id: "titre-mon-activite" }, t("settings_user.activity.title")),
    h("p", { class: "u-muted" }, t("settings_user.activity.help")),
    body,
    h("p", {}, h("a", { href: "#/parametres/appareils" }, t("settings_user.activity.back")))));

  async function load() {
    let list;
    try {
      list = await withLoading(body, api("GET", "/me/audit"));
    } catch (e) {
      if (!disposed) clear(body, errorState({ error: e, title: t("settings_user.activity.load_failed"), onRetry: load }));
      return;
    }
    if (disposed) return;
    const rows = (Array.isArray(list) ? list : []).map((e) => ({
      key: String(e.id),
      at: e.at,
      text: eventText(e),
      device: e.user_agent ? deviceText(e.user_agent) : "",
      ip: e.ip || "",
    }));
    if (!rows.length) {
      clear(body, emptyState({ icon: "history", title: t("settings_user.activity.empty") }));
      return;
    }
    let page = 1;
    const slice = () => rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
    const table = dataTable({
      caption: plural("settings_user.activity.caption", rows.length),
      rows: slice(),
      rowKey: (r) => r.key,
      rowLabel: (r) => r.text,
      page,
      pageSize: PAGE_SIZE,
      total: rows.length,
      onPage: (n) => {
        page = n;
        table.update({ page, rows: slice() });
      },
      columns: [
        { key: "at", label: t("settings_user.activity.col_date"), render: (r) => h("span", { title: fmtDate(r.at) }, relTime(r.at)) },
        { key: "text", label: t("settings_user.activity.col_event"), render: (r) => r.text },
        { key: "device", label: t("settings_user.activity.col_device"), render: (r) => r.device || h("span", { class: "u-muted" }, t("settings_user.activity.no_device")) },
        { key: "ip", label: t("settings_user.activity.col_ip"), render: (r) => (r.ip ? h("span", { class: "u-mono" }, r.ip) : "") },
      ],
    });
    clear(body, table.el);
  }

  await load();
  return { dispose() { disposed = true; }, isDirty: () => false };
}
