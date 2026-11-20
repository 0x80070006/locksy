// Liens envoyés (#/liens, cahier §3.3.5) : les liens sécurisés créés par la
// personne, actifs et terminés, avec leur état lisible et « Révoquer ».
//
// Le nom de l'élément ne vient jamais du serveur : il est lu dans le coffre
// déchiffré (élément rattaché au lien) ou dans les préférences chiffrées
// (prefs.links, nom gardé localement à la création) ; sinon « Élément
// supprimé ». Serveur sans GET /shares?all=1 : la liste des liens actifs
// (GET /shares) suffit.

import { t, plural, h, clear, button, badge, confirm, notify, dataTable, emptyState, errorState, withLoading, keepFocus, fmtDate, fmtNumber, errorText } from "../../ui/index.js";
import { api } from "../../api.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";

/** Motifs de fin connus (shares.ended_reason) ; libellés tools.links.reason.<motif>. */
const REASONS = new Set(["revoked", "revoked_admin", "expired", "exhausted", "item_deleted", "access_lost", "owner_disabled", "rotated"]);

/** Liens de la personne : tous (serveur récent) ou actifs seulement (repli). */
export async function loadLinks() {
  let rows;
  try {
    rows = await api("GET", "/shares?all=1");
  } catch (e) {
    if (e?.status !== 400 && e?.status !== 404) throw e;
    rows = await api("GET", "/shares");
  }
  const now = Date.now() / 1000;
  return (Array.isArray(rows) ? rows : []).map((r) => {
    let state = r.state || "active";
    let reason = r.ended_reason || null;
    // Lien encore marqué actif mais échu ou épuisé (maintenance pas encore passée).
    if (state === "active" && r.views >= r.max_views) { state = "exhausted"; reason = "exhausted"; }
    else if (state === "active" && r.expires_at <= now) { state = "expired"; reason = "expired"; }
    if (state !== "active" && !reason) reason = REASONS.has(state) ? state : "revoked";
    return { ...r, state, reason };
  });
}

/** Nom local du lien : élément du coffre, nom gardé à la création, ou « Élément supprimé ». */
export function linkLabel(link, prefsLinks = {}, items = V.state.items) {
  const local = prefsLinks?.[link.id];
  const itemId = link.item_id || local?.item_id;
  const item = itemId ? items.get(itemId) : null;
  if (item?.data && !item.deleted_at && item.data.name) return { text: item.data.name, known: true };
  if (local?.label) return { text: local.label, known: true };
  return { text: t("tools.links.item_deleted"), known: false };
}

function stateBadge(link) {
  if (link.state === "active") return badge({ tone: "ok", icon: "check", label: t("tools.links.state_active") });
  const reason = REASONS.has(link.reason) ? link.reason : "revoked";
  const tone = reason === "revoked_admin" || reason === "owner_disabled" ? "warn" : "neutral";
  return badge({ tone, label: t(`tools.links.reason.${reason}`) });
}

export async function render(ctx) {
  const settings = ctx.settings || S;
  const body = h("div", { class: "l-stack", "data-gap": "5" });
  clear(ctx.root, h("div", { class: "l-stack", "data-gap": "5" },
    h("h1", { tabindex: "-1" }, t("tools.links.title")),
    h("p", { class: "u-muted" }, t("tools.links.intro")),
    body));
  let disposed = false;

  async function revoke(link, label) {
    const { confirmed } = await confirm({
      level: 1,
      title: t("tools.links.revoke_title"),
      message: t("tools.links.revoke_message"),
      objectName: label,
      confirmLabel: t("common.action.revoke"),
      danger: true,
    });
    if (!confirmed) return;
    try {
      await api("DELETE", `/shares/${encodeURIComponent(link.id)}`);
    } catch (e) {
      notify({ text: t("tools.links.revoke_failed", { reason: errorText(e) }), tone: "danger" });
      return;
    }
    notify({ text: t("tools.links.revoked"), tone: "ok" });
    await keepFocus(body, load);
  }

  function table(caption, rows, prefsLinks, active) {
    return dataTable({
      caption,
      rows,
      rowKey: (r) => r.id,
      rowLabel: (r) => linkLabel(r, prefsLinks).text,
      columns: [
        {
          key: "item", label: t("tools.links.col_item"),
          render: (r) => {
            const l = linkLabel(r, prefsLinks);
            return l.known ? h("strong", {}, l.text) : h("span", { class: "u-muted" }, l.text);
          },
        },
        { key: "state", label: t("tools.links.col_state"), render: stateBadge },
        {
          key: "date", label: active ? t("tools.links.col_expires") : t("tools.links.col_ended"),
          render: (r) => fmtDate(active ? r.expires_at : (r.ended_at || r.expires_at)),
        },
        {
          key: "views", label: t("tools.links.col_views"), numeric: true,
          render: (r) => t("tools.links.views", { views: fmtNumber(r.views), max: fmtNumber(r.max_views) }),
        },
        active ? {
          key: "action", label: t("tools.links.col_action"),
          render: (r) => button({
            label: t("common.action.revoke"), variant: "danger",
            attrs: { "aria-label": t("tools.links.revoke_named", { name: linkLabel(r, prefsLinks).text }), "data-focus-key": `revoquer:${r.id}` },
            onClick: () => revoke(r, linkLabel(r, prefsLinks).text),
          }),
        } : null,
      ].filter(Boolean),
    }).el;
  }

  async function load() {
    let links;
    try {
      links = await withLoading(body, loadLinks());
    } catch (e) {
      if (!disposed) clear(body, errorState({ error: e, title: t("tools.links.load_failed"), onRetry: load }));
      return;
    }
    if (disposed) return;
    const prefsLinks = settings.prefs?.().links || {};
    const active = links.filter((l) => l.state === "active");
    const ended = links.filter((l) => l.state !== "active");
    if (!links.length) {
      clear(body, emptyState({ icon: "link", title: t("tools.links.empty_title"), text: t("tools.links.empty_text") }));
      return;
    }
    clear(body,
      active.length
        ? table(plural("tools.links.active", active.length), active, prefsLinks, true)
        : h("p", { class: "u-muted" }, t("tools.links.none_active")),
      ended.length ? table(plural("tools.links.ended", ended.length), ended, prefsLinks, false) : null);
  }

  await load();
  return { dispose() { disposed = true; }, isDirty: () => false };
}
