// Onglet « Par lien sécurisé » de la fenêtre de partage (cahier §3.3.5) :
// pour une personne sans Locksy. Durée et nombre d'ouvertures bornés par la
// politique (share.*) ; contenu choisi champ par champ ; le nom n'est PAS
// envoyé tant que « Inclure le nom » n'est pas coché (correctif P0 01-5) ;
// le lien est rattaché à l'élément (révocation automatique côté serveur) et
// la correspondance lien -> élément est gardée dans les préférences chiffrées.
//
//   linkPayload(data, parts, includeName) -> objet chiffré dans le lien
//   renderLinkTab(panel, item, env)        remplit le panneau de l'onglet

import {
  t, plural, fmtDate, h, icon, button, field, selectInput, durationSelect, formatDuration, checkboxGroup, copySecret,
  confirm, notify, errorText, policyHint, textInput, announce,
} from "../../ui/index.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";
import { policy, offline } from "./common.js";

const EXPIRY_PRESETS = [60, 240, 1440, 4320, 10_080, 43_200];
const VIEW_PRESETS = [1, 2, 3, 5, 10, 20, 50, 100];

/** Parties partageables d'un élément, selon son type : [{ value, labelKey, checked }]. */
export function shareableParts(d) {
  const parts = [];
  const add = (value, labelKey, present, checked = true) => { if (present) parts.push({ value, labelKey, checked }); };
  switch (d.kind) {
    case "login":
      add("username", "common.glossary.username", !!d.username);
      add("password", "common.glossary.password", !!d.password);
      add("urls", "vault.field.site", (d.urls || []).length > 0);
      add("totp", "common.glossary.verification_code", !!d.totp, false);
      break;
    case "card": add("card", "vault.kind.card", !!(d.card?.number || d.card?.holder)); break;
    case "identity": add("identity", "vault.kind.identity", Object.values(d.identity || {}).some(Boolean)); break;
    case "ssh": add("ssh", "vault.link.part.ssh", Object.values(d.ssh || {}).some(Boolean)); break;
    default: break;
  }
  add("notes", "vault.field.notes", !!d.notes, d.kind === "note");
  return parts;
}

/** Charge chiffrée du lien : uniquement les parties choisies (et le nom s'il est inclus). */
export function linkPayload(d, parts, includeName) {
  const chosen = new Set(parts);
  const out = {};
  if (includeName && d.name) out.name = d.name;
  if (chosen.has("username") && d.username) out.username = d.username;
  if (chosen.has("password") && d.password) out.password = d.password;
  if (chosen.has("urls") && (d.urls || []).length) out.urls = [...d.urls];
  if (chosen.has("totp") && d.totp) out.totp = d.totp;
  if (chosen.has("notes") && d.notes) out.notes = d.notes;
  if (chosen.has("card") && d.card) out.card = { ...d.card };
  if (chosen.has("identity") && d.identity) out.identity = { ...d.identity };
  if (chosen.has("ssh") && d.ssh) out.ssh = { ...d.ssh };
  return out;
}

/** Bornes de l'organisation : { maxMinutes, maxViews, minutes, views }. */
function bounds() {
  const maxMinutes = Number(policy("share.max_expiry_minutes", 43_200)) || 43_200;
  const maxViews = Number(policy("share.max_views", 100)) || 100;
  const minutes = Math.min(Number(S.effective("share.default_expiry_minutes").value) || 1440, maxMinutes);
  const views = Math.min(Number(S.effective("share.default_views").value) || 1, maxViews);
  return { maxMinutes, maxViews, minutes, views };
}

export function renderLinkTab(panel, item, env) {
  const d = item.data;
  if (policy("share.enabled", true) === false) {
    panel.replaceChildren(h("div", { class: "c-panel__body l-stack", "data-gap": "3" },
      policyHint({ mode: "enforced" }),
      h("p", {}, t("vault.link.disabled"))));
    return;
  }
  const b = bounds();
  let minutes = b.minutes;
  const expiry = durationSelect({
    label: t("vault.link.expiry"), value: minutes, presets: EXPIRY_PRESETS.filter((m) => m <= 43_200), min: 5, max: b.maxMinutes,
    disabledReason: t("vault.link.limited", { max: formatDuration(b.maxMinutes) }),
    onChange: (v) => { minutes = v; },
  });
  const viewOptions = S.optionsFor("share.default_views", VIEW_PRESETS);
  const viewsSelect = selectInput({
    name: "ouvertures",
    value: String(b.views),
    options: VIEW_PRESETS.map((v, i) => {
      const blocked = v > b.maxViews || viewOptions[i]?.disabled;
      return {
        value: String(v),
        label: blocked ? t("vault.link.views_unavailable", { label: plural("vault.link.views_n", v) }) : plural("vault.link.views_n", v),
        disabled: blocked,
        title: blocked ? t("vault.link.views_limited", { max: b.maxViews }) : undefined,
      };
    }),
  });
  const parts = shareableParts(d);
  let chosen = parts.filter((p) => p.checked).map((p) => p.value);
  const contents = checkboxGroup({
    legend: t("vault.link.contents"), name: "contenu",
    options: parts.map((p) => ({ value: p.value, label: t(p.labelKey) })),
    values: chosen,
    onChange: (v) => { chosen = v; },
  });
  const includeName = h("input", { type: "checkbox", name: "inclure_nom" });
  const nameBox = h("label", { class: "l-cluster" }, includeName, t("vault.link.include_name"));
  const nameHelp = h("p", { class: "u-muted" }, t("vault.link.include_name_help", { name: d.name || "" }));
  // Résultat affiché ; seule la phrase de confirmation est annoncée par
  // #status (A1), jamais l'adresse du lien.
  const result = h("div");

  const create = button({
    label: t("vault.link.create"), icon: "link", variant: "primary", busyLabel: t("vault.link.creating"),
    disabled: offline(), reason: offline() ? t("vault.offline_reason") : undefined,
    onClick: async () => {
      const payload = linkPayload(d, chosen, includeName.checked);
      if (!Object.keys(payload).some((k) => k !== "name")) {
        notify({ text: t("vault.link.nothing"), tone: "danger" });
        return;
      }
      let link;
      try {
        link = await V.createShareLink(payload, minutes, Number(viewsSelect.value), { itemId: item.id, collectionId: item.collection_id });
      } catch (e) {
        notify({ text: t("vault.link.failed", { reason: errorText(e) }), tone: "danger" });
        return;
      }
      // Correspondance lien -> élément (nom local), jamais dans l'élément ni sur le serveur en clair.
      const links = { ...(S.prefs().links || {}) };
      links[link.id] = { item_id: item.id, label: d.name || "" };
      S.savePrefs({ links }).catch(() => notify({ text: t("vault.link.label_not_saved"), tone: "warn" }));
      showResult(link);
      await copySecret(link.url, { kind: "secret", labelKey: "vault.link.copied_toast" });
    },
  });

  function showResult(link) {
    const box = textInput({ value: link.url, readonly: true, autocomplete: "off" });
    box.setAttribute("aria-label", t("vault.link.url"));
    box.classList.add("u-mono");
    const revoke = button({
      label: t("common.action.revoke"), icon: "close", variant: "danger", busyLabel: t("vault.link.revoking"),
      onClick: async () => {
        const { confirmed } = await confirm({
          level: 1, title: t("vault.link.revoke_title"), message: t("vault.link.revoke_text"),
          confirmLabel: t("common.action.revoke"), danger: true,
        });
        if (!confirmed) return;
        try {
          await V.revokeShareLink(link.id);
        } catch (e) {
          notify({ text: t("vault.link.revoke_failed", { reason: errorText(e) }), tone: "danger" });
          return;
        }
        result.replaceChildren(h("div", { class: "c-alert", "data-tone": "neutral" }, icon("check"), h("p", {}, t("vault.link.revoked"))));
        notify({ text: t("vault.link.revoked"), tone: "ok" });
      },
    });
    const created = t("vault.link.created", { date: fmtDate(link.expires_at), views: plural("vault.link.views_n", link.max_views) });
    announce(created);
    result.replaceChildren(h("div", { class: "c-alert", "data-tone": "ok" }, icon("check"),
      h("div", { class: "l-stack", "data-gap": "2" },
        h("p", {}, created),
        box,
        h("div", { class: "l-cluster" },
          button({ label: t("vault.link.copy"), icon: "copy", onClick: () => copySecret(link.url, { kind: "secret", labelKey: "vault.link.copied_toast" }) }),
          revoke))));
    env.countsChanged?.();
  }

  panel.replaceChildren(h("div", { class: "l-stack", "data-gap": "3" },
    h("p", {}, t("vault.link.intro")),
    expiry,
    field({ label: t("vault.link.views"), input: viewsSelect }),
    contents,
    h("div", { class: "l-stack", "data-gap": "1" }, nameBox, nameHelp),
    h("div", { class: "l-cluster" }, create),
    result));
}
