// Paramètres de l'utilisateur (cahier §3.3.8, contrat C4.3) :
// #/parametres/:section, section ∈ compte | preferences | appareils |
// donnees | activite (« Mon activité », ouverte depuis Appareils et sessions).
// Chaque section est un module chargé à la demande qui exporte
// render(conteneur, ctx) -> { dispose(), isDirty() }.

import { t, h, clear, sideNav, alertCard, errorState } from "../../ui/index.js";
import * as V from "../../vault.js";

export const SECTIONS = Object.freeze([
  { id: "compte", groupKey: "settings_user.nav.group_account", labelKey: "settings_user.nav.account", load: () => import("./account.js") },
  { id: "appareils", groupKey: "settings_user.nav.group_account", labelKey: "settings_user.nav.devices", load: () => import("./devices.js") },
  { id: "preferences", groupKey: "settings_user.nav.group_custom", labelKey: "settings_user.nav.preferences", load: () => import("./preferences.js") },
  { id: "donnees", groupKey: "settings_user.nav.group_data", labelKey: "settings_user.nav.data", load: () => import("./data.js") },
  { id: "activite", labelKey: "settings_user.nav.activity", load: () => import("./activity.js"), hidden: true, parent: "appareils" },
]);

/** Section demandée : paramètre du routeur, sinon segment de l'adresse ; « compte » par défaut. */
export function sectionOf(ctx) {
  const wanted = ctx?.params?.section
    ?? String(globalThis.location?.hash ?? "").replace(/^#/, "").split("?")[0].split("/").filter(Boolean)[1];
  return SECTIONS.find((s) => s.id === wanted) || SECTIONS[0];
}

export async function render(ctx) {
  const section = sectionOf(ctx);
  const nav = sideNav({
    label: t("settings_user.nav.label"),
    current: section.parent || section.id,
    items: SECTIONS.filter((s) => !s.hidden).flatMap((s, i, all) => [
      ...(s.groupKey && all[i - 1]?.groupKey !== s.groupKey ? [{ group: t(s.groupKey) }] : []),
      { id: s.id, label: t(s.labelKey), href: `#/parametres/${s.id}` },
    ]),
  });
  const content = h("div", { class: "l-stack", "data-gap": "5" });
  const profile = V.state.profile;
  clear(ctx.root, h("div", { class: "l-stack", "data-gap": "5" },
    h("h1", { tabindex: "-1" }, t("settings_user.title")),
    profile?.must_setup_2fa && section.id !== "compte"
      ? alertCard({ tone: "warn", text: t("settings_user.account.twofa_required"), action: { label: t("settings_user.account.twofa_required_go"), href: "#/parametres/compte" } })
      : null,
    nav,
    content));
  let view = { dispose() {}, isDirty: () => false };
  try {
    const mod = await section.load();
    view = (await mod.render(content, ctx)) || view;
  } catch (e) {
    clear(content, errorState({ error: e, title: t("settings_user.load_failed"), onRetry: () => ctx.refresh?.() }));
  }
  return {
    dispose: () => view.dispose?.(),
    isDirty: () => !!view.isDirty?.(),
    // « Enregistrer » dans la demande de la garde de saisie, si la section le permet.
    save: typeof view.save === "function" ? () => view.save() : undefined,
  };
}
