// Pages statiques (cahier §2.10 A20, §3.1) : aide et raccourcis, déclaration
// d'accessibilité, mentions légales, charte d'utilisation. Accessibles sans
// session (sauf la charte), dans la coquille quand le coffre est ouvert.
//
// render(ctx) affiche ctx.route.page ∈ help | accessibility | notice | charter.
// Charte à accepter (après connexion, legal.charter_version supérieure à la
// version acceptée) : charterGate(ctx, required, { onLogout }) -> promesse
// résolue à vrai à l'acceptation (POST /me/charter), à faux à la déconnexion.

import { t, errorText, h, clear, icon, button, hotkeys, keysLabel, notify } from "../ui/index.js";
import * as S from "../settings-client.js";
import { api } from "../api.js";

/** Glossaire de l'aide : [mot, explication]. */
const WORDS = Object.freeze([
  ["shell.help.word.lock", "shell.help.word.lock_text"],
  ["shell.help.word.logout", "shell.help.word.logout_text"],
  ["shell.help.word.trash", "shell.help.word.trash_text"],
  ["shell.help.word.secure_link", "shell.help.word.secure_link_text"],
  ["shell.help.word.two_factor", "shell.help.word.two_factor_text"],
]);
/** Mesures d'accessibilité déjà en place (déclaration). */
const MEASURES = Object.freeze([
  "legal.a11y.measure.keyboard", "legal.a11y.measure.screen_reader", "legal.a11y.measure.contrast",
  "legal.a11y.measure.zoom", "legal.a11y.measure.motion",
]);

/** Page dans la coquille (coffre ouvert) ou seule, avec un lien de retour (avant connexion, coffre verrouillé). */
function page(ctx, titleKey, ...content) {
  const back = ctx.unlocked ? null : h("p", {}, h("a", { href: "#/connexion" }, t("auth.action.back_to_login")));
  const body = h("article", { class: "l-stack", "data-gap": "4" }, h("h1", {}, t(titleKey)), ...content, back);
  clear(ctx.root, ctx.unlocked ? h("div", { class: "c-card" }, body) : h("div", { class: "l-auth" }, h("div", { class: "l-auth__card" }, body)));
  return { dispose() {}, isDirty: () => false };
}

const paragraphs = (text) => String(text || "").split(/\n\s*\n/).map((p) => p.trim()).filter(Boolean).map((p) => h("p", {}, p));

function helpPage(ctx) {
  const groups = ["global", "vault", "list", "editor"].map((scope) => {
    const entries = hotkeys.list().filter((e) => e.scope === scope);
    if (!entries.length) return null;
    return h("section", { class: "l-stack", "data-gap": "2" },
      h("h2", {}, t(`ui.hotkeys.scope.${scope}`)),
      h("dl", { class: "c-hotkeys" }, entries.flatMap((e) => [h("dt", {}, t(e.labelKey)), h("dd", {}, keysLabel(e.keys))])));
  });
  const support = S.publicSettings()?.branding?.support_contact;
  return page(ctx, "shell.title.help",
    h("p", {}, t("shell.help.intro")),
    h("section", { class: "l-stack", "data-gap": "2" }, h("h2", {}, t("shell.help.shortcuts")),
      hotkeys.isEnabled() ? null : h("p", { class: "u-muted" }, t("ui.hotkeys.single_off")), groups),
    h("section", { class: "l-stack", "data-gap": "2" }, h("h2", {}, t("shell.help.words")),
      h("dl", { class: "l-stack", "data-gap": "2" }, WORDS.flatMap(([word, text]) => [
        h("dt", {}, h("strong", {}, t(word))), h("dd", {}, t(text)),
      ]))),
    h("section", { class: "l-stack", "data-gap": "2" }, h("h2", {}, t("shell.help.contact")),
      h("p", {}, support ? t("auth.login.support", { contact: support }) : t("shell.help.contact_admin"))));
}

function accessibilityPage(ctx) {
  const pub = S.publicSettings();
  const url = pub?.legal?.accessibility_url;
  const contact = pub?.branding?.support_contact || pub?.legal?.dpo_contact;
  return page(ctx, "legal.a11y.title",
    h("p", {}, t("legal.a11y.intro", { org: pub?.branding?.org_name || t("legal.a11y.org_default") })),
    h("h2", {}, t("legal.a11y.status_title")),
    h("p", {}, t("legal.a11y.status")),
    h("h2", {}, t("legal.a11y.measures_title")),
    h("ul", {}, MEASURES.map((key) => h("li", {}, t(key)))),
    h("h2", {}, t("legal.a11y.limits_title")),
    h("p", {}, t("legal.a11y.limits")),
    h("h2", {}, t("legal.a11y.contact_title")),
    h("p", {}, contact ? t("legal.a11y.contact", { contact }) : t("legal.a11y.contact_admin")),
    url ? h("p", {}, h("a", { href: url, rel: "noopener noreferrer", target: "_blank" }, t("legal.a11y.org_page"))) : null,
    h("h2", {}, t("legal.a11y.remedy_title")),
    h("p", {}, t("legal.a11y.remedy")));
}

function noticePage(ctx) {
  const pub = S.publicSettings();
  const legal = pub?.legal || {};
  const link = (href, key) => (href ? h("p", {}, h("a", { href, rel: "noopener noreferrer", target: "_blank" }, t(key))) : null);
  return page(ctx, "legal.notice.title",
    h("p", {}, t("legal.notice.operator", { org: pub?.branding?.org_name || t("legal.a11y.org_default") })),
    h("p", {}, t("legal.notice.zero_knowledge")),
    legal.dpo_contact ? h("p", {}, t("legal.notice.dpo", { contact: legal.dpo_contact })) : null,
    link(legal.notice_url, "legal.notice.org_page"),
    link(legal.privacy_url, "legal.link.privacy"));
}

function charterText() {
  return S.effective("legal.charter_text").value || "";
}

function charterPage(ctx) {
  const text = charterText();
  return page(ctx, "legal.charter.title", ...(text ? paragraphs(text) : [h("p", { class: "u-muted" }, t("legal.charter.none"))]));
}

/**
 * Charte à accepter avant d'ouvrir le coffre. Résout quand la personne a
 * accepté ; la déconnexion reste possible (onLogout).
 */
export function charterGate(ctx, required, { onLogout } = {}) {
  return new Promise((resolve) => {
    const err = h("p", { class: "c-field__error", role: "alert", hidden: true });
    const accept = button({
      label: t("legal.charter.accept"), variant: "primary", busyLabel: t("common.state.saving"),
      onClick: async () => {
        err.hidden = true;
        try {
          await api("POST", "/me/charter", { version: required });
          notify({ text: t("legal.charter.accepted"), tone: "ok" });
          resolve(true);
        } catch (e) {
          clear(err, icon("error", { size: "sm" }), errorText(e));
          err.hidden = false;
        }
      },
    });
    const logout = h("a", { href: "#/connexion", onclick: (e) => { e.preventDefault(); resolve(false); onLogout?.(); } }, t("common.action.logout"));
    const body = h("article", { class: "l-stack", "data-gap": "4" },
      h("h1", { tabindex: "-1" }, t("legal.charter.title")),
      h("p", {}, t("legal.charter.intro")),
      h("div", { class: "c-card" }, paragraphs(charterText())),
      err, accept, h("p", {}, logout));
    clear(ctx.root, h("div", { class: "l-auth" }, h("div", { class: "l-auth__card" }, body)));
    body.querySelector("h1").focus();
  });
}

export async function render(ctx) {
  switch (ctx.route?.page) {
    case "accessibility":
      return accessibilityPage(ctx);
    case "notice":
      return noticePage(ctx);
    case "charter":
      return charterPage(ctx);
    default:
      return helpPage(ctx);
  }
}
