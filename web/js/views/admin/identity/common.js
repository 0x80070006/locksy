// Connexion d'entreprise : outils communs aux écrans (aperçu, SSO, Active
// Directory, SCIM). Aucun texte en dur : tout passe par t() (identity.*).

import { api } from "../../../api.js";
import {
  alertCard, announce, button, clear, copySecret, errorText, field, h, icon, radioCards, relTime, t, technicalDetails, textInput,
} from "../../../ui/index.js";

/** Durée de validité d'un test réussi pour pouvoir imposer une méthode (G-14). */
export const TEST_VALIDITY_SECS = 24 * 3600;

/** Adresse d'une page de la connexion d'entreprise (« », « sso », « ad », « scim »). */
export const hrefOf = (section = "") => (section ? `#/admin/connexion/${section}` : "#/admin/connexion");

/** Va à une page de la connexion d'entreprise (le routeur suit le fragment). */
export function goTo(section = "") {
  location.hash = hrefOf(section);
}

/** Secondes Unix. */
export const nowSecs = () => Math.floor(Date.now() / 1000);

/** GET qui renvoie null si la route n'existe pas sur ce serveur (404). */
export async function getOrNull(path) {
  try {
    return await api("GET", path);
  } catch (e) {
    if (e?.status === 404) return null;
    throw e;
  }
}

/** Vrai si l'administrateur courant a réussi un test de moins de 24 h. */
export function testedRecently(method) {
  const at = Number(method?.last_ok_by_me_at);
  return Number.isFinite(at) && at > 0 && nowSecs() - at < TEST_VALIDITY_SECS;
}

/** Texte d'un code d'échec renvoyé par un test (identity.* ou errors.*). */
export const reasonText = (code) => errorText({ code: String(code || "unknown") });

/** Message français d'une erreur ; route absente (serveur pas encore à jour) : le dire, plutôt que « introuvable ». */
export function errorMessage(err) {
  return err?.status === 404 && err.code === "not_found" ? t("identity.unavailable") : errorText(err);
}

/**
 * Bloc d'erreur attaché à l'objet : titre facultatif (« Le jeton n'a pas été
 * révoqué. »), message français, et texte technique du fournisseur (s'il y en
 * a un) dans « Détails techniques ».
 */
export function errorBlock(err, { title } = {}) {
  const technical = err?.params?.technical;
  return h("div", { class: "l-stack", "data-gap": "2" },
    alertCard({ tone: "danger", title, text: errorMessage(err) }),
    technical ? technicalDetails({ body: h("p", { class: "u-mono" }, String(technical)) }) : null);
}

/**
 * Zone de résultat d'une action (succès, information ou erreur), vidée à
 * chaque essai. Le message est aussi annoncé : le résultat arrive souvent
 * après coup (test dans une autre fenêtre, synchronisation), loin du focus.
 */
export function resultArea() {
  const el = h("div", { class: "l-stack", "data-gap": "2" });
  const show = (tone, text, extra = null) => {
    clear(el, alertCard({ tone, text }), extra);
    announce(text, { assertive: tone === "warn" });
  };
  return {
    el,
    clear: () => clear(el),
    ok: (text, extra) => show("ok", text, extra),
    info: (text) => show("info", text),
    warn: (text) => show("warn", text),
    error: (err, { title } = {}) => {
      clear(el, errorBlock(err, { title }));
      announce(title ? `${title} ${errorMessage(err)}` : errorMessage(err), { assertive: true });
    },
  };
}

/**
 * Valeur à copier (adresse de retour, adresse de base) : champ en lecture
 * seule et bouton « Copier » nommé.
 */
export function copyField({ label, help, value, copyLabel }) {
  const input = textInput({ value, readonly: true, spellcheck: false });
  input.classList.add("u-mono");
  const copy = button({
    label: t("common.action.copy"), icon: "copy", attrs: { "aria-label": copyLabel },
    onClick: () => copySecret(value, { kind: "text", labelKey: "identity.copy.done" }),
  });
  return field({ label, help, input, control: h("div", { class: "c-field__control" }, input, copy) });
}

/** Section des Réglages qui porte chaque clé du registre citée par ces écrans. */
const SETTING_SECTIONS = Object.freeze({
  "directory.deprovision": "retention",
  "directory.delete_after_days": "retention",
  "directory.max_deprovision_percent": "retention",
  "scim.token_ttl_days": "advanced",
});

/**
 * Réglages de l'organisation liés à une méthode (départ d'une personne de
 * l'annuaire, validité du jeton…) : ils s'éditent dans Réglages, avec leur
 * historique ; chaque lien ouvre la bonne section.
 */
export function relatedSettings(keys, id) {
  return h("section", { class: "c-card l-stack", "data-gap": "2", "aria-labelledby": id },
    h("h2", { id }, t("identity.related.title")),
    h("p", { class: "u-muted" }, t("identity.related.intro")),
    h("ul", { class: "l-stack", "data-gap": "2" },
      ...keys.map((key) => h("li", {},
        h("a", { href: `#/admin/reglages/${SETTING_SECTIONS[key]}` }, t(`settings.${key}.label`)),
        h("p", { class: "u-muted" }, t(`settings.${key}.help`))))));
}

/** Lien de retour vers l'aperçu de la connexion d'entreprise. */
export function backLink() {
  return h("p", {}, h("a", { href: hrefOf() }, icon("arrow-left", { size: "sm" }), t("identity.back")));
}

/** En-tête d'une page : titre (h1 focalisable) et introduction. */
export function pageHeader(titleKey, introKey) {
  return [
    h("h1", { tabindex: "-1" }, t(titleKey)),
    introKey ? h("p", { class: "u-muted" }, t(introKey)) : null,
  ];
}

/** Mode d'une méthode à partir de son état : "off" | "offered" | "enforced". */
export function modeOf(active, enforced) {
  if (!active) return "off";
  return enforced ? "enforced" : "offered";
}

/**
 * Choix du mode (Désactivé, Proposé, Imposé). « Imposé » reste visible mais
 * désactivé, avec la raison écrite sous le groupe, tant que l'administrateur
 * n'a pas réussi de test récent (canEnforce : test récent, ou méthode déjà
 * imposée, que le serveur laisse en l'état).
 */
export function modeChoice({ kind, value, canEnforce, onChange }) {
  const options = ["off", "offered", "enforced"].map((m) => ({
    value: m,
    label: t(`identity.mode.${m}`),
    description: t(`identity.${kind}.mode.${m}`),
    disabled: m === "enforced" && !canEnforce,
    reason: m === "enforced" && !canEnforce ? t("identity.mode.enforce_locked") : undefined,
  }));
  return radioCards({
    legend: t(`identity.${kind}.mode.legend`),
    options,
    value,
    onChange,
    help: canEnforce ? undefined : t("identity.mode.enforce_locked"),
  });
}

/** Ligne « Dernier test réussi par vous… » / « Dernier échec… » d'une méthode. */
export function testLines(method) {
  const lines = [];
  if (method?.last_ok_by_me_at) lines.push(t("identity.test.ok_by_me", { when: relTime(method.last_ok_by_me_at) }));
  else lines.push(t("identity.test.never_by_me"));
  const err = method?.last_error || (method?.last_test && !method.last_test.ok
    ? { at: method.last_test.at, code: method.last_test.error_code } : null);
  if (err) lines.push(t("identity.test.last_error", { when: relTime(err.at), reason: reasonText(err.code) }));
  return lines;
}

/**
 * Suivi des modifications d'un formulaire décrit par une fonction qui
 * renvoie ses valeurs : { isDirty(), reset() }.
 */
export function changeTracker(values) {
  let base = JSON.stringify(values());
  return {
    isDirty: () => JSON.stringify(values()) !== base,
    reset: () => { base = JSON.stringify(values()); },
  };
}

/** Lit l'état d'un interrupteur construit par toggle(). */
export const toggleState = (el) => el.querySelector("[role=switch]")?.getAttribute("aria-checked") === "true";
