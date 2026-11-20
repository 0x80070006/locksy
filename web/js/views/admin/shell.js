// Coquille de l'administration (cahier §3.4.1) et outils communs aux écrans
// d'administration : feuille de style dédiée, bandeau « Vous gérez les accès,
// pas les secrets », navigation « Administration », confirmation d'identité
// (jeton d'usage unique), détection d'une route serveur pas encore livrée
// (repli R11), requête du fragment, libellés des rôles et des personnes.
//
// La recherche du coffre n'a pas sa place ici : les écrans d'administration
// ne montrent jamais le contenu des coffres (noms chiffrés, illisibles par
// l'administrateur).

import { t, h, clear, icon, sideNav, confirm, setHashParams, fmtDate } from "../../ui/index.js";
import { ApiError, exchangeReauth } from "../../api.js";
import * as V from "../../vault.js";

const CSS_HREF = "/css/admin.css";

/** Entrées de la navigation « Administration » (annexe C). */
const NAV = Object.freeze([
  { id: "home", href: "#/admin", key: "admin.nav.home", icon: "shield" },
  { id: "people", href: "#/admin/personnes", key: "admin.nav.people", icon: "users" },
  { id: "settings", href: "#/admin/reglages/login", key: "admin.nav.settings", icon: "settings" },
  { id: "identity", href: "#/admin/connexion", key: "admin.nav.identity", icon: "building" },
  { id: "journal", href: "#/admin/journal", key: "admin.nav.journal", icon: "history" },
]);

/** Charge admin.css une fois (feuille propre à l'administration, §2.8). */
export function ensureAdminCss() {
  if (document.querySelector(`link[href="${CSS_HREF}"]`)) return;
  document.head.append(h("link", { rel: "stylesheet", href: CSS_HREF }));
}

/**
 * Coquille : bandeau, colonne de navigation (« Administration », puis la
 * navigation propre à l'écran, ex. les sections des réglages) et zone de
 * contenu. adminShell(ctx, current) -> { el, content, subnav }.
 */
export function adminShell(ctx, current) {
  ensureAdminCss();
  const content = h("div", { class: "a-settings__content l-stack", "data-gap": "5" });
  const subnav = h("div", { class: "l-stack", "data-gap": "2" });
  const nav = sideNav({
    label: t("admin.nav.label"),
    current,
    items: NAV.map((n) => ({ id: n.id, href: n.href, icon: n.icon, label: t(n.key) })),
  });
  const version = ctx?.health?.version;
  // La navigation « Administration » est dans la barre latérale ; ici, seulement
  // la navigation propre à l'écran (ex. les sections des réglages).
  nav.hidden = true;
  const aside = h("div", { class: "a-aside l-stack", "data-gap": "3" },
    nav,
    subnav,
    h("p", { class: "u-muted" },
      version ? t("admin.shell.version", { version }) : null,
      version ? " · " : null,
      h("a", { href: "#/aide" }, t("admin.shell.help"))));
  const el = h("div", { class: "a-page l-stack", "data-gap": "4" },
    h("p", { class: "a-banner" }, icon("shield", { size: "sm" }), " ", t("admin.banner")),
    h("div", { class: "a-settings" }, aside, content));
  clear(ctx.root, el);
  return { el, content, subnav };
}

/** Utilisateur connecté : { id, name, email, role }. */
export function me(ctx) {
  return ctx?.user || V.state.profile || {};
}

export const isOwner = (ctx) => (ctx?.role || me(ctx).role) === "owner";

/** Libellé d'un rôle d'organisation (Utilisateur, Administrateur, Propriétaire). */
export const roleLabel = (role) => (["owner", "admin", "user"].includes(role) ? t(`ui.role.${role}`) : t("admin.people.role_unknown"));

/** Rang d'un rôle : une élévation demande le mot de passe maître. */
export const roleRank = (role) => ({ user: 0, admin: 1, owner: 2 })[role] ?? 0;

/** Nom à afficher d'une personne : nom, sinon adresse. */
export const personName = (p) => (p?.name && String(p.name).trim()) || p?.email || t("admin.people.unnamed");

/** Date d'un champ date (AAAA-MM-JJ) -> horodatage Unix de fin de journée locale. */
export function dateInputToTs(value) {
  if (!value) return null;
  const d = new Date(`${value}T23:59:59`);
  return Number.isNaN(d.getTime()) ? null : Math.floor(d.getTime() / 1000);
}

/** Horodatage -> valeur d'un champ date (AAAA-MM-JJ, heure locale). */
export function tsToDateInput(ts) {
  if (!ts) return "";
  const d = new Date(Number(ts) * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** « 18 nov. 2026 » ou « Aucune ». */
export const dateOrNone = (ts) => (ts ? fmtDate(ts, "date") : t("admin.value.none"));

/**
 * Vrai si l'erreur dit que la route n'existe pas encore sur ce serveur
 * (404 sans code métier, 405, 501) : la vue se replie sur l'API historique.
 */
export function routeMissing(e) {
  if (!(e instanceof ApiError) && !(e && typeof e.status === "number")) return false;
  return (e.status === 404 && e.code !== "not_found") || e.status === 405 || e.status === 501;
}

/** Met à jour la requête du fragment sans recharger l'écran. */
export function setQuery(ctx, values) {
  if (typeof ctx?.setQuery === "function") ctx.setQuery(values);
  else setHashParams(values);
}

/** Va à une adresse de l'application (« /admin/personnes »). */
export function go(ctx, path) {
  if (typeof ctx?.navigate === "function") return ctx.navigate(path);
  location.hash = `#${path}`;
  return Promise.resolve();
}

/**
 * Jeton de confirmation d'identité pour `action` à partir du mot de passe
 * maître : preuve dérivée dans le navigateur, échangée contre un jeton
 * d'usage unique (POST /auth/reauth, contrat C1.3). Serveur sans cette route :
 * la preuve historique (b64 de l'auth_key) est renvoyée telle quelle.
 */
export async function stepUpToken(action, password) {
  const proof = await V.authProof(password);
  try {
    return await exchangeReauth(action, proof);
  } catch (e) {
    if (routeMissing(e)) return proof;
    throw e;
  }
}

/**
 * Confirmation d'identité (mot de passe maître) puis action : run({ reauth }).
 * Les actions d'administration n'exigent jamais le code de vérification
 * (contrat C1.3). Renvoie undefined si la personne annule.
 */
export async function reauthThen(action, run, { title, message, objectName, confirmLabel, danger } = {}) {
  const res = await confirm({
    level: 3,
    title: title || t("admin.reauth.title"),
    message: message || t("admin.reauth.message"),
    objectName,
    danger,
    confirmLabel: confirmLabel || t("admin.reauth.confirm"),
    reauth: (password) => stepUpToken(action, password),
  });
  return res.confirmed ? run({ reauth: res.reauth }) : undefined;
}

/**
 * Action qui peut exiger une confirmation d'identité : premier essai sans
 * jeton ; sur 428 reauth_required, confirmation puis nouvel essai.
 */
export async function withStepUp(action, run, texts) {
  try {
    return await run({});
  } catch (e) {
    if (e?.status === 428 && e.code === "reauth_required") return reauthThen(action, run, texts);
    throw e;
  }
}

/** Contenu « Cette page arrive bientôt » (module absent ou serveur plus ancien). */
export function comingSoon(container) {
  clear(container,
    h("h1", { tabindex: "-1" }, t("admin.soon.title")),
    h("p", {}, t("admin.soon.text")));
}

/** Neutralise une cellule CSV contre l'injection de formules (= + - @ tabulation, retour). */
function csvCell(value) {
  let s = String(value ?? "");
  if (/^\s*[=+\-@\t\r\n]/.test(s)) s = `'${s}`;
  return /[";\n\r]/.test(s) ? `"${s.replace(/"/g, "\"\"")}"` : s;
}

/** Fichier CSV (séparateur « ; », BOM pour les tableurs) à partir de lignes. */
export function csvBlob(rows) {
  const text = rows.map((r) => r.map(csvCell).join(";")).join("\r\n");
  return new Blob(["﻿", text, "\r\n"], { type: "text/csv;charset=utf-8" });
}

/** Nom de fichier daté : « locksy-<nom>-AAAA-MM-JJ.<ext> ». */
export const datedName = (name, ext) => `locksy-${name}-${new Date().toISOString().slice(0, 10)}.${ext}`;
