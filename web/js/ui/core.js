// Socle des composants : construction du DOM, icônes, identifiants, pastilles.
//
// Tout le contenu passe par textContent (via h()) : aucune donnée n'est jamais
// interprétée comme du HTML. h() refuse la clé « style » : la CSP interdit les
// styles en ligne ; une couleur calculée passe par une propriété personnalisée
// posée en CSSOM (el.style.setProperty("--tile", c)), lue par une classe.

import { t } from "../i18n.js";

const SVG_NS = "http://www.w3.org/2000/svg";

/**
 * Crée un élément. attrs : class, dataset, value, checked, on<événement>
 * (fonction), sinon setAttribute (true -> attribut vide ; false, null et
 * undefined sont ignorés). Les enfants sont des nœuds ou du texte.
 */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "style") throw new Error(t("ui.dev.style_forbidden"));
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else if (k === "dataset") Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

/** Vide l'élément puis y place les enfants donnés. */
export function clear(el, ...children) {
  el.replaceChildren();
  append(el, children);
  return el;
}

// ------------------------------------------------------------------ Icônes

let iconBase = "/icons/sprite.svg";

/** Adresse du sprite d'icônes (l'extension sert le sien depuis lib/sprite.svg). */
export function setIconBase(url) {
  iconBase = String(url || "/icons/sprite.svg");
}

/**
 * Icône du sprite (design/icons). Décorative par défaut (aria-hidden) ;
 * avec `label`, elle est nommée (role=img). `size` : "sm" | "md" | "lg".
 */
export function icon(name, { label, size } = {}) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", "c-icon");
  svg.setAttribute("focusable", "false");
  if (size && size !== "md") svg.setAttribute("data-size", size);
  if (label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
  } else {
    svg.setAttribute("aria-hidden", "true");
  }
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", `${iconBase}#${name}`);
  svg.append(use);
  return svg;
}

// ------------------------------------------------------------------ Identifiants

let counter = 0;

/** Identifiant unique dans la page : « fld-12 ». */
export function uid(prefix = "ui") {
  counter += 1;
  return `${prefix}-${counter}`;
}

// ------------------------------------------------------------------ Adresse

/**
 * Met à jour la requête du fragment (#/route?cle=valeur) sans recharger ni
 * ajouter d'entrée d'historique ; une valeur vide retire le paramètre.
 * Jamais de donnée sensible dans l'adresse (règle R5).
 */
export function setHashParams(params) {
  const [path, query = ""] = location.hash.slice(1).split("?");
  const q = new URLSearchParams(query);
  for (const [k, v] of Object.entries(params)) {
    if (v === null || v === undefined || v === "") q.delete(k);
    else q.set(k, String(v));
  }
  const s = q.toString();
  history.replaceState(history.state, "", `#${path}${s ? `?${s}` : ""}`);
}

// ------------------------------------------------------------------ Pastilles

/** Couleurs des pastilles, dans l'ordre de design/tokens.json (« tile »). Vérifié par la galerie. */
export const TILE_COLORS = Object.freeze(["#2f5fa7", "#0d6b64", "#5a6a1f", "#a8452a", "#6d4aa8", "#9a3a6a", "#3c5a78", "#2f7a3a"]);

/** Couleur stable d'une pastille pour un nom (même nom, même couleur). */
export function colorFor(name) {
  let n = 0;
  for (const ch of String(name || "?")) n = (n * 31 + ch.codePointAt(0)) >>> 0;
  return TILE_COLORS[n % TILE_COLORS.length];
}

/** Initiales d'un nom : « Hugo Martin » -> « HM », « gmail » -> « G » (au plus `max`). */
export function initials(name, max = 2) {
  const words = String(name || "").trim().split(/[\s._@-]+/u).filter(Boolean);
  if (!words.length) return "?";
  return words.slice(0, Math.max(1, max)).map((w) => [...w][0].toLocaleUpperCase("fr-FR")).join("");
}
