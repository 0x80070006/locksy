// Boutons. Une action principale a toujours un libellé visible ; un bouton à
// icône seule exige un libellé (aria-label et infobulle).
//
// onClick peut renvoyer une promesse : pendant l'attente, le bouton porte
// aria-busy et aria-disabled, affiche busyLabel et ignore les clics (il garde
// le focus). En cas de rejet, il redevient actif et l'erreur est transmise à
// onError, ou remonte à l'appelant (promesse rejetée non traitée) : le
// composant n'affiche rien lui-même.
// Un bouton désactivé AVEC une raison reste focalisable (aria-disabled) et
// sa raison est reliée par aria-describedby (et affichée au survol).

import { t } from "../i18n.js";
import { h, icon as iconEl, uid } from "./core.js";

const VARIANTS = new Set(["primary", "secondary", "quiet", "danger"]);

function classes(variant, iconOnly) {
  const v = VARIANTS.has(variant) ? variant : "secondary";
  return ["c-button", v !== "secondary" ? `c-button--${v}` : "", iconOnly ? "c-button--icon" : ""].filter(Boolean).join(" ");
}

/** Pose ou retire l'état désactivé, avec raison facultative. */
export function setDisabled(btn, disabled, reason) {
  btn.querySelector(":scope > .c-button__reason")?.remove();
  const ids = (btn.getAttribute("aria-describedby") || "").split(" ").filter((id) => id && !id.startsWith("btn-r-"));
  if (btn.dataset.titleBefore !== undefined) {
    if (btn.dataset.titleBefore) btn.title = btn.dataset.titleBefore;
    else btn.removeAttribute("title");
    delete btn.dataset.titleBefore;
  }
  btn.disabled = !!disabled && !reason;
  btn.removeAttribute("aria-disabled");
  if (disabled && reason) {
    const id = uid("btn-r");
    btn.append(h("span", { id, class: "c-button__reason", hidden: true }, reason));
    ids.push(id);
    btn.setAttribute("aria-disabled", "true");
    btn.dataset.titleBefore = btn.getAttribute("title") || "";
    btn.title = reason;
  }
  if (ids.length) btn.setAttribute("aria-describedby", ids.join(" "));
  else btn.removeAttribute("aria-describedby");
}

/** Vrai si le bouton est désactivé ou en cours. */
export const isInactive = (btn) => btn.disabled || btn.getAttribute("aria-disabled") === "true";

/**
 * Met le bouton « en cours » le temps de la promesse (aria-busy, aria-disabled,
 * libellé busyLabel), puis le rend actif. Renvoie la promesse d'origine.
 */
export function busyWhile(btn, promise, busyLabel) {
  const labelEl = btn.querySelector(":scope > .c-button__label");
  const before = labelEl?.textContent;
  btn.setAttribute("aria-busy", "true");
  btn.setAttribute("aria-disabled", "true");
  if (busyLabel && labelEl) labelEl.textContent = busyLabel;
  const done = () => {
    btn.removeAttribute("aria-busy");
    if (!btn.querySelector(":scope > .c-button__reason")) btn.removeAttribute("aria-disabled");
    if (busyLabel && labelEl) labelEl.textContent = before;
  };
  return Promise.resolve(promise).finally(done);
}

/** Exécute le gestionnaire, avec l'état « en cours » si une promesse est renvoyée. */
function wire(btn, { onClick, onError, busyLabel }) {
  if (typeof onClick !== "function") return;
  btn.addEventListener("click", (e) => {
    if (isInactive(btn)) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return;
    }
    const out = onClick(e);
    if (!out || typeof out.then !== "function") return;
    busyWhile(btn, out, busyLabel).catch((err) => {
      if (typeof onError === "function") onError(err);
      else throw err;
    });
  });
}

/**
 * Bouton avec libellé visible.
 * { label, icon, variant: "primary"|"secondary"|"quiet"|"danger", onClick,
 *   busyLabel, disabled, reason, type = "button", onError, attrs }
 */
export function button({ label, icon, variant = "secondary", onClick, busyLabel, disabled, reason, type = "button", onError, attrs = {} }) {
  const btn = h("button", { ...attrs, type, class: classes(variant, false) },
    icon ? iconEl(icon) : null, h("span", { class: "c-button__label" }, label));
  if (disabled) setDisabled(btn, true, reason);
  wire(btn, { onClick, onError, busyLabel });
  return btn;
}

/**
 * Bouton à icône seule : `label` obligatoire (nom accessible et infobulle).
 * `pressed` (booléen) en fait un bouton à bascule (aria-pressed).
 */
export function iconButton({ icon, label, onClick, pressed, variant = "quiet", disabled, reason, onError, attrs = {} }) {
  if (!label) throw new Error(t("ui.dev.label_required"));
  const btn = h("button", {
    ...attrs, type: "button", class: classes(variant, true), "aria-label": label, title: label,
    "aria-pressed": pressed === undefined ? undefined : String(!!pressed),
  }, iconEl(icon));
  if (disabled) setDisabled(btn, true, reason);
  wire(btn, { onClick, onError });
  return btn;
}

/** Change l'état d'un bouton à bascule. */
export function setPressed(btn, pressed) {
  btn.setAttribute("aria-pressed", String(!!pressed));
}
