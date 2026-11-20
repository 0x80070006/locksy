// Bulle non modale ancrée à un bouton : aria-expanded sur l'ancre, Échap ou
// un clic ailleurs la ferme et rend le focus à l'ancre.

import { h, uid } from "./core.js";
import { focusables, focusSafely } from "./focus.js";

/** Place l'élément juste après l'ancre, dans un conteneur positionné (.c-anchor). */
export function anchorHost(anchor) {
  if (anchor.parentElement?.classList.contains("c-anchor")) return anchor.parentElement;
  const host = h("span", { class: "c-anchor" });
  anchor.replaceWith(host);
  host.append(anchor);
  return host;
}

/**
 * popover({ anchor, body, label, onClose }) -> { el, close() }
 * Le focus va au premier élément focalisable de la bulle (ou à la bulle).
 */
export function popover({ anchor, body, label, onClose }) {
  const id = uid("bulle");
  const el = h("div", { class: "c-popover", id, role: "dialog", "aria-label": label, tabindex: "-1" }, body);
  let closed = false;

  const close = ({ restoreFocus = true } = {}) => {
    if (closed) return;
    closed = true;
    document.removeEventListener("pointerdown", onOutside, true);
    anchor.setAttribute("aria-expanded", "false");
    anchor.removeAttribute("aria-controls");
    const hadFocus = el.contains(document.activeElement);
    el.remove();
    if (restoreFocus && hadFocus) focusSafely(anchor);
    onClose?.();
  };
  const onOutside = (e) => {
    if (!el.contains(e.target) && !anchor.contains(e.target)) close({ restoreFocus: false });
  };
  el.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    e.preventDefault();
    e.stopPropagation();
    close();
  });
  el.addEventListener("focusout", (e) => {
    if (e.relatedTarget && !el.contains(e.relatedTarget) && e.relatedTarget !== anchor) close({ restoreFocus: false });
  });

  anchor.setAttribute("aria-expanded", "true");
  anchor.setAttribute("aria-controls", id);
  anchorHost(anchor).append(el);
  document.addEventListener("pointerdown", onOutside, true);
  focusSafely(focusables(el)[0] || el);
  return { el, close };
}
