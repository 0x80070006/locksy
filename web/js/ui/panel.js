// Panneau latéral (ordinateur) ou plein écran (moins de 600 px, ou feuille
// basse avec mobile: "sheet") : modal, le reste de la page devient inerte,
// le focus y reste confiné, Échap et « Fermer » passent par la même garde de
// saisie que les fenêtres ; le focus revient au déclencheur.

import { t } from "../i18n.js";
import { h, uid } from "./core.js";
import { button, iconButton } from "./button.js";
import { dirtyGuard } from "./dirty.js";
import { focusables, focusSafely } from "./focus.js";
import { rememberOpener, returnFocus, trackOverlay } from "./dialog.js";

/** Éléments laissés actifs sous un panneau : régions d'annonce, toasts, fenêtres. */
const KEEP_ACTIVE = "#status, #alert, .c-toasts, dialog, script";

/**
 * panel({ title, body, actions, onClose, dirty = () => false, onSave, mobile, initialFocus })
 *   -> { el, close() }
 * actions : éléments, ou { label, variant, icon, onClick, busyLabel } ;
 * onClick renvoie false (ou une promesse de false) pour garder le panneau ouvert.
 * close() ferme sans garde ; la croix, Échap et `cancel: true` passent par la garde.
 */
export function panel({ title, body, actions = [], onClose, dirty = () => false, onSave, mobile, initialFocus }) {
  const opener = document.activeElement;
  const titleId = uid("pnl-t");
  let closed = false;
  let primary = null;
  const inerted = [];

  const run = async (spec) => {
    if (spec.cancel && dirty()) return requestClose();
    const result = typeof spec.onClick === "function" ? await spec.onClick({ panel: el }) : undefined;
    if (result !== false) close();
    return result !== false;
  };
  const buttons = actions.filter(Boolean).map((a) => {
    if (a instanceof Node) return a;
    const btn = button({ label: a.label, icon: a.icon, variant: a.variant, busyLabel: a.busyLabel, onClick: () => run(a) });
    if (!primary && a.variant === "primary") primary = a;
    return btn;
  });

  const el = h("div", {
    class: "c-panel", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId, tabindex: "-1",
    "data-mobile": mobile === "sheet" ? "sheet" : undefined,
  },
  h("div", { class: "c-panel__head" },
    h("h2", { class: "c-panel__title", id: titleId }, title),
    iconButton({ icon: "close", label: t("common.action.close"), onClick: () => requestClose() })),
  h("div", { class: "c-panel__body" }, body),
  buttons.length ? h("div", { class: "c-panel__actions" }, buttons) : null);

  const guard = dirtyGuard(dirty, { unload: true, onSave: onSave || (primary ? () => run(primary) : undefined) });

  function close() {
    if (closed) return;
    closed = true;
    untrack();
    guard.destroy();
    for (const node of inerted) node.inert = false;
    el.remove();
    returnFocus(opener);
    onClose?.();
  }

  async function requestClose() {
    if (closed) return;
    if (!dirty() || (await guard.confirmLeave()) === "discard") close();
  }

  el.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !e.defaultPrevented) {
      e.preventDefault();
      requestClose();
      return;
    }
    if (e.key !== "Tab") return;
    const list = focusables(el);
    if (!list.length) return;
    const first = list[0];
    const last = list[list.length - 1];
    if (e.shiftKey && (document.activeElement === first || document.activeElement === el)) {
      e.preventDefault();
      focusSafely(last);
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      focusSafely(first);
    }
  });

  for (const node of document.body.children) {
    if (node.matches(KEEP_ACTIVE) || node.inert) continue;
    node.inert = true;
    inerted.push(node);
  }
  const untrack = trackOverlay(close);
  rememberOpener(el, opener);
  document.body.append(el);
  focusSafely(initialFocus?.(el)
    || el.querySelector("[autofocus]")
    || el.querySelector(".c-panel__body :is(input:not([type=hidden]), select, textarea)")
    || el);
  return { el, close };
}
