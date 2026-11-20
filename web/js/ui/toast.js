// Notifications passagères (règle A11) : 6 s, 10 s pour une erreur, 8 s avec
// une action ; pause au survol et au focus ; action atteignable au clavier
// (F6 depuis la page, ou Tab) ; le texte est annoncé par #status (#alert pour
// une erreur). Jamais de secret dans le texte. Toute information d'un toast
// doit aussi être disponible ailleurs (journal, état de l'objet).

import { errorText, t } from "../i18n.js";
import { h, icon } from "./core.js";
import { button, iconButton } from "./button.js";
import { announce } from "./status.js";
import { focusSafely } from "./focus.js";

const MAX_VISIBLE = 3;
export const TONE_ICONS = Object.freeze({ ok: "check", warn: "warn", danger: "error", info: "info", neutral: "info" });

let box = null;
let returnTo = null;
const dismissers = new WeakMap();

let f6Installed = false;

function container() {
  if (!box || !box.isConnected) {
    box = h("div", { class: "c-toasts" });
    document.body.append(box);
  }
  if (!f6Installed) {
    f6Installed = true;
    document.addEventListener("keydown", onF6);
  }
  return box;
}

/** F6 : va au dernier toast, puis revient où l'on était. */
function onF6(e) {
  if (e.key !== "F6" || e.ctrlKey || e.altKey || e.metaKey || !box?.isConnected || !box.firstElementChild) return;
  e.preventDefault();
  if (box.contains(document.activeElement)) {
    focusSafely(returnTo);
    returnTo = null;
    return;
  }
  returnTo = document.activeElement;
  focusSafely(box.lastElementChild.querySelector("button"));
}

/**
 * notify({ text, tone = "info", action: { label, run, doneText }, timeout, onClose }) -> { dismiss() }
 * tone : "ok" | "warn" | "danger" | "info" | "neutral".
 * action.run() est appelée au clic (« Annuler » par défaut), puis le toast se
 * ferme et doneText est annoncé (« Action annulée » par défaut ; null : rien).
 */
export function notify({ text, tone = "info", action, timeout, onClose } = {}) {
  const duration = Math.max(1000, Number(timeout) || (tone === "danger" ? 10000 : action ? 8000 : 6000));
  let remaining = duration;
  let startedAt = 0;
  let timer = 0;
  let done = false;

  const dismiss = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    const hadFocus = el.contains(document.activeElement);
    el.remove();
    if (hadFocus) {
      focusSafely(returnTo);
      returnTo = null;
    }
    onClose?.();
  };
  const pause = () => {
    if (!timer) return;
    clearTimeout(timer);
    timer = 0;
    remaining = Math.max(1000, remaining - (Date.now() - startedAt));
  };
  const resume = () => {
    if (done || timer || el.matches(":hover") || el.contains(document.activeElement)) return;
    startedAt = Date.now();
    timer = setTimeout(dismiss, remaining);
  };

  const actionBtn = action && typeof action.run === "function"
    ? button({
      label: action.label || t("common.action.undo"),
      variant: "quiet",
      onClick: async () => {
        try {
          await action.run();
        } catch (err) {
          dismiss();
          notify({ text: errorText(err), tone: "danger" });
          return;
        }
        dismiss();
        const doneText = action.doneText === undefined ? t("ui.toast.undone") : action.doneText;
        if (doneText) announce(doneText);
      },
    })
    : null;

  const el = h("div", { class: "c-toast", "data-tone": tone },
    icon(TONE_ICONS[tone] || "info"),
    h("p", { class: "c-toast__text" }, text),
    actionBtn,
    iconButton({ icon: "close", label: t("common.action.close"), onClick: dismiss }));
  el.addEventListener("mouseenter", pause);
  el.addEventListener("mouseleave", resume);
  el.addEventListener("focusin", pause);
  el.addEventListener("focusout", () => setTimeout(resume, 0));

  const list = container();
  list.append(el);
  dismissers.set(el, dismiss);
  while (list.children.length > MAX_VISIBLE) {
    const oldest = list.firstElementChild;
    (dismissers.get(oldest) || (() => oldest.remove()))();
  }
  announce(text, { assertive: tone === "danger" });
  resume();
  return { dismiss };
}
