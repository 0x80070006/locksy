// Garde de saisie : « Quitter sans enregistrer ? » (Rester / Abandonner /
// Enregistrer). Source : un <form> (comparaison avec l'état initial) ou une
// fonction qui dit si la saisie est modifiée. Tant qu'elle est modifiée, la
// fermeture de l'onglet demande confirmation (beforeunload).

import { t } from "../i18n.js";
import { dialog } from "./dialog.js";

/** Empreinte des valeurs d'un formulaire (champs nommés ou identifiés). */
function snapshot(form) {
  const parts = [];
  for (const el of form.elements) {
    const name = el.name || el.id;
    if (!name || el.type === "button" || el.type === "submit") continue;
    if (el.type === "checkbox" || el.type === "radio") parts.push(`${name}=${el.checked ? el.value : ""}`);
    else if (el.type === "file") parts.push(`${name}=${[...(el.files || [])].map((f) => f.name).join("|")}`);
    else parts.push(`${name}=${el.value}`);
  }
  return parts.join("\u0000");
}

/**
 * dirtyGuard(form | () => boolean, { onSave, unload = true })
 *   -> { isDirty(), reset(), confirmLeave() -> "save" | "discard" | "stay", destroy() }
 * confirmLeave() renvoie "discard" sans rien demander si rien n'a changé ;
 * « Enregistrer » appelle onSave() : "save" si elle réussit, sinon "stay"
 * (l'erreur est affichée par l'appelant, la saisie n'est pas perdue).
 */
export function dirtyGuard(source, { onSave, unload = true } = {}) {
  const fromForm = typeof source !== "function";
  let base = fromForm ? snapshot(source) : "";
  const isDirty = () => (fromForm ? snapshot(source) !== base : !!source());
  const onBeforeUnload = (e) => {
    if (!isDirty()) return;
    e.preventDefault();
    e.returnValue = "";
  };
  if (unload) window.addEventListener("beforeunload", onBeforeUnload);
  let pending = null;
  return {
    isDirty,
    reset() {
      if (fromForm) base = snapshot(source);
    },
    confirmLeave() {
      if (!isDirty()) return Promise.resolve("discard");
      pending ??= askLeave(onSave).finally(() => { pending = null; });
      return pending;
    },
    destroy() {
      window.removeEventListener("beforeunload", onBeforeUnload);
    },
  };
}

function askLeave(onSave) {
  return new Promise((resolve) => {
    let choice = "stay";
    const actions = [
      { label: t("common.action.stay"), value: "stay", cancel: true },
      { label: t("common.action.discard"), variant: "danger", value: "discard", onClick: () => { choice = "discard"; } },
    ];
    if (typeof onSave === "function") {
      actions.push({
        label: t("common.action.save"), variant: "primary", value: "save", busyLabel: t("common.state.saving"),
        onClick: async () => {
          try {
            choice = (await onSave()) === false ? "stay" : "save";
          } catch {
            choice = "stay";
          }
        },
      });
    }
    dialog({
      title: t("ui.dirty.title"),
      description: t("ui.dirty.text"),
      actions,
      size: "sm",
      initialFocus: (dlg) => dlg.querySelector(".c-dialog__actions button"),
      onClose: () => resolve(choice),
    });
  });
}
