// Confirmation proportionnée au risque :
//   niveau 0 : aucune fenêtre, l'action est faite et un toast propose
//              « Annuler » pendant 8 s ;
//   niveau 1 : fenêtre qui nomme l'objet ;
//   niveau 2 : + résumé chiffré de l'impact ;
//   niveau 3 : + saisie du nom de l'objet et du mot de passe maître.

import { errorText, t } from "../i18n.js";
import { h, icon } from "./core.js";
import { dialog } from "./dialog.js";
import { field, fieldError, fieldInput, textInput } from "./field.js";
import { passwordField } from "./password.js";
import { notify } from "./toast.js";
import { normalize } from "./search.js";

/**
 * confirm({ level = 1, title, message, objectName, impact, confirmLabel, danger, reauth, undo, undoText })
 *   -> Promise<{ confirmed, reauth?, undone? }>
 *
 * Niveau 0 : résout tout de suite { confirmed: true, undone } ; `undone` est
 *   une promesse qui vaut vrai si l'utilisateur clique « Annuler » dans les 8 s
 *   (undo() est alors appelée) ; message est le texte du toast.
 * Niveau 3 : reauth(motDePasse) -> preuve (ou promesse) ; une erreur reste
 *   affichée sous le champ ; reauth === true renvoie le mot de passe tel quel.
 * impact : texte ou liste de textes (« 12 personnes perdront l'accès »).
 */
export function confirm({ level = 1, title, message, objectName, impact, confirmLabel = t("common.action.confirm"), danger = false, reauth, undo, undoText }) {
  if (level === 0) {
    let settle;
    const undone = new Promise((resolve) => { settle = resolve; });
    let used = false;
    notify({
      text: message || title,
      tone: "info",
      timeout: 8000,
      action: {
        label: t("common.action.undo"),
        doneText: undoText,
        run: async () => {
          used = true;
          await undo?.();
          settle(true);
        },
      },
      onClose: () => { if (!used) settle(false); },
    });
    return Promise.resolve({ confirmed: true, undone });
  }

  return new Promise((resolve) => {
    let result = { confirmed: false };
    const parts = [];
    if (message) parts.push(h("p", {}, message));
    if (objectName) parts.push(h("p", { class: "c-card" }, h("strong", {}, objectName)));
    if (level >= 2 && impact) {
      const lines = Array.isArray(impact) ? impact : [impact];
      parts.push(h("div", { class: "c-alert", "data-tone": "warn" }, icon("warn"),
        h("ul", { class: "l-stack", "data-gap": "1" }, lines.map((line) => h("li", {}, line)))));
    }
    let nameField = null;
    let pwField = null;
    if (level >= 3) {
      if (objectName) {
        nameField = field({ label: t("ui.confirm.type_name", { name: objectName }), input: textInput({ autocomplete: "off", spellcheck: false }) });
        parts.push(nameField);
      }
      if (reauth) {
        pwField = passwordField({ label: t("common.glossary.master_password"), autocomplete: "current-password" });
        parts.push(pwField);
      }
    }

    const check = async () => {
      if (nameField) {
        const ok = normalize(fieldInput(nameField).value) === normalize(objectName);
        fieldError(nameField, ok ? null : t("ui.confirm.name_mismatch", { name: objectName }));
        if (!ok) return false;
      }
      if (pwField) {
        const password = fieldInput(pwField).value;
        if (!password) {
          fieldError(pwField, t("ui.confirm.password_required"));
          return false;
        }
        try {
          result = { confirmed: true, reauth: typeof reauth === "function" ? await reauth(password) : password };
        } catch (err) {
          fieldError(pwField, errorText(err));
          return false;
        }
        return true;
      }
      result = { confirmed: true };
      return true;
    };

    dialog({
      title,
      body: parts.length ? h("div", { class: "l-stack", "data-gap": "3" }, parts) : null,
      size: "sm",
      actions: [
        { label: t("common.action.cancel"), value: "cancel" },
        { label: confirmLabel, variant: danger ? "danger" : "primary", submit: true, value: "confirm", busyLabel: t("ui.confirm.checking"), onClick: check },
      ],
      // Niveau 1 et 2 : le focus va sur « Annuler » (aucune validation par erreur).
      initialFocus: (dlg) => (level >= 3 ? dlg.querySelector("input") : dlg.querySelector(".c-dialog__actions button")),
      onClose: () => resolve(result),
    });
  });
}
