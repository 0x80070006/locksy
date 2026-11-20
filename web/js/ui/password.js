// Champ de mot de passe : « Afficher le mot de passe » (aria-pressed), alerte
// « Majuscules activées », bouton « Générer » facultatif et jauge de force
// cohérente avec le reste de l'interface (strength.js).

import { t } from "../i18n.js";
import { call } from "../wasm.js";
import { h, icon, uid } from "./core.js";
import { button, iconButton, setPressed } from "./button.js";
import { describe, field, textInput } from "./field.js";
import { strengthMeter, updateStrength } from "./strength.js";

/** Estimation par le noyau (WebAssembly) ; null si le module n'est pas chargé. */
function wasmEstimate(password) {
  try {
    const r = call("strength", { password });
    return { score: r.score, issues: r.warnings || [] };
  } catch {
    return null;
  }
}

/**
 * passwordField({ label, value, name, autocomplete = "current-password", help, error,
 *   required, optional, withStrength, estimate, withGenerate, onGenerate, capsLockHint = true })
 *   -> HTMLElement (le champ s'obtient par fieldInput()).
 * estimate(password) -> { score 0..4, issues[] } | null (par défaut : le noyau).
 * onGenerate() -> mot de passe (ou promesse) : il remplace la saisie.
 */
export function passwordField({
  label, value, name, autocomplete = "current-password", help, error, required, optional,
  withStrength = false, estimate = wasmEstimate, withGenerate = false, onGenerate, capsLockHint = true,
}) {
  const input = textInput({ type: "password", name, value, autocomplete, required, spellcheck: false });
  input.setAttribute("autocapitalize", "off");
  let shown = false;
  const reveal = iconButton({
    icon: "eye", label: t("ui.password.show"), pressed: false,
    onClick: () => {
      shown = !shown;
      input.type = shown ? "text" : "password";
      setPressed(reveal, shown);
      reveal.replaceChildren(icon(shown ? "eye-off" : "eye"));
    },
  });
  const generate = withGenerate && typeof onGenerate === "function"
    ? button({
      label: t("common.action.generate"), icon: "generate",
      onClick: async () => {
        const next = await onGenerate();
        if (typeof next !== "string") return;
        input.value = next;
        input.dispatchEvent(new Event("input", { bubbles: true }));
      },
    })
    : null;
  const control = h("div", { class: "c-field__control c-password" }, input, reveal, generate);
  const el = field({ label, help, error, optional, input, control });

  if (capsLockHint) {
    const capsId = uid("caps");
    const caps = h("p", { class: "c-password__caps", id: capsId, hidden: true }, icon("warn", { size: "sm" }), t("ui.password.caps_on"));
    control.after(caps);
    const check = (e) => {
      const on = typeof e.getModifierState === "function" && e.getModifierState("CapsLock");
      caps.hidden = !on;
      describe(input, on ? [capsId] : [], on ? [] : [capsId]);
    };
    input.addEventListener("keydown", check);
    input.addEventListener("keyup", check);
    input.addEventListener("blur", () => {
      caps.hidden = true;
      describe(input, [], [capsId]);
    });
  }

  if (withStrength) {
    const meter = strengthMeter({ score: null });
    meter.classList.add("c-password__strength");
    (el.querySelector(".c-password__caps") || control).after(meter);
    let timer = 0;
    const refresh = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        const r = input.value ? estimate(input.value) : null;
        updateStrength(meter, r ? { score: r.score, issues: r.issues } : { score: null });
      }, 120);
    };
    input.addEventListener("input", refresh);
    if (input.value) refresh();
  }
  return el;
}
