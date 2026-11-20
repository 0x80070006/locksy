// Récapitulatif des modifications : « avant → après » par réglage ; une baisse
// de sécurité est mise en évidence par une icône ET le texte « Sécurité
// abaissée » (jamais par la seule couleur).

import { t } from "../i18n.js";
import { h, icon } from "./core.js";
import { formatSettingValue, settingLabel } from "./setting-field.js";

/**
 * diffList({ changes: [{ key, def, label, old, new, lowered }], format }) -> HTMLElement
 * format(change, valeur) -> texte ; par défaut, mise en forme selon change.def
 * (schéma du réglage) ou selon le type de la valeur.
 */
export function diffList({ changes = [], format }) {
  const show = (c, v) => (typeof format === "function" ? format(c, v) : formatSettingValue(c.def, v));
  return h("ul", { class: "c-diff" }, changes.map((c) => h("li", { class: "c-diff__row", "data-lowered": c.lowered ? "" : undefined },
    h("strong", {}, c.label || settingLabel(c.key)),
    h("span", {},
      h("span", {}, show(c, c.old)),
      h("span", { "aria-hidden": "true" }, " → "),
      h("span", { class: "u-sr-only" }, ` ${t("ui.diff.becomes")} `),
      h("span", {}, show(c, c.new))),
    c.lowered ? h("span", { class: "c-badge", "data-tone": "warn" }, icon("warn", { size: "sm" }), t("ui.diff.lowered")) : null)));
}
