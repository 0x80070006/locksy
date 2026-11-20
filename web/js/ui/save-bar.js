// Barre collante « 2 modifications non enregistrées » avec « Tout annuler »
// et « Vérifier et enregistrer ». Masquée sans modification.

import { plural, t } from "../i18n.js";
import { h } from "./core.js";
import { button } from "./button.js";

/**
 * saveBar({ count, onReset, onSave, saveLabel, resetLabel }) -> { el, update({ count }), destroy() }
 * onSave peut renvoyer une promesse (bouton « en cours »).
 */
export function saveBar({ count = 0, onReset, onSave, saveLabel = t("ui.save_bar.save"), resetLabel = t("ui.save_bar.reset") }) {
  const text = h("p", {});
  const el = h("div", { class: "c-save-bar", role: "region", "aria-label": t("ui.save_bar.region") },
    text,
    h("div", { class: "l-cluster" },
      button({ label: resetLabel, variant: "quiet", onClick: () => onReset?.() }),
      button({ label: saveLabel, variant: "primary", busyLabel: t("common.state.saving"), onClick: () => onSave?.() })));
  const update = ({ count: n = 0 } = {}) => {
    el.hidden = n <= 0;
    text.textContent = plural("ui.save_bar.count", n);
  };
  update({ count });
  return {
    el,
    update,
    destroy() {
      el.remove();
    },
  };
}
