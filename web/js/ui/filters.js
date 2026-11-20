// Barre de filtres : un menu par filtre (choix unique, menuitemradio), le
// nombre de filtres actifs et « Effacer les filtres ». Les valeurs peuvent
// être recopiées dans le fragment de l'adresse (lien partageable, bouton
// Précédent du navigateur).

import { plural, t } from "../i18n.js";
import { clear, h, setHashParams } from "./core.js";
import { button } from "./button.js";
import { menuButton } from "./menu.js";
import { keepFocus } from "./focus.js";

/**
 * filterBar({ label, filters: [{ key, label, options: [{ value, label }] }], values, onChange, syncUrl = true })
 *   -> { el, update(props), destroy() }
 * La première option de chaque filtre est la valeur « sans filtre ».
 * onChange(valeurs) à chaque choix ; syncUrl : true (paramètres du fragment) ou fonction(valeurs).
 */
export function filterBar({ label = t("ui.filters.label"), filters = [], values = {}, onChange, syncUrl = true }) {
  let p = { filters, values: { ...values }, onChange, syncUrl };
  const el = h("div", { class: "c-filters", role: "group", "aria-label": label });

  const defaultOf = (f) => String(f.options[0]?.value ?? "");
  const valueOf = (f) => String(p.values[f.key] ?? defaultOf(f));
  const activeCount = () => p.filters.filter((f) => valueOf(f) !== defaultOf(f)).length;

  const set = (next) => {
    p.values = next;
    if (typeof p.syncUrl === "function") p.syncUrl({ ...next });
    else if (p.syncUrl) {
      setHashParams(Object.fromEntries(p.filters.map((f) => [f.key, valueOf(f) === defaultOf(f) ? null : valueOf(f)])));
    }
    paint();
    p.onChange?.({ ...next });
  };

  function paint() {
    keepFocus(el, () => {
      const count = activeCount();
      clear(el,
        p.filters.map((f) => {
          const current = f.options.find((o) => String(o.value) === valueOf(f));
          const name = valueOf(f) === defaultOf(f) ? f.label : t("ui.filters.value", { label: f.label, value: current?.label ?? "" });
          const menu = menuButton({
            label: name,
            items: () => f.options.map((o) => ({
              label: o.label, checked: String(o.value) === valueOf(f),
              onSelect: () => set({ ...p.values, [f.key]: String(o.value) }),
            })),
          });
          menu.firstElementChild.dataset.focusKey = `filtre:${f.key}`;
          return menu;
        }),
        count ? h("span", { class: "u-muted" }, plural("ui.filters.active", count)) : null,
        count ? button({
          label: t("ui.filters.clear"), variant: "quiet",
          onClick: () => set(Object.fromEntries(p.filters.map((f) => [f.key, defaultOf(f)]))),
          attrs: { "data-focus-key": "effacer" },
        }) : null);
    });
  }

  paint();
  return {
    el,
    update(next = {}) {
      p = { ...p, ...next, values: next.values ? { ...next.values } : p.values };
      paint();
    },
    destroy() {
      el.remove();
    },
  };
}
