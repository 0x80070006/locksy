// Navigation latérale nommée : liens avec aria-current="page", compteurs,
// badges et intertitres de groupe.

import { fmtNumber } from "../i18n.js";
import { h, icon } from "./core.js";
import { badge } from "./badges.js";

/**
 * sideNav({ label, items: [{ id, label, href, icon, count, badge, group }], current, onSelect })
 *   -> HTMLElement (<nav aria-label>)
 * Une entrée { group: "Coffres" } est un intertitre. badge : { tone, label }.
 * onSelect(id, event) est appelée au clic (le lien reste un vrai lien).
 */
export function sideNav({ label, items = [], current, onSelect }) {
  const nav = h("nav", { class: "c-sidenav", "aria-label": label },
    items.map((it) => {
      if (it.group) return h("p", { class: "c-sidenav__group" }, it.group);
      return h("a", {
        class: "c-sidenav__item", href: it.href || `#${it.id}`, "data-id": it.id,
        "aria-current": it.id === current ? "page" : undefined,
      },
      it.icon ? icon(it.icon) : null,
      h("span", {}, it.label),
      it.badge ? badge(it.badge) : null,
      typeof it.count === "number" ? h("span", { class: "c-sidenav__count" }, fmtNumber(it.count)) : null);
    }));
  if (typeof onSelect === "function") {
    nav.addEventListener("click", (e) => {
      const a = e.target.closest("a[data-id]");
      if (a && !e.ctrlKey && !e.metaKey && !e.shiftKey && e.button === 0) onSelect(a.dataset.id, e);
    });
  }
  return nav;
}

/** Change l'entrée courante d'une navigation construite par sideNav(). */
export function setNavCurrent(nav, id) {
  for (const a of nav.querySelectorAll("a[data-id]")) {
    if (a.dataset.id === id) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
}
