// Menus d'actions (bouton aria-haspopup="menu") : flèches, Début, Fin,
// saisie d'une lettre, Échap rend le focus au bouton, clic ailleurs ferme.
// Une action désactivée reste visible avec sa raison (aria-describedby).

import { h, icon, uid } from "./core.js";
import { focusSafely } from "./focus.js";
import { anchorHost } from "./popover.js";
import { normalize } from "./search.js";

const ITEM = "[role^=menuitem]";
const openMenus = new WeakMap();

/**
 * Ouvre le menu d'un bouton existant (utile pour les listes : le menu n'est
 * construit qu'au clic). items : [{ label, icon, onSelect, danger, disabled,
 * reason, checked }] ou "separator". `focus` : "first" | "last".
 * Renvoie la fonction qui ferme le menu.
 */
export function openMenu(btn, items, { focus = "first", onClose } = {}) {
  openMenus.get(btn)?.();
  const id = uid("menu");
  if (!btn.id) btn.id = uid("menu-btn");
  const actions = [];
  const menu = h("ul", { class: "c-menu", role: "menu", id, "aria-labelledby": btn.id },
    items.filter(Boolean).map((it) => {
      if (it === "separator" || it.separator) return h("li", { role: "separator", class: "c-menu__sep" });
      const index = actions.push(it) - 1;
      const reasonId = it.disabled && it.reason ? uid("menu-r") : undefined;
      return h("li", { role: "none" },
        h("button", {
          type: "button", class: "c-menu__item", tabindex: "-1", "data-index": String(index),
          role: it.checked === undefined ? "menuitem" : "menuitemradio",
          "aria-checked": it.checked === undefined ? undefined : String(!!it.checked),
          "aria-disabled": it.disabled ? "true" : undefined, "aria-describedby": reasonId,
          "data-tone": it.danger ? "danger" : undefined, title: it.disabled ? it.reason : undefined,
        },
        it.icon ? icon(it.icon) : null,
        h("span", {}, it.label),
        reasonId ? h("span", { id: reasonId, hidden: true }, it.reason) : null));
    }));

  let typed = "";
  let typedTimer = 0;
  const itemsEls = () => [...menu.querySelectorAll(ITEM)];
  const move = (to) => {
    const list = itemsEls();
    if (!list.length) return;
    const i = list.indexOf(document.activeElement);
    const next = to === "first" ? 0 : to === "last" ? list.length - 1 : (i + to + list.length) % list.length;
    focusSafely(list[next]);
  };
  const close = ({ restoreFocus = true } = {}) => {
    if (openMenus.get(btn) !== close) return;
    openMenus.delete(btn);
    document.removeEventListener("pointerdown", onOutside, true);
    btn.setAttribute("aria-expanded", "false");
    btn.removeAttribute("aria-controls");
    const hadFocus = menu.contains(document.activeElement);
    menu.remove();
    if (restoreFocus || hadFocus) focusSafely(btn);
    onClose?.();
  };
  const onOutside = (e) => {
    if (!menu.contains(e.target) && !btn.contains(e.target)) close({ restoreFocus: false });
  };

  menu.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") move(1);
    else if (e.key === "ArrowUp") move(-1);
    else if (e.key === "Home") move("first");
    else if (e.key === "End") move("last");
    else if (e.key === "Escape") close();
    else if (e.key === "Tab") {
      close({ restoreFocus: true });
      return;
    } else if (e.key.length === 1 && /\p{L}|\p{N}/u.test(e.key) && !e.ctrlKey && !e.altKey && !e.metaKey) {
      clearTimeout(typedTimer);
      typed += normalize(e.key);
      typedTimer = setTimeout(() => { typed = ""; }, 500);
      const hit = itemsEls().find((b) => normalize(b.textContent).startsWith(typed));
      if (hit) focusSafely(hit);
    } else return;
    e.preventDefault();
    e.stopPropagation();
  });
  menu.addEventListener("click", (e) => {
    const target = e.target.closest(ITEM);
    if (!target || target.getAttribute("aria-disabled") === "true") return;
    const it = actions[Number(target.dataset.index)];
    close();
    it?.onSelect?.();
  });

  btn.setAttribute("aria-haspopup", "menu");
  btn.setAttribute("aria-expanded", "true");
  btn.setAttribute("aria-controls", id);
  anchorHost(btn).append(menu);
  openMenus.set(btn, close);
  document.addEventListener("pointerdown", onOutside, true);
  move(focus);
  return close;
}

/**
 * menuButton({ label, icon, items, iconOnly = false, variant = "secondary" }) -> HTMLElement
 * Bouton qui ouvre un menu ; `iconOnly` : libellé en aria-label et infobulle.
 */
export function menuButton({ label, icon: name, items, iconOnly = false, variant = "secondary" }) {
  const cls = ["c-button", variant !== "secondary" ? `c-button--${variant}` : "", iconOnly ? "c-button--icon" : ""].filter(Boolean).join(" ");
  const btn = h("button", {
    type: "button", class: cls, "aria-haspopup": "menu", "aria-expanded": "false",
    "aria-label": iconOnly ? label : undefined, title: iconOnly ? label : undefined,
  }, iconOnly
    ? icon(name || "more")
    : [name ? icon(name) : null, h("span", { class: "c-button__label" }, label), icon("chevron-down", { size: "sm" })]);
  const list = () => (typeof items === "function" ? items() : items);
  btn.addEventListener("click", () => {
    if (openMenus.has(btn)) openMenus.get(btn)();
    else openMenu(btn, list());
  });
  btn.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    openMenu(btn, list(), { focus: e.key === "ArrowUp" ? "last" : "first" });
  });
  return h("span", { class: "c-anchor" }, btn);
}
