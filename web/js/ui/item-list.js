// Liste d'éléments (règle A5) : <ul> de <li>, chaque ligne porte un lien
// principal (nom + sous-titre), un bouton « Copier le mot de passe de … » et
// un bouton « Plus d'actions pour … ». Jamais de role=button contenant des
// boutons.
//
// - Délégation d'événements : trois écouteurs sur la liste, AUCUN par ligne.
// - Tabindex itinérant : une seule ligne dans l'ordre de tabulation ;
//   ↑ ↓ Début Fin se déplacent, une lettre saute au prochain nom qui commence
//   par elle.
// - update() fait un rendu par différence (clé stable) : focus, sélection
//   (aria-current) et défilement sont conservés.
// - Au-delà de `virtualizeAbove` lignes (500), seule la fenêtre visible est
//   rendue (aria-setsize, aria-posinset) ; deux lignes d'espacement, dont la
//   hauteur passe par la propriété --row-h (CSSOM), tiennent la place des autres.

import { h, icon } from "./core.js";
import { itemAvatar } from "./avatar.js";
import { focusSafely, isEditable, scrollParent } from "./focus.js";
import { openMenu } from "./menu.js";
import { normalize } from "./search.js";

const OVERSCAN = 8;
const DEFAULT_ROW_H = 56;

/**
 * itemList({ label, items, render, keyOf, onOpen, onPrimary, onMenu, selectedKey, virtualizeAbove = 500 })
 *   -> { el, update(items | props), select(key), focusKey(key), destroy() }
 *
 * render(item) -> { title, subtitle, href, avatar: { name, kind } | null, primaryLabel, menuLabel }
 *   primaryLabel / menuLabel : noms accessibles des boutons de la ligne
 *   (« Copier le mot de passe de Gmail », « Plus d'actions pour Gmail ») ;
 *   absents : pas de bouton.
 * onOpen(item, event) : clic simple ou Entrée sur le lien (le lien reste un
 *   vrai lien : Ctrl+clic ouvre un onglet).
 * onPrimary(item, bouton) ; onMenu(item, bouton) -> éléments de menu (le menu
 *   est alors ouvert sur le bouton) ou rien (l'appelant s'en charge).
 */
export function itemList({ label, items = [], render, keyOf = (it) => it.id, onOpen, onPrimary, onMenu, selectedKey = null, virtualizeAbove = 500 }) {
  let list = [];
  let keys = [];
  let indexOf = new Map();
  let selected = selectedKey === null || selectedKey === undefined ? null : String(selectedKey);
  let active = null;
  let virtual = false;
  let rowH = DEFAULT_ROW_H;
  let range = [0, 0];
  let scroller = null;
  let watching = false;
  let frame = 0;
  let typed = "";
  let typedTimer = 0;
  const rows = new Map();
  const titles = new Map();

  const ul = h("ul", { class: "c-item-list", role: "list", "aria-label": label });
  const spacer = (pos) => h("li", { class: "c-item-list__row", "data-spacer": pos, "aria-hidden": "true", hidden: true });
  const before = spacer("avant");
  const after = spacer("apres");

  // ------------------------------------------------------------ Lignes

  const signature = (d) => [d.title, d.subtitle, d.href, d.primaryLabel, d.menuLabel, d.avatar?.name, d.avatar?.kind].join("\u0001");

  function buildContent(d) {
    const main = d.href
      ? h("a", { class: "c-item-list__main", href: d.href, "data-part": "main" })
      : h("button", { type: "button", class: "c-item-list__main", "data-part": "main" });
    main.append(h("span", { class: "c-item-list__title" }, d.title ?? ""),
      d.subtitle ? h("span", { class: "c-item-list__sub" }, d.subtitle) : null);
    const actions = h("div", { class: "c-item-list__actions" },
      d.primaryLabel ? h("button", {
        type: "button", class: "c-button c-button--quiet c-button--icon", "data-action": "primary",
        "aria-label": d.primaryLabel, title: d.primaryLabel,
      }, icon("copy")) : null,
      d.menuLabel ? h("button", {
        type: "button", class: "c-button c-button--quiet c-button--icon", "data-action": "menu",
        "aria-haspopup": "menu", "aria-expanded": "false", "aria-label": d.menuLabel, title: d.menuLabel,
      }, icon("more")) : null);
    return [d.avatar ? itemAvatar({ item: d.avatar }) : h("span", { "aria-hidden": "true" }), main, actions];
  }

  function paintState(row, key, index) {
    const on = key === active;
    for (const el of row.li.querySelectorAll("a, button")) el.tabIndex = on ? 0 : -1;
    const main = row.li.querySelector("[data-part=main]");
    if (key === selected) main.setAttribute("aria-current", "true");
    else main.removeAttribute("aria-current");
    if (virtual) {
      row.li.setAttribute("aria-setsize", String(list.length));
      row.li.setAttribute("aria-posinset", String(index + 1));
    } else {
      row.li.removeAttribute("aria-setsize");
      row.li.removeAttribute("aria-posinset");
    }
  }

  function syncRow(key, index) {
    const d = render(list[index]) || {};
    const sig = signature(d);
    let row = rows.get(key);
    if (!row) {
      row = { li: h("li", { class: "c-item-list__row", "data-key": key }, buildContent(d)), sig };
      rows.set(key, row);
    } else if (row.sig !== sig) {
      const focusPart = row.li.contains(document.activeElement) ? partOf(document.activeElement) : null;
      row.li.replaceChildren(...buildContent(d));
      row.sig = sig;
      if (focusPart) focusSafely(row.li.querySelector(focusPart));
    }
    paintState(row, key, index);
    return row;
  }

  const partOf = (el) => (el.dataset.action ? `[data-action="${el.dataset.action}"]` : "[data-part=main]");

  /** Place les lignes [start, end) dans l'ordre, retire les autres, sans recréer celles qui existent. */
  function reconcile(start, end) {
    const wanted = new Set(keys.slice(start, end));
    for (const [key, row] of rows) {
      if (!wanted.has(key)) {
        row.li.remove();
        rows.delete(key);
      }
    }
    let cursor = before.nextSibling;
    for (let i = start; i < end; i++) {
      const row = syncRow(keys[i], i);
      if (row.li === cursor) cursor = cursor.nextSibling;
      else ul.insertBefore(row.li, cursor);
    }
    range = [start, end];
    setSpacer(before, virtual ? start * rowH : 0);
    setSpacer(after, virtual ? (list.length - end) * rowH : 0);
  }

  function setSpacer(el, px) {
    el.hidden = px <= 0;
    if (px > 0) el.style.setProperty("--row-h", `${Math.round(px)}px`);
  }

  // ------------------------------------------------------------ Fenêtre virtuelle

  const isRoot = (el) => el === document.scrollingElement || el === document.documentElement;

  function viewport() {
    scroller ??= scrollParent(ul);
    const root = isRoot(scroller);
    const top = root ? 0 : scroller.getBoundingClientRect().top;
    const offset = ul.getBoundingClientRect().top - top + scroller.scrollTop;
    const height = root ? window.innerHeight : scroller.clientHeight;
    return { offset, top: scroller.scrollTop - offset, height };
  }

  function measure() {
    const sample = rows.values().next().value?.li;
    const hgt = sample?.offsetHeight;
    if (hgt > 0) rowH = hgt;
  }

  function windowFor(view) {
    const first = Math.floor(Math.max(0, view.top) / rowH) - OVERSCAN;
    const last = Math.ceil((Math.max(0, view.top) + view.height) / rowH) + OVERSCAN;
    return [Math.max(0, Math.min(first, list.length)), Math.max(0, Math.min(last, list.length))];
  }

  function renderWindow() {
    frame = 0;
    if (!virtual || !ul.isConnected) return;
    const [start, end] = windowFor(viewport());
    if (start === range[0] && end === range[1]) return;
    const hadFocus = ul.contains(document.activeElement) && document.activeElement !== ul;
    reconcile(start, end);
    measure();
    if (hadFocus && !ul.contains(document.activeElement)) focusList();
  }

  const onScroll = () => {
    if (!frame) frame = requestAnimationFrame(renderWindow);
  };

  let resizeObs = null;
  let unwatch = () => {};
  function watchViewport() {
    if (watching || !ul.isConnected) return;
    watching = true;
    scroller = scrollParent(ul);
    const target = isRoot(scroller) ? window : scroller;
    target.addEventListener("scroll", onScroll, { passive: true });
    unwatch = () => target.removeEventListener("scroll", onScroll);
  }
  if (typeof ResizeObserver === "function") {
    resizeObs = new ResizeObserver(() => {
      if (!virtual) return;
      watchViewport();
      measure();
      range = [-1, -1];
      renderWindow();
    });
    resizeObs.observe(ul);
  }

  /** Focus de repli : la liste elle-même (jamais <body>) ; les flèches reprennent à la ligne active. */
  function focusList() {
    ul.tabIndex = -1;
    focusSafely(ul);
  }

  // ------------------------------------------------------------ Navigation

  function setActive(key) {
    if (key === active) return;
    const previous = active;
    active = key;
    for (const k of [previous, key]) {
      const row = rows.get(k);
      if (row && indexOf.has(k)) paintState(row, k, indexOf.get(k));
    }
  }

  /** Rend la ligne `index` visible (fenêtre virtuelle) et lui donne le focus. */
  function focusIndex(index) {
    if (!list.length) return;
    const i = Math.max(0, Math.min(list.length - 1, index));
    const key = keys[i];
    if (virtual && ul.isConnected && (i < range[0] || i >= range[1])) {
      const view = viewport();
      const rowTop = view.offset + i * rowH;
      scroller.scrollTop = i * rowH < view.top ? rowTop : rowTop - view.height + rowH;
      reconcile(...windowFor(viewport()));
    }
    setActive(key);
    const main = rows.get(key)?.li.querySelector("[data-part=main]");
    if (main) {
      focusSafely(main, { preventScroll: false });
      main.scrollIntoView?.({ block: "nearest" });
    }
  }

  function titleOf(i) {
    const key = keys[i];
    if (!titles.has(key)) titles.set(key, normalize(render(list[i])?.title));
    return titles.get(key);
  }

  function jumpTo(ch) {
    clearTimeout(typedTimer);
    typed += normalize(ch);
    typedTimer = setTimeout(() => { typed = ""; }, 600);
    const from = indexOf.get(active) ?? -1;
    const startAt = typed.length === 1 ? from + 1 : Math.max(0, from);
    for (let n = 0; n < list.length; n++) {
      const i = (startAt + n) % list.length;
      if (titleOf(i).startsWith(typed)) {
        focusIndex(i);
        return true;
      }
    }
    return false;
  }

  ul.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.altKey || e.metaKey || isEditable(e.target)) return;
    const current = indexOf.get(active) ?? 0;
    const moves = { ArrowDown: current + 1, ArrowUp: current - 1, Home: 0, End: list.length - 1 };
    if (e.key in moves) {
      e.preventDefault();
      focusIndex(e.target === ul && e.key.startsWith("Arrow") ? current : moves[e.key]);
      return;
    }
    if (e.key.length === 1 && /[\p{L}\p{N}]/u.test(e.key)) {
      e.preventDefault();
      jumpTo(e.key);
    }
  });

  ul.addEventListener("focusin", (e) => {
    const li = e.target.closest?.("li[data-key]");
    if (li) setActive(li.dataset.key);
  });

  ul.addEventListener("click", (e) => {
    const li = e.target.closest("li[data-key]");
    if (!li) return;
    const item = list[indexOf.get(li.dataset.key)];
    setActive(li.dataset.key);
    const action = e.target.closest("[data-action]");
    if (action?.dataset.action === "primary") {
      onPrimary?.(item, action);
    } else if (action?.dataset.action === "menu") {
      const entries = onMenu?.(item, action);
      if (Array.isArray(entries)) openMenu(action, entries);
    } else if (e.target.closest("[data-part=main]") && onOpen) {
      if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
      e.preventDefault();
      onOpen(item, e);
    }
  });

  // ------------------------------------------------------------ Rendu

  function apply(nextItems) {
    const hadFocus = ul.contains(document.activeElement);
    const focusPart = hadFocus && document.activeElement !== ul ? partOf(document.activeElement) : null;
    const sc = ul.isConnected ? (scroller ?? scrollParent(ul)) : null;
    const top = sc?.scrollTop;
    const oldIndex = indexOf.get(active);
    list = nextItems;
    keys = new Array(list.length);
    indexOf = new Map();
    for (let i = 0; i < list.length; i++) {
      keys[i] = String(keyOf(list[i]));
      indexOf.set(keys[i], i);
    }
    titles.clear();
    virtual = list.length > virtualizeAbove;
    if (active === null || !indexOf.has(active)) {
      // Ligne active disparue : la suivante prend sa place (même position).
      const sameSpot = oldIndex !== undefined ? keys[Math.min(oldIndex, list.length - 1)] : undefined;
      active = sameSpot ?? (selected !== null && indexOf.has(selected) ? selected : keys[0] ?? null);
    }
    if (!before.isConnected) ul.append(before, after);
    if (virtual) {
      if (ul.isConnected) {
        watchViewport();
        reconcile(...windowFor(viewport()));
      } else {
        reconcile(0, Math.min(list.length, 40));
      }
    } else {
      reconcile(0, list.length);
    }
    if (sc && sc.scrollTop !== top) {
      sc.scrollTop = top;
      if (virtual) reconcile(...windowFor(viewport()));
    }
    if (hadFocus && !ul.contains(document.activeElement)) {
      const row = rows.get(active);
      if (!focusSafely(row?.li.querySelector(focusPart || "[data-part=main]"))) focusList();
    }
  }

  apply(items);

  return {
    el: ul,
    update(next) {
      const props = Array.isArray(next) ? { items: next } : next || {};
      if (props.label !== undefined) ul.setAttribute("aria-label", props.label);
      if (props.selectedKey !== undefined) selected = props.selectedKey === null ? null : String(props.selectedKey);
      apply(props.items || list);
    },
    select(key) {
      selected = key === null ? null : String(key);
      for (const [k, row] of rows) paintState(row, k, indexOf.get(k));
    },
    focusKey(key) {
      if (indexOf.has(String(key))) focusIndex(indexOf.get(String(key)));
    },
    destroy() {
      cancelAnimationFrame(frame);
      unwatch();
      resizeObs?.disconnect();
      ul.remove();
    },
  };
}
