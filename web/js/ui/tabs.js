// Onglets (tablist) : flèches gauche et droite, Début, Fin, aria-selected,
// activation automatique. Chaque panneau est rendu à sa première ouverture
// puis conservé (la saisie n'est pas perdue en changeant d'onglet).

import { h, setHashParams, uid } from "./core.js";
import { focusSafely } from "./focus.js";

/**
 * tabs({ label, tabs: [{ id, label, render }], value, onChange, syncUrl })
 *   -> { el, update(props), destroy(), select(id) }
 * render(panneau) remplit le panneau ; syncUrl : true (paramètre « onglet » du
 * fragment) ou fonction (id) -> void.
 */
export function tabs({ label, tabs: list = [], value, onChange, syncUrl }) {
  const base = uid("onglets");
  let props = { list, onChange, syncUrl };
  let current = value ?? list[0]?.id;
  const rendered = new Set();
  const tablist = h("div", { class: "c-tabs__list", role: "tablist", "aria-label": label });
  const panels = h("div", {});
  const el = h("div", { class: "c-tabs" }, tablist, panels);

  const tabId = (id) => `${base}-${id}`;
  const panelId = (id) => `${base}-${id}-panneau`;

  const build = () => {
    tablist.replaceChildren(...props.list.map((tab) => h("button", {
      type: "button", role: "tab", class: "c-tabs__tab", id: tabId(tab.id), "aria-controls": panelId(tab.id),
      "data-tab": tab.id, "aria-selected": String(tab.id === current), tabindex: tab.id === current ? "0" : "-1",
    }, tab.label)));
    const keep = new Set(props.list.map((tab) => tab.id));
    for (const p of [...panels.children]) if (!keep.has(p.dataset.tab)) { p.remove(); rendered.delete(p.dataset.tab); }
    for (const tab of props.list) {
      if (!panels.querySelector(`[data-tab="${CSS.escape(tab.id)}"]`)) {
        panels.append(h("div", {
          role: "tabpanel", class: "c-tabs__panel", id: panelId(tab.id), "aria-labelledby": tabId(tab.id),
          tabindex: "0", "data-tab": tab.id, hidden: true,
        }));
      }
    }
    show(current, { notify: false });
  };

  const show = (id, { notify = true, focus = false } = {}) => {
    const tab = props.list.find((x) => x.id === id) || props.list[0];
    if (!tab) return;
    const changed = tab.id !== current;
    current = tab.id;
    for (const b of tablist.children) {
      const on = b.dataset.tab === current;
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
      if (on && focus) focusSafely(b);
    }
    for (const p of panels.children) {
      p.hidden = p.dataset.tab !== current;
      if (!p.hidden && !rendered.has(current)) {
        rendered.add(current);
        tab.render?.(p);
      }
    }
    if (!notify || !changed) return;
    if (typeof props.syncUrl === "function") props.syncUrl(current);
    else if (props.syncUrl) setHashParams({ onglet: current });
    props.onChange?.(current);
  };

  tablist.addEventListener("click", (e) => {
    const b = e.target.closest("[role=tab]");
    if (b) show(b.dataset.tab);
  });
  tablist.addEventListener("keydown", (e) => {
    const ids = props.list.map((x) => x.id);
    const i = ids.indexOf(current);
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: ids.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    show(ids[(next + ids.length) % ids.length], { focus: true });
  });

  build();
  return {
    el,
    select: (id) => show(id),
    update(next = {}) {
      if (next.tabs) props.list = next.tabs;
      if (next.onChange) props.onChange = next.onChange;
      if (next.value !== undefined) current = next.value;
      build();
    },
    destroy() {
      el.remove();
    },
  };
}
