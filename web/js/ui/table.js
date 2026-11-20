// Tableau de données (règle A19) : <caption>, <th scope>, tri annoncé par
// aria-sort, cases de sélection nommées, barre d'actions sur la sélection,
// pagination ; la ligne s'ouvre par un lien (ou bouton) dans sa première
// cellule ; sous 600 px, les lignes deviennent des cartes (data-cards).
// Le tableau défile dans son propre conteneur (région focalisable).

import { fmtNumber, plural, t } from "../i18n.js";
import { clear, h, icon, uid } from "./core.js";
import { button } from "./button.js";
import { keepFocus } from "./focus.js";
import { skeleton } from "./empty.js";

const NEXT_DIR = { ascending: "descending", descending: "ascending" };

/**
 * dataTable({ caption, columns: [{ key, label, sortable, render, numeric }], rows, rowKey,
 *   rowLabel, rowHref, selectable, onRowOpen, sort: { key, dir }, onSort, page, pageSize, total,
 *   onPage, empty, loading, bulkActions: [{ label, icon, danger, onClick(rows) }] })
 *   -> { el, update(props), selection(), destroy() }
 * rowLabel(row) : nom de la ligne (cases « Sélectionner … ») ; par défaut la
 * première colonne. dir : "ascending" | "descending".
 */
export function dataTable(initial) {
  let p = { columns: [], rows: [], rowKey: (r) => r.id, page: 1, pageSize: 50, bulkActions: [], ...initial };
  const selected = new Set();
  const captionId = uid("tableau");
  const el = h("div", { class: "l-stack", "data-gap": "2" });

  const keyOf = (r) => String(p.rowKey(r));
  const labelOf = (r) => String(p.rowLabel ? p.rowLabel(r) : r[p.columns[0]?.key] ?? "");
  const cell = (col, r) => (col.render ? col.render(r) : r[col.key] ?? "");

  function header() {
    const cols = p.columns.map((col) => {
      if (!col.sortable) return h("th", { scope: "col" }, col.label);
      const dir = p.sort?.key === col.key ? p.sort.dir : "none";
      return h("th", { scope: "col", "aria-sort": dir },
        h("button", { type: "button", "data-sort": col.key, "data-focus-key": `tri:${col.key}` },
          col.label, dir === "none" ? null : icon("chevron-down", { size: "sm" })));
    });
    const all = p.rows.length > 0 && p.rows.every((r) => selected.has(keyOf(r)));
    const head = p.selectable
      ? [h("th", { scope: "col", class: "c-table__select" },
        h("input", { type: "checkbox", "data-select-all": "", "data-focus-key": "tout", checked: all, "aria-label": t("ui.table.select_all") })), ...cols]
      : cols;
    return h("thead", {}, h("tr", {}, head));
  }

  function body() {
    const span = p.columns.length + (p.selectable ? 1 : 0);
    if (p.loading) return h("tbody", {}, h("tr", {}, h("td", { colspan: span }, skeleton({ lines: 3 }))));
    if (!p.rows.length) return h("tbody", {}, h("tr", {}, h("td", { colspan: span }, p.empty ?? t("ui.table.empty"))));
    return h("tbody", {}, p.rows.map((r) => {
      const key = keyOf(r);
      const on = selected.has(key);
      const cells = p.columns.map((col, i) => {
        let content = cell(col, r);
        if (i === 0 && p.rowHref) content = h("a", { href: p.rowHref(r), "data-focus-key": `ouvrir:${key}` }, content);
        else if (i === 0 && p.onRowOpen) content = h("button", { type: "button", class: "c-button c-button--quiet", "data-open": key, "data-focus-key": `ouvrir:${key}` }, content);
        return h("td", { "data-label": col.label, "data-num": col.numeric ? "" : undefined }, content);
      });
      return h("tr", { "data-key": key, "aria-selected": p.selectable ? String(on) : undefined },
        p.selectable ? h("td", { class: "c-table__select" }, h("input", {
          type: "checkbox", "data-select": key, "data-focus-key": `case:${key}`, checked: on,
          "aria-label": t("ui.table.select_row", { name: labelOf(r) }),
        })) : null,
        cells);
    }));
  }

  function bulkbar() {
    if (!p.selectable || !selected.size || !p.bulkActions.length) return null;
    const rows = p.rows.filter((r) => selected.has(keyOf(r)));
    return h("div", { class: "c-table__bulkbar", role: "region", "aria-label": t("ui.table.selection_region") },
      h("span", {}, plural("ui.table.selected", selected.size)),
      p.bulkActions.map((a) => button({ label: a.label, icon: a.icon, variant: a.danger ? "danger" : "secondary", onClick: () => a.onClick(rows) })),
      button({ label: t("ui.table.clear_selection"), variant: "quiet", onClick: () => { selected.clear(); paint(); } }));
  }

  function pager() {
    const total = p.total ?? p.rows.length;
    const pages = Math.max(1, Math.ceil(total / Math.max(1, p.pageSize)));
    if (!p.onPage || pages <= 1) return null;
    return h("nav", { class: "c-table__pager", "aria-label": t("ui.table.pagination") },
      h("span", {}, t("ui.table.page", { page: fmtNumber(p.page), pages: fmtNumber(pages) })),
      button({ label: t("ui.table.previous"), icon: "arrow-left", disabled: p.page <= 1, onClick: () => p.onPage(p.page - 1) }),
      button({ label: t("ui.table.next"), icon: "chevron-right", disabled: p.page >= pages, onClick: () => p.onPage(p.page + 1) }));
  }

  function paint() {
    keepFocus(el, () => clear(el,
      bulkbar(),
      h("div", { class: "c-table__scroll", role: "region", "aria-labelledby": captionId, tabindex: "0" },
        h("table", { class: "c-table", "data-cards": "", "aria-busy": p.loading ? "true" : undefined },
          h("caption", { id: captionId }, p.caption), header(), body())),
      pager()));
  }

  el.addEventListener("click", (e) => {
    const sortBtn = e.target.closest("[data-sort]");
    if (sortBtn && p.onSort) {
      const key = sortBtn.dataset.sort;
      p.onSort({ key, dir: p.sort?.key === key ? NEXT_DIR[p.sort.dir] || "ascending" : "ascending" });
      return;
    }
    const open = e.target.closest("[data-open]");
    if (open) p.onRowOpen?.(p.rows.find((r) => keyOf(r) === open.dataset.open));
  });
  el.addEventListener("change", (e) => {
    const box = e.target;
    if (box.matches?.("[data-select-all]")) {
      for (const r of p.rows) {
        if (box.checked) selected.add(keyOf(r));
        else selected.delete(keyOf(r));
      }
    } else if (box.matches?.("[data-select]")) {
      if (box.checked) selected.add(box.dataset.select);
      else selected.delete(box.dataset.select);
    } else return;
    paint();
    p.onSelectionChange?.([...selected]);
  });

  paint();
  return {
    el,
    update(next = {}) {
      p = { ...p, ...next };
      const present = new Set(p.rows.map(keyOf));
      for (const k of [...selected]) if (!present.has(k)) selected.delete(k);
      paint();
    },
    selection: () => p.rows.filter((r) => selected.has(keyOf(r))),
    destroy() {
      el.remove();
    },
  };
}
