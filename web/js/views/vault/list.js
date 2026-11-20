// Liste des éléments (cahier §3.3.2) : itemList en <ul> avec lien principal,
// « Copier le mot de passe de <nom> » et « Plus d'actions pour <nom> » ;
// filtre « Type » et « Tri » (préférence synchronisée) ; mise à jour par
// différence : défilement, sélection et focus survivent aux mises à jour.
// La corbeille réutilise cette liste avec ses propres lignes (trash.js).
//
// createList({ env }) -> { el, update(view), focusKey(id), scrollTop, destroy() }
//   view = { context: { kind: "all"|"favorites"|"collection"|"trash", collectionId },
//            selectedId, headingLevel, type, trashScope }

import {
  t, plural, fmtDate, h, icon, button, field, selectInput, itemList, emptyState, focusSafely, announce,
} from "../../ui/index.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";
import {
  KINDS, kindLabel, collectionOf, collectionLabel, canWrite, canManage, favorites, subtitle, primarySecret, usernameOf,
  safeUrl, errorNotice, roleLabel, policy,
} from "./common.js";
import * as A from "./actions.js";
import { trashRow, trashScopes, trashNames, inTrashScope } from "./trash.js";
import { onboarding } from "./onboarding.js";

const SORTS = ["name", "recent"];

/** Éléments à afficher pour une vue, triés. */
export function itemsFor(view) {
  const ctx = view.context;
  const favs = favorites();
  const sort = S.prefs().ui?.sort === "recent" ? "recent" : "name";
  const out = [];
  for (const i of V.state.items.values()) {
    if (!i.data) continue;
    if (ctx.kind === "trash" ? !i.deleted_at : i.deleted_at) continue;
    if (ctx.kind === "collection" && i.collection_id !== ctx.collectionId) continue;
    if (ctx.kind === "favorites" && !favs.has(i.id)) continue;
    if (ctx.kind === "trash" && !inTrashScope(i, view.trashScope)) continue;
    if (view.type && view.type !== "all" && i.data.kind !== view.type) continue;
    out.push(i);
  }
  const byName = (a, b) => String(a.data.name).localeCompare(String(b.data.name), "fr", { sensitivity: "base" });
  if (ctx.kind === "trash") out.sort((a, b) => (b.deleted_at - a.deleted_at) || byName(a, b));
  else if (sort === "recent") out.sort((a, b) => (b.updated_at - a.updated_at) || byName(a, b));
  else out.sort(byName);
  return out;
}

function titleFor(ctx) {
  if (ctx.kind === "favorites") return t("vault.list.title.favorites");
  if (ctx.kind === "trash") return t("common.glossary.trash");
  if (ctx.kind === "collection") return collectionLabel(collectionOf(ctx.collectionId));
  return t("vault.list.title.all");
}

export function createList({ env }) {
  let view = null;
  let rows = [];

  const headingSlot = h("div", { class: "l-stack", "data-gap": "1" });
  // Compteur visible ; son changement (filtre, recherche) est annoncé par
  // #status, la seule région polie de l'application (A1).
  const countEl = h("p", { class: "u-muted" });
  let lastCount = null;
  const typeSelect = selectInput({
    name: "type",
    options: [{ value: "all", label: t("vault.filter.type.all") }, ...KINDS.map((k) => ({ value: k, label: t(`vault.filter.type.${k}`) }))],
    value: "all",
  });
  typeSelect.addEventListener("change", () => env.setType(typeSelect.value));
  const sortSelect = selectInput({
    name: "sort",
    options: SORTS.map((s) => ({ value: s, label: t(`vault.sort.${s}`) })),
    value: S.prefs().ui?.sort === "recent" ? "recent" : "name",
  });
  sortSelect.addEventListener("change", async () => {
    const before = S.prefs().ui?.sort === "recent" ? "recent" : "name";
    try {
      await S.savePrefs({ ui: { sort: sortSelect.value } });
    } catch (e) {
      sortSelect.value = before;
      errorNotice(e);
      return;
    }
    redraw();
  });
  const typeField = field({ label: t("vault.filter.type.label"), input: typeSelect });
  const sortField = field({ label: t("vault.sort.label"), input: sortSelect });
  const trashScopeSlot = h("div", {});
  const filters = h("div", { class: "l-cluster" }, typeField, sortField);
  const banner = h("div", { class: "l-stack", "data-gap": "2" });
  const body = h("div", {});

  const list = itemList({
    label: t("vault.list.label"),
    items: [],
    render: (i) => renderRow(i),
    onOpen: (i) => env.navigate(`/element/${encodeURIComponent(i.id)}`),
    onPrimary: (i) => A.copyPrimary(i),
    onMenu: (i) => rowMenu(i),
  });

  const el = h("section", { class: "l-stack", "data-gap": "0", "aria-label": t("vault.list.region") },
    h("div", { class: "c-panel__body" }, headingSlot, countEl, trashScopeSlot, filters, banner),
    body);

  function renderRow(i) {
    const d = i.data;
    const name = d.name || t("vault.list.untitled");
    if (view?.context.kind === "trash") return trashRow(i, name);
    const secret = primarySecret(d);
    const col = view?.context.kind === "collection" ? null : collectionOf(i.collection_id);
    const sub = subtitle(d) || kindLabel(d.kind);
    return {
      title: name,
      subtitle: col && !col.personal ? `${sub} · ${collectionLabel(col)}` : sub,
      href: `#/element/${encodeURIComponent(i.id)}`,
      avatar: { name: d.name, kind: d.kind },
      primaryLabel: secret ? t(secret.labelKey, { name }) : undefined,
      menuLabel: t("vault.list.more", { name }),
    };
  }

  function rowMenu(i) {
    const d = i.data;
    if (view?.context.kind === "trash") {
      const writable = canWrite(i.collection_id);
      const reason = writable ? undefined : t("vault.detail.read_only");
      return [
        { label: t("common.action.restore"), icon: "restore", disabled: !writable, reason, onSelect: () => A.restore(i, env) },
        { label: t("common.action.delete_forever"), icon: "trash", danger: true, disabled: !writable, reason, onSelect: () => A.purge(i, env) },
      ];
    }
    const fav = favorites().has(i.id);
    const user = usernameOf(d);
    const writable = canWrite(i.collection_id);
    return [
      { label: t("ui.secret.copy_username"), icon: "user", disabled: !user, reason: user ? undefined : t("vault.list.no_username"), onSelect: () => A.copyUsername(i) },
      { label: t("ui.secret.copy_totp"), icon: "clock", disabled: !d.totp, reason: d.totp ? undefined : t("vault.list.no_code"), onSelect: () => A.copyCode(i) },
      { label: t("vault.detail.open_site"), icon: "external", disabled: !safeUrl((d.urls || [])[0]), reason: safeUrl((d.urls || [])[0]) ? undefined : t("vault.list.no_site"), onSelect: () => A.openSite(i) },
      { label: t(fav ? "vault.detail.favorite_remove" : "vault.detail.favorite_add"), icon: fav ? "star-filled" : "star", onSelect: async () => { await A.toggleFavorite(i); redraw(); env.countsChanged(); } },
      "separator",
      { label: t("common.action.move_to_trash"), icon: "trash", danger: true, disabled: !writable, reason: writable ? undefined : t("vault.detail.read_only"),
        onSelect: () => A.moveToTrash(i, env) },
    ];
  }

  function paintHeading() {
    const ctx = view.context;
    const level = view.headingLevel === 1 ? "h1" : "h2";
    const heading = h(level, { tabindex: "-1" }, titleFor(ctx));
    const extra = [];
    if (ctx.kind === "collection") {
      const c = collectionOf(ctx.collectionId);
      if (c && !c.personal) {
        extra.push(h("div", { class: "l-cluster", "data-justify": "between" },
          h("p", { class: "u-muted" }, plural("vault.collection.members", c.member_count || 0), " · ", t("vault.collection.your_role", { role: roleLabel(c.role).toLowerCase() })),
          button({ label: t(canManage(c.id) ? "vault.collection.manage" : "vault.collection.view_members"), icon: "users", variant: "quiet", onClick: () => env.manageCollection(c.id) })));
        if (c.rotation_suggested_at && canManage(c.id)) {
          extra.push(h("div", { class: "c-alert", "data-tone": "warn" }, icon("warn"),
            h("div", { class: "l-stack", "data-gap": "2" },
              h("p", {}, t("vault.collection.rotation_suggested", { date: fmtDate(c.rotation_suggested_at, "date") })),
              h("div", {}, button({ label: t("vault.collection.rotate"), icon: "refresh", onClick: () => env.manageCollection(c.id, { rotate: true }) })))));
        }
      }
    }
    if (ctx.kind === "trash") {
      extra.push(h("p", { class: "u-muted" }, plural("vault.trash.retention", Number(policy("retention.trash_days", 30)) || 30)));
    }
    headingSlot.replaceChildren(heading, ...extra);
  }

  function emptyFor(n) {
    const ctx = view.context;
    if (view.type && view.type !== "all") {
      return emptyState({ title: t("vault.list.empty.type"), actions: [{ label: t("vault.list.empty.all_types"), onClick: () => env.setType("all") }] });
    }
    if (ctx.kind === "favorites") return emptyState({ icon: "star", title: t("vault.list.empty.favorites_title"), text: t("vault.list.empty.favorites") });
    if (ctx.kind === "trash") return emptyState({ icon: "trash", title: t("vault.list.empty.trash") });
    if (ctx.kind === "collection") {
      const writable = canWrite(ctx.collectionId);
      return emptyState({
        icon: "folder", title: t("vault.list.empty.collection"),
        actions: writable ? [{ label: t("vault.list.empty.add"), variant: "primary", onClick: () => env.navigate(`/nouveau?coffre=${encodeURIComponent(ctx.collectionId)}`) }] : [],
      });
    }
    return n === 0 ? onboarding({ env }) : emptyState({ title: t("vault.list.empty.all") });
  }

  function redraw() {
    if (!view) return;
    rows = itemsFor(view);
    const ctx = view.context;
    countEl.textContent = plural("vault.list.count", rows.length);
    if (lastCount !== null && lastCount !== rows.length) announce(countEl.textContent);
    lastCount = rows.length;
    typeSelect.value = view.type || "all";
    sortSelect.value = S.prefs().ui?.sort === "recent" ? "recent" : "name";
    sortField.hidden = ctx.kind === "trash";
    trashScopeSlot.replaceChildren(ctx.kind === "trash" ? trashScopes(view.trashScope, (v) => env.setTrashScope(v)) : "");
    list.update({ items: rows, selectedKey: view.selectedId ?? null, label: t(ctx.kind === "trash" ? "vault.trash.list_label" : "vault.list.label") });
    if (rows.length) {
      if (!list.el.isConnected || list.el.parentNode !== body) body.replaceChildren(list.el);
    } else {
      const anyLive = [...V.state.items.values()].some((i) => i.data && !i.deleted_at);
      body.replaceChildren(h("div", { class: "c-panel__body" }, emptyFor(anyLive ? 1 : 0)));
    }
  }

  return {
    el,
    update(next) {
      view = next;
      paintHeading();
      if (next.context.kind === "trash") {
        // Noms des auteurs : annuaire chargé une fois, puis lignes redessinées.
        trashNames().then((changed) => { if (changed && view === next) redraw(); });
      }
      redraw();
    },
    /** Rafraîchit les lignes (favori, tri) sans changer de vue. */
    redraw,
    focusKey(id) {
      list.focusKey(id);
    },
    focusFirst() {
      if (rows.length) list.focusKey(rows[0].id);
      else focusSafely(el.querySelector("h1, h2"));
    },
    rows: () => rows,
    destroy() {
      list.destroy();
    },
  };
}
