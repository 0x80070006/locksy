// Écran du coffre (cahier §3.3.2 à §3.3.5, contrat C4.3) : liste et fiche
// côte à côte (une seule des deux sous 600 px), édition dans le panneau de la
// fiche, corbeille. Un seul module pour toutes les routes du coffre :
//   #/coffre, #/coffre/favoris, #/coffre/c/:collectionId, #/corbeille   liste ;
//   #/element/:id                                                       fiche ;
//   #/element/:id/modifier (?regenerer=1 : « Corriger » du bilan)       édition ;
//   #/nouveau/:type? (?coffre=<id>, ?copie=<id>)                        création.
// Le titre de l'onglet ne contient jamais de nom d'élément ni de coffre (R5) :
// seul le titre par défaut de la route est utilisé ; l'adresse ne porte que
// des identifiants et des choix d'affichage (type, vue de la corbeille).
//
// render(ctx) -> { dispose(), isDirty(), save?(), focused }

import { t, h, icon, emptyState, hotkeys } from "../../ui/index.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";
import { createList } from "./list.js";
import { renderDetail } from "./detail.js";
import { renderEditor } from "./editor.js";
import * as A from "./actions.js";
import { KINDS, collectionOf, favorites, primarySecret, usernameOf, errorNotice } from "./common.js";

const MOBILE_QUERY = "(width < 37.5em)";

/**
 * Mémoire de l'écran entre deux routes (jamais stockée) : dernière liste
 * affichée (la fiche s'ouvre à côté d'elle) et position de défilement par liste.
 */
const memory = { context: { kind: "all" }, scroll: new Map(), migratedFor: null };

const contextKey = (c) => `${c.kind}:${c.collectionId || ""}`;

/** Adresse de la liste d'un contexte. */
export function listPath(c = memory.context) {
  switch (c.kind) {
    case "favorites": return "/coffre/favoris";
    case "trash": return "/corbeille";
    case "collection": return `/coffre/c/${encodeURIComponent(c.collectionId)}`;
    default: return "/coffre";
  }
}

/** Ce que demande la route : { mode: list|detail|edit|new, context, id }. */
function readRoute(ctx) {
  const pattern = ctx.route?.pattern || ctx.path;
  const p = ctx.params || {};
  switch (pattern) {
    case "/coffre/favoris": return { mode: "list", context: { kind: "favorites" } };
    case "/corbeille": return { mode: "list", context: { kind: "trash" } };
    case "/coffre/c/:collectionId": return { mode: "list", context: { kind: "collection", collectionId: p.collectionId } };
    case "/element/:id": return { mode: "detail", id: p.id };
    case "/element/:id/modifier": return { mode: "edit", id: p.id };
    case "/nouveau/:type?": return { mode: "new", type: p.type };
    default: return { mode: "list", context: { kind: "all" } };
  }
}

/** Nombre d'éléments par entrée de la barre latérale (favoris personnels seulement). */
function counts() {
  const favs = favorites();
  const perCollection = {};
  let all = 0;
  let fav = 0;
  let trash = 0;
  for (const i of V.state.items.values()) {
    if (i.deleted_at) {
      trash++;
      continue;
    }
    all++;
    if (favs.has(i.id)) fav++;
    perCollection[i.collection_id] = (perCollection[i.collection_id] || 0) + 1;
  }
  for (const id of V.state.collections.keys()) perCollection[id] ??= 0;
  return { all, favorites: fav, collections: perCollection, trash };
}

export async function render(ctx) {
  const route = readRoute(ctx);
  if (route.context) memory.context = route.context;
  // Fiche d'un élément de la corbeille ouverte depuis une autre liste : contexte inchangé.
  const context = memory.context;
  const query = ctx.query || new URLSearchParams();
  const mobile = window.matchMedia(MOBILE_QUERY);
  const cleanups = [];
  let pane = null; // { el, destroy(), setMobile?, isDirty?, save?, focus? }
  let disposed = false;

  const listState = {
    context,
    selectedId: route.id || null,
    headingLevel: route.mode === "list" ? 1 : 2,
    type: KINDS.includes(query.get("type")) ? query.get("type") : "all",
    trashScope: query.get("vue") || "all",
  };

  const env = {
    shell: ctx.shell,
    navigate: (path, opts) => ctx.navigate(path, opts),
    listPath: () => listPath(),
    /** Resynchronise puis redessine ; une panne est signalée sans rien défaire. */
    async reload() {
      try {
        await ctx.refresh();
      } catch (e) {
        errorNotice(e);
      }
    },
    setType(v) {
      listState.type = KINDS.includes(v) ? v : "all";
      ctx.setQuery({ type: listState.type === "all" ? null : listState.type });
      list.update(listState);
    },
    setTrashScope(v) {
      listState.trashScope = v;
      ctx.setQuery({ vue: v === "all" ? null : v });
      list.update(listState);
    },
    countsChanged() {
      ctx.shell?.setSidebarCounts?.(counts());
      list.redraw();
    },
    async manageCollection(id, opts = {}) {
      const m = await import("./collections.js");
      return m.manageCollection(id, { env, ...opts });
    },
    async openShare(item) {
      const m = await import("./share-dialog.js");
      return m.openShareDialog(item, env);
    },
  };

  const list = createList({ env });
  const listPane = h("div", { class: "l-stack", "data-gap": "0" }, list.el);
  const sidePane = h("div", {});
  const split = h("div", { class: "l-split", "data-view": route.mode === "list" ? "list" : "detail" }, listPane, sidePane);
  ctx.root.replaceChildren(split);

  // ---------------------------------------------------------- Panneau de droite
  function showPane(next) {
    pane?.destroy?.();
    pane = next;
    sidePane.replaceChildren(next ? next.el : "");
  }

  function missing(textKey) {
    return {
      el: h("div", { class: "c-panel__body" }, emptyState({
        icon: "search", title: t("vault.detail.not_found_title"), text: t(textKey), level: 1,
        actions: [{ label: t("vault.detail.back"), href: `#${listPath()}`, variant: "primary" }],
      })),
    };
  }

  function placeholder() {
    return {
      el: h("div", { class: "c-panel__body" }, h("div", { class: "c-empty" }, icon("vault"),
        h("p", { class: "c-empty__text" }, t("vault.detail.pick")))),
    };
  }

  function detailFor(id) {
    const item = V.state.items.get(id);
    if (!item) return missing("vault.detail.not_found_text");
    if (!item.data) return missing("vault.detail.unreadable");
    return renderDetail({ item, env, heading: 1, mobile: mobile.matches });
  }

  function editorFor() {
    if (route.mode === "new") {
      const kind = KINDS.includes(route.type) ? route.type : "login";
      const copyOf = query.get("copie") ? V.state.items.get(query.get("copie")) : null;
      const preferred = query.get("coffre") || (context.kind === "collection" ? context.collectionId : null);
      return renderEditor({
        kind: copyOf?.data?.kind || kind,
        collectionId: preferred,
        template: copyOf?.data || null,
        env,
      });
    }
    const item = V.state.items.get(route.id);
    if (!item) return missing("vault.detail.not_found_text");
    if (!item.data) return missing("vault.detail.unreadable");
    return renderEditor({ item, regenerate: query.get("regenerer") === "1", env });
  }

  if (route.mode === "list") showPane(placeholder());
  else if (route.mode === "detail") showPane(detailFor(route.id));
  else showPane(editorFor());

  // Coffre filtré introuvable (retiré, adresse ancienne) : message, pas d'écran vide.
  if (context.kind === "collection" && !collectionOf(context.collectionId)) {
    listPane.replaceChildren(missing("vault.collection.not_found").el);
  } else {
    list.update(listState);
    const top = memory.scroll.get(contextKey(context));
    if (top) listPane.scrollTop = top;
  }
  ctx.shell?.setSearchScope?.(context.kind === "collection" ? context.collectionId : null);
  ctx.shell?.setSidebarCounts?.(counts());

  // ---------------------------------------------------------- Mises à jour
  const onMobile = () => pane?.setMobile?.(mobile.matches);
  mobile.addEventListener("change", onMobile);
  cleanups.push(() => mobile.removeEventListener("change", onMobile));

  if (ctx.onRefresh) {
    cleanups.push(ctx.onRefresh(() => {
      if (disposed) return;
      if (!(context.kind === "collection" && !collectionOf(context.collectionId))) list.update(listState);
      ctx.shell?.setSidebarCounts?.(counts());
      // La fiche suit les changements ; l'éditeur garde la saisie (conflit traité à l'enregistrement).
      if (route.mode === "detail") showPane(detailFor(route.id));
    }));
  }
  // Tri changé ailleurs (préférences rechargées, autre onglet) : liste remise en ordre.
  cleanups.push(S.subscribe("ui.sort", () => list.redraw()));

  // ---------------------------------------------------------- Raccourcis
  /** Élément visé : ligne focalisée de la liste, sinon la fiche ouverte. */
  function targetItem() {
    const li = document.activeElement?.closest?.(".c-item-list__row[data-key]");
    const id = li?.dataset.key || (route.mode === "detail" ? route.id : null);
    return id ? V.state.items.get(id) : null;
  }
  cleanups.push(hotkeys.enterScope("vault"));
  cleanups.push(hotkeys.register({ id: "item.new", run: () => ctx.navigate("/nouveau") }));
  cleanups.push(hotkeys.register({
    id: "item.copy_password",
    run: () => {
      const item = targetItem();
      if (item && primarySecret(item.data)) A.copyPrimary(item);
    },
  }));
  cleanups.push(hotkeys.register({
    id: "item.copy_username",
    run: () => {
      const item = targetItem();
      if (item && usernameOf(item.data)) A.copyUsername(item);
    },
  }));

  // Reprise unique des anciens favoris dans les préférences (§4.9).
  const me = V.state.profile?.id;
  if (me && memory.migratedFor !== me) {
    memory.migratedFor = me;
    A.migrateLegacyFavorites().then((changed) => { if (changed && !disposed) env.countsChanged(); });
  }

  // Focus : « Nom » dans l'éditeur ; sinon le routeur le place sur le titre.
  let focused = false;
  if (pane?.focus) {
    pane.focus();
    focused = true;
  }

  return {
    focused,
    isDirty: () => !!pane?.isDirty?.(),
    save: pane?.save ? () => pane.save() : undefined,
    dispose() {
      disposed = true;
      if (context.kind !== "collection" || collectionOf(context.collectionId)) memory.scroll.set(contextKey(context), listPane.scrollTop);
      while (cleanups.length) {
        try { cleanups.pop()(); } catch { /* déjà retiré */ }
      }
      showPane(null);
      list.destroy();
    },
  };
}
