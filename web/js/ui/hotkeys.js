// Raccourcis clavier : un registre unique (règle A6, cahier §3.2).
//
// HOTKEYS est la copie exacte de design/hotkeys.json (lu aussi par le client
// Windows) ; la galerie vérifie l'égalité. Une vue branche une action sur une
// entrée du registre par hotkeys.register({ id, run }) et active sa portée par
// hotkeys.enterScope("vault"). La portée « global » est toujours active.
//
// Règles :
// - une touche simple (sans Ctrl ni Alt : « / », « ? », « N ») n'agit jamais
//   dans un champ de saisie, et seulement si hotkeys.setEnabled(true) (préférence
//   et politique client.single_key_shortcuts, décidées par l'appelant) ;
// - quand une fenêtre modale est ouverte, seules les entrées de la portée
//   « editor » agissent, et seulement depuis cette fenêtre ;
// - un événement déjà traité (defaultPrevented) est ignoré : la saisie d'une
//   lettre dans une liste (itemList) ne déclenche pas « N ».
// Les entrées sans action (navigation de liste, Échap) sont documentaires :
// elles apparaissent dans l'aide, le comportement vient du composant.
// Aucun raccourci n'utilise Ctrl N, T, W, L, R, B ni ne détourne Ctrl C / Ctrl V.

import { t } from "../i18n.js";
import { h } from "./core.js";
import { isEditable } from "./focus.js";
import { dialog } from "./dialog.js";

export const HOTKEYS = Object.freeze([
  { id: "search.focus", keys: ["Ctrl+K", "/"], scope: "global", labelKey: "ui.hotkeys.search_focus", singleKey: false },
  { id: "lock", keys: ["Ctrl+Alt+L"], scope: "global", labelKey: "ui.hotkeys.lock", singleKey: false },
  { id: "help", keys: ["?"], scope: "global", labelKey: "ui.hotkeys.help", singleKey: true },
  { id: "dialog.close", keys: ["Escape"], scope: "global", labelKey: "ui.hotkeys.close", singleKey: false },
  { id: "item.new", keys: ["N"], scope: "vault", labelKey: "ui.hotkeys.item_new", singleKey: true },
  { id: "item.copy_password", keys: ["Ctrl+Shift+C"], scope: "vault", labelKey: "ui.hotkeys.copy_password", singleKey: false },
  { id: "item.copy_username", keys: ["Ctrl+Shift+U"], scope: "vault", labelKey: "ui.hotkeys.copy_username", singleKey: false },
  { id: "list.move", keys: ["ArrowUp", "ArrowDown", "Home", "End"], scope: "list", labelKey: "ui.hotkeys.list_move", singleKey: false },
  { id: "list.jump", keys: ["Letter"], scope: "list", labelKey: "ui.hotkeys.list_jump", singleKey: false },
  { id: "list.open", keys: ["Enter"], scope: "list", labelKey: "ui.hotkeys.list_open", singleKey: false },
  { id: "editor.save", keys: ["Ctrl+Enter", "Ctrl+S"], scope: "editor", labelKey: "ui.hotkeys.save", singleKey: false },
].map((e) => Object.freeze({ ...e, keys: Object.freeze([...e.keys]) })));

const SCOPES = ["global", "vault", "list", "editor"];
const MODIFIERS = new Set(["ctrl", "alt", "shift"]);
const KEY_LABELS = {
  ctrl: "ui.key.ctrl", alt: "ui.key.alt", shift: "ui.key.shift", enter: "ui.key.enter", escape: "ui.key.escape",
  arrowup: "ui.key.arrow_up", arrowdown: "ui.key.arrow_down", home: "ui.key.home", end: "ui.key.end", letter: "ui.key.letter",
};

/** « Ctrl+Shift+C » -> { ctrl, alt, shift, key: "c", single }. */
export function parseKey(text) {
  const parts = String(text).split("+");
  const key = parts.pop().toLowerCase();
  const mods = new Set(parts.map((p) => p.toLowerCase()));
  for (const m of mods) if (!MODIFIERS.has(m)) throw new Error(t("ui.dev.hotkey_modifier", { modifier: m, keys: text }));
  const ctrl = mods.has("ctrl");
  const alt = mods.has("alt");
  return { ctrl, alt, shift: mods.has("shift"), key, single: !ctrl && !alt };
}

/** Vrai si l'événement clavier correspond à la touche décrite. */
export function matches(e, parsed) {
  if ((e.ctrlKey || e.metaKey) !== parsed.ctrl || e.altKey !== parsed.alt) return false;
  const printable = parsed.key.length === 1;
  const letter = /^[a-z]$/.test(parsed.key);
  // « ? » ou « / » : la touche Maj dépend de la disposition du clavier.
  if (!(printable && !letter) && e.shiftKey !== parsed.shift) return false;
  if (String(e.key).toLowerCase() === parsed.key) return true;
  // Combinaison avec Ctrl ou Alt : la touche physique fait foi (dispositions non latines).
  return letter && (parsed.ctrl || parsed.alt) && e.code === `Key${parsed.key.toUpperCase()}`;
}

const byId = new Map(HOTKEYS.map((e) => [e.id, e]));
const bindings = new Map();
const activeScopes = new Map(SCOPES.map((s) => [s, s === "global" ? 1 : 0]));
let singleKeysEnabled = true;
let installed = false;

function modalOpen() {
  return document.querySelector("dialog[open]:modal, [aria-modal='true']:not([hidden])");
}

function onKeydown(e) {
  if (e.defaultPrevented || e.isComposing || e.repeat) return;
  const modal = modalOpen();
  const editable = isEditable(e.target);
  for (const { entry, run, parsed } of bindings.values()) {
    if (!activeScopes.get(entry.scope)) continue;
    if (modal && (entry.scope !== "editor" || !modal.contains(e.target))) continue;
    const hit = parsed.find((p) => matches(e, p));
    if (!hit) continue;
    if (hit.single && (!singleKeysEnabled || editable)) continue;
    e.preventDefault();
    run(e);
    return;
  }
}

function install() {
  if (installed) return;
  installed = true;
  document.addEventListener("keydown", onKeydown);
}

export const hotkeys = {
  /** Entrées du registre (copie). */
  list() {
    return HOTKEYS.map((e) => ({ ...e, keys: [...e.keys] }));
  },

  /**
   * Branche une action sur une entrée du registre. Les touches, la portée et le
   * libellé viennent du registre ; une entrée absente du registre est refusée.
   * Renvoie la fonction qui retire l'action.
   */
  register({ id, run }) {
    const entry = byId.get(id);
    if (!entry) throw new Error(t("ui.dev.hotkey_unknown", { id }));
    if (typeof run !== "function") throw new Error(t("ui.dev.hotkey_no_action", { id }));
    install();
    const binding = { entry, run, parsed: entry.keys.filter((k) => k !== "Letter").map(parseKey) };
    bindings.set(id, binding);
    return () => {
      if (bindings.get(id) === binding) bindings.delete(id);
    };
  },

  /** Active une portée ("vault", "list", "editor") ; renvoie la fonction qui la quitte. */
  enterScope(scope) {
    if (!activeScopes.has(scope)) throw new Error(t("ui.dev.hotkey_scope", { scope }));
    activeScopes.set(scope, activeScopes.get(scope) + 1);
    let left = false;
    return () => {
      if (left || scope === "global") return;
      left = true;
      activeScopes.set(scope, Math.max(0, activeScopes.get(scope) - 1));
    };
  },

  /** Active ou coupe les touches simples (préférence et politique client.single_key_shortcuts). */
  setEnabled(allowed) {
    singleKeysEnabled = !!allowed;
  },

  isEnabled() {
    return singleKeysEnabled;
  },

  /** Fenêtre « Raccourcis clavier », générée depuis le registre. */
  helpDialog() {
    const groups = SCOPES.map((scope) => {
      const entries = HOTKEYS.filter((e) => e.scope === scope);
      const list = h("dl", { class: "c-hotkeys" }, entries.flatMap((e) => {
        const off = !singleKeysEnabled && e.keys.every((k) => parseKeySafe(k).single);
        return [
          h("dt", {}, t(e.labelKey), off ? h("span", { class: "u-muted" }, ` (${t("ui.hotkeys.disabled")})`) : null),
          h("dd", {}, keysLabel(e.keys)),
        ];
      }));
      return h("section", { class: "l-stack", "data-gap": "2" }, h("h3", {}, t(`ui.hotkeys.scope.${scope}`)), list);
    });
    return dialog({
      title: t("ui.hotkeys.title"),
      description: singleKeysEnabled ? undefined : t("ui.hotkeys.single_off"),
      body: h("div", { class: "l-stack" }, groups),
      actions: [{ label: t("common.action.close"), variant: "primary" }],
      size: "md",
    });
  },
};

function parseKeySafe(k) {
  return k === "Letter" ? { single: false } : parseKey(k);
}

/** Touches affichées : un <kbd class="c-kbd"> par touche, « ou » entre deux combinaisons. */
export function keysLabel(keys) {
  const out = [];
  keys.forEach((combo, i) => {
    if (i > 0) out.push(h("span", { class: "u-muted" }, t("ui.hotkeys.or")));
    combo.split("+").forEach((part, j) => {
      if (j > 0) out.push(h("span", { "aria-hidden": "true" }, "+"));
      const known = KEY_LABELS[part.toLowerCase()];
      out.push(h("kbd", { class: "c-kbd" }, known ? t(known) : part.toUpperCase()));
    });
  });
  return out;
}
