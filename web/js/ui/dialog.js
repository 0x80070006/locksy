// Fenêtre modale native (règle A4) : <dialog> + showModal() donnent le fond
// inerte et le piège du focus ; Échap ne ferme que la fenêtre du dessus ; le
// corps est dans un <form method="dialog"> : Entrée valide l'action principale ;
// le focus revient au déclencheur à la fermeture ; garde « dirty » sur Échap
// et sur « Annuler ».

import { h, uid } from "./core.js";
import { button, busyWhile, isInactive } from "./button.js";
import { dirtyGuard } from "./dirty.js";
import { focusables, focusSafely, focusHeading } from "./focus.js";

const open = new Set();
/** Fenêtres ouvertes avec une garde de saisie (consultées par le routeur). */
const guarded = new Set();
const openers = new WeakMap();
const hosts = new WeakMap();

/**
 * Mémorise le déclencheur d'une fenêtre ou d'un panneau, et la fenêtre qui
 * contenait ce déclencheur (pour rendre le focus).
 */
export function rememberOpener(overlay, opener) {
  openers.set(overlay, opener);
  const host = opener?.closest?.("dialog, [aria-modal='true']");
  if (host) hosts.set(opener, host);
}

/**
 * Rend le focus au déclencheur. S'il a disparu avec une fenêtre déjà fermée
 * (garde « Enregistrer » qui ferme la fenêtre du dessous), on remonte au
 * déclencheur de cette fenêtre. Déclencheur introuvable (vue redessinée
 * derrière la fenêtre) : titre de la vue. Le focus ne retombe jamais sur <body>.
 */
export function returnFocus(opener) {
  let target = opener;
  for (let i = 0; i < 8 && target && !target.isConnected; i++) {
    const host = hosts.get(target);
    target = host ? openers.get(host) : null;
  }
  if (target && target !== document.body && focusSafely(target)) return;
  const active = document.activeElement;
  if (!active || active === document.body) focusHeading(document.querySelector("main") || document);
}

/** Inscrit une fenêtre ou un panneau ouvert (closeAll les ferme tous). */
export function trackOverlay(close) {
  open.add(close);
  return () => open.delete(close);
}

/**
 * Fenêtre ouverte dont la saisie est modifiée (la plus récente), ou null :
 * { confirmLeave() -> "stay" | "discard" | "save", close() }. Le routeur la
 * consulte avant de changer d'écran : un changement d'adresse ne fait pas
 * disparaître la saisie d'une fenêtre sans demande.
 */
export function modifiedDialog() {
  return [...guarded].reverse().find((g) => g.dirty()) || null;
}

/** Ferme toutes les fenêtres et panneaux ouverts, sans garde (verrouillage, fin de session). */
export function closeAll() {
  for (const close of [...open].reverse()) close();
}

/**
 * dialog({ title, description, body, actions, size = "md", dirty = () => false,
 *          initialFocus, onClose, onSave }) -> HTMLDialogElement
 *
 * actions : éléments déjà construits, ou descriptions
 *   { label, variant, value, onClick, busyLabel, cancel, disabled, reason }.
 *   - la première action « primary » (ou `submit: true`) est le bouton par défaut
 *     (Entrée dans un champ) ;
 *   - onClick({ dialog, form }) : renvoyer false (ou une promesse de false)
 *     garde la fenêtre ouverte ; sinon elle se ferme avec `value` ;
 *   - `cancel: true` passe par la garde de saisie si dirty() est vrai.
 * onClose(returnValue) est appelée après la fermeture. onSave sert à
 * « Enregistrer » de la garde (par défaut : l'action principale).
 */
export function dialog({ title, description, body, actions = [], size = "md", dirty = () => false, initialFocus, onClose, onSave }) {
  const opener = document.activeElement;
  const titleId = uid("dlg-t");
  const descId = description ? uid("dlg-d") : undefined;
  const specs = new Map();
  let primary = null;
  let closed = false;

  const buttons = actions.filter(Boolean).map((a) => {
    if (a instanceof Node) return a;
    const submit = !primary && (a.submit || a.variant === "primary");
    const btn = button({
      label: a.label, icon: a.icon, variant: a.variant, busyLabel: a.busyLabel, disabled: a.disabled, reason: a.reason,
      type: submit ? "submit" : "button",
      onClick: submit ? undefined : () => activate(a, btn),
    });
    if (submit) primary = { spec: a, btn };
    specs.set(btn, a);
    return btn;
  });

  const form = h("form", { method: "dialog", class: "c-dialog__form" },
    h("h2", { id: titleId, class: "c-dialog__title" }, title),
    description ? h("p", { id: descId, class: "c-dialog__desc" }, description) : null,
    body,
    buttons.length ? h("div", { class: "c-dialog__actions" }, buttons) : null);
  const dlg = h("dialog", {
    class: "c-dialog", "data-size": size && size !== "md" ? size : undefined,
    "aria-labelledby": titleId, "aria-describedby": descId,
  }, form);

  // Garde de saisie : Échap, « Annuler », changement d'écran (routeur) et
  // fermeture de l'onglet (beforeunload, retiré à la fermeture).
  const guard = dirtyGuard(dirty, { unload: true, onSave: onSave || (primary ? () => activate(primary.spec, primary.btn) : undefined) });
  const entry = { dirty: () => !closed && dirty(), confirmLeave: () => guard.confirmLeave(), close: () => close("cancel") };
  guarded.add(entry);

  function close(value = "") {
    if (closed) return;
    if (dlg.open) dlg.close(String(value));
    else finish();
  }

  function finish() {
    if (closed) return;
    closed = true;
    untrack();
    guarded.delete(entry);
    guard.destroy();
    dlg.remove();
    returnFocus(opener);
    onClose?.(dlg.returnValue);
  }

  async function askLeave() {
    if ((await guard.confirmLeave()) === "discard") close("cancel");
  }

  /** Exécute une action ; renvoie vrai si la fenêtre a été fermée. */
  async function activate(spec, btn) {
    if (closed) return true;
    if (spec.cancel && dirty()) {
      await askLeave();
      return closed;
    }
    let result;
    if (typeof spec.onClick === "function") {
      const out = spec.onClick({ dialog: dlg, form });
      // Le bouton « submit » n'a pas de gestionnaire propre : l'état « en cours » est posé ici.
      const wait = out && typeof out.then === "function";
      result = wait && btn.type === "submit" ? await busyWhile(btn, out, spec.busyLabel) : await out;
    }
    if (result === false) return false;
    close(spec.value ?? "");
    return true;
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const btn = e.submitter && specs.has(e.submitter) ? e.submitter : primary?.btn;
    if (!btn || isInactive(btn)) return;
    activate(specs.get(btn), btn);
  });
  dlg.addEventListener("keydown", (e) => {
    // Échap avec une saisie modifiée : garde, la fenêtre reste ouverte.
    if (e.key === "Escape" && dirty()) {
      e.preventDefault();
      e.stopPropagation();
      askLeave();
      return;
    }
    // Tab boucle dans la fenêtre (le navigateur laisserait sortir vers sa barre d'adresse).
    if (e.key !== "Tab") return;
    const list = focusables(dlg);
    if (!list.length) return;
    const edge = e.shiftKey ? list[0] : list[list.length - 1];
    if (document.activeElement !== edge) return;
    e.preventDefault();
    focusSafely(e.shiftKey ? list[list.length - 1] : list[0]);
  });
  dlg.addEventListener("cancel", (e) => {
    if (!dirty()) return;
    e.preventDefault();
    askLeave();
  });
  dlg.addEventListener("close", finish);
  const untrack = trackOverlay(() => close("cancel"));
  rememberOpener(dlg, opener);

  document.body.append(dlg);
  dlg.showModal();
  const target = initialFocus?.(dlg)
    || dlg.querySelector("[autofocus]")
    || dlg.querySelector("input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled])")
    || primary?.btn
    || dlg.querySelector("button");
  focusSafely(target);
  return dlg;
}
