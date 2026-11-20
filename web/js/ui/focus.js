// Focus et navigation au clavier (règles A3, A4) : conservation du focus
// autour d'un rendu, focus du titre au changement de route, éléments
// focalisables, champs de saisie.

const FOCUSABLE = [
  "a[href]", "button:not([disabled])", "input:not([disabled]):not([type=hidden])", "select:not([disabled])",
  "textarea:not([disabled])", "summary", "[tabindex]:not([tabindex='-1'])", "[contenteditable='true']",
].join(", ");

/** Éléments focalisables visibles d'un conteneur, dans l'ordre du document. */
export function focusables(root) {
  return [...root.querySelectorAll(FOCUSABLE)].filter((el) => el.getClientRects().length > 0 && !el.closest("[inert]"));
}

/** Vrai si l'élément reçoit du texte (champ, zone de texte, liste, contenu éditable). */
export function isEditable(el) {
  if (!(el instanceof Element)) return false;
  if (el.isContentEditable) return true;
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) return true;
  if (!(el instanceof HTMLInputElement)) return false;
  return !["button", "submit", "reset", "checkbox", "radio", "range", "color", "file", "image"].includes(el.type);
}

/** Donne le focus sans faire défiler, si l'élément existe encore. */
export function focusSafely(el, { preventScroll = true } = {}) {
  if (!el || !el.isConnected || typeof el.focus !== "function") return false;
  try {
    el.focus({ preventScroll });
  } catch {
    return false;
  }
  return document.activeElement === el;
}

/** Plus proche ancêtre qui défile verticalement (ou l'élément racine du document). */
export function scrollParent(el) {
  for (let p = el?.parentElement; p; p = p.parentElement) {
    const { overflowY } = getComputedStyle(p);
    if ((overflowY === "auto" || overflowY === "scroll") && p.scrollHeight > p.clientHeight) return p;
  }
  return document.scrollingElement || document.documentElement;
}

/**
 * Rend `renderFn()` dans `container` en conservant le focus et le défilement :
 * l'élément actif est retrouvé après le rendu par son attribut data-focus-key ;
 * à défaut, le focus revient sur le conteneur (jamais sur <body>).
 * Accepte une fonction asynchrone (renvoie alors une promesse).
 */
export function keepFocus(container, renderFn) {
  const active = document.activeElement;
  const inside = active && container.contains(active);
  const key = inside ? active.closest("[data-focus-key]")?.dataset.focusKey : undefined;
  const scroller = scrollParent(container);
  const top = scroller.scrollTop;
  const restore = () => {
    scroller.scrollTop = top;
    if (!inside || container.contains(document.activeElement)) return;
    const again = key !== undefined ? container.querySelector(`[data-focus-key="${CSS.escape(key)}"]`) : null;
    if (focusSafely(again)) return;
    if (!container.hasAttribute("tabindex")) container.setAttribute("tabindex", "-1");
    focusSafely(container);
  };
  const out = renderFn();
  if (out && typeof out.then === "function") return out.then((v) => { restore(); return v; });
  restore();
  return out;
}

/** Focus programmatique sur le titre h1 de la vue (changement de route, règle A3). */
export function focusHeading(root = document) {
  const heading = root.querySelector("h1");
  if (!heading) return false;
  if (!heading.hasAttribute("tabindex")) heading.setAttribute("tabindex", "-1");
  return focusSafely(heading, { preventScroll: false });
}
