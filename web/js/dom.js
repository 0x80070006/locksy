// Petits outils d'interface. Tout le contenu utilisateur passe par
// textContent : aucune donnée n'est jamais interprétée comme du HTML.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else if (k === "dataset") Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export function clear(el, ...children) {
  el.replaceChildren();
  append(el, children);
  return el;
}

const SVG_NS = "http://www.w3.org/2000/svg";
const ICONS = {
  lock: "M7 11V8a5 5 0 0 1 10 0v3M5 11h14v10H5z",
  vault: "M4 4h16v16H4zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM12 12h.01M4 8h2M4 16h2",
  star: "M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z",
  trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
  key: "M14 7a4 4 0 1 1-3.5 6L4 19.5V21h3v-2h2v-2h2l1.5-1.5A4 4 0 0 1 14 7zM16 9h.01",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  users: "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8",
  wand: "M15 4V2M15 16v-2M8 9h2M20 9h2M17.8 11.8l1.4 1.4M17.8 6.2l1.4-1.4M12.2 6.2l-1.4-1.4M3 21l9-9",
  heart: "M3 12h4l3-8 4 16 3-8h4",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  eye: "M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  eyeoff: "M17.9 17.9A10 10 0 0 1 12 19c-7 0-11-7-11-7a18 18 0 0 1 5-5.9M9.9 4.2A9 9 0 0 1 12 4c7 0 11 7 11 7a18 18 0 0 1-2.2 3.2M1 1l22 22",
  plus: "M12 5v14M5 12h14",
  search: "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3",
  menu: "M3 6h18M3 12h18M3 18h18",
  external: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3",
  refresh: "M23 4v6h-6M1 20v-6h6M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15",
  back: "M19 12H5M12 19l-7-7 7-7",
  edit: "M12 20h9M16.5 3.5a2.1 2.1 0 1 1 3 3L7 19l-4 1 1-4z",
  share: "M4 12v8h16v-8M16 6l-4-4-4 4M12 2v13",
  folder: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
  x: "M18 6L6 18M6 6l12 12",
  logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
};

export function icon(name) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("width", "18");
  svg.setAttribute("height", "18");
  const p = document.createElementNS(SVG_NS, "path");
  p.setAttribute("d", ICONS[name] || ICONS.key);
  svg.append(p);
  return svg;
}

let logoCount = 0;
/** Logo Locksy (identique à branding/locksy.svg). */
export function logo() {
  const n = ++logoCount;
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 512 512");
  svg.setAttribute("aria-hidden", "true");
  const el = (tag, attrs, parent = svg) => {
    const e = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    parent.append(e);
    return e;
  };
  const defs = el("defs", {});
  const grad = (id, x2, y2, a, b) => {
    const g = el("linearGradient", { id, x1: 0, y1: 0, x2, y2 }, defs);
    el("stop", { offset: 0, "stop-color": a }, g);
    el("stop", { offset: 1, "stop-color": b }, g);
  };
  grad(`lk-fond-${n}`, 1, 1, "#16927f", "#0b4a5a");
  grad(`lk-trou-${n}`, 0, 1, "#11806f", "#0b4a5a");
  el("rect", { width: 512, height: 512, rx: 116, fill: `url(#lk-fond-${n})` });
  el("path", { d: "M168 240 V184 a88 88 0 0 1 176 0 V240", fill: "none", stroke: "#fff", "stroke-width": 46, "stroke-linecap": "round" });
  el("rect", { x: 112, y: 226, width: 288, height: 214, rx: 54, fill: "#fff" });
  el("path", { d: "M226 278 a14 14 0 0 1 14 -14 h4 a14 14 0 0 1 14 14 v80 h48 a14 14 0 0 1 14 14 v4 a14 14 0 0 1 -14 14 h-66 a14 14 0 0 1 -14 -14 z", fill: `url(#lk-trou-${n})` });
  return svg;
}

// ---------- Notifications ----------
let toastBox = null;
export function toast(message, kind = "") {
  if (!toastBox) {
    toastBox = h("div", { class: "toasts", role: "status", "aria-live": "polite" });
    document.body.append(toastBox);
  }
  const t = h("div", { class: `toast ${kind}` }, message);
  toastBox.append(t);
  setTimeout(() => t.remove(), kind === "bad" ? 6000 : 3200);
}

// ---------- Fenêtres modales ----------
export function modal({ title, body, actions = [], wide = false, onClose }) {
  const close = () => {
    overlay.remove();
    document.removeEventListener("keydown", onKey);
    onClose?.();
  };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  const foot = actions.length
    ? h("div", { class: "modal-foot" }, actions.map((a) =>
        h("button", {
          class: `btn ${a.kind || ""}`,
          type: a.submit ? "submit" : "button",
          onclick: async (e) => {
            if (a.submit) return;
            e.preventDefault();
            const r = await a.onClick?.(close, e);
            if (r !== false && !a.keepOpen) close();
          },
        }, a.label)))
    : null;
  const box = h("div", { class: `modal ${wide ? "wide" : ""}`, role: "dialog", "aria-modal": "true", "aria-label": title },
    h("div", { class: "modal-head" }, h("h2", {}, title),
      h("button", { class: "btn ghost icon", "aria-label": "Fermer", onclick: close }, icon("x"))),
    h("div", { class: "modal-body" }, body),
    foot);
  const overlay = h("div", { class: "overlay", onmousedown: (e) => { if (e.target === overlay) close(); } }, box);
  document.body.append(overlay);
  document.addEventListener("keydown", onKey);
  setTimeout(() => box.querySelector("input:not([type=checkbox]), select, textarea")?.focus(), 30);
  return { close, box };
}

export function confirmDialog({ title, message, confirmLabel = "Confirmer", danger = false }) {
  return new Promise((resolve) => {
    let done = false;
    modal({
      title,
      body: h("p", {}, message),
      onClose: () => { if (!done) resolve(false); },
      actions: [
        { label: "Annuler", onClick: () => { done = true; resolve(false); } },
        { label: confirmLabel, kind: danger ? "danger" : "primary", onClick: () => { done = true; resolve(true); } },
      ],
    });
  });
}

// ---------- Divers ----------
export function fmtDate(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}

export function fmtDay(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString("fr-FR", { dateStyle: "medium" });
}

export function relTime(ts) {
  const d = Math.round((Date.now() / 1000 - ts));
  if (d < 60) return "à l'instant";
  if (d < 3600) return `il y a ${Math.round(d / 60)} min`;
  if (d < 86400) return `il y a ${Math.round(d / 3600)} h`;
  if (d < 86400 * 60) return `il y a ${Math.round(d / 86400)} j`;
  return fmtDay(ts);
}

const PALETTE = ["#1b6b5f", "#2f5fa7", "#8a4fb5", "#b5562f", "#3d7f2c", "#a63d62", "#5a6b2a", "#2b7c8c"];
export function colorFor(text) {
  let n = 0;
  for (const ch of text || "?") n = (n * 31 + ch.codePointAt(0)) >>> 0;
  return PALETTE[n % PALETTE.length];
}

export function initials(text) {
  const t = (text || "?").trim();
  return (t[0] || "?").toUpperCase();
}

export function safeUrl(u) {
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(u) ? u : `https://${u}`);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}
