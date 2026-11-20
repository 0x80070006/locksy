// Pastilles d'initiale (décoratives : le nom est toujours écrit à côté). La
// couleur, stable pour un nom, est posée en CSSOM sur --tile (CSP).

import { colorFor, h, icon, initials } from "./core.js";

const KIND_ICONS = Object.freeze({ login: "key", note: "note", card: "card", identity: "id", ssh: "ssh" });

/** Pastille d'une personne : { name, size } (« lg » pour une fiche). */
export function avatar({ name, size }) {
  const el = h("span", { class: "c-avatar", "aria-hidden": "true", "data-size": size }, initials(name, 2));
  el.style.setProperty("--tile", colorFor(name));
  return el;
}

/** Pastille d'un élément : { item: { name, kind } } ; icône du type si le nom est vide. */
export function itemAvatar({ item, size }) {
  const name = String(item?.name ?? item?.title ?? "").trim();
  const el = h("span", { class: "c-avatar", "aria-hidden": "true", "data-size": size },
    name ? initials(name, 1) : icon(KIND_ICONS[item?.kind] || "key", { size: "sm" }));
  el.style.setProperty("--tile", colorFor(name || item?.kind || "?"));
  return el;
}
