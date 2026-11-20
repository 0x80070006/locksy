// Annonces aux lecteurs d'écran (règle A1) : deux régions seulement dans la
// page, #status (role=status, poli) et #alert (role=alert, immédiat). Elles
// sont posées par index.html ; à défaut, elles sont créées ici à la première
// annonce. Aucune autre région n'existe : les composants passent par announce().
// Jamais de secret dans un texte annoncé (règle A2).

import { h } from "./core.js";

const timers = new Map();

/** Région #status ou #alert, créée au besoin à la fin de <body>. */
export function liveRegion(assertive = false) {
  const id = assertive ? "alert" : "status";
  let el = document.getElementById(id);
  if (!el) {
    el = h("div", { id, role: assertive ? "alert" : "status", class: "u-sr-only" });
    document.body.append(el);
  }
  return el;
}

/**
 * Annonce un texte. La région est vidée puis remplie au tick suivant, pour
 * qu'un même texte répété soit de nouveau lu. `delay` (ms) retarde l'annonce
 * (ex. 500 ms après une génération de mot de passe).
 */
export function announce(text, { assertive = false, delay = 0 } = {}) {
  const region = liveRegion(assertive);
  clearTimeout(timers.get(region));
  region.textContent = "";
  const message = String(text ?? "").trim();
  if (!message) return;
  timers.set(region, setTimeout(() => {
    timers.delete(region);
    region.textContent = message;
  }, Math.max(30, Number(delay) || 0)));
}
