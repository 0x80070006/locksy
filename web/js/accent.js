// Couleur de l'organisation (réglage branding.accent_color, publié par
// /settings/public). Le serveur n'accepte qu'une couleur lisible dans les deux
// thèmes : texte (blanc ou presque noir) à 4,5:1 sur l'accent, accent à 3:1
// sur les surfaces claire et sombre. Elle remplace donc l'accent des deux
// thèmes ; le texte d'accent (liens, sur la surface) garde les teintes du
// thème, seules garanties à 4,5:1.
//
// Exports :
//   DEFAULT_ACCENT              accent de Locksy (aucune personnalisation).
//   onAccent(hex)               texte le plus lisible sur l'accent (#ffffff ou #0b1a17).
//   applyAccent(root, hex)      pose les jetons sur `root` (CSSOM, permis par la CSP) ;
//                               couleur absente, invalide ou par défaut : jetons du thème.

export const DEFAULT_ACCENT = "#0d6b64";
const ON_LIGHT = "#ffffff";
const ON_DARK = "#0b1a17";
const PROPS = ["--color-accent", "--color-accent-hover", "--color-on-accent"];

/** [r, g, b] d'une couleur #rrggbb, ou null. */
function rgb(hex) {
  const m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(String(hex || "").trim());
  return m ? m.slice(1).map((x) => parseInt(x, 16)) : null;
}

/** Luminance relative (WCAG 2.x). */
function luminance([r, g, b]) {
  const lin = (c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function ratio(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

export function onAccent(hex) {
  const c = rgb(hex);
  if (!c) return ON_LIGHT;
  return ratio(c, rgb(ON_LIGHT)) >= ratio(c, rgb(ON_DARK)) ? ON_LIGHT : ON_DARK;
}

/** Survol : 12 % vers le texte posé dessus (plus sombre sous un texte blanc). */
function hover(hex) {
  const c = rgb(hex);
  const target = onAccent(hex) === ON_LIGHT ? 0 : 255;
  const mix = c.map((v) => Math.round(v + (target - v) * 0.12));
  return `#${mix.map((v) => v.toString(16).padStart(2, "0")).join("")}`;
}

export function applyAccent(root, hex) {
  const value = String(hex || "").trim().toLowerCase();
  if (!root?.style) return;
  if (!rgb(value) || value === DEFAULT_ACCENT) {
    for (const p of PROPS) root.style.removeProperty(p);
    return;
  }
  root.style.setProperty("--color-accent", value);
  root.style.setProperty("--color-accent-hover", hover(value));
  root.style.setProperty("--color-on-accent", onAccent(value));
}
