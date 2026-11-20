// Tests de web/js/accent.js : couleur de l'organisation posée en jetons CSS
// (branding.accent_color, handoff Q3b-H6).
//   node --test tools/test
import { test } from "node:test";
import assert from "node:assert/strict";

import { applyAccent, onAccent, DEFAULT_ACCENT } from "../../web/js/accent.js";

/** Élément simulé : seules les propriétés personnalisées comptent. */
function racine() {
  const props = new Map();
  return {
    props,
    style: {
      setProperty: (k, v) => props.set(k, v),
      removeProperty: (k) => props.delete(k),
    },
  };
}

test("texte sur l'accent : le plus lisible des deux", () => {
  assert.equal(onAccent("#326fa5"), "#ffffff");
  assert.equal(onAccent("#1b6b5f"), "#ffffff");
  assert.equal(onAccent("#f0c068"), "#0b1a17");
  assert.equal(onAccent("pas une couleur"), "#ffffff");
});

test("couleur de l'organisation posée sur la racine, survol dérivé", () => {
  const r = racine();
  applyAccent(r, " #326FA5 ");
  assert.equal(r.props.get("--color-accent"), "#326fa5");
  assert.equal(r.props.get("--color-on-accent"), "#ffffff");
  const survol = r.props.get("--color-accent-hover");
  assert.match(survol, /^#[0-9a-f]{6}$/);
  assert.notEqual(survol, "#326fa5");
  // Le texte d'accent sur la surface garde les teintes du thème.
  assert.equal(r.props.has("--color-accent-text"), false);
});

test("couleur absente, invalide ou par défaut : jetons du thème", () => {
  for (const v of [undefined, "", "rouge", "#12345", DEFAULT_ACCENT, DEFAULT_ACCENT.toUpperCase()]) {
    const r = racine();
    applyAccent(r, "#326fa5");
    applyAccent(r, v);
    assert.equal(r.props.size, 0, String(v));
  }
  // Sans élément : aucune erreur.
  applyAccent(null, "#326fa5");
});
