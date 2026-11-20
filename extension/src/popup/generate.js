// Générateur du popup : préférences de l'utilisateur (generator.*) bornées par
// la politique (longueur et nombre de mots minimaux). Écran « Générer » :
// mot de passe affiché, « Un autre », « Copier ».

import { h, t, secretRow } from "../lib/ui/index.js";
import { call } from "../lib/wasm.js";
import * as Settings from "../lib/settings-client.js";
import * as V from "../lib/vault.js";
import { go, screen, action, armClipboard } from "./context.js";

function value(key, fallback) {
  try {
    const v = Settings.effective(key)?.value;
    return v === undefined || v === null ? fallback : v;
  } catch {
    return fallback;
  }
}

const int = (v, d) => (Number.isInteger(Number(v)) && Number(v) > 0 ? Number(v) : d);

/** Nouveau mot de passe (ou phrase de passe) selon les préférences et la politique. */
export function generate() {
  const p = Settings.prefs().generator || {};
  if (p.style === "words") {
    const words = Math.max(int(p.words, 5), int(value("generator.min_words", 4), 4));
    return call("generate_passphrase", {
      options: { words, separator: typeof p.separator === "string" ? p.separator : "-", capitalize: p.capitalize !== false, include_number: p.number !== false },
    }).value;
  }
  const length = Math.max(int(value("generator.length", 20), 20), int(value("generator.min_length", 12), 12));
  return call("generate_password", {
    options: { length, lower: true, upper: true, digits: p.digits !== false, symbols: p.symbols !== false, avoid_ambiguous: value("generator.avoid_ambiguous", true) !== false },
  }).value;
}

/**
 * Mot de passe jamais utilisé : on en tire jusqu'à 8 avant de renoncer, en
 * écartant ceux déjà présents dans le coffre ou (politique « uniques ») chez
 * un autre compte. Le dernier tirage est rendu en cas d'échec.
 */
export async function generateFresh() {
  let last = generate();
  for (let i = 0; i < 8; i++) {
    if (!(await V.passwordTaken(last))) return last;
    last = generate();
  }
  return last;
}

export function renderGenerate() {
  const slot = h("div", {});
  const draw = () => slot.replaceChildren(secretRow({ label: t("extension.generate.label"), value: generate(), kind: "password", masked: false, mono: true, onCopied: () => armClipboard("password") }));
  draw();
  screen({ title: t("extension.generate.title"), back: () => go("main"), session: true },
    slot,
    h("p", { class: "u-muted" }, t("extension.generate.hint")),
    action({ label: t("extension.generate.another"), icon: "refresh", onClick: draw }));
}
