// Secrets : copie avec effacement différé du presse-papiers, ligne de fiche
// (libellé, valeur masquée, « Afficher », « Copier »), affichage d'un secret
// révélé (groupes de 4, chiffres et symboles repérés autrement que par la
// couleur). Jamais de secret dans un texte annoncé ni d'annonce automatique
// sur la valeur (règle A2).

import { t } from "../i18n.js";
import { clear, h, icon } from "./core.js";
import { iconButton, setPressed } from "./button.js";
import { notify } from "./toast.js";
import { writeSecret } from "./clipboard.js";

export { clearClipboardNow } from "./clipboard.js";

const MASK = "•".repeat(12);
const KINDS = new Set(["password", "username", "totp", "secret", "text"]);
let policy = { clearSeconds: () => 30 };

/** Branche le délai d'effacement (préférence et politique client.clipboard_clear_seconds). */
export function setClipboardPolicy({ clearSeconds }) {
  if (typeof clearSeconds === "function") policy = { clearSeconds };
}

function clearDelay() {
  const s = Number(policy.clearSeconds());
  return Number.isFinite(s) && s > 0 ? Math.round(s) : 0;
}

/**
 * Copie une valeur. Toast « Mot de passe copié, effacé dans 30 s » (sans la
 * valeur) ; effacement selon la politique, seulement si le presse-papiers
 * contient toujours cette valeur. kind : "password" | "username" | "totp" |
 * "secret" | "text" (« text » n'est jamais effacé). labelKey remplace le
 * message (paramètre {s}). Renvoie vrai si la copie a réussi.
 */
export async function copySecret(value, { kind = "password", labelKey } = {}) {
  const k = KINDS.has(kind) ? kind : "secret";
  const s = k === "text" ? 0 : clearDelay();
  if (!(await writeSecret(value, s))) {
    notify({ text: t("ui.copy.failed"), tone: "danger" });
    return false;
  }
  const key = labelKey || (s > 0 ? `ui.copy.${k}_clear` : `ui.copy.${k}`);
  notify({ text: t(key, { s }), tone: "ok" });
  return true;
}

const isDigit = (ch) => /\p{Nd}/u.test(ch);
const isSymbol = (ch) => !/[\p{L}\p{N}]/u.test(ch);

/**
 * Secret révélé : groupes de 4 caractères (espacement CSS, aucun espace réel :
 * la copie reste exacte), chiffres soulignés, symboles en gras.
 */
export function formatSecret(value) {
  const chars = [...String(value ?? "")];
  const groups = [];
  for (let i = 0; i < chars.length; i += 4) {
    groups.push(h("span", { class: "c-secret__group" }, chars.slice(i, i + 4).map((ch) => {
      if (isDigit(ch)) return h("span", { class: "c-secret__digit" }, ch);
      if (isSymbol(ch)) return h("span", { class: "c-secret__symbol" }, ch);
      return ch;
    })));
  }
  return h("span", { class: "c-secret" }, groups);
}

const COPY_KEYS = { password: "ui.secret.copy_password", username: "ui.secret.copy_username", totp: "ui.secret.copy_totp" };
const SHOW_KEYS = { password: "ui.password.show", secret: "ui.secret.show" };

/**
 * Ligne de fiche : { label, value, kind = "password", masked = true, mono,
 *   copyLabelKey, onCopied, clickToCopy } -> HTMLElement
 * Bouton « Copier » libellé (nom accessible « Copier le mot de passe ») ;
 * « Afficher » (aria-pressed) si la valeur est masquée.
 */
export function secretRow({ label, value, kind = "password", masked = kind === "password", mono = false, copyLabelKey, onCopied, clickToCopy = false }) {
  const valueEl = h("div", { class: `c-secret-row__value${mono ? " u-mono" : ""}` });
  let shown = !masked;
  const paint = () => {
    if (!shown) clear(valueEl, h("span", { "aria-hidden": "true" }, MASK), h("span", { class: "u-sr-only" }, t("ui.secret.hidden")));
    else if (kind === "password" || kind === "secret") clear(valueEl, formatSecret(value));
    else clear(valueEl, String(value ?? ""));
  };
  paint();

  const copy = async () => {
    if (await copySecret(value, { kind })) onCopied?.();
  };
  const copyName = t(copyLabelKey || COPY_KEYS[kind] || "ui.secret.copy_value");
  const copyBtn = h("button", { type: "button", class: "c-button", "aria-label": copyName, title: copyName, onclick: copy },
    icon("copy"), h("span", { class: "c-button__label", "aria-hidden": "true" }, t("common.action.copy")));
  let reveal = null;
  if (masked) {
    reveal = iconButton({
      icon: "eye", label: t(SHOW_KEYS[kind] || "ui.secret.show"), pressed: false,
      onClick: () => {
        shown = !shown;
        setPressed(reveal, shown);
        reveal.replaceChildren(icon(shown ? "eye-off" : "eye"));
        paint();
      },
    });
  }
  // Copie au clic sur la valeur (préférence) ; le bouton « Copier » reste l'accès au clavier.
  if (clickToCopy) valueEl.addEventListener("click", copy);
  return h("div", { class: "c-secret-row" },
    h("div", { class: "c-field__label" }, label),
    h("div", { class: "c-secret-row__actions" }, reveal, copyBtn),
    valueEl);
}
