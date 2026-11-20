// Code de vérification d'un site (« 273 647 ») : anneau de décompte posé en
// CSSOM (--progress, de 0 à 1), texte changé seulement quand le code change,
// AUCUNE annonce automatique (la zone porte aria-live="off", règle A2).

import { t } from "../i18n.js";
import { call } from "../wasm.js";
import { h, icon } from "./core.js";
import { copySecret } from "./secret.js";

/** Calcul par le noyau WebAssembly : { code, remaining, period }. */
function wasmTotp(config, time) {
  return call("totp", { secret: config, time });
}

/** « 273647 » -> « 273 647 » ; « 12345678 » -> « 1234 5678 ». */
export function groupCode(code) {
  const s = String(code ?? "");
  const half = Math.ceil(s.length / 2);
  return s.length >= 6 ? `${s.slice(0, half)} ${s.slice(half)}` : s;
}

/**
 * totpCode({ config, onCopy, generate, now }) -> { el, update(props), destroy() }
 *   config   : clé ou URI de configuration du site (jamais affichée) ;
 *   generate : (config, secondes) -> { code, remaining, period } (défaut : noyau) ;
 *   onCopy   : (code) -> void ; défaut : copie avec effacement différé.
 */
export function totpCode({ config, onCopy, generate = wasmTotp, now = () => Date.now() / 1000 }) {
  let props = { config, onCopy, generate };
  let current = "";
  let timer = 0;

  const codeEl = h("span", { class: "c-totp__code", "aria-live": "off" });
  const ring = h("span", { class: "c-totp__ring", role: "img" });
  const copyName = t("ui.secret.copy_totp");
  const copyBtn = h("button", {
    type: "button", class: "c-button", "aria-label": copyName, title: copyName,
    onclick: () => {
      if (!current) return;
      if (typeof props.onCopy === "function") props.onCopy(current);
      else copySecret(current, { kind: "totp" });
    },
  }, icon("copy"), h("span", { class: "c-button__label", "aria-hidden": "true" }, t("common.action.copy")));
  const el = h("div", { class: "c-totp" }, codeEl, ring, copyBtn);

  let invalid = false;
  let wasConnected = false;
  const tick = () => {
    timer = 0;
    if (el.isConnected) wasConnected = true;
    else if (wasConnected) return; // retiré de la page : le décompte s'arrête
    let r;
    try {
      r = props.generate(props.config, Math.floor(now()));
    } catch {
      r = null;
    }
    if (!r || !r.code) {
      if (!invalid) {
        invalid = true;
        current = "";
        codeEl.textContent = t("ui.totp.invalid");
        ring.hidden = true;
        copyBtn.disabled = true;
      }
      return;
    }
    if (invalid || r.code !== current) {
      invalid = false;
      current = r.code;
      codeEl.textContent = groupCode(r.code);
      ring.hidden = false;
      copyBtn.disabled = false;
    }
    const period = Number(r.period) || 30;
    const remaining = Math.max(0, Math.min(period, Number(r.remaining) || 0));
    el.style.setProperty("--progress", String(remaining / period));
    ring.setAttribute("aria-label", t("ui.totp.remaining", { s: remaining }));
    timer = setTimeout(tick, 1000 - ((now() * 1000) % 1000) + 5);
  };
  tick();

  return {
    el,
    update(next = {}) {
      props = { ...props, ...next };
      clearTimeout(timer);
      current = "";
      invalid = false;
      tick();
    },
    destroy() {
      clearTimeout(timer);
      timer = 0;
    },
  };
}
