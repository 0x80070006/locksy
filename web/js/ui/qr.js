// Lecture d'un QR code de configuration (otpauth://) depuis une image
// déposée, collée ou choisie. Le détecteur du navigateur (BarcodeDetector)
// est essayé d'abord ; à défaut, le décodeur vendorisé (web/vendor/qr, même
// origine, compatible CSP) est chargé à la demande. L'image ne quitte jamais
// le navigateur ; la clé lue n'est ni affichée ni annoncée.

import { t } from "../i18n.js";
import { h, icon, uid } from "./core.js";
import { announce } from "./status.js";

let decoderUrl = "/vendor/qr/jsqr-1.4.0.mjs";
const MAX_SIDE = 1600;

/** Adresse du décodeur vendorisé (l'extension sert le sien depuis lib/). */
export function setQrDecoderUrl(url) {
  decoderUrl = String(url);
}

async function nativeDetect(bitmap) {
  if (typeof globalThis.BarcodeDetector !== "function") return null;
  try {
    const formats = await globalThis.BarcodeDetector.getSupportedFormats();
    if (!formats.includes("qr_code")) return null;
    const codes = await new globalThis.BarcodeDetector({ formats: ["qr_code"] }).detect(bitmap);
    return codes[0]?.rawValue || null;
  } catch {
    return null;
  }
}

async function vendoredDetect(bitmap) {
  const { default: jsQR } = await import(decoderUrl);
  const scale = Math.min(1, MAX_SIDE / Math.max(bitmap.width, bitmap.height));
  const w = Math.max(1, Math.round(bitmap.width * scale));
  const hgt = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = hgt;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0, w, hgt);
  const found = jsQR(ctx.getImageData(0, 0, w, hgt).data, w, hgt, { inversionAttempts: "attemptBoth" });
  return found?.data || null;
}

/** Texte contenu dans le QR code d'une image (Blob), ou null. */
export async function decodeQrImage(blob) {
  const bitmap = await createImageBitmap(blob);
  try {
    return (await nativeDetect(bitmap)) ?? (await vendoredDetect(bitmap));
  } finally {
    bitmap.close?.();
  }
}

/**
 * qrImport({ onResult, label }) -> HTMLElement
 * onResult(uri) reçoit l'adresse otpauth:// lue. Les erreurs (aucun QR code,
 * QR code sans code de vérification, image illisible) s'affichent dans la zone.
 */
export function qrImport({ onResult, label = t("common.glossary.scan_qr") }) {
  const titleId = uid("qr");
  const fileId = uid("qr-fichier");
  const errorEl = h("p", { class: "c-field__error", hidden: true, id: `${titleId}-erreur` }, icon("error", { size: "sm" }), h("span", {}));
  const file = h("input", { type: "file", id: fileId, accept: "image/*", class: "u-sr-only", "aria-describedby": `${titleId}-aide ${errorEl.id}` });
  const zone = h("div", { class: "c-qr-drop", role: "group", "aria-labelledby": titleId, tabindex: "0" },
    icon("qr", { size: "lg" }),
    h("p", { id: titleId, class: "c-empty__title" }, label),
    h("p", { class: "c-field__help", id: `${titleId}-aide` }, t("ui.qr.help")),
    h("label", { class: "c-button", for: fileId }, icon("upload"), t("ui.qr.choose")),
    file,
    errorEl);

  const fail = (key) => {
    errorEl.hidden = false;
    errorEl.lastElementChild.textContent = t(key);
    announce(t(key), { assertive: true });
  };
  const read = async (blob) => {
    if (!blob || !String(blob.type).startsWith("image/")) return fail("ui.qr.not_image");
    errorEl.hidden = true;
    zone.setAttribute("aria-busy", "true");
    let text = null;
    try {
      text = await decodeQrImage(blob);
    } catch {
      return fail("ui.qr.unreadable");
    } finally {
      zone.removeAttribute("aria-busy");
    }
    if (!text) return fail("ui.qr.not_found");
    if (!/^otpauth:\/\//i.test(text)) return fail("ui.qr.not_otp");
    announce(t("ui.qr.read"));
    onResult?.(text);
  };

  file.addEventListener("change", () => read(file.files?.[0]));
  zone.addEventListener("paste", (e) => {
    const item = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith("image/"));
    if (!item) return;
    e.preventDefault();
    read(item.getAsFile());
  });
  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.dataset.over = "";
  });
  zone.addEventListener("dragleave", () => zone.removeAttribute("data-over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.removeAttribute("data-over");
    read(e.dataTransfer?.files?.[0]);
  });
  return zone;
}
