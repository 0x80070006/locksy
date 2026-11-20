// Document offscreen (raison CLIPBOARD) : efface le presse-papiers à la
// demande du service worker, qui n'a pas accès au presse-papiers lui-même.
//
// navigator.clipboard exige une page qui a le focus ; un document offscreen ne
// l'a jamais. On passe donc par document.execCommand("copy"), autorisé ici par
// la permission « clipboardWrite » du manifeste.

/** Remplace le contenu du presse-papiers. Renvoie vrai si la commande a abouti. */
function wipe() {
  // 1. Événement « copy » intercepté : le presse-papiers reçoit une chaîne
  //    vide à la place de son contenu (Chrome remplace tout le contenu par
  //    celui du DataTransfer, donc le secret disparaît).
  let handled = false;
  const onCopy = (e) => {
    e.clipboardData.setData("text/plain", "");
    e.preventDefault();
    handled = true;
  };
  document.addEventListener("copy", onCopy, { once: true });
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  document.removeEventListener("copy", onCopy);
  if (ok && handled) return true;
  // 2. Repli : copie d'une espace depuis un champ sélectionné (certaines
  //    versions ignorent une chaîne vide). Le secret est remplacé de même.
  const ta = document.createElement("textarea");
  ta.value = " ";
  document.body.append(ta);
  ta.select();
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  ta.remove();
  return ok;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.target !== "offscreen" || msg.type !== "locksy:clear-clipboard") return false;
  sendResponse({ ok: wipe() });
  return false;
});
