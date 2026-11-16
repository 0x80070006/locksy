// Page publique d'un lien de partage. La clé est dans le fragment (#) de
// l'adresse : le navigateur ne l'envoie jamais au serveur.

import { h, clear, icon, logo, toast, fmtDate, safeUrl } from "./dom.js";
import { loadCrypto, call } from "./wasm.js";
import * as A from "./aad.js";

const root = document.getElementById("app");
const id = location.pathname.split("/").pop();
const keyText = location.hash.slice(1);
// Retire la clé de la barre d'adresse et de l'historique.
history.replaceState(null, "", location.pathname);

function card(...content) {
  clear(root, h("div", { class: "auth" }, h("div", { class: "auth-card" }, h("div", { class: "brand" }, logo(), "Locksy"), ...content)));
}

function row(label, value, secret) {
  const v = h("div", { class: `v ${secret ? "mono" : ""}` }, value);
  return h("div", { class: "fieldline" },
    h("div", { style: "min-width:0" }, h("div", { class: "k" }, label), v),
    h("div", { class: "actions" }, h("button", { class: "btn ghost icon", "aria-label": `Copier ${label}`, onclick: async () => {
      try { await navigator.clipboard.writeText(value); toast(`${label} copié.`); } catch { toast("Copie refusée par le navigateur.", "bad"); }
    } }, icon("copy"))));
}

async function reveal(btn) {
  btn.disabled = true;
  let key;
  try {
    await loadCrypto();
    key = call("import_key", { key: keyText });
  } catch {
    return card(h("h1", {}, "Lien incomplet"), h("p", {}, "La clé de déchiffrement manque ou est abîmée. Demandez à l'expéditeur de vous renvoyer le lien en entier."));
  }
  const res = await fetch(`/api/public/shares/${encodeURIComponent(id)}`, { cache: "no-store", credentials: "omit" });
  if (!res.ok) {
    call("drop_key", { key });
    const msg = res.status === 429 ? "Trop de tentatives. Réessayez dans une minute." : "Ce lien n'existe pas, a expiré ou a déjà été consulté le nombre de fois autorisé.";
    return card(h("h1", {}, "Lien indisponible"), h("p", {}, msg));
  }
  const share = await res.json();
  let d;
  try {
    d = JSON.parse(call("decrypt", { key, data: share.data, aad: A.share() }));
  } catch {
    return card(h("h1", {}, "Déchiffrement impossible"), h("p", {}, "La clé ne correspond pas à ce contenu."));
  } finally {
    call("drop_key", { key });
  }
  const links = (d.urls || []).map((u) => {
    const s = safeUrl(u);
    return s ? h("a", { href: s, target: "_blank", rel: "noopener noreferrer" }, u) : h("span", {}, u);
  });
  card(
    h("h1", {}, d.name || "Secret partagé"),
    h("div", { class: "card fields" },
      d.username ? row("Identifiant", d.username) : null,
      d.password ? row("Mot de passe", d.password, true) : null,
      links.length ? h("div", { class: "fieldline" }, h("div", {}, h("div", { class: "k" }, "Sites"), h("div", { class: "v", style: "display:grid;gap:4px" }, links))) : null,
      d.notes ? h("div", { class: "fieldline" }, h("div", {}, h("div", { class: "k" }, "Notes"), h("div", { class: "v pre" }, d.notes))) : null),
    h("div", { class: "notice warn small" },
      share.views_left > 0
        ? `Ce lien peut encore être ouvert ${share.views_left} fois, jusqu'au ${fmtDate(share.expires_at)}.`
        : "C'était la dernière consultation : ce lien est maintenant détruit. Enregistrez ces informations si besoin."),
    h("p", { class: "small muted" }, "Contenu chiffré de bout en bout : le serveur n'a jamais eu accès à ces informations."));
}

if (!id || !keyText) {
  card(h("h1", {}, "Lien incomplet"), h("p", {}, "Ce lien de partage n'est pas complet."));
} else {
  const btn = h("button", { class: "btn primary block", onclick: () => reveal(btn) }, icon("eye"), "Afficher le secret");
  card(h("h1", {}, "Quelqu'un vous a partagé un secret"),
    h("p", {}, "Ce lien a un nombre de consultations limité. N'affichez le secret que lorsque vous êtes prêt à le noter."),
    btn);
}
