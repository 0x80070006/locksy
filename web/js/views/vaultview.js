// Coffre : liste des éléments, fiche détaillée, édition, coffres partagés.

import { h, clear, icon, toast, modal, confirmDialog, fmtDate, relTime, colorFor, initials, safeUrl } from "../dom.js";
import { call } from "../wasm.js";
import { api } from "../api.js";
import * as V from "../vault.js";
import { ui, refresh, go } from "../app.js";
import { copySecret, prefs } from "../prefs.js";
import { saveBlob } from "../api.js";
import { openEditor } from "./editor.js";

const KIND_LABEL = { login: "Identifiant", note: "Note sécurisée", card: "Carte bancaire", identity: "Identité", ssh: "Clé SSH" };
const ROLE_LABEL = { manager: "Gestionnaire", editor: "Éditeur", reader: "Lecteur" };
const ROLE_HELP = {
  manager: "Gère les membres et le contenu",
  editor: "Ajoute et modifie les éléments",
  reader: "Consulte et copie uniquement",
};

export const canWrite = (collectionId) => ["manager", "editor"].includes(V.state.collections.get(collectionId)?.role);

function subtitle(d) {
  switch (d.kind) {
    case "login": return d.username || (d.urls || [])[0] || "";
    case "card": { const n = (d.card?.number || "").replace(/\D/g, ""); return n.length >= 4 ? `•••• ${n.slice(-4)}` : ""; }
    case "identity": return `${d.identity?.first_name || ""} ${d.identity?.last_name || ""}`.trim();
    case "ssh": return (d.ssh?.public_key || "").split(/\s+/).pop() || "";
    default: return (d.notes || "").split("\n")[0].slice(0, 60);
  }
}

function matches(item, q) {
  if (!q) return true;
  const d = item.data;
  const hay = [d.name, d.username, ...(d.urls || []), ...(d.tags || []), d.notes, d.card?.holder, d.identity?.email]
    .filter(Boolean).join(" ").toLowerCase();
  return q.toLowerCase().split(/\s+/).every((w) => hay.includes(w));
}

function filtered() {
  const f = ui.filter;
  return [...V.state.items.values()]
    .filter((i) => i.data)
    .filter((i) => (f.trash ? i.deleted_at : !i.deleted_at))
    .filter((i) => !f.collection || i.collection_id === f.collection)
    .filter((i) => !f.favorites || i.data.favorite)
    .filter((i) => f.type === "all" || i.data.kind === f.type)
    .filter((i) => matches(i, ui.search))
    .sort((a, b) => {
      const sort = prefs.get("sort", "name");
      if (sort === "recent") return b.updated_at - a.updated_at;
      return (b.data.favorite - a.data.favorite) || a.data.name.localeCompare(b.data.name, "fr", { sensitivity: "base" });
    });
}

// ------------------------------------------------------------ Copie rapide et raccourcis

let currentRows = [];
let rerenderVault = null;

async function quickCopy(item, what) {
  const d = item.data;
  let value = "";
  let label = "";
  if (what === "user") { value = d.username || d.identity?.email || ""; label = "Identifiant"; }
  if (what === "password") { value = d.password || d.card?.number || ""; label = d.password ? "Mot de passe" : "Numéro"; }
  if (what === "totp" && d.totp) {
    try { value = call("totp", { secret: d.totp, time: Math.floor(Date.now() / 1000) }).code; label = "Code 2FA"; } catch { value = ""; }
  }
  if (!value) return toast("Rien à copier pour cet élément.", "bad");
  const msg = await copySecret(value, `${label} de « ${d.name} » copié`);
  toast(msg || "Copie refusée par le navigateur.", msg ? "" : "bad");
}

function shortcutsHelp() {
  const row = (k, t) => h("tr", {}, h("td", {}, k.split(" ").map((x) => h("kbd", {}, x))), h("td", {}, t));
  modal({
    title: "Raccourcis clavier",
    body: h("div", { class: "table-wrap" }, h("table", { style: "min-width:0" }, h("tbody", {},
      row("/", "Rechercher"),
      row("↑ ↓", "Parcourir la liste"),
      row("u", "Copier l'identifiant de l'élément affiché"),
      row("p", "Copier le mot de passe"),
      row("c", "Copier le code de double authentification"),
      row("e", "Modifier l'élément"),
      row("n", "Nouvel élément"),
      row("Ctrl L", "Verrouiller (client Windows) · Échap : fermer une fenêtre"),
      row("?", "Afficher cette aide")))),
    actions: [{ label: "Fermer", kind: "primary" }],
  });
}

document.addEventListener("keydown", (e) => {
  if (ui.view !== "vault" || !V.isUnlocked() || document.querySelector(".overlay")) return;
  const t = e.target;
  const typing = t instanceof HTMLElement && (t.closest("input, textarea, select") || t.isContentEditable);
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  const item = ui.selected && V.state.items.get(ui.selected);
  const key = e.key;
  if (key === "/") { e.preventDefault(); document.querySelector(".topbar .search input")?.focus(); return; }
  if (key === "?") { e.preventDefault(); shortcutsHelp(); return; }
  if (key === "ArrowDown" || key === "ArrowUp") {
    if (!currentRows.length) return;
    e.preventDefault();
    const idx = currentRows.findIndex((r) => r.id === ui.selected);
    const next = key === "ArrowDown" ? Math.min(currentRows.length - 1, idx + 1) : Math.max(0, idx - 1);
    ui.selected = currentRows[idx < 0 ? 0 : next].id;
    rerenderVault?.();
    document.querySelector(".list-item.active")?.scrollIntoView({ block: "nearest" });
    return;
  }
  if (key === "n" && !ui.filter.trash) { e.preventDefault(); newItem(); return; }
  if (!item?.data) return;
  if (key === "u") quickCopy(item, "user");
  else if (key === "p") quickCopy(item, "password");
  else if (key === "c") quickCopy(item, "totp");
  else if (key === "e" && canWrite(item.collection_id) && !item.deleted_at) { e.preventDefault(); openEditor({ item }); }
});

export function renderVault(container) {
  const f = ui.filter;
  const col = f.collection ? V.state.collections.get(f.collection) : null;
  const wrap = h("div", { class: `vault ${ui.selected ? "has-detail" : ""}` });
  const list = h("div", { class: "list" });
  const detail = h("div", { class: "detail-pane" });

  const title = f.trash ? "Corbeille" : f.favorites ? "Favoris" : col ? (col.personal ? "Personnel" : col.name) : "Tous les éléments";
  const types = [["all", "Tout"], ["login", "Identifiants"], ["note", "Notes"], ["card", "Cartes"], ["identity", "Identités"], ["ssh", "SSH"]];
  const head = h("div", { class: "list-head" },
    h("div", { class: "row between" },
      h("div", {}, h("h2", {}, title), col && !col.personal ? h("div", { class: "small muted" }, `${col.member_count} membre(s) · vous êtes ${ROLE_LABEL[col.role].toLowerCase()}`) : null),
      h("div", { class: "row" },
        col && !col.personal ? h("button", { class: "btn small", onclick: () => manageCollection(col.id) }, icon("users"), "Partage") : null,
        !f.trash ? h("button", { class: "btn primary small", onclick: () => newItem() }, icon("plus"), "Ajouter") : null)),
    h("div", { class: "row between" },
      h("div", { class: "filters" }, types.map(([k, label]) =>
        h("button", { class: `chip ${f.type === k ? "on" : ""}`, onclick: () => { ui.filter = { ...f, type: k }; renderVault(clear(container)); } }, label))),
      (() => {
        const s = h("select", { class: "input sort", "aria-label": "Trier" },
          h("option", { value: "name", selected: prefs.get("sort", "name") === "name" }, "A → Z"),
          h("option", { value: "recent", selected: prefs.get("sort", "name") === "recent" }, "Récents"));
        s.addEventListener("change", () => { prefs.set("sort", s.value); renderVault(clear(container)); });
        return s;
      })()),
    f.trash ? h("div", { class: "small muted" }, "Les éléments sont supprimés définitivement après le délai fixé par l'organisation (30 jours par défaut).") : null);

  rerenderVault = () => renderVault(clear(container));
  const draw = () => {
    const rows = filtered();
    currentRows = rows;
    clear(list, rows.length ? rows.map((i) => {
      const d = i.data;
      const quick = (what, ic, title) => h("button", { class: "btn ghost icon", title, "aria-label": title, onclick: (e) => { e.stopPropagation(); quickCopy(i, what); } }, icon(ic));
      const row = h("div", { class: `list-item ${ui.selected === i.id ? "active" : ""}`, role: "button", tabindex: 0,
        onclick: () => { ui.selected = i.id; renderVault(clear(container)); },
        onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); ui.selected = i.id; renderVault(clear(container)); } } },
        h("div", { class: "icon-tile", style: `background:${colorFor(d.name)}` }, initials(d.name)),
        h("div", { class: "meta" },
          h("div", { class: "title" }, d.name || "(sans nom)", (d.attachments || []).length ? h("span", { class: "clip", title: "Pièces jointes", "aria-label": "Pièces jointes" }, icon("clip")) : null),
          h("div", { class: "sub" }, subtitle(d) || KIND_LABEL[d.kind])),
        h("div", { class: "quick" },
          d.username ? quick("user", "users", "Copier l'identifiant (u)") : null,
          d.password || d.card?.number ? quick("password", "key", "Copier le mot de passe (p)") : null,
          d.totp ? quick("totp", "clock", "Copier le code 2FA (c)") : null),
        d.favorite ? h("span", { class: "fav", style: "color:var(--warn)", "aria-label": "Favori" }, icon("star")) : null);
      return row;
    }) : emptyState());
  };
  const emptyState = () => h("div", { class: "empty" }, icon(f.trash ? "trash" : "vault"),
    h("strong", {}, ui.search ? "Aucun résultat" : f.trash ? "La corbeille est vide" : "Aucun élément ici"),
    h("span", { class: "small" }, ui.search ? "Essayez d'autres mots." : f.trash ? "" : "Ajoutez votre premier identifiant, ou importez un fichier depuis les paramètres."),
    !ui.search && !f.trash ? h("button", { class: "btn primary small", onclick: () => newItem() }, icon("plus"), "Ajouter un élément") : null,
    ui.search && !f.trash ? h("button", { class: "btn primary small", onclick: () => newItem({ name: ui.search.trim() }) }, icon("plus"), `Créer « ${ui.search.trim()} »`) : null);
  draw();
  const onSearch = () => draw();
  document.addEventListener("locksy:search", onSearch);
  const obs = new MutationObserver(() => { if (!container.isConnected) { document.removeEventListener("locksy:search", onSearch); obs.disconnect(); } });
  obs.observe(document.body, { childList: true });

  const item = ui.selected && V.state.items.get(ui.selected);
  if (item?.data) renderDetail(detail, item, () => renderVault(clear(container)));
  else detail.append(onboarding(() => renderVault(clear(container))) || h("div", { class: "empty", style: "height:100%;align-content:center" }, icon("key"),
    h("span", {}, "Sélectionnez un élément pour l'afficher."),
    h("span", { class: "small" }, "Astuce : appuyez sur ", h("kbd", {}, "?"), " pour voir les raccourcis clavier.")));

  wrap.append(h("section", { class: "list-pane", "aria-label": "Liste" }, head, list), detail);
  container.append(wrap);
}

function newItem(extra = {}) {
  const f = ui.filter;
  const writable = [...V.state.collections.values()].filter((c) => canWrite(c.id));
  const target = f.collection && canWrite(f.collection) ? f.collection : writable[0]?.id;
  if (!target) return toast("Vous n'avez de droits d'écriture sur aucun coffre.", "bad");
  openEditor({ collectionId: target, kind: f.type !== "all" ? f.type : "login", ...extra });
}

// ------------------------------------------------------------ Bien démarrer

function onboarding(rerender) {
  if (prefs.get("onboardingHidden", false) || ui.search || ui.filter.trash) return null;
  const live = [...V.state.items.values()].filter((i) => i.data && !i.deleted_at);
  const shared = [...V.state.collections.values()].some((c) => !c.personal);
  const p = V.state.profile;
  const manual = (k) => prefs.get(`ob.${k}`, false);
  const steps = [
    { done: live.length > 0, title: "Ajoutez ou importez vos identifiants", text: "Depuis Bitwarden, KeePass, LastPass, votre navigateur… ou un par un.",
      actions: [["Ajouter", () => newItem()], ["Importer un fichier", () => { ui.settingsTab = "data"; go("settings"); }]] },
    { done: p.totp_enabled, title: "Activez la double authentification", text: "Un code de votre téléphone en plus du mot de passe maître (inutile si vous vous connectez par l'annuaire de l'entreprise).",
      actions: [["Activer", () => { ui.settingsTab = "security"; go("settings"); }]] },
    { done: manual("recovery"), title: "Rangez votre clé de récupération hors de l'ordinateur", text: "Imprimée, dans un coffre physique : c'est le seul moyen de rouvrir votre coffre si vous oubliez le mot de passe maître.",
      check: "recovery" },
    { done: manual("extension"), title: "Installez l'extension du navigateur", text: "Edge ou Chrome : vos identifiants s'affichent et se remplissent sur chaque site (Ctrl+Maj+L).", check: "extension" },
    { done: manual("desktop"), title: "Installez le client Windows", text: "Pour retrouver vos accès sans navigateur ; le coffre se verrouille tout seul après inactivité.", check: "desktop" },
    { done: shared, title: "Partagez un coffre avec votre équipe", text: "Les comptes communs dans un coffre partagé, avec des droits de lecture ou d'édition.",
      actions: [["Créer un coffre partagé", () => newCollectionDialog()]] },
  ];
  const done = steps.filter((s) => s.done).length;
  if (done === steps.length) return null;
  return h("div", { class: "detail" },
    h("div", { class: "row between" }, h("h2", {}, "Bien démarrer avec Locksy"),
      h("button", { class: "btn ghost small", onclick: () => { prefs.set("onboardingHidden", true); rerender(); } }, "Masquer")),
    h("div", { class: "row" }, h("div", { class: "progress" }, h("span", { style: `width:${Math.round((100 * done) / steps.length)}%` })),
      h("span", { class: "small muted" }, `${done} sur ${steps.length}`)),
    h("div", { class: "card steps" }, steps.map((s) => h("div", { class: `step ${s.done ? "done" : ""}` },
      h("div", { class: "tick", "aria-hidden": "true" }, s.done ? "✓" : ""),
      h("div", { style: "min-width:0;flex:1" }, h("strong", {}, s.title), h("div", { class: "small muted" }, s.text),
        !s.done && (s.actions || s.check) ? h("div", { class: "row", style: "margin-top:8px" },
          (s.actions || []).map(([l, fn]) => h("button", { class: "btn small", onclick: fn }, l)),
          s.check ? h("button", { class: "btn small ghost", onclick: () => { prefs.set(`ob.${s.check}`, true); rerender(); } }, "C'est fait") : null) : null)))));
}

// ------------------------------------------------------------ Fiche

let totpTimer = null;

function copyBtn(value, label) {
  return h("button", { class: "btn ghost icon", title: `Copier ${label.toLowerCase()}`, "aria-label": `Copier ${label}`, onclick: async () => {
    const msg = await copySecret(value, `${label} copié`);
    toast(msg || "Copie refusée par le navigateur.", msg ? "" : "bad");
  } }, icon("copy"));
}

function line(label, value, { secret = false, copy = true, pre = false, mono = false, extra = null } = {}) {
  if (value === undefined || value === null || value === "") return null;
  const v = h("div", { class: `v ${pre ? "pre" : ""} ${mono ? "mono" : ""}` }, secret ? "••••••••••••" : value);
  let shown = !secret;
  const toggle = secret ? h("button", { class: "btn ghost icon", title: "Afficher", "aria-label": "Afficher ou masquer", onclick: () => {
    shown = !shown;
    v.textContent = shown ? value : "••••••••••••";
    v.classList.toggle("mono", shown || mono);
    clear(toggle, icon(shown ? "eyeoff" : "eye"));
  } }, icon("eye")) : null;
  return h("div", { class: "fieldline" },
    h("div", { style: "min-width:0" }, h("div", { class: "k" }, label), v, extra),
    h("div", { class: "actions" }, toggle, copy ? copyBtn(value, label) : null));
}

function totpLine(secret) {
  if (!secret) return null;
  const code = h("span");
  const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "ring");
  const bg = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  for (const c of [bg, circle]) { c.setAttribute("cx", 12); c.setAttribute("cy", 12); c.setAttribute("r", 9); }
  bg.setAttribute("class", "bg");
  circle.setAttribute("class", "fg");
  circle.setAttribute("stroke-dasharray", String(2 * Math.PI * 9));
  svg.append(bg, circle);
  let current = "";
  const tick = () => {
    try {
      const r = call("totp", { secret, time: Math.floor(Date.now() / 1000) });
      current = r.code;
      code.textContent = `${r.code.slice(0, r.code.length / 2)} ${r.code.slice(r.code.length / 2)}`;
      circle.setAttribute("stroke-dashoffset", String(2 * Math.PI * 9 * (1 - r.remaining / r.period)));
    } catch (e) {
      code.textContent = "Secret TOTP invalide";
      clearInterval(totpTimer);
    }
  };
  clearInterval(totpTimer);
  tick();
  totpTimer = setInterval(() => { if (!code.isConnected) clearInterval(totpTimer); else tick(); }, 1000);
  return h("div", { class: "fieldline" },
    h("div", {}, h("div", { class: "k" }, "Code de double authentification"), h("div", { class: "totp" }, code, svg)),
    h("div", { class: "actions" }, h("button", { class: "btn ghost icon", "aria-label": "Copier le code", onclick: async () => {
      const msg = await copySecret(current, "Code copié");
      toast(msg || "Copie refusée.", msg ? "" : "bad");
    } }, icon("copy"))));
}

function strengthBadge(password) {
  const s = call("strength", { password });
  const kind = s.score >= 4 ? "ok" : s.score >= 3 ? "accent" : s.score >= 2 ? "warn" : "bad";
  return h("div", { class: "row", style: "margin-top:4px" }, h("span", { class: `chip ${kind}` }, s.label), s.warnings[0] ? h("span", { class: "small muted" }, s.warnings[0]) : null);
}

function renderDetail(pane, item, rerender) {
  const d = item.data;
  const col = V.state.collections.get(item.collection_id);
  const writable = canWrite(item.collection_id);
  const urls = (d.urls || []).map((u) => {
    const safe = safeUrl(u);
    return h("div", { class: "fieldline" },
      h("div", { style: "min-width:0" }, h("div", { class: "k" }, "Site"), h("div", { class: "v" }, u)),
      h("div", { class: "actions" }, safe ? h("a", { class: "btn ghost icon", href: safe, target: "_blank", rel: "noopener noreferrer", title: "Ouvrir", "aria-label": "Ouvrir le site" }, icon("external")) : null, copyBtn(u, "Adresse")));
  });
  const reused = d.password && [...V.state.items.values()].some((o) => o.id !== item.id && !o.deleted_at && o.data?.password === d.password);

  const main = h("div", { class: "card fields" },
    d.kind === "login" ? [
      line("Identifiant", d.username),
      line("Mot de passe", d.password, { secret: true, mono: true, extra: d.password ? h("div", {}, strengthBadge(d.password), reused ? h("span", { class: "chip warn", style: "margin-top:4px" }, "Réutilisé ailleurs") : null) : null }),
      totpLine(d.totp), urls,
    ] : null,
    d.kind === "card" ? [
      line("Titulaire", d.card.holder), line("Numéro", d.card.number, { secret: true, mono: true }),
      line("Expiration", d.card.expiry), line("Cryptogramme", d.card.cvv, { secret: true }), line("Code PIN", d.card.pin, { secret: true }),
    ] : null,
    d.kind === "identity" ? [
      line("Prénom", d.identity.first_name), line("Nom", d.identity.last_name), line("E-mail", d.identity.email),
      line("Téléphone", d.identity.phone), line("Adresse", d.identity.address, { pre: true }), line("Société", d.identity.company),
      line("N° de document", d.identity.document_number, { secret: true }),
    ] : null,
    d.kind === "ssh" ? [
      line("Clé publique", d.ssh.public_key, { mono: true }), line("Clé privée", d.ssh.private_key, { secret: true, mono: true, pre: true }),
      line("Phrase de passe", d.ssh.passphrase, { secret: true }),
    ] : null,
    (d.fields || []).map((f) => line(f.label || "Champ", f.value, { secret: f.hidden })),
    line("Notes", d.notes, { pre: true, copy: d.kind === "note" }));

  const expired = d.expires_at && d.expires_at < V.now();
  const history = (d.password_history || []).length
    ? h("details", { class: "card history" }, h("summary", {}, `Historique des mots de passe (${d.password_history.length})`),
        h("div", { class: "fields" }, d.password_history.map((p) => line(`Remplacé le ${fmtDate(p.changed_at)}`, p.password, { secret: true, mono: true }))))
    : null;

  const fileInput = h("input", { type: "file", class: "hidden", onchange: async () => {
    const file = fileInput.files[0];
    if (!file) return;
    toast(`Chiffrement de « ${file.name} »…`);
    try { await V.addAttachment(item, file); await refresh("Pièce jointe ajoutée (chiffrée)."); } catch (e) { toast(e.message, "bad"); }
  } });
  const attachments = (d.attachments || []).length || (writable && !item.deleted_at)
    ? h("div", { class: "card" },
        h("div", { class: "fieldline" }, h("div", { class: "k" }, `Pièces jointes${(d.attachments || []).length ? ` (${d.attachments.length})` : ""}`),
          writable && !item.deleted_at ? h("div", { class: "actions" }, h("button", { class: "btn small", onclick: () => fileInput.click() }, icon("plus"), "Joindre un fichier"), fileInput) : null),
        (d.attachments || []).map((a) => h("div", { class: "fieldline" },
          h("div", { style: "min-width:0" }, h("div", { class: "v row", style: "gap:6px" }, icon("clip"), a.name), h("div", { class: "small muted" }, V.formatSize(a.size))),
          h("div", { class: "actions" },
            h("button", { class: "btn ghost small", onclick: async () => {
              try { saveBlob(await V.downloadAttachment(a), a.name); } catch (e) { toast(e.message, "bad"); }
            } }, "Télécharger"),
            writable && !item.deleted_at ? h("button", { class: "btn ghost icon", title: "Supprimer", "aria-label": `Supprimer ${a.name}`, onclick: async () => {
              if (!(await confirmDialog({ title: "Supprimer la pièce jointe ?", message: `« ${a.name} » sera supprimé définitivement.`, confirmLabel: "Supprimer", danger: true }))) return;
              try { await V.removeAttachment(item, a); await refresh("Pièce jointe supprimée."); } catch (e) { toast(e.message, "bad"); }
            } }, icon("trash")) : null))),
        !(d.attachments || []).length ? h("div", { class: "fieldline" }, h("div", { class: "small muted" }, "Contrats, certificats, licences… chiffrés dans votre navigateur, 10 Mo au plus.")) : null)
    : null;

  const actions = item.deleted_at
    ? [
        writable ? h("button", { class: "btn", onclick: async () => { await api("POST", `/items/${item.id}/restore`); await refresh("Élément restauré."); } }, "Restaurer") : null,
        writable ? h("button", { class: "btn danger", onclick: async () => {
          if (!(await confirmDialog({ title: "Supprimer définitivement ?", message: `« ${d.name} » sera effacé sans retour possible.`, confirmLabel: "Supprimer", danger: true }))) return;
          await api("DELETE", `/items/${item.id}/purge`);
          ui.selected = null;
          await refresh("Élément supprimé définitivement.");
        } }, icon("trash"), "Supprimer définitivement") : null,
      ]
    : [
        writable ? h("button", { class: "btn primary", onclick: () => openEditor({ item }) }, icon("edit"), "Modifier") : null,
        h("button", { class: "btn", onclick: () => shareDialog(item) }, icon("share"), "Partager par lien"),
        writable ? h("button", { class: "btn ghost", title: "Créer une copie", onclick: () => openEditor({ collectionId: item.collection_id, template: d }) }, icon("copy"), "Dupliquer") : null,
        writable ? h("button", { class: "btn ghost", title: d.favorite ? "Retirer des favoris" : "Ajouter aux favoris", onclick: async () => {
          await V.updateItem(item, { ...d, favorite: !d.favorite });
          await refresh();
        } }, icon("star"), d.favorite ? "Retirer des favoris" : "Favori") : null,
        writable ? h("button", { class: "btn danger", onclick: async () => {
          await api("DELETE", `/items/${item.id}`);
          ui.selected = null;
          await refresh("Élément placé dans la corbeille.");
        } }, icon("trash"), "Corbeille") : null,
      ];

  clear(pane, h("article", { class: "detail" },
    h("button", { class: "btn ghost small back-to-list", onclick: () => { ui.selected = null; rerender(); } }, icon("back"), "Retour à la liste"),
    h("div", { class: "detail-head" },
      h("div", { class: "icon-tile", style: `background:${colorFor(d.name)}` }, initials(d.name)),
      h("div", { style: "min-width:0" }, h("h2", {}, d.name || "(sans nom)"),
        h("div", { class: "row small muted" }, `${KIND_LABEL[d.kind]} · ${col?.personal ? "Personnel" : col?.name}`,
          !writable ? h("span", { class: "chip" }, "Lecture seule") : null))),
    expired ? h("div", { class: "notice warn" }, `Ce mot de passe devait être renouvelé le ${fmtDate(d.expires_at)}.`) : null,
    (d.tags || []).length ? h("div", { class: "row" }, d.tags.map((t) => h("span", { class: "chip accent" }, t))) : null,
    main, attachments, history,
    h("div", { class: "row" }, actions),
    h("div", { class: "meta-line" }, `Créé ${relTime(item.created_at)} · modifié ${relTime(item.updated_at)}`,
      d.password_changed_at ? ` · mot de passe changé ${relTime(d.password_changed_at)}` : "")));
}

// ------------------------------------------------------------ Partage par lien

function shareDialog(item) {
  const d = item.data;
  const fields = [
    ["name", "Nom", d.name], ["username", "Identifiant", d.username], ["password", "Mot de passe", d.password],
    ["urls", "Sites", (d.urls || []).join("\n")], ["notes", "Notes", d.notes],
  ].filter(([, , v]) => v);
  const checks = fields.map(([k, label]) => {
    const cb = h("input", { type: "checkbox", checked: k !== "notes", dataset: { k } });
    return h("label", { class: "check" }, cb, label);
  });
  const expiry = h("select", { class: "input", id: "share-exp" },
    [[60, "1 heure"], [1440, "1 jour"], [10080, "7 jours"], [43200, "30 jours"]].map(([v, l]) => h("option", { value: v, selected: v === 1440 }, l)));
  const views = h("select", { class: "input", id: "share-views" }, [1, 2, 5, 10].map((v) => h("option", { value: v }, `${v} consultation${v > 1 ? "s" : ""}`)));
  const result = h("div", { class: "hidden" });
  modal({
    title: "Partager par lien sécurisé",
    body: h("div", { class: "form" },
      h("p", { class: "muted small" }, "Le contenu est chiffré dans votre navigateur. La clé figure dans le lien, après le #, et n'est jamais envoyée au serveur. Le lien s'autodétruit après le nombre de consultations choisi."),
      h("div", { class: "field" }, h("span", { class: "label" }, "Informations à inclure"), h("div", { class: "grid2" }, checks)),
      h("div", { class: "grid2" },
        h("div", { class: "field" }, h("label", { for: "share-exp" }, "Expire après"), expiry),
        h("div", { class: "field" }, h("label", { for: "share-views" }, "Nombre de consultations"), views)),
      result),
    actions: [
      { label: "Fermer" },
      { label: "Créer le lien", kind: "primary", keepOpen: true, onClick: async () => {
        const payload = { name: d.name };
        for (const c of checks) {
          const cb = c.querySelector("input");
          if (cb.checked) payload[cb.dataset.k] = cb.dataset.k === "urls" ? d.urls : d[cb.dataset.k];
        }
        try {
          const { url, expires_at } = await V.createShareLink(payload, Number(expiry.value), Number(views.value));
          const box = h("input", { class: "input mono", readonly: true, value: url });
          clear(result, h("div", { class: "notice" }, h("div", { class: "field" },
            h("span", { class: "label" }, `Lien valable jusqu'au ${fmtDate(expires_at)}`),
            h("div", { class: "input-row" }, box, h("button", { class: "btn", onclick: async () => {
              try { await navigator.clipboard.writeText(url); toast("Lien copié."); } catch { box.select(); }
            } }, icon("copy"), "Copier")),
            h("span", { class: "small muted" }, "Transmettez-le par un canal différent de l'identifiant, par exemple par SMS."))));
          result.classList.remove("hidden");
          box.select();
        } catch (e) {
          toast(e.message, "bad");
        }
      } },
    ],
  });
}

// ------------------------------------------------------------ Coffres partagés

export function newCollectionDialog() {
  const name = h("input", { class: "input", id: "col-name", maxlength: 80, placeholder: "Ex. Équipe support, Comptes réseaux sociaux…" });
  modal({
    title: "Nouveau coffre partagé",
    body: h("div", { class: "form" },
      h("div", { class: "field" }, h("label", { for: "col-name" }, "Nom du coffre"), name),
      h("p", { class: "small muted" }, "Vous en serez gestionnaire. Vous pourrez ensuite y inviter des collègues, avec des droits de lecture, d'édition ou de gestion.")),
    actions: [
      { label: "Annuler" },
      { label: "Créer", kind: "primary", onClick: async () => {
        if (!name.value.trim()) { toast("Donnez un nom au coffre.", "bad"); return false; }
        const id = await V.createCollection(name.value.trim());
        ui.filter = { type: "all", collection: id };
        ui.selected = null;
        await refresh("Coffre créé.");
        manageCollection(id);
      } },
    ],
  });
}

export async function manageCollection(collectionId) {
  const col = V.state.collections.get(collectionId);
  const isManager = col.role === "manager";
  const body = h("div", { class: "form" }, h("div", { class: "busy" }, h("span", { class: "spinner" })));
  const m = modal({ title: `Partage : ${col.name}`, body, wide: true });
  const draw = async () => {
    let members, directory;
    try {
      [members, directory] = await Promise.all([api("GET", `/collections/${collectionId}/members`), api("GET", "/directory")]);
    } catch (e) {
      clear(body, h("div", { class: "notice bad" }, e.message));
      return;
    }
    const me = V.state.profile.id;
    const rows = members.map((mb) => {
      const roleSel = h("select", { class: "input", disabled: !isManager || mb.user_id === me, "aria-label": `Rôle de ${mb.name}` },
        Object.entries(ROLE_LABEL).map(([k, l]) => h("option", { value: k, selected: mb.role === k }, l)));
      roleSel.addEventListener("change", async () => {
        try { await api("PUT", `/collections/${collectionId}/members/${mb.user_id}`, { role: roleSel.value }); toast("Rôle mis à jour."); }
        catch (e) { toast(e.message, "bad"); roleSel.value = mb.role; }
      });
      return h("tr", {},
        h("td", {}, h("div", { style: "font-weight:600" }, mb.name, mb.user_id === me ? " (vous)" : ""), h("div", { class: "small muted" }, mb.email)),
        h("td", { class: "mono small" }, V.fingerprint(mb.public_key)),
        h("td", {}, roleSel),
        h("td", {}, isManager && mb.user_id !== me ? h("button", { class: "btn danger small", onclick: async () => {
          if (!(await confirmDialog({ title: "Retirer l'accès ?", message: `${mb.name} perdra l'accès à ce coffre. La clé du coffre sera renouvelée et tout son contenu rechiffré, pour que d'anciennes copies ne servent plus à rien.`, confirmLabel: "Retirer et renouveler la clé", danger: true }))) return;
          try { await V.rotateCollection(collectionId, [mb.user_id]); toast("Accès retiré, clé renouvelée."); await V.sync(); draw(); }
          catch (e) { toast(e.message, "bad"); }
        } }, "Retirer") : null));
    });
    const candidates = directory.filter((u) => !members.some((mb) => mb.user_id === u.id));
    const userSel = h("select", { class: "input", id: "add-user" }, h("option", { value: "" }, "Choisir une personne…"),
      candidates.map((u) => h("option", { value: u.id }, `${u.name} — ${u.email}`)));
    const roleSel = h("select", { class: "input", id: "add-role" }, Object.entries(ROLE_LABEL).map(([k, l]) => h("option", { value: k, selected: k === "editor" }, `${l} · ${ROLE_HELP[k]}`)));
    const fp = h("div", { class: "small muted" });
    userSel.addEventListener("change", () => {
      const u = candidates.find((c) => c.id === userSel.value);
      fp.textContent = u ? `Empreinte de sa clé : ${V.fingerprint(u.public_key)}. Pour un partage très sensible, vérifiez-la avec cette personne de vive voix.` : "";
    });
    const leave = !col.personal ? h("button", { class: "btn ghost small", onclick: async () => {
      if (!(await confirmDialog({ title: "Quitter ce coffre ?", message: "Vous n'y aurez plus accès, sauf nouvelle invitation.", confirmLabel: "Quitter", danger: true }))) return;
      try { await api("DELETE", `/collections/${collectionId}/members/${me}`); m.close(); ui.filter = { type: "all" }; await refresh("Vous avez quitté le coffre."); }
      catch (e) { toast(e.message, "bad"); }
    } }, "Quitter le coffre") : null;
    clear(body,
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Membre"), h("th", {}, "Empreinte de clé"), h("th", {}, "Rôle"), h("th", {}, ""))),
        h("tbody", {}, rows))),
      isManager ? h("div", { class: "card section" },
        h("h3", {}, "Donner accès"),
        candidates.length ? h("div", { class: "grid2" }, h("div", { class: "field" }, h("label", { for: "add-user" }, "Personne"), userSel), h("div", { class: "field" }, h("label", { for: "add-role" }, "Rôle"), roleSel)) : h("p", { class: "muted small" }, "Toutes les personnes de l'organisation ont déjà accès."),
        fp,
        candidates.length ? h("div", { class: "row end" }, h("button", { class: "btn primary", onclick: async () => {
          const u = candidates.find((c) => c.id === userSel.value);
          if (!u) return toast("Choisissez une personne.", "bad");
          try { await V.addMember(collectionId, u, roleSel.value); toast(`${u.name} a maintenant accès.`); await V.sync(); draw(); }
          catch (e) { toast(e.message, "bad"); }
        } }, icon("plus"), "Donner accès")) : null) : null,
      isManager ? h("div", { class: "card section" },
        h("h3", {}, "Réglages du coffre"),
        h("div", { class: "row" },
          h("button", { class: "btn", onclick: () => renameDialog(col, draw) }, icon("edit"), "Renommer"),
          h("button", { class: "btn", onclick: async () => {
            try { await V.rotateCollection(collectionId, []); await V.sync(); toast("Clé du coffre renouvelée."); } catch (e) { toast(e.message, "bad"); }
          } }, icon("refresh"), "Renouveler la clé"),
          h("button", { class: "btn danger", onclick: async () => {
            if (!(await confirmDialog({ title: "Supprimer ce coffre ?", message: "Le coffre et tous ses éléments seront supprimés pour tous ses membres. Cette action est définitive.", confirmLabel: "Supprimer le coffre", danger: true }))) return;
            try { await api("DELETE", `/collections/${collectionId}`); m.close(); ui.filter = { type: "all" }; await refresh("Coffre supprimé."); } catch (e) { toast(e.message, "bad"); }
          } }, icon("trash"), "Supprimer le coffre"))) : null,
      h("div", { class: "row between" }, leave, h("button", { class: "btn", onclick: () => { m.close(); refresh(); } }, "Terminé")));
  };
  draw();
}

function renameDialog(col, after) {
  const name = h("input", { class: "input", id: "rename", value: col.name, maxlength: 80 });
  modal({
    title: "Renommer le coffre",
    body: h("div", { class: "field" }, h("label", { for: "rename" }, "Nouveau nom"), name),
    actions: [{ label: "Annuler" }, { label: "Renommer", kind: "primary", onClick: async () => {
      try { await V.renameCollection(col.id, name.value.trim()); await V.sync(); toast("Coffre renommé."); after(); } catch (e) { toast(e.message, "bad"); return false; }
    } }],
  });
}
