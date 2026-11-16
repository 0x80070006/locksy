// Formulaire de création et de modification d'un élément.

import { h, clear, icon, toast, modal } from "../dom.js";
import { call } from "../wasm.js";
import * as V from "../vault.js";
import { ui, refresh } from "../app.js";
import { canWrite } from "./vaultview.js";

const KINDS = [["login", "Identifiant"], ["note", "Note sécurisée"], ["card", "Carte bancaire"], ["identity", "Identité"], ["ssh", "Clé SSH"]];

function input(id, label, value, opts = {}) {
  const el = opts.multiline
    ? h("textarea", { class: `input ${opts.mono ? "mono" : ""}`, id, rows: opts.rows || 4, spellcheck: "false" })
    : h("input", { class: `input ${opts.mono ? "mono" : ""}`, id, type: opts.type || "text", autocomplete: "off", spellcheck: "false", placeholder: opts.placeholder || "" });
  el.value = value ?? "";
  return { el, field: h("div", { class: "field" }, h("label", { for: id }, label), opts.wrap ? opts.wrap(el) : el) };
}

export function openEditor({ item = null, collectionId = null, kind = "login", name: initialName = "", template = null }) {
  const isNew = !item;
  const data = structuredClone(item?.data || template || V.emptyItem(kind));
  if (template) {
    // Copie : nouvel élément, sans historique ni pièces jointes (propres à l'original).
    data.name = `${template.name} (copie)`;
    data.password_history = [];
    data.attachments = [];
  } else if (isNew && initialName) {
    data.name = initialName;
  }
  data.card ||= {}; data.identity ||= {}; data.ssh ||= {};
  const writable = [...V.state.collections.values()].filter((c) => canWrite(c.id));
  let currentKind = data.kind;

  const kindSel = h("select", { class: "input", id: "kind", disabled: !isNew }, KINDS.map(([k, l]) => h("option", { value: k, selected: k === data.kind }, l)));
  const colSel = h("select", { class: "input", id: "collection" }, writable.map((c) =>
    h("option", { value: c.id, selected: c.id === (item?.collection_id || collectionId) }, c.personal ? "Personnel" : c.name)));
  const name = input("name", "Nom", data.name, { placeholder: "Ex. Messagerie, Banque, Wi-Fi bureau…" });

  // Mot de passe avec générateur et jauge.
  const pwMeter = h("div", { class: "row" });
  const pw = input("password", "Mot de passe", data.password, { mono: true, type: "password", wrap: (el) => h("div", { class: "input-row" }, el,
    h("button", { class: "btn icon", type: "button", title: "Afficher", "aria-label": "Afficher ou masquer", onclick: () => { el.type = el.type === "password" ? "text" : "password"; } }, icon("eye")),
    h("button", { class: "btn", type: "button", onclick: () => {
      const g = call("generate_password", { options: { length: 20, lower: true, upper: true, digits: true, symbols: true, avoid_ambiguous: true } });
      el.value = g.value;
      el.type = "text";
      el.dispatchEvent(new Event("input"));
    } }, icon("wand"), "Générer")) });
  const updateMeter = () => {
    if (!pw.el.value) return clear(pwMeter);
    const s = call("strength", { password: pw.el.value });
    clear(pwMeter, h("div", { class: `strength s${s.score}` }, h("span"), h("span"), h("span"), h("span"), h("span")),
      h("span", { class: "small muted" }, `${s.label} · ${Math.round(s.entropy_bits)} bits`));
  };
  pw.el.addEventListener("input", updateMeter);
  updateMeter();

  const username = input("username", "Identifiant", data.username, { placeholder: "Adresse e-mail ou nom d'utilisateur" });
  const urls = input("urls", "Sites (un par ligne)", (data.urls || []).join("\n"), { multiline: true, rows: 2 });
  const totpPreview = h("div", { class: "small muted" });
  const totp = input("totp", "Clé de double authentification (TOTP)", data.totp, { mono: true, placeholder: "Secret base32 ou lien otpauth://" });
  const checkTotp = () => {
    if (!totp.el.value.trim()) return (totpPreview.textContent = "Facultatif : Locksy affichera alors les codes à 6 chiffres.");
    try {
      const r = call("totp", { secret: totp.el.value.trim(), time: Math.floor(Date.now() / 1000) });
      totpPreview.textContent = `Code actuel : ${r.code}`;
    } catch (e) {
      totpPreview.textContent = e.message;
    }
  };
  totp.el.addEventListener("input", checkTotp);
  checkTotp();

  const card = {
    holder: input("c-holder", "Titulaire", data.card.holder), number: input("c-number", "Numéro", data.card.number, { mono: true }),
    expiry: input("c-exp", "Expiration (MM/AA)", data.card.expiry), cvv: input("c-cvv", "Cryptogramme", data.card.cvv, { type: "password" }),
    pin: input("c-pin", "Code PIN", data.card.pin, { type: "password" }),
  };
  const ident = {
    first_name: input("i-first", "Prénom", data.identity.first_name), last_name: input("i-last", "Nom", data.identity.last_name),
    email: input("i-email", "E-mail", data.identity.email), phone: input("i-phone", "Téléphone", data.identity.phone),
    company: input("i-company", "Société", data.identity.company), document_number: input("i-doc", "N° de pièce d'identité", data.identity.document_number),
    address: input("i-address", "Adresse", data.identity.address, { multiline: true, rows: 2 }),
  };
  const ssh = {
    public_key: input("s-pub", "Clé publique", data.ssh.public_key, { multiline: true, mono: true, rows: 2 }),
    private_key: input("s-priv", "Clé privée", data.ssh.private_key, { multiline: true, mono: true, rows: 6 }),
    passphrase: input("s-pass", "Phrase de passe", data.ssh.passphrase, { type: "password" }),
  };
  const notes = input("notes", "Notes", data.notes, { multiline: true, rows: 4 });
  const tags = input("tags", "Étiquettes (séparées par des virgules)", (data.tags || []).join(", "), { placeholder: "finance, prod, client-x" });
  const expiresVal = data.expires_at ? new Date(data.expires_at * 1000).toISOString().slice(0, 10) : "";
  const expires = input("expires", "À renouveler avant le (facultatif)", expiresVal, { type: "date" });
  const fav = h("input", { type: "checkbox", checked: data.favorite });

  // Champs personnalisés.
  const fieldsBox = h("div", { class: "form" });
  const fieldRows = [];
  const addField = (f = { label: "", value: "", hidden: false }) => {
    const label = h("input", { class: "input", placeholder: "Libellé", value: f.label, "aria-label": "Libellé du champ" });
    const value = h("input", { class: "input", placeholder: "Valeur", value: f.value, type: f.hidden ? "password" : "text", "aria-label": "Valeur du champ" });
    const hidden = h("input", { type: "checkbox", checked: f.hidden });
    hidden.addEventListener("change", () => { value.type = hidden.checked ? "password" : "text"; });
    const row = h("div", { class: "input-row" }, label, value, h("label", { class: "check small", title: "Masquer" }, hidden, "Secret"),
      h("button", { class: "btn ghost icon", type: "button", "aria-label": "Supprimer le champ", onclick: () => { row.remove(); fieldRows.splice(fieldRows.indexOf(entry), 1); } }, icon("x")));
    const entry = { label, value, hidden };
    fieldRows.push(entry);
    fieldsBox.append(row);
  };
  (data.fields || []).forEach(addField);

  const sections = {
    login: h("div", { class: "form" }, username.field, pw.field, pwMeter, urls.field, totp.field, totpPreview),
    card: h("div", { class: "grid2" }, Object.values(card).map((x) => x.field)),
    identity: h("div", { class: "grid2" }, Object.values(ident).map((x) => x.field)),
    ssh: h("div", { class: "form" }, Object.values(ssh).map((x) => x.field)),
    note: h("div"),
  };
  const kindBox = h("div");
  const showKind = () => { currentKind = kindSel.value; clear(kindBox, sections[currentKind]); };
  kindSel.addEventListener("change", showKind);
  showKind();

  const body = h("form", { class: "form", onsubmit: (e) => e.preventDefault() },
    h("div", { class: "grid2" }, h("div", { class: "field" }, h("label", { for: "kind" }, "Type"), kindSel),
      h("div", { class: "field" }, h("label", { for: "collection" }, "Coffre"), colSel)),
    name.field, kindBox, notes.field,
    h("details", {}, h("summary", { style: "cursor:pointer;font-weight:600" }, "Plus d'options"),
      h("div", { class: "form", style: "margin-top:12px" },
        tags.field, expires.field,
        h("div", { class: "field" }, h("span", { class: "label" }, "Champs personnalisés"), fieldsBox,
          h("div", {}, h("button", { class: "btn small", type: "button", onclick: () => addField() }, icon("plus"), "Ajouter un champ"))),
        h("label", { class: "check" }, fav, "Afficher dans les favoris"))));

  modal({
    title: template ? "Dupliquer l'élément" : isNew ? "Nouvel élément" : `Modifier « ${data.name} »`,
    body,
    wide: true,
    actions: [
      { label: "Annuler" },
      { label: isNew ? "Enregistrer" : "Enregistrer les modifications", kind: "primary", onClick: async () => {
        if (!name.el.value.trim()) { toast("Le nom est obligatoire.", "bad"); name.el.focus(); return false; }
        let out = {
          ...data,
          kind: currentKind,
          name: name.el.value.trim(),
          favorite: fav.checked,
          tags: tags.el.value.split(",").map((t) => t.trim()).filter(Boolean),
          notes: notes.el.value,
          fields: fieldRows.map((f) => ({ label: f.label.value.trim(), value: f.value.value, hidden: f.hidden.checked })).filter((f) => f.label || f.value),
          expires_at: expires.el.value ? Math.floor(new Date(expires.el.value + "T12:00:00").getTime() / 1000) : 0,
        };
        if (currentKind === "login") {
          out.username = username.el.value.trim();
          out.urls = urls.el.value.split("\n").map((u) => u.trim()).filter(Boolean);
          out.totp = totp.el.value.trim();
          if (out.totp) { try { call("totp", { secret: out.totp, time: 0 }); } catch (e) { toast(e.message, "bad"); return false; } }
          out = V.applyPassword(out, pw.el.value);
        }
        if (currentKind === "card") out.card = Object.fromEntries(Object.entries(card).map(([k, x]) => [k, x.el.value.trim()]));
        if (currentKind === "identity") out.identity = Object.fromEntries(Object.entries(ident).map(([k, x]) => [k, x.el.value]));
        if (currentKind === "ssh") out.ssh = Object.fromEntries(Object.entries(ssh).map(([k, x]) => [k, x.el.value]));
        try {
          if (isNew) ui.selected = await V.createItem(colSel.value, out);
          else await V.updateItem(item, out, colSel.value);
          await refresh(isNew ? "Élément enregistré." : "Modifications enregistrées.");
        } catch (e) {
          toast(e.message, "bad");
          return false;
        }
      } },
    ],
  });
}
