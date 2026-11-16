// Pages outils : générateur, santé, liens de partage, paramètres.

import { h, clear, icon, toast, modal, confirmDialog, fmtDate, relTime } from "../dom.js";
import { call, nextFrame } from "../wasm.js";
import { api, saveBlob } from "../api.js";
import * as V from "../vault.js";
import { ui, go, refresh, showRecoveryKey } from "../app.js";
import { prefs, copySecret } from "../prefs.js";

function page(title, subtitle, ...content) {
  return h("div", { class: "page" }, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, title), subtitle ? h("p", { class: "muted" }, subtitle) : null)), ...content);
}

// ------------------------------------------------------------ Générateur

export function renderGenerator(container) {
  const opts = prefs.get("generator", { mode: "password", length: 20, lower: true, upper: true, digits: true, symbols: true, avoid_ambiguous: true, words: 5, separator: "-", capitalize: true, include_number: true });
  const out = h("div", { class: "gen-output", "aria-live": "polite" });
  const info = h("div", { class: "row" });
  let current = "";
  const generate = () => {
    try {
      const g = opts.mode === "password"
        ? call("generate_password", { options: opts })
        : call("generate_passphrase", { options: { words: opts.words, separator: opts.separator, capitalize: opts.capitalize, include_number: opts.include_number } });
      current = g.value;
      out.textContent = g.value;
      const s = call("strength", { password: g.value });
      clear(info, h("div", { class: `strength s${s.score}` }, h("span"), h("span"), h("span"), h("span"), h("span")),
        h("span", { class: "small muted" }, `${Math.round(g.entropy_bits)} bits d'entropie · ${s.label}`));
      prefs.set("generator", opts);
    } catch (e) {
      out.textContent = e.message;
    }
  };
  const check = (key, label) => {
    const cb = h("input", { type: "checkbox", checked: opts[key] });
    cb.addEventListener("change", () => { opts[key] = cb.checked; generate(); });
    return h("label", { class: "check" }, cb, label);
  };
  const range = (key, min, max, label) => {
    const value = h("strong", {}, String(opts[key]));
    const r = h("input", { type: "range", min, max, value: opts[key], "aria-label": label });
    r.addEventListener("input", () => { opts[key] = Number(r.value); value.textContent = r.value; generate(); });
    return h("div", { class: "field" }, h("div", { class: "row between" }, h("span", { class: "label" }, label), value), r);
  };
  const settings = h("div");
  const drawSettings = () => clear(settings, opts.mode === "password"
    ? h("div", { class: "form" }, range("length", 8, 128, "Longueur"),
        h("div", { class: "grid2" }, check("lower", "Minuscules (a-z)"), check("upper", "Majuscules (A-Z)"), check("digits", "Chiffres (0-9)"), check("symbols", "Symboles (!@#…)"), check("avoid_ambiguous", "Éviter les caractères ambigus (l, I, O, 0…)")))
    : h("div", { class: "form" }, range("words", 3, 12, "Nombre de mots"),
        h("div", { class: "grid2" }, check("capitalize", "Majuscule à chaque mot"), check("include_number", "Ajouter un nombre"),
          (() => { const s = h("input", { class: "input", value: opts.separator, maxlength: 3, "aria-label": "Séparateur" }); s.addEventListener("input", () => { opts.separator = s.value; generate(); }); return h("div", { class: "field" }, h("span", { class: "label" }, "Séparateur"), s); })())));
  const modeBtn = (mode, label) => h("button", { class: `tab ${opts.mode === mode ? "on" : ""}`, onclick: () => { opts.mode = mode; renderGenerator(clear(container)); } }, label);
  drawSettings();
  generate();
  container.append(page("Générateur", "Mots de passe tirés au hasard par le générateur cryptographique de votre système, sans biais.",
    h("div", { class: "card" },
      h("div", { class: "tabs", style: "padding:0 12px" }, modeBtn("password", "Mot de passe"), modeBtn("passphrase", "Phrase de passe")),
      h("div", { class: "section" }, out, info,
        h("div", { class: "row" },
          h("button", { class: "btn primary", onclick: async () => { const m = await copySecret(current, "Copié"); toast(m || "Copie refusée.", m ? "" : "bad"); } }, icon("copy"), "Copier"),
          h("button", { class: "btn", onclick: generate }, icon("refresh"), "Régénérer"))),
      h("div", { class: "section" }, settings)),
    h("p", { class: "small muted" }, "Les phrases de passe utilisent des mots prononçables générés au hasard : plus faciles à taper et à retenir, avec une robustesse comparable.")));
}

// ------------------------------------------------------------ Santé

export function renderHealth(container) {
  const r = V.healthReport();
  const count = (k) => r.rows.filter((x) => x[k]).length;
  const tone = r.score >= 85 ? "ok" : r.score >= 60 ? "warn" : "bad";
  const issues = (x) => [x.weak && h("span", { class: "chip bad" }, x.strength.label), x.reused && h("span", { class: "chip warn" }, "Réutilisé"),
    x.old && h("span", { class: "chip warn" }, "Plus d'un an"), x.expired && h("span", { class: "chip bad" }, "À renouveler"),
    x.no2fa && h("span", { class: "chip" }, "Pas de 2FA enregistrée")].filter(Boolean);
  const problems = r.rows.filter((x) => x.weak || x.reused || x.old || x.expired)
    .sort((a, b) => a.strength.score - b.strength.score);
  const open = (id) => { ui.selected = id; ui.filter = { type: "all" }; go("vault"); };
  container.append(page("Santé des mots de passe", "Analyse faite dans votre navigateur : le serveur n'en sait rien.",
    h("div", { class: "stats" },
      h("div", { class: "stat" }, h("div", { class: "n", style: `color:var(--${tone})` }, `${r.score} %`), h("div", { class: "l" }, "Score global")),
      h("div", { class: "stat" }, h("div", { class: "n" }, count("weak")), h("div", { class: "l" }, "Faibles")),
      h("div", { class: "stat" }, h("div", { class: "n" }, count("reused")), h("div", { class: "l" }, "Réutilisés")),
      h("div", { class: "stat" }, h("div", { class: "n" }, count("old")), h("div", { class: "l" }, "Inchangés depuis plus d'un an")),
      h("div", { class: "stat" }, h("div", { class: "n" }, count("expired")), h("div", { class: "l" }, "Date de renouvellement dépassée"))),
    problems.length
      ? h("div", { class: "table-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, h("th", {}, "Élément"), h("th", {}, "Problèmes"), h("th", {}, "Dernier changement"), h("th", {}, ""))),
          h("tbody", {}, problems.map((x) => h("tr", {},
            h("td", {}, h("strong", {}, x.item.data.name), h("div", { class: "small muted" }, x.item.data.username)),
            h("td", {}, h("div", { class: "row" }, issues(x))),
            h("td", { class: "small" }, relTime(x.item.data.password_changed_at || x.item.created_at)),
            h("td", {}, h("button", { class: "btn small", onclick: () => open(x.item.id) }, "Ouvrir")))))))
      : h("div", { class: "card section" }, h("strong", {}, "Rien à signaler."), h("span", { class: "muted" }, `${r.total} mot(s) de passe analysé(s).`))));
}

// ------------------------------------------------------------ Liens de partage

export async function renderShares(container) {
  const body = h("div", { class: "busy" }, h("span", { class: "spinner" }));
  container.append(page("Liens de partage", "Liens actifs créés depuis vos éléments. Le contenu reste illisible pour le serveur.", body));
  try {
    const shares = await api("GET", "/shares");
    clear(body);
    body.className = "";
    body.append(shares.length
      ? h("div", { class: "table-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, h("th", {}, "Créé"), h("th", {}, "Expire"), h("th", {}, "Consultations"), h("th", {}, ""))),
          h("tbody", {}, shares.map((s) => h("tr", {},
            h("td", {}, fmtDate(s.created_at)), h("td", {}, fmtDate(s.expires_at)), h("td", { class: "num" }, `${s.views} / ${s.max_views}`),
            h("td", {}, h("button", { class: "btn danger small", onclick: async () => {
              await api("DELETE", `/shares/${encodeURIComponent(s.id)}`);
              toast("Lien désactivé.");
              renderShares(clear(container));
            } }, "Désactiver")))))))
      : h("div", { class: "card section" }, h("strong", {}, "Aucun lien actif."), h("span", { class: "muted" }, "Ouvrez un élément puis « Partager par lien » pour en créer un.")));
  } catch (e) {
    clear(body, h("div", { class: "notice bad" }, e.message));
  }
}

// ------------------------------------------------------------ Paramètres

export function renderSettings(container) {
  const p = V.state.profile;
  const tabs = [["account", "Compte"], ["security", "Sécurité"], ["sessions", "Appareils"], ["data", "Import et export"], ["prefs", "Préférences"], ["activity", "Mon activité"]];
  const tab = ui.settingsTab || (p.must_setup_2fa ? "security" : "account");
  const body = h("div", { class: "card" });
  container.append(page("Paramètres", null,
    p.must_setup_2fa ? h("div", { class: "notice warn" }, "Votre organisation impose la double authentification. Activez-la ci-dessous pour accéder à votre coffre.") : null,
    h("div", { class: "tabs" }, tabs.map(([k, l]) => h("button", { class: `tab ${tab === k ? "on" : ""}`, onclick: () => { ui.settingsTab = k; renderSettings(clear(container)); } }, l))),
    body));
  ({ account, security, sessions, data, prefs: prefsTab, activity })[tab](body, () => renderSettings(clear(container)));
}

function pwField(id, label, autocomplete = "current-password") {
  const el = h("input", { class: "input", id, type: "password", autocomplete });
  return { el, field: h("div", { class: "field" }, h("label", { for: id }, label), el) };
}

function account(body) {
  const p = V.state.profile;
  const name = h("input", { class: "input", id: "pname", value: p.name, maxlength: 100 });
  body.append(h("div", { class: "section" }, h("h3", {}, "Profil"),
    h("div", { class: "grid2" }, h("div", { class: "field" }, h("label", { for: "pname" }, "Nom affiché"), name),
      h("div", { class: "field" }, h("span", { class: "label" }, "Adresse e-mail"), h("div", {}, p.email))),
    h("div", { class: "row" }, h("span", { class: "chip accent" }, { owner: "Propriétaire", admin: "Administrateur", user: "Utilisateur" }[p.role]),
      h("span", { class: "small muted" }, `Compte créé le ${fmtDate(p.created_at)}`)),
    h("div", {}, h("button", { class: "btn primary", onclick: async () => {
      try { V.state.profile = await api("PUT", "/me", { name: name.value }); toast("Profil mis à jour."); refresh(); } catch (e) { toast(e.message, "bad"); }
    } }, "Enregistrer"))),
    h("div", { class: "section" }, h("h3", {}, "Empreinte de votre clé"),
      h("p", { class: "small muted" }, "Quand quelqu'un partage un coffre avec vous, il peut vérifier cette empreinte avec vous pour s'assurer que le serveur n'a pas substitué une autre clé."),
      h("div", { class: "mono" }, V.fingerprint(p.public_key))));
}

function security(body, rerender) {
  const p = V.state.profile;
  const cur = pwField("cur", "Mot de passe maître actuel");
  const n1 = pwField("n1", "Nouveau mot de passe maître", "new-password");
  const n2 = pwField("n2", "Confirmation", "new-password");
  const changeBtn = h("button", { class: "btn primary", onclick: async () => {
    if (n1.el.value.length < 12 || call("strength", { password: n1.el.value }).score < 3) return toast("Nouveau mot de passe trop faible (12 caractères et score « Fort » minimum).", "bad");
    if (n1.el.value !== n2.el.value) return toast("Les deux saisies ne correspondent pas.", "bad");
    changeBtn.disabled = true;
    await nextFrame();
    try { await V.changePassword(cur.el.value, n1.el.value); toast("Mot de passe maître changé. Vos autres appareils ont été déconnectés."); cur.el.value = n1.el.value = n2.el.value = ""; }
    catch (e) { toast(e.message, "bad"); }
    changeBtn.disabled = false;
  } }, "Changer le mot de passe maître");

  const twofa = h("div", { class: "section" }, h("h3", {}, "Double authentification"));
  if (p.totp_enabled) {
    const code = h("input", { class: "input", id: "dis-code", inputmode: "numeric", maxlength: 6, placeholder: "123456" });
    twofa.append(h("div", { class: "row" }, h("span", { class: "chip ok" }, "Activée"), h("span", { class: "small muted" }, "Un code de votre application est demandé à chaque connexion.")),
      h("div", { class: "input-row", style: "max-width:420px" }, code, h("button", { class: "btn danger", onclick: async () => {
        try { V.state.profile = await api("POST", "/me/2fa/disable", { code: code.value }); toast("Double authentification désactivée."); rerender(); } catch (e) { toast(e.message, "bad"); }
      } }, "Désactiver")));
  } else {
    twofa.append(h("p", { class: "muted" }, "Ajoutez un code à 6 chiffres généré par une application (Microsoft Authenticator, Google Authenticator, FreeOTP, Aegis…). Même si votre mot de passe fuitait, personne ne pourrait se connecter sans votre téléphone."),
      h("div", {}, h("button", { class: "btn primary", onclick: async () => {
        try {
          const s = await api("POST", "/me/2fa/setup");
          const code = h("input", { class: "input", id: "en-code", inputmode: "numeric", maxlength: 6, placeholder: "123456", style: "font-size:1.3rem;letter-spacing:.3em" });
          const img = h("img", { alt: "QR code à scanner", src: `data:image/svg+xml;base64,${btoa(s.qr_svg)}` });
          modal({
            title: "Activer la double authentification",
            body: h("div", { class: "form" },
              h("p", {}, "1. Scannez ce QR code avec votre application d'authentification."),
              h("div", { class: "qr" }, img),
              h("details", {}, h("summary", { style: "cursor:pointer" }, "Saisie manuelle"), h("div", { class: "mono", style: "margin-top:8px" }, s.secret)),
              h("div", { class: "field" }, h("label", { for: "en-code" }, "2. Saisissez le code affiché"), code)),
            actions: [{ label: "Annuler" }, { label: "Activer", kind: "primary", onClick: async () => {
              try { V.state.profile = await api("POST", "/me/2fa/enable", { code: code.value }); toast("Double authentification activée."); refresh(); } catch (e) { toast(e.message, "bad"); return false; }
            } }],
          });
        } catch (e) { toast(e.message, "bad"); }
      } }, icon("shield"), "Activer")));
  }

  const rcur = pwField("rcur", "Mot de passe maître actuel");
  body.append(twofa,
    h("div", { class: "section" }, h("h3", {}, "Mot de passe maître"),
      h("p", { class: "small muted" }, "Votre coffre n'est pas rechiffré : seule la clé qui le protège l'est. L'opération est instantanée."),
      h("div", { class: "grid2" }, cur.field, n1.field, n2.field), h("div", {}, changeBtn)),
    h("div", { class: "section" }, h("h3", {}, "Clé de récupération"),
      h("p", { class: "small muted" }, "Générez une nouvelle clé si vous pensez que l'ancienne a été vue. L'ancienne cessera immédiatement de fonctionner."),
      h("div", { style: "max-width:420px" }, rcur.field),
      h("div", {}, h("button", { class: "btn", onclick: async () => {
        try {
          const display = await V.rotateRecovery(rcur.el.value);
          rcur.el.value = "";
          const root = document.getElementById("app");
          const saved = [...root.childNodes];
          showRecoveryKey(display, () => { root.replaceChildren(...saved); toast("Nouvelle clé de récupération enregistrée."); });
        } catch (e) { toast(e.message, "bad"); }
      } }, icon("key"), "Générer une nouvelle clé"))));
}

async function sessions(body, rerender) {
  body.append(h("div", { class: "busy" }, h("span", { class: "spinner" })));
  try {
    const list = await api("GET", "/me/sessions");
    clear(body, h("div", { class: "section" }, h("h3", {}, "Appareils connectés"),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Appareil"), h("th", {}, "Adresse IP"), h("th", {}, "Dernière activité"), h("th", {}, ""))),
        h("tbody", {}, list.map((s) => h("tr", {},
          h("td", {}, s.device || "Inconnu", s.current ? h("span", { class: "chip ok", style: "margin-left:6px" }, "Cet appareil") : null),
          h("td", { class: "mono small" }, s.ip), h("td", {}, relTime(s.last_seen_at)),
          h("td", {}, s.current ? null : h("button", { class: "btn small danger", onclick: async () => {
            await api("DELETE", `/me/sessions/${s.id}`); toast("Appareil déconnecté."); rerender();
          } }, "Déconnecter")))))))));
  } catch (e) {
    clear(body, h("div", { class: "notice bad" }, e.message));
  }
}

// ---- Import / export

function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === "," || c === ";") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field); rows.push(row); row = []; field = "";
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((v) => v.trim()));
}

const COLS = {
  name: ["name", "title", "nom", "titre", "account", "entry"],
  url: ["url", "login_uri", "website", "site", "uri", "web site", "adresse"],
  username: ["username", "login_username", "user", "login", "identifiant", "email", "user name"],
  password: ["password", "login_password", "pass", "mot de passe", "motdepasse"],
  notes: ["notes", "note", "extra", "comments", "commentaire"],
  totp: ["totp", "login_totp", "otp", "otpauth", "one-time password"],
  tags: ["folder", "grouping", "group", "tags", "dossier", "category"],
};

export function csvToItems(text) {
  const rows = parseCsv(text.replace(/^﻿/, ""));
  if (rows.length < 2) throw new Error("Fichier vide ou sans en-tête.");
  const header = rows[0].map((c) => c.trim().toLowerCase());
  const idx = Object.fromEntries(Object.entries(COLS).map(([k, names]) => [k, header.findIndex((c) => names.includes(c))]));
  if (idx.password < 0 && idx.notes < 0) throw new Error("Colonnes non reconnues. Il faut au moins une colonne « password » ou « notes ».");
  return rows.slice(1).map((r) => {
    const get = (k) => (idx[k] >= 0 ? (r[idx[k]] || "").trim() : "");
    const item = V.emptyItem(get("password") || get("username") ? "login" : "note");
    item.name = get("name") || get("url").replace(/^https?:\/\//, "").split("/")[0] || "Élément importé";
    item.username = get("username");
    item.password = get("password");
    item.urls = get("url") ? [get("url")] : [];
    item.notes = idx.notes >= 0 ? (r[idx.notes] || "") : "";
    item.totp = get("totp");
    item.tags = get("tags") ? get("tags").split(/[\\/,]/).map((t) => t.trim()).filter(Boolean) : [];
    item.password_changed_at = V.now();
    return item;
  });
}

function data(body) {
  const writable = [...V.state.collections.values()].filter((c) => ["manager", "editor"].includes(c.role));
  const target = h("select", { class: "input", id: "imp-col" }, writable.map((c) => h("option", { value: c.id }, c.personal ? "Personnel" : c.name)));
  const file = h("input", { type: "file", id: "imp-file", accept: ".csv,.json,text/csv,application/json", class: "input" });
  const expPw = h("input", { class: "input", id: "exp-pw", type: "password", autocomplete: "new-password" });
  const live = () => [...V.state.items.values()].filter((i) => i.data && !i.deleted_at);
  body.append(
    h("div", { class: "section" }, h("h3", {}, "Importer"),
      h("p", { class: "small muted" }, "Formats acceptés : CSV exporté par Bitwarden, LastPass, 1Password, KeePass/KeePassXC, Dashlane, Chrome, Edge, Firefox ; ou une sauvegarde chiffrée Locksy (.json). Le fichier est lu et chiffré dans ce navigateur."),
      h("div", { class: "grid2" }, h("div", { class: "field" }, h("label", { for: "imp-file" }, "Fichier"), file), h("div", { class: "field" }, h("label", { for: "imp-col" }, "Coffre de destination"), target)),
      h("div", {}, h("button", { class: "btn primary", onclick: async () => {
        const f = file.files[0];
        if (!f) return toast("Choisissez un fichier.", "bad");
        if (f.size > 20 * 1024 * 1024) return toast("Fichier trop volumineux (20 Mo maximum).", "bad");
        try {
          const text = await f.text();
          let items;
          if (f.name.endsWith(".json")) {
            const pw = await askPassword("Mot de passe de la sauvegarde");
            if (!pw) return;
            await nextFrame();
            items = JSON.parse(call("unprotect_export", { password: pw, data: text })).items;
          } else {
            items = csvToItems(text);
          }
          if (!(await confirmDialog({ title: "Confirmer l'import", message: `${items.length} élément(s) seront ajoutés au coffre choisi.`, confirmLabel: "Importer" }))) return;
          await V.importItems(target.value, items);
          file.value = "";
          await refresh(`${items.length} élément(s) importé(s). Pensez à supprimer le fichier source, qui est en clair.`);
        } catch (e) { toast(e.message, "bad"); }
      } }, "Importer"))),
    h("div", { class: "section" }, h("h3", {}, "Sauvegarde chiffrée"),
      h("p", { class: "small muted" }, "Exporte tous vos éléments lisibles dans un fichier chiffré (Argon2id + XChaCha20-Poly1305), protégé par un mot de passe que vous choisissez. Réimportable dans Locksy."),
      h("div", { class: "input-row", style: "max-width:520px" }, expPw, h("button", { class: "btn primary", onclick: async () => {
        if (expPw.value.length < 12) return toast("Mot de passe d'au moins 12 caractères.", "bad");
        await nextFrame();
        const json = call("protect_export", { password: expPw.value, plaintext: JSON.stringify({ exported_at: V.now(), items: live().map((i) => i.data) }) });
        expPw.value = "";
        saveBlob(new Blob([json], { type: "application/json" }), `locksy-sauvegarde-${new Date().toISOString().slice(0, 10)}.json`);
        toast("Sauvegarde chiffrée téléchargée.");
      } }, "Exporter"))),
    h("div", { class: "section" }, h("h3", {}, "Export en clair (CSV)"),
      h("div", { class: "notice warn small" }, "Le fichier contiendra tous vos mots de passe en clair. À réserver à une migration, et à supprimer aussitôt après."),
      h("div", {}, h("button", { class: "btn danger", onclick: async () => {
        if (!(await confirmDialog({ title: "Exporter en clair ?", message: "Toute personne qui accède à ce fichier verra vos mots de passe.", confirmLabel: "Exporter quand même", danger: true }))) return;
        const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
        const lines = [["name", "url", "username", "password", "totp", "notes", "folder"].join(",")];
        for (const i of live()) {
          const col = V.state.collections.get(i.collection_id);
          lines.push([i.data.name, (i.data.urls || [])[0], i.data.username, i.data.password, i.data.totp, i.data.notes, col?.personal ? "Personnel" : col?.name].map(esc).join(","));
        }
        saveBlob(new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv" }), "locksy-export.csv");
      } }, "Exporter en CSV"))));
}

function askPassword(title) {
  return new Promise((resolve) => {
    const el = h("input", { class: "input", type: "password", id: "ask-pw" });
    let done = false;
    modal({ title, body: h("div", { class: "field" }, h("label", { for: "ask-pw" }, "Mot de passe"), el), onClose: () => { if (!done) resolve(null); },
      actions: [{ label: "Annuler" }, { label: "Valider", kind: "primary", onClick: () => { done = true; resolve(el.value); } }] });
  });
}

function prefsTab(body) {
  const sel = (id, key, fallback, options) => {
    const s = h("select", { class: "input", id }, options.map(([v, l]) => h("option", { value: v, selected: String(prefs.get(key, fallback)) === String(v) }, l)));
    s.addEventListener("change", () => { prefs.set(key, Number(s.value)); toast("Préférence enregistrée."); });
    return s;
  };
  const hide = h("input", { type: "checkbox", checked: prefs.get("lockOnHide", false) });
  hide.addEventListener("change", () => prefs.set("lockOnHide", hide.checked));
  body.append(h("div", { class: "section" }, h("h3", {}, "Ce navigateur"),
    h("div", { class: "grid2" },
      h("div", { class: "field" }, h("label", { for: "p-lock" }, "Locksyillage automatique après inactivité"),
        sel("p-lock", "autoLockMinutes", 10, [[1, "1 minute"], [5, "5 minutes"], [10, "10 minutes"], [30, "30 minutes"], [60, "1 heure"], [0, "Jamais"]])),
      h("div", { class: "field" }, h("label", { for: "p-clip" }, "Effacement du presse-papiers"),
        sel("p-clip", "clipboardSeconds", 30, [[15, "15 secondes"], [30, "30 secondes"], [60, "1 minute"], [120, "2 minutes"], [0, "Jamais"]]))),
    h("label", { class: "check" }, hide, "Locksyiller dès que l'onglet passe en arrière-plan")));
}

async function activity(body) {
  body.append(h("div", { class: "busy" }, h("span", { class: "spinner" })));
  try {
    const list = await api("GET", "/me/audit");
    clear(body, h("div", { class: "section" }, h("h3", {}, "Mes 200 dernières actions"),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Date"), h("th", {}, "Action"), h("th", {}, "Détails"), h("th", {}, "Adresse IP"))),
        h("tbody", {}, list.map((e) => h("tr", {}, h("td", { class: "small" }, fmtDate(e.at)), h("td", {}, h("span", { class: "chip" }, e.action)),
          h("td", { class: "small" }, e.details), h("td", { class: "mono small" }, e.ip))))))));
  } catch (e) {
    clear(body, h("div", { class: "notice bad" }, e.message));
  }
}
