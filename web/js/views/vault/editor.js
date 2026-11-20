// Création et modification d'un élément, dans le panneau de la fiche (cahier
// §3.3.3) : plus de fenêtre modale. Focus initial sur « Nom » (correctif P0
// 01-4) ; mot de passe pré-généré à la création avec la mention « Saisir mon
// mot de passe actuel » ; « Rangé dans » avec l'impact d'un changement de
// coffre ; code de vérification par QR code ou clé collée ; type SSH complet
// (hôte, identifiant, port, mot de passe, clés, phrase) ; Ctrl+Entrée ou
// Ctrl+S enregistrent ; garde de sortie ; conflit 409 sans perte de saisie.
//
// renderEditor({ item, kind, collectionId, template, regenerate, env })
//   -> { el, isDirty(), save(), focus(), destroy() }

import {
  t, plural, fmtDate, relTime, h, icon, button, iconButton, field, fieldInput, fieldError, textInput, textArea, selectInput,
  passwordField, radioCards, chipsInput, qrImport, audienceLine, dirtyGuard, hotkeys, notify, dialog, secretRow, errorText,
  focusSafely, setDisabled, busyWhile, announce,
} from "../../ui/index.js";
import { api } from "../../api.js";
import { call } from "../../wasm.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";
import { KINDS, KIND_ICONS, writableCollections, collectionLabel, collectionOf, defaultCollection, policy, offline } from "./common.js";

// ------------------------------------------------------------ Génération

/**
 * Mot de passe selon les préférences du générateur : longueur choisie, sinon
 * celle proposée par l'organisation, jamais sous son minimum.
 */
export function generatePassword() {
  const g = S.prefs().generator || {};
  const min = Number(policy("generator.min_length", 12)) || 12;
  const proposed = Number(policy("generator.length", 20)) || 20;
  try {
    if (g.style === "words") {
      return call("generate_passphrase", { options: {
        words: Math.max(4, Number(g.words) || 5), separator: String(g.separator ?? "-"),
        capitalize: g.capitalize !== false, include_number: g.number !== false,
      } }).value;
    }
    return call("generate_password", { options: {
      length: Math.min(128, Math.max(min, Number(g.length) || proposed)), lower: true, upper: true,
      digits: g.digits !== false, symbols: g.symbols !== false, avoid_ambiguous: g.avoid_ambiguous !== false,
    } }).value;
  } catch {
    return "";
  }
}

// ------------------------------------------------------------ Validation

/** Adresse plausible : http(s)://hôte ou hôte avec un point, sans espace. */
export function looksLikeSite(raw) {
  const s = String(raw || "").trim();
  if (!s) return true;
  if (/\s/.test(s)) return false;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
    return (u.protocol === "https:" || u.protocol === "http:") && (u.hostname.includes(".") || u.hostname === "localhost");
  } catch {
    return false;
  }
}

function totpValid(secret) {
  if (!secret) return true;
  try {
    call("totp", { secret, time: 0 });
    return true;
  } catch {
    return false;
  }
}

const portValid = (p) => !p || (/^\d{1,5}$/.test(p) && Number(p) >= 1 && Number(p) <= 65535);

/** Données de départ : valeurs par défaut du type, puis celles de l'élément (aucun champ inconnu perdu). */
function startData(source, kind) {
  const empty = V.emptyItem(source?.kind || kind);
  const d = structuredClone(source || empty);
  for (const k of ["card", "identity", "ssh"]) d[k] = { ...empty[k], ...(d[k] || {}) };
  for (const [k, v] of Object.entries(empty)) if (!(k in d)) d[k] = structuredClone(v);
  return d;
}

// ------------------------------------------------------------ Éditeur

export function renderEditor({ item = null, kind = "login", collectionId = null, template = null, regenerate = false, env }) {
  const isNew = !item;
  const data = startData(item?.data || template, KINDS.includes(kind) ? kind : "login");
  if (template) {
    // Copie : nouvel élément, sans historique ni pièces jointes (propres à l'original).
    data.name = t("vault.editor.copy_name", { name: template.name || "" });
    data.password_history = [];
    data.attachments = [];
  }
  let currentKind = data.kind;
  const cleanups = [];
  let committed = false;
  let saving = null;

  // ---------------------------------------------------------- Champs communs
  const nameField = field({ label: t("vault.editor.name"), input: textInput({ name: "name", value: data.name, maxlength: 200, required: true, autocomplete: "off" }) });
  const nameInput = fieldInput(nameField);

  const targets = writableCollections();
  const startCollection = item?.collection_id || defaultCollection(collectionId);
  const colSelect = selectInput({
    name: "collection",
    options: targets.map((c) => ({ value: c.id, label: collectionLabel(c) })),
    value: startCollection,
  });
  const audience = h("div", {});
  // Impact du changement de coffre : affiché, et annoncé par #status (A1).
  const impact = h("div");
  const colField = field({ label: t("vault.editor.collection"), input: colSelect, control: h("div", { class: "l-stack", "data-gap": "2" }, colSelect, audience, impact) });
  let impactSeq = 0;
  const paintAudience = async () => {
    const c = collectionOf(colSelect.value);
    audience.replaceChildren(audienceLine({ collection: { name: collectionLabel(c), personal: c?.personal }, members: c?.member_count || 0 }));
    impact.replaceChildren();
    if (!c || c.personal || colSelect.value === startCollection) return;
    const my = ++impactSeq;
    let names = null;
    try {
      const members = await api("GET", `/collections/${encodeURIComponent(c.id)}/members`);
      names = (members || []).filter((m) => m.user_id !== V.state.profile?.id).map((m) => m.name || m.email);
    } catch { /* repli sur le nombre de membres */ }
    if (my !== impactSeq) return;
    const text = names && names.length
      ? t("vault.editor.impact_names", { vault: collectionLabel(c), names: joinNames(names) })
      : plural("vault.editor.impact_count", Math.max(0, (c.member_count || 1) - 1), { vault: collectionLabel(c) });
    impact.replaceChildren(h("div", { class: "c-alert", "data-tone": "warn" }, icon("users"), h("p", {}, text)));
    announce(text);
  };
  colSelect.addEventListener("change", paintAudience);
  paintAudience();

  const notesField = field({ label: t("vault.field.notes"), input: textArea({ name: "notes", value: data.notes, rows: 4 }) });
  const notesBox = h("details", { class: "c-card", open: !!data.notes || data.kind === "note" }, h("summary", {}, t("vault.field.notes")), notesField);

  // ---------------------------------------------------------- Plus d'options
  const customRows = h("div", { class: "l-stack", "data-gap": "2" });
  const customs = [];
  const addCustom = (f = { label: "", value: "", hidden: false }) => {
    const label = textInput({ value: f.label, autocomplete: "off" });
    label.setAttribute("aria-label", t("vault.editor.custom_label"));
    label.placeholder = t("vault.editor.custom_label");
    const value = textInput({ value: f.value, type: f.hidden ? "password" : "text", autocomplete: "off" });
    value.setAttribute("aria-label", t("vault.editor.custom_value"));
    value.placeholder = t("vault.editor.custom_value");
    const hidden = h("input", { type: "checkbox", checked: !!f.hidden });
    hidden.addEventListener("change", () => { value.type = hidden.checked ? "password" : "text"; });
    const entry = { label, value, hidden };
    const row = h("div", { class: "l-cluster" }, label, value, h("label", { class: "l-cluster" }, hidden, t("vault.editor.custom_secret")),
      iconButton({ icon: "close", label: t("vault.editor.custom_remove"), onClick: () => { row.remove(); customs.splice(customs.indexOf(entry), 1); } }));
    customs.push(entry);
    customRows.append(row);
    return entry;
  };
  (data.fields || []).forEach(addCustom);
  let tags = [...(data.tags || [])];
  const tagsField = chipsInput({ label: t("vault.editor.tags"), values: tags, onChange: (v) => { tags = v; }, max: 20 });
  const expiresInput = textInput({ name: "expires", type: "date", value: data.expires_at ? new Date(data.expires_at * 1000).toISOString().slice(0, 10) : "" });
  const moreOpen = (data.fields || []).length > 0 || tags.length > 0 || !!data.expires_at;
  const more = h("details", { class: "c-card", open: moreOpen },
    h("summary", {}, t("vault.editor.more")),
    h("div", { class: "l-stack", "data-gap": "3" },
      h("fieldset", { class: "l-stack", "data-gap": "2" }, h("legend", {}, t("vault.editor.custom_fields")), customRows,
        h("div", {}, button({ label: t("vault.editor.custom_add"), icon: "plus", variant: "quiet", onClick: () => focusSafely(addCustom().label) }))),
      tagsField,
      field({ label: t("vault.editor.expires"), help: t("vault.editor.expires_help"), input: expiresInput }),
      isNew ? null : h("p", { class: "u-muted" }, icon("attachment", { size: "sm" }), " ", t("vault.editor.attachments_hint"))));

  // ---------------------------------------------------------- Sections par type
  const sections = {};
  const section = (k) => (sections[k] ??= buildSection(k, data, { isNew, regenerate, env }));
  const kindBox = h("div", { class: "l-stack", "data-gap": "3" });
  const showKind = (k) => {
    currentKind = k;
    kindBox.replaceChildren(section(k).el);
    if (k === "note") notesBox.open = true;
    title.textContent = t(isNew ? `vault.editor.title_new.${k}` : "vault.editor.title_edit");
  };

  const chooser = isNew && !template ? h("div", { class: "l-stack", "data-gap": "2" },
    radioCards({
      legend: t("vault.editor.kind_question"), name: "kind", value: currentKind,
      options: KINDS.map((k) => ({ value: k, label: t(`vault.editor.kind.${k}`), icon: KIND_ICONS[k] })),
      onChange: (k) => showKind(k),
    }),
    h("a", { href: "#/parametres/donnees" }, t("vault.editor.import_many"), " ", icon("chevron-right", { size: "sm" }))) : null;

  // ---------------------------------------------------------- Barre et formulaire
  const title = h("h1", { class: "c-panel__title", tabindex: "-1" });
  const banner = h("div", { class: "l-stack", "data-gap": "2" });
  const saveBtn = button({ label: t("common.action.save"), icon: "check", variant: "primary", busyLabel: t("common.state.saving"), onClick: () => save() });
  const cancelBtn = button({ label: t("common.action.cancel"), onClick: () => cancel() });
  if (offline()) setDisabled(saveBtn, true, t("vault.offline_reason"));
  if (!targets.length) setDisabled(saveBtn, true, t("vault.editor.no_target"));

  const form = h("form", { class: "l-stack", "data-gap": "4", novalidate: true, onsubmit: (e) => { e.preventDefault(); save(); } },
    chooser, nameField, kindBox, colField, notesBox, more,
    h("p", { class: "u-muted" }, t("vault.editor.hotkey_hint")));
  showKind(currentKind);

  const el = h("section", { class: "l-stack", "data-gap": "0" },
    h("header", { class: "c-panel__head" }, title, cancelBtn, saveBtn),
    h("div", { class: "c-panel__body" }, banner, targets.length ? null : h("div", { class: "c-alert", "data-tone": "warn" }, icon("warn"), h("p", {}, t("vault.editor.no_target"))), form));

  // ---------------------------------------------------------- Lecture du formulaire
  function collect() {
    const out = structuredClone(data);
    out.kind = currentKind;
    out.name = nameInput.value.trim();
    out.notes = fieldInput(notesField).value;
    out.fields = customs.map((f) => ({ label: f.label.value.trim(), value: f.value.value, hidden: f.hidden.checked })).filter((f) => f.label || f.value);
    out.tags = [...tags];
    out.expires_at = expiresInput.value ? Math.floor(new Date(`${expiresInput.value}T12:00:00`).getTime() / 1000) : 0;
    section(currentKind).read(out);
    // Les favoris sont personnels : un élément neuf ne porte plus `favorite`.
    if (isNew) delete out.favorite;
    return out;
  }
  // Empreinte de la saisie, sans les dates calculées à chaque lecture (historique du mot de passe).
  const snapshot = () => JSON.stringify([{ ...collect(), password_changed_at: 0, password_history: [] }, colSelect.value]);
  const initial = snapshot();
  // ?regenerer=1 (« Corriger » du bilan) : nouveau mot de passe proposé, saisie modifiée.
  if (regenerate && !isNew && sections[currentKind]?.regenerate) sections[currentKind].regenerate();

  const isDirty = () => !committed && snapshot() !== initial;
  const guard = dirtyGuard(isDirty, { onSave: () => save() });
  cleanups.push(() => guard.destroy());

  // ---------------------------------------------------------- Validation
  function validate(out) {
    const problems = [];
    const check = (fieldEl, ok, key) => {
      fieldError(fieldEl, ok ? null : t(key), { announce: false });
      if (!ok) problems.push(fieldEl);
    };
    check(nameField, !!out.name, "vault.editor.error.name");
    section(currentKind).validate?.(check);
    if (problems.length) {
      focusSafely(fieldInput(problems[0]));
      notify({ text: t("vault.editor.error.summary"), tone: "danger" });
    }
    return problems.length === 0;
  }

  // ---------------------------------------------------------- Enregistrer
  function showError(e) {
    banner.replaceChildren(h("div", { class: "c-alert", "data-tone": "danger", role: "alert" }, icon("error"), h("p", {}, errorText(e))));
  }

  function showConflict(out, target) {
    const fresh = V.state.items.get(item.id);
    const when = fresh ? relTime(fresh.updated_at) : null;
    const theirs = button({ label: t("vault.editor.conflict_view"), onClick: () => theirVersion(fresh) });
    const mine = button({
      label: t("vault.editor.conflict_keep"), variant: "primary", busyLabel: t("common.state.saving"),
      onClick: async () => {
        if (!fresh) return;
        try {
          await V.updateItem(fresh, out, target);
        } catch (e) {
          showError(e);
          return;
        }
        await done(item.id, false);
      },
    });
    banner.replaceChildren(h("div", { class: "c-alert", "data-tone": "warn", role: "alert" }, icon("warn"),
      h("div", { class: "l-stack", "data-gap": "2" },
        h("p", {}, when ? t("vault.editor.conflict_when", { when }) : t("vault.editor.conflict")),
        h("div", { class: "l-cluster" }, fresh?.data ? theirs : null, fresh ? mine : null))));
  }

  async function done(id, created) {
    committed = true;
    notify({ text: t(created ? "vault.editor.saved_new" : "vault.editor.saved"), tone: "ok" });
    await env.reload();
    env.navigate(`/element/${encodeURIComponent(id)}`, { replace: true });
  }

  function save() {
    if (saving) return saving;
    saving = (async () => {
      banner.replaceChildren();
      const out = collect();
      if (!validate(out)) return false;
      const target = colSelect.value;
      if (!target) {
        showError({ code: "no_target", message: t("vault.editor.no_target") });
        return false;
      }
      try {
        if (isNew) {
          const id = await V.createItem(target, out);
          await done(id, true);
        } else {
          await V.updateItem(item, out, target);
          await done(item.id, false);
        }
        return true;
      } catch (e) {
        if (!isNew && e?.status === 409 && e.code !== "rekey_required") {
          try { await V.sync(); } catch { /* le message de conflit suffit */ }
          showConflict(out, target);
        } else {
          showError(e);
        }
        notify({ text: errorText(e), tone: "danger" });
        return false;
      }
    })();
    saving.finally(() => { saving = null; });
    return saving;
  }

  async function cancel() {
    // « Enregistrer » dans la garde a déjà enregistré et affiché la fiche.
    if ((await guard.confirmLeave()) !== "discard") return;
    committed = true;
    env.navigate(isNew ? env.listPath() : `/element/${encodeURIComponent(item.id)}`, { replace: true });
  }

  // Échap : même garde qu'« Annuler » (sauf dans une fenêtre ou un menu ouvert par-dessus).
  el.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || e.defaultPrevented) return;
    if (e.target.closest?.("[role=menu], .c-popover")) return;
    e.preventDefault();
    cancel();
  });
  cleanups.push(hotkeys.register({ id: "editor.save", run: () => busyWhile(saveBtn, save(), t("common.state.saving")) }));
  cleanups.push(hotkeys.enterScope("editor"));

  return {
    el,
    isDirty,
    save,
    focus() {
      // Focus sur « Nom » (vide ou non) ; en correction, sur le mot de passe proposé.
      if (regenerate && sections[currentKind]?.passwordInput) focusSafely(sections[currentKind].passwordInput);
      else focusSafely(nameInput);
    },
    destroy() {
      while (cleanups.length) cleanups.pop()();
      for (const s of Object.values(sections)) s.destroy?.();
    },
  };
}

function joinNames(names) {
  if (names.length <= 1) return names.join("");
  if (names.length > 4) return t("vault.editor.names_more", { first: names.slice(0, 3).join(", "), n: names.length - 3 });
  return t("vault.editor.names_and", { first: names.slice(0, -1).join(", "), last: names.at(-1) });
}

/** Version enregistrée par quelqu'un d'autre (lecture seule, sans quitter l'éditeur). */
function theirVersion(fresh) {
  const d = fresh.data;
  const rows = [
    secretRow({ label: t("vault.editor.name"), value: d.name, kind: "text", masked: false }),
    d.username ? secretRow({ label: t("common.glossary.username"), value: d.username, kind: "username", masked: false }) : null,
    d.password ? secretRow({ label: t("common.glossary.password"), value: d.password, kind: "password", masked: true, mono: true }) : null,
    (d.urls || []).length ? secretRow({ label: t("vault.field.site"), value: d.urls.join(" "), kind: "text", masked: false }) : null,
    d.notes ? secretRow({ label: t("vault.field.notes"), value: d.notes, kind: "text", masked: false }) : null,
  ].filter(Boolean);
  dialog({
    title: t("vault.editor.conflict_theirs_title"),
    description: t("vault.editor.conflict_theirs_text", { when: fmtDate(fresh.updated_at) }),
    body: h("div", { class: "c-card" }, rows),
    actions: [{ label: t("common.action.close"), variant: "primary" }],
  });
}

// ------------------------------------------------------------ Sections

function buildSection(kind, data, opts) {
  switch (kind) {
    case "login": return loginSection(data, opts);
    case "card": return cardSection(data);
    case "identity": return identitySection(data);
    case "ssh": return sshSection(data, opts);
    default: return { el: h("div", {}), read() {} };
  }
}

/** Champ texte simple dans un field(). */
function textField(label, value, { name, mono, help, inputmode, autocomplete = "off", type = "text", multiline = false, rows = 3 } = {}) {
  const input = multiline ? textArea({ name, value, rows }) : textInput({ name, value, type, autocomplete, inputmode, spellcheck: false });
  if (mono) input.classList.add("u-mono");
  return field({ label, help, input });
}

const val = (f) => fieldInput(f).value;

/** Bouton « Générer » : panneau du générateur s'il est livré, sinon génération locale. */
async function openGenerator(input, env) {
  try {
    const mod = await import("../tools/generator.js");
    if (typeof mod.openGeneratorPanel === "function") {
      mod.openGeneratorPanel({
        anchor: document.activeElement,
        settings: S,
        onUse: (value) => {
          input.value = value;
          input.dispatchEvent(new Event("input", { bubbles: true }));
        },
      });
      return undefined;
    }
  } catch { /* module absent : génération locale */ }
  return generatePassword();
}

function loginSection(data, { isNew, env }) {
  const urls = data.urls?.length ? data.urls : [""];
  const urlFields = [];
  const urlBox = h("div", { class: "l-stack", "data-gap": "2" });
  const addUrl = (value = "") => {
    const f = textField(urlFields.length ? t("vault.editor.site_other") : t("vault.editor.site"), value, { name: `url${urlFields.length}`, inputmode: "url" });
    urlFields.push(f);
    urlBox.append(f);
    return f;
  };
  urls.forEach((u) => addUrl(u));
  const addUrlBtn = button({ label: t("vault.editor.site_add"), icon: "plus", variant: "quiet", onClick: () => focusSafely(fieldInput(addUrl())) });

  const userField = textField(t("common.glossary.username"), data.username, { name: "username", autocomplete: "off" });
  const pre = isNew && !data.password ? generatePassword() : "";
  let pwInput = null;
  const pwField = passwordField({
    label: t("common.glossary.password"), name: "password", value: data.password || pre, autocomplete: "new-password",
    withStrength: true, withGenerate: true, onGenerate: () => openGenerator(pwInput, env),
  });
  pwInput = fieldInput(pwField);
  const mention = h("div", { class: "c-alert", "data-tone": "info", hidden: !pre }, icon("info"),
    h("div", { class: "l-stack", "data-gap": "2" }, h("p", {}, t("vault.editor.generated_mention")),
      h("div", {}, button({
        label: t("vault.editor.type_current"), variant: "quiet",
        onClick: () => {
          pwInput.value = "";
          pwInput.dispatchEvent(new Event("input", { bubbles: true }));
          mention.hidden = true;
          focusSafely(pwInput);
        },
      }))));
  const regenMention = h("div", { class: "c-alert", "data-tone": "info", hidden: true }, icon("info"), h("p", {}, t("vault.editor.regenerated_mention")));

  // Code de vérification
  const totpField = textField(t("vault.editor.totp_key"), data.totp, { name: "totp", mono: true, help: t("vault.editor.totp_help") });
  const totpInput = fieldInput(totpField);
  // Code courant affiché pour vérifier la clé, jamais annoncé (règle A2).
  const preview = h("p", { class: "u-muted" });
  const paintPreview = () => {
    const s = totpInput.value.trim();
    if (!s) return preview.replaceChildren();
    try {
      const r = call("totp", { secret: s, time: Math.floor(Date.now() / 1000) });
      preview.textContent = t("vault.editor.totp_current", { code: r.code });
      fieldError(totpField, null);
    } catch {
      preview.replaceChildren();
    }
  };
  totpInput.addEventListener("input", paintPreview);
  paintPreview();
  const setTotp = (value) => {
    totpInput.value = value;
    totpInput.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const qrZone = h("div", { hidden: true }, qrImport({ onResult: (uri) => { setTotp(uri); qrZone.hidden = true; focusSafely(totpInput); } }));
  const scanBtn = button({ label: t("common.glossary.scan_qr"), icon: "qr", onClick: () => { qrZone.hidden = !qrZone.hidden; } });
  const pasteBtn = button({
    label: t("common.glossary.paste_key"), icon: "copy",
    onClick: async () => {
      try {
        const text = (await navigator.clipboard.readText()).trim();
        if (text) {
          setTotp(text);
          return;
        }
      } catch { /* lecture refusée par le navigateur */ }
      focusSafely(totpInput);
      notify({ text: t("vault.editor.paste_manual"), tone: "info" });
    },
  });
  const fill = h("input", { type: "checkbox", name: "totp_fill", checked: !!data.totp_fill });
  const totpBox = h("details", { class: "c-card", open: !!data.totp },
    h("summary", {}, t("common.glossary.verification_code")),
    h("div", { class: "l-stack", "data-gap": "3" },
      h("div", { class: "l-cluster" }, scanBtn, pasteBtn), qrZone, totpField, preview,
      h("label", { class: "l-cluster" }, fill, t("vault.editor.totp_fill"))));

  return {
    el: h("div", { class: "l-stack", "data-gap": "3" }, urlBox, h("div", {}, addUrlBtn), userField, pwField, mention, regenMention, totpBox),
    passwordInput: pwInput,
    regenerate() {
      const next = generatePassword();
      if (!next) return;
      pwInput.value = next;
      pwInput.dispatchEvent(new Event("input", { bubbles: true }));
      regenMention.hidden = false;
    },
    read(out) {
      out.urls = urlFields.map((f) => val(f).trim()).filter(Boolean);
      out.username = val(userField).trim();
      out.totp = totpInput.value.trim();
      out.totp_fill = fill.checked;
      Object.assign(out, V.applyPassword(out, pwInput.value));
    },
    validate(check) {
      urlFields.forEach((f) => check(f, looksLikeSite(val(f)), "vault.editor.error.site"));
      check(totpField, totpValid(totpInput.value.trim()), "vault.editor.error.totp");
    },
  };
}

function cardSection(data) {
  const c = data.card || {};
  const f = {
    holder: textField(t("vault.field.card_holder"), c.holder, { name: "card_holder", autocomplete: "off" }),
    number: textField(t("vault.field.card_number"), c.number, { name: "card_number", mono: true, inputmode: "numeric" }),
    expiry: textField(t("vault.field.card_expiry"), c.expiry, { name: "card_expiry", help: t("vault.editor.card_expiry_help"), inputmode: "numeric" }),
    cvv: textField(t("vault.field.card_cvv"), c.cvv, { name: "card_cvv", type: "password", inputmode: "numeric" }),
    pin: textField(t("vault.field.card_pin"), c.pin, { name: "card_pin", type: "password", inputmode: "numeric" }),
  };
  return {
    el: h("div", { class: "l-stack", "data-gap": "3" }, Object.values(f)),
    read(out) {
      out.card = { ...out.card, ...Object.fromEntries(Object.entries(f).map(([k, x]) => [k, val(x).trim()])) };
    },
  };
}

function identitySection(data) {
  const i = data.identity || {};
  const f = {
    first_name: textField(t("vault.field.first_name"), i.first_name, { name: "first_name" }),
    last_name: textField(t("vault.field.last_name"), i.last_name, { name: "last_name" }),
    email: textField(t("vault.field.email"), i.email, { name: "email", type: "email" }),
    phone: textField(t("vault.field.phone"), i.phone, { name: "phone", type: "tel" }),
    company: textField(t("vault.field.company"), i.company, { name: "company" }),
    document_number: textField(t("vault.field.document_number"), i.document_number, { name: "document_number" }),
    address: textField(t("vault.field.address"), i.address, { name: "address", multiline: true, rows: 2 }),
  };
  return {
    el: h("div", { class: "l-stack", "data-gap": "3" }, Object.values(f)),
    read(out) {
      out.identity = { ...out.identity, ...Object.fromEntries(Object.entries(f).map(([k, x]) => [k, val(x)])) };
    },
  };
}

function sshSection(data, { env }) {
  const s = data.ssh || {};
  const host = textField(t("vault.field.ssh_host"), s.host, { name: "ssh_host", mono: true, help: t("vault.editor.ssh_host_help") });
  const user = textField(t("common.glossary.username"), s.username, { name: "ssh_username" });
  // Port gardé en texte (contrat C3.2) : « 22 », ou vide.
  const port = textField(t("vault.field.ssh_port"), s.port, { name: "ssh_port", inputmode: "numeric", help: t("vault.editor.ssh_port_help") });
  let pwInput = null;
  const pw = passwordField({
    label: t("vault.field.ssh_password"), name: "ssh_password", value: s.password, autocomplete: "new-password",
    withStrength: true, withGenerate: true, onGenerate: () => openGenerator(pwInput, env),
  });
  pwInput = fieldInput(pw);
  const priv = textField(t("vault.field.ssh_private_key"), s.private_key, { name: "ssh_private_key", mono: true, multiline: true, rows: 6 });
  const pub = textField(t("vault.field.ssh_public_key"), s.public_key, { name: "ssh_public_key", mono: true, multiline: true, rows: 2 });
  const phrase = passwordField({ label: t("vault.field.ssh_passphrase"), name: "ssh_passphrase", value: s.passphrase, autocomplete: "off" });
  return {
    el: h("div", { class: "l-stack", "data-gap": "3" }, host, user, port, pw, priv, pub, phrase),
    passwordInput: pwInput,
    read(out) {
      out.ssh = {
        ...out.ssh,
        host: val(host).trim(), username: val(user).trim(), port: val(port).trim(), password: pwInput.value,
        private_key: val(priv), public_key: val(pub).trim(), passphrase: fieldInput(phrase).value,
      };
    },
    validate(check) {
      check(port, portValid(val(port).trim()), "vault.editor.error.port");
    },
  };
}
