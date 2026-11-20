// Paramètres › Importer ou exporter (cahier §3.3.8, écarts #9, #10, #36).
//
// Import : fichier CSV (tableur ou autre gestionnaire), sauvegarde chiffrée
// Locksy, base KeePass ou export Bitwarden (déchiffrés hors du fil principal
// par import-worker.js). Lecture et chiffrement dans le navigateur ; aperçu
// avant envoi (nombre d'éléments, séparateur détecté, erreurs ligne par
// ligne, avertissements, coffre de destination de chaque dossier) ; envoi par
// lots de 500 avec reprise au lot refusé.
//
// Export : sauvegarde chiffrée par un mot de passe d'export (au moins
// export.min_password_length caractères) ou CSV en clair ; confirmation
// d'identité (« vault.export ») et trace serveur (POST /me/export) AVANT de
// produire le fichier. Serveur sans la route (404) : l'export continue ;
// export.enabled = false : section désactivée avec la raison.

import {
  t, plural, has, h, clear, uid, button, field, fieldError, fieldInput, selectInput, radioCards, passwordField,
  alertCard, notify, confirm, dataTable, errorText, fmtNumber, fmtBytes,
} from "../../ui/index.js";
import { api, saveBlob, withReauth } from "../../api.js";
import { call, nextFrame } from "../../wasm.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";
import { importFile, importInBatches, normalizeFolder } from "../../import.js";

const MIB = 1024 * 1024;
const PREVIEW_ROWS = 10;
const SEPARATOR_NAMES = Object.freeze({ ",": "comma", ";": "semicolon", "\t": "tab" });
const ACCEPT = Object.freeze({
  csv: ".csv,.txt,text/csv,text/plain",
  locksy: ".json,application/json",
  kdbx: ".kdbx",
  bitwarden_json: ".json,application/json",
});
const FORMAT_LABELS = Object.freeze({
  csv: "settings_user.import.format_csv",
  locksy: "settings_user.import.format_locksy",
  kdbx: "import.format.kdbx",
  bitwarden_json: "import.format.bitwarden_json",
});
const FORMAT_HINTS = Object.freeze({
  csv: "settings_user.import.format_csv_hint",
  locksy: "settings_user.import.format_locksy_hint",
  kdbx: "import.format.kdbx_hint",
  bitwarden_json: "import.format.bitwarden_json_hint",
});
const WITH_PASSWORD = new Set(["locksy", "kdbx", "bitwarden_json"]);
const EXPORT_SCOPES = Object.freeze(["all", "personal", "shared"]);

const num = (v, fallback) => (Number.isFinite(Number(v)) && v !== null && v !== "" ? Number(v) : fallback);

/** Texte comparable (noms de coffres et de dossiers) : sans accents ni casse. */
const fold = (s) => String(s ?? "").normalize("NFD").replace(/\p{M}+/gu, "").toLowerCase().trim();

/** Libellé d'une erreur d'import (codes d'import.js, du worker ou du noyau). */
export function importErrorText(err) {
  const code = err?.code;
  if (code && has(`settings_user.import.error.${code}`)) return t(`settings_user.import.error.${code}`);
  if (code && has(`import.error.${code}`)) return t(`import.error.${code}`);
  if (err && typeof err.status === "number") return errorText(err);
  return t("settings_user.import.error.generic");
}

/** Coffres où la personne peut ajouter des éléments. */
export function writableVaults(collections = V.state.collections.values(), settings = S) {
  const personalOn = settings.effective("vault.personal_enabled").value !== false;
  return [...collections].filter((c) => (c.personal ? personalOn : ["manager", "editor"].includes(c.role)));
}

const vaultName = (c) => (c.personal ? t("common.glossary.personal_vault") : c.name);

/** Création de coffres partagés permise à cette personne ? */
function canCreateVaults(ctx, settings) {
  const role = ctx.role ?? V.state.profile?.role;
  return role === "owner" || role === "admin" || settings.effective("vault.users_can_create_shared").value !== false;
}

/**
 * Plan d'import : coffre de chaque élément selon le traitement des dossiers.
 * mode "tags" : tout va dans `targetId`, le chemin du dossier devient des
 * étiquettes ; mode "vaults" : le premier niveau du dossier désigne un coffre
 * (existant du même nom, sinon créé si permis, sinon coffre de destination
 * avec le dossier en étiquettes). Renvoie { entries: [{ data, vault, key,
 * favorite }], folders: [{ folder, vault: { id?, name, created } }] } ;
 * vault.id absent = coffre à créer. Les favoris sont personnels (préférences
 * chiffrées) : `favorite` est retiré de l'élément et rendu à part.
 */
export function planImport(items, { mode, targetId, vaults, allowCreate }) {
  const byName = new Map(vaults.filter((c) => !c.personal).map((c) => [fold(c.name), c]));
  const target = vaults.find((c) => c.id === targetId);
  const folders = new Map();
  const entries = items.map((it) => {
    const path = normalizeFolder(it.folder);
    const { favorite, ...rest } = it.data || {};
    const data = { ...rest, tags: [...(rest.tags || [])] };
    let vault = { id: targetId, name: target ? vaultName(target) : "", created: false };
    let asTags = mode === "tags";
    if (mode === "vaults" && path) {
      const top = path.split("/")[0];
      const existing = byName.get(fold(top));
      if (existing) vault = { id: existing.id, name: existing.name, created: false };
      else if (allowCreate) vault = { id: undefined, name: top, created: true };
      else asTags = true;
      if (!asTags && path.includes("/")) data.tags.unshift(...path.split("/").slice(1));
    }
    if (asTags && path) data.tags.unshift(...path.split("/"));
    data.tags = [...new Set(data.tags.filter(Boolean))];
    const key = vault.id ?? `nouveau:${fold(vault.name)}`;
    if (path && !folders.has(path)) folders.set(path, { folder: path, vault, key });
    return { data, vault, key, favorite: favorite === true };
  });
  return { entries, folders: [...folders.values()] };
}

/** Éléments exportables (déchiffrés, hors corbeille) selon la portée. */
export function exportItems(scope, items = V.state.items.values(), collections = V.state.collections) {
  return [...items].filter((i) => {
    if (!i?.data || i.deleted_at) return false;
    const personal = !!collections.get(i.collection_id)?.personal;
    return scope === "personal" ? personal : scope === "shared" ? !personal : true;
  });
}

/** CSV de migration (séparateur virgule, BOM pour les tableurs). */
export function exportCsv(items, collections = V.state.collections) {
  const esc = (v) => `"${String(v ?? "").replace(/"/g, "\"\"")}"`;
  const lines = [["name", "url", "username", "password", "totp", "notes", "folder", "tags"].join(",")];
  for (const i of items) {
    const col = collections.get(i.collection_id);
    const folder = col ? vaultName(col) : "";
    lines.push([i.data.name, (i.data.urls || []).join("\n"), i.data.username, i.data.password, i.data.totp, i.data.notes, folder, (i.data.tags || []).join(", ")].map(esc).join(","));
  }
  return `﻿${lines.join("\r\n")}\r\n`;
}

const today = () => new Date().toISOString().slice(0, 10);

// ------------------------------------------------------------ Import

function importSection(ctx, settings) {
  const vaults = writableVaults(undefined, settings);
  const maxMib = num(settings.effective("import.max_file_mib").value, 20);
  const formatId = uid("format");
  const root = h("section", { class: "c-card l-stack", "data-gap": "4", "aria-labelledby": formatId });
  if (!vaults.length) {
    clear(root, h("h2", { id: formatId }, t("settings_user.import.heading")),
      alertCard({ tone: "info", text: t("settings_user.import.no_vault") }));
    return root;
  }

  let format = "csv";
  let result = null; // dernier fichier lu
  let run = null; // import en cours ou interrompu
  let controller = null;

  const fileInput = h("input", { type: "file", class: "c-input", accept: ACCEPT.csv });
  const fileField = field({ label: t("settings_user.import.file"), input: fileInput, help: t("settings_user.import.file_help", { max: fmtBytes(maxMib * MIB) }) });
  const password = passwordField({ label: t("import.field.password"), autocomplete: "off", capsLockHint: true });
  const keyInput = h("input", { type: "file", class: "c-input" });
  const keyField = field({ label: t("import.field.keyfile"), input: keyInput, optional: true });
  const hint = h("p", { class: "u-muted" });
  const progress = h("p", { class: "u-muted", hidden: true });
  const preview = h("div", { class: "l-stack", "data-gap": "4" });

  const formatPicker = radioCards({
    legend: t("settings_user.import.format"),
    value: format,
    options: Object.keys(FORMAT_LABELS).map((f) => ({ value: f, label: t(FORMAT_LABELS[f]) })),
    onChange: (v) => {
      format = v;
      fileInput.accept = ACCEPT[v];
      paintFormat();
      resetPreview();
    },
  });

  function paintFormat() {
    hint.textContent = t(FORMAT_HINTS[format]);
    password.hidden = !WITH_PASSWORD.has(format);
    keyField.hidden = format !== "kdbx";
  }

  function resetPreview() {
    result = null;
    run = null;
    clear(preview);
    progress.hidden = true;
  }

  fileInput.addEventListener("change", resetPreview);

  const read = button({
    label: t("settings_user.import.read"), icon: "upload", variant: "primary", busyLabel: t("settings_user.import.reading"),
    onClick: async () => {
      resetPreview();
      fieldError(fileField, null, { announce: false });
      fieldError(password, null, { announce: false });
      const file = fileInput.files?.[0];
      if (!file) return fieldError(fileField, t("settings_user.import.error.no_file"));
      if (file.size > maxMib * MIB) return fieldError(fileField, t("settings_user.import.file_too_large", { max: fmtBytes(maxMib * MIB) }));
      const secret = fieldInput(password).value;
      if (WITH_PASSWORD.has(format) && format !== "bitwarden_json" && !secret && !keyInput.files?.[0]) {
        return fieldError(password, t("settings_user.import.password_required"));
      }
      controller = new AbortController();
      progress.hidden = false;
      progress.textContent = t("import.progress.parse");
      await nextFrame();
      try {
        result = await importFile(file, {
          format,
          password: secret,
          keyfile: keyInput.files?.[0],
          maxBytes: maxMib * MIB,
          folderMode: "vaults",
          signal: controller.signal,
          unprotect: (pw, text) => call("unprotect_export", { password: pw, data: text }),
          onProgress: (phase) => {
            if (has(`import.progress.${phase}`)) progress.textContent = t(`import.progress.${phase}`);
          },
        });
      } catch (e) {
        progress.hidden = true;
        const message = importErrorText(e);
        if (e?.code === "wrong_password" || e?.code === "keyfile_required") fieldError(password, message);
        else clear(preview, alertCard({ tone: "danger", text: message }));
        return;
      } finally {
        controller = null;
      }
      progress.hidden = true;
      fieldInput(password).value = "";
      showPreview();
    },
  });

  /** Aperçu : nombre, séparateur, erreurs ligne par ligne, avertissements, coffres. */
  function showPreview() {
    const items = result.items;
    const errors = result.errors || [];
    const hasFolders = items.some((it) => normalizeFolder(it.folder));
    const allowCreate = canCreateVaults(ctx, settings);
    let mode = "tags";
    let targetId = settings.prefs?.().ui?.default_collection;
    if (!vaults.some((c) => c.id === targetId)) targetId = (vaults.find((c) => c.personal) || vaults[0]).id;

    const target = selectInput({ value: targetId, options: vaults.map((c) => ({ value: c.id, label: vaultName(c) })) });
    const targetField = field({ label: t("settings_user.import.target"), input: target });
    const foldersEl = h("div", { class: "l-stack", "data-gap": "2" });
    const submitEl = h("div", { class: "l-cluster" });

    const planNow = () => planImport(items, { mode, targetId: target.value, vaults, allowCreate });

    function paintPlan() {
      const plan = planNow();
      if (hasFolders && mode === "vaults") {
        clear(foldersEl, dataTable({
          caption: plural("settings_user.import.folders_caption", plan.folders.length),
          rows: plan.folders,
          rowKey: (f) => f.folder,
          rowLabel: (f) => f.folder,
          columns: [
            { key: "folder", label: t("settings_user.import.col_folder"), render: (f) => f.folder },
            {
              key: "vault", label: t("settings_user.import.col_vault"),
              render: (f) => (f.vault.created ? t("settings_user.import.vault_new", { name: f.vault.name }) : f.vault.name),
            },
          ],
        }).el);
      } else clear(foldersEl);
      clear(submitEl, items.length ? button({
        label: plural("settings_user.import.submit", items.length), icon: "upload", variant: "primary",
        busyLabel: t("settings_user.import.importing"),
        onClick: () => startImport(plan),
      }) : null);
    }

    target.addEventListener("change", paintPlan);
    const folderChoice = hasFolders ? radioCards({
      legend: t("settings_user.import.folders"),
      value: mode,
      options: [
        { value: "tags", label: t("settings_user.import.folders_tags"), description: t("settings_user.import.folders_tags_help") },
        {
          value: "vaults", label: t("settings_user.import.folders_vaults"),
          description: t(allowCreate ? "settings_user.import.folders_vaults_help" : "settings_user.import.folders_vaults_existing"),
        },
      ],
      onChange: (v) => {
        mode = v;
        paintPlan();
      },
    }) : null;

    const warnings = summarizeWarnings(result.warnings || []);
    clear(preview,
      h("h3", {}, t("settings_user.import.preview")),
      items.length
        ? alertCard({ tone: errors.length ? "warn" : "ok", text: plural("settings_user.import.ready", items.length) })
        : alertCard({ tone: "danger", text: t("settings_user.import.nothing") }),
      result.separator ? h("p", { class: "u-muted" }, t("settings_user.import.separator", { name: t(`settings_user.import.separator_${SEPARATOR_NAMES[result.separator] || "comma"}`) })) : null,
      errors.length ? errorReport(errors) : null,
      warnings.length ? h("ul", { class: "l-stack", "data-gap": "1" }, warnings.map((w) => h("li", {}, w))) : null,
      items.length ? previewTable(items) : null,
      items.length ? targetField : null,
      folderChoice,
      foldersEl,
      submitEl);
    paintPlan();
    preview.querySelector("h3")?.setAttribute("tabindex", "-1");
    preview.querySelector("h3")?.focus();
  }

  /** Envoi : coffres à créer d'abord, puis les lots de chaque coffre ; reprise possible. */
  async function startImport(plan) {
    run ??= { plan, created: new Map(), group: 0, start: 0, done: 0, favorites: [] };
    const total = run.plan.entries.length;
    progress.hidden = false;
    const say = () => { progress.textContent = t("settings_user.import.progress", { done: fmtNumber(run.done), total: fmtNumber(total) }); };
    say();
    try {
      for (const f of run.plan.folders) {
        if (f.vault.created && !run.created.has(f.key)) {
          run.created.set(f.key, await V.createCollection(f.vault.name));
        }
      }
      if (run.created.size) await V.sync();
    } catch (e) {
      return interrupted(e);
    }
    const groups = new Map();
    for (const e of run.plan.entries) {
      const id = e.vault.id ?? run.created.get(e.key);
      if (!groups.has(id)) groups.set(id, []);
      groups.get(id).push(e);
    }
    const list = [...groups.entries()];
    for (; run.group < list.length; run.group++) {
      const [vaultId, datas] = list[run.group];
      const before = run.done;
      const res = await importInBatches(datas, {
        start: run.start,
        send: async (chunk) => {
          const ids = await V.importItems(vaultId, chunk.map((e) => e.data));
          // Identifiants rendus par le module du coffre : les favoris importés le restent.
          if (Array.isArray(ids)) chunk.forEach((e, n) => { if (e.favorite && ids[n]) run.favorites.push(ids[n]); });
        },
        onProgress: (n) => {
          run.done = before + (n - run.start);
          say();
        },
      });
      if (res.error) {
        run.start = res.failedAt;
        return interrupted(res.error);
      }
      run.done = before + (datas.length - run.start);
      run.start = 0;
    }
    progress.hidden = true;
    const count = total;
    if (run.favorites.length) {
      const current = settings.prefs?.().favorites || [];
      await settings.savePrefs({ favorites: [...new Set([...current, ...run.favorites])] })
        .catch(() => notify({ text: t("settings_user.import.favorites_failed"), tone: "warn" }));
    }
    resetPreview();
    fileInput.value = "";
    clear(preview, alertCard({ tone: "ok", title: plural("settings_user.import.done", count), text: t("settings_user.import.done_help") }));
    notify({ text: plural("settings_user.import.done", count), tone: "ok" });
    await ctx.refresh?.();
    return undefined;
  }

  function interrupted(error) {
    progress.hidden = true;
    const remaining = run.plan.entries.length - run.done;
    const alert = alertCard({
      tone: "danger",
      title: t("settings_user.import.interrupted", { done: fmtNumber(run.done), total: fmtNumber(run.plan.entries.length) }),
      text: importErrorText(error),
    });
    const resume = button({
      label: plural("settings_user.import.resume", remaining), icon: "refresh", variant: "primary",
      busyLabel: t("settings_user.import.importing"),
      onClick: () => startImport(run.plan),
    });
    clear(preview, alert, h("div", { class: "l-cluster" }, resume));
    resume.focus();
    notify({ text: t("settings_user.import.interrupted_short"), tone: "danger" });
  }

  paintFormat();
  clear(root,
    h("h2", { id: formatId }, t("settings_user.import.heading")),
    h("p", { class: "u-muted" }, t("settings_user.import.help")),
    formatPicker, hint, fileField, password, keyField,
    h("div", { class: "l-cluster" }, read),
    progress, preview);
  root.dispose = () => controller?.abort();
  return root;
}

/** Erreurs de lecture ligne par ligne (les 50 premières, puis le reste en nombre). */
function errorReport(errors) {
  const shown = errors.slice(0, 50);
  return h("div", { class: "c-alert", "data-tone": "warn" },
    h("div", { class: "l-stack", "data-gap": "2" },
      h("p", { class: "c-status__title" }, plural("settings_user.import.errors", errors.length)),
      h("ul", { class: "l-stack", "data-gap": "1" }, shown.map((e) => h("li", {},
        t("settings_user.import.error_line", { line: fmtNumber(e.line), reason: t(`settings_user.import.csv_error.${e.code}`) })))),
      errors.length > shown.length ? h("p", {}, plural("settings_user.import.errors_more", errors.length - shown.length)) : null));
}

/** Avertissements du noyau regroupés par code (import.warning.<code>, pluriel si besoin). */
function summarizeWarnings(warnings) {
  const counts = new Map();
  for (const w of warnings) counts.set(w.code, (counts.get(w.code) || 0) + 1);
  return [...counts.entries()].map(([code, n]) => {
    const key = `import.warning.${code}`;
    if (!has(key)) return t("settings_user.import.warning_other");
    return plural(key, n);
  });
}

/** Les premiers éléments lus : nom, identifiant, dossier (jamais le mot de passe). */
function previewTable(items) {
  const rows = items.slice(0, PREVIEW_ROWS).map((it, i) => ({ key: String(i), ...it }));
  return dataTable({
    caption: items.length > PREVIEW_ROWS
      ? t("settings_user.import.preview_caption_some", { n: fmtNumber(PREVIEW_ROWS), total: fmtNumber(items.length) })
      : plural("settings_user.import.preview_caption", items.length),
    rows,
    rowKey: (r) => r.key,
    rowLabel: (r) => r.data.name,
    columns: [
      { key: "name", label: t("settings_user.import.col_name"), render: (r) => r.data.name || h("span", { class: "u-muted" }, t("settings_user.import.no_name")) },
      { key: "username", label: t("settings_user.import.col_username"), render: (r) => r.data.username || "" },
      { key: "folder", label: t("settings_user.import.col_folder"), render: (r) => normalizeFolder(r.folder) },
    ],
  }).el;
}

// ------------------------------------------------------------ Export

function exportSection(settings) {
  const titleId = uid("export");
  const root = h("section", { class: "c-card l-stack", "data-gap": "4", "aria-labelledby": titleId });
  const title = h("h2", { id: titleId }, t("settings_user.export.heading"));

  const disabled = (reason) => clear(root, title,
    alertCard({ tone: "info", text: reason }),
    h("div", { class: "l-cluster" }, button({ label: t("settings_user.export.submit"), icon: "download", disabled: true, reason })));

  if (settings.effective("export.enabled").value === false) {
    disabled(t("settings_user.export.disabled"));
    return root;
  }

  const minLength = Math.max(12, num(settings.effective("export.min_password_length").value, 12));
  let format = "locksy";
  const scope = selectInput({ value: "all", options: EXPORT_SCOPES.map((s) => ({ value: s, label: t(`settings_user.export.scope_${s}`) })) });
  const scopeField = field({ label: t("settings_user.export.scope"), input: scope });
  const pw = passwordField({
    label: t("settings_user.export.password"), autocomplete: "new-password", withStrength: true, required: true,
    help: plural("settings_user.export.password_help", minLength),
  });
  const again = passwordField({ label: t("settings_user.export.password_confirm"), autocomplete: "new-password", required: true, capsLockHint: false });
  const csvWarning = alertCard({ tone: "warn", text: t("settings_user.export.csv_warning") });
  const alertEl = h("div", {});

  const picker = radioCards({
    legend: t("settings_user.export.format"),
    value: format,
    options: [
      { value: "locksy", label: t("settings_user.export.format_locksy"), description: t("settings_user.export.format_locksy_help") },
      { value: "csv", label: t("settings_user.export.format_csv"), description: t("settings_user.export.format_csv_help") },
    ],
    onChange: (v) => {
      format = v;
      paint();
    },
  });

  function paint() {
    pw.hidden = format !== "locksy";
    again.hidden = format !== "locksy";
    csvWarning.hidden = format !== "csv";
  }

  /** Trace serveur (POST /me/export) ; vrai si l'export peut continuer. */
  async function record(reauth, body) {
    try {
      await api("POST", "/me/export", body, { reauth, retry: false });
    } catch (e) {
      if (e?.status === 404) return true; // serveur antérieur : pas de trace, l'export continue
      throw e;
    }
    return true;
  }

  const submit = button({
    label: t("settings_user.export.submit"), icon: "download", variant: "primary", busyLabel: t("settings_user.export.busy"),
    onClick: async () => {
      clear(alertEl);
      for (const el of [pw, again]) fieldError(el, null, { announce: false });
      const items = exportItems(scope.value);
      if (!items.length) return fieldError(scopeField, t("settings_user.export.nothing"));
      const secret = fieldInput(pw).value;
      if (format === "locksy") {
        if ([...secret].length < minLength) return fieldError(pw, plural("settings_user.export.password_short", minLength));
        if (secret !== fieldInput(again).value) return fieldError(again, t("settings_user.password.mismatch"));
      } else {
        const { confirmed } = await confirm({
          level: 2, title: t("settings_user.export.csv_confirm_title"), message: t("settings_user.export.csv_confirm_message"),
          impact: plural("settings_user.export.csv_impact", items.length), confirmLabel: t("settings_user.export.csv_confirm"), danger: true,
        });
        if (!confirmed) return undefined;
      }
      const body = { scope: scope.value, items: items.length, attachments: false, format };
      let allowed;
      try {
        allowed = await withReauth("vault.export", ({ reauth }) => record(reauth, body), {
          title: t("settings_user.export.reauth_title"),
          message: plural("settings_user.export.reauth_message", items.length),
        });
      } catch (e) {
        if (e?.code === "export_disabled") {
          disabled(errorText(e));
          return undefined;
        }
        clear(alertEl, alertCard({ tone: "danger", text: t("settings_user.export.failed", { reason: errorText(e) }) }));
        return undefined;
      }
      if (!allowed) return undefined;
      await nextFrame();
      try {
        if (format === "locksy") {
          const json = call("protect_export", { password: secret, plaintext: JSON.stringify({ exported_at: V.now(), items: items.map((i) => i.data) }) });
          saveBlob(new Blob([json], { type: "application/json" }), "locksy-sauvegarde-" + today() + ".json");
        } else {
          saveBlob(new Blob([exportCsv(items)], { type: "text/csv;charset=utf-8" }), "locksy-export-" + today() + ".csv");
        }
      } catch (e) {
        clear(alertEl, alertCard({ tone: "danger", text: t("settings_user.export.failed", { reason: errorText(e) }) }));
        return undefined;
      }
      fieldInput(pw).value = "";
      fieldInput(again).value = "";
      notify({ text: plural(format === "locksy" ? "settings_user.export.done" : "settings_user.export.done_csv", items.length), tone: "ok" });
      return undefined;
    },
  });

  paint();
  clear(root, title,
    h("p", { class: "u-muted" }, t("settings_user.export.help")),
    alertEl, picker, scopeField, pw, again, csvWarning,
    h("div", { class: "l-cluster" }, submit));
  return root;
}

// ------------------------------------------------------------ Vue

export async function render(container, ctx) {
  const settings = ctx.settings || S;
  const imp = importSection(ctx, settings);
  const exp = exportSection(settings);
  clear(container, imp, exp);
  return {
    dispose() { imp.dispose?.(); },
    isDirty: () => false,
  };
}

