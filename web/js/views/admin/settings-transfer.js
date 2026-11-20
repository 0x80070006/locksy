// Réglages › Importer / exporter (cahier §3.4.6, §4.5) : export JSON des
// valeurs différentes du défaut, sans secret (à ressaisir après import), avec
// une empreinte ; import en deux temps : essai à blanc (aucune écriture) avec
// une case par réglage, puis récapitulatif et application en une révision.
// Réservé aux propriétaires (le serveur le vérifie aussi).
// Repli R11 : serveur sans ces routes (404) -> explication.

import {
  t, plural, h, clear, button, notify, errorText, checkboxGroup, alertCard,
  settingLabel, formatSettingValue,
} from "../../ui/index.js";
import { api, apiFull, saveBlob } from "../../api.js";
import { datedName, isOwner, routeMissing } from "./shell.js";
import { loadSettings, settingsNav, defOf, openRecap } from "./settings.js";

const EXPORT_FORMAT_HINT = "application/json";

export async function renderPage(ctx, container, route) {
  try {
    await loadSettings();
  } catch {
    /* la navigation des sections se limitera aux pages annexes */
  }
  if (route.subnav) clear(route.subnav, settingsNav("transfert"));
  const status = h("div", { class: "l-stack", "data-gap": "3" });
  const importZone = h("div", { class: "l-stack", "data-gap": "3" });

  if (!isOwner(ctx)) {
    clear(container,
      h("h1", { tabindex: "-1" }, t("admin.transfer.title")),
      alertCard({ tone: "info", text: t("admin.transfer.owner_only") }));
    return { dispose() {}, isDirty: () => false };
  }

  const exportBtn = button({
    label: t("admin.transfer.export"), icon: "download", busyLabel: t("admin.transfer.exporting"),
    onClick: async () => {
      try {
        const doc = await api("GET", "/admin/settings/export");
        saveBlob(new Blob([`${JSON.stringify(doc, null, 2)}\n`], { type: EXPORT_FORMAT_HINT }), datedName("reglages", "json"));
        notify({ text: plural("admin.transfer.exported", Object.keys(doc.values || {}).length), tone: "ok" });
      } catch (e) {
        if (routeMissing(e)) clear(status, alertCard({ tone: "info", text: t("admin.transfer.unavailable") }));
        else notify({ text: errorText(e), tone: "danger" });
      }
    },
  });

  const file = h("input", { type: "file", accept: ".json,application/json", class: "u-sr-only", id: "reglages-import" });
  const pick = h("label", { for: "reglages-import", class: "c-button" }, t("admin.transfer.choose_file"));
  file.addEventListener("change", () => {
    const f = file.files?.[0];
    file.value = "";
    if (f) readFile(f);
  });

  clear(container,
    h("h1", { tabindex: "-1" }, t("admin.transfer.title")),
    h("section", { class: "l-stack", "data-gap": "3" },
      h("h2", {}, t("admin.transfer.export_title")),
      h("p", {}, t("admin.transfer.export_text")),
      h("div", { class: "l-cluster" }, exportBtn)),
    h("section", { class: "l-stack", "data-gap": "3" },
      h("h2", {}, t("admin.transfer.import_title")),
      h("p", {}, t("admin.transfer.import_text")),
      h("div", { class: "l-cluster" }, file, pick),
      importZone),
    status);

  /** Lecture du fichier puis essai à blanc. */
  async function readFile(f) {
    let doc;
    try {
      doc = JSON.parse(await f.text());
      if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error("format");
    } catch {
      clear(importZone, alertCard({ tone: "danger", text: t("admin.transfer.unreadable") }));
      return;
    }
    clear(importZone, h("p", { class: "u-muted" }, t("admin.transfer.checking")));
    let dry;
    try {
      dry = await api("POST", "/admin/settings/import?dry_run=true", doc);
    } catch (e) {
      clear(importZone, alertCard({ tone: "danger", text: routeMissing(e) ? t("admin.transfer.unavailable") : errorText(e) }));
      return;
    }
    showDryRun(doc, dry);
  }

  /** Différences de l'essai à blanc, une case par réglage. */
  function showDryRun(doc, dry) {
    const diff = dry.diff || [];
    const errors = Object.entries(dry.errors || {});
    const skipped = dry.skipped || [];
    if (!dry.ok) {
      clear(importZone,
        alertCard({ tone: "danger", title: plural("admin.transfer.errors", errors.length),
          text: errors.map(([k]) => settingLabel(k)).join(", ") }));
      return;
    }
    if (!diff.length) {
      clear(importZone, alertCard({ tone: "info", text: t("admin.transfer.nothing") }),
        skipped.length ? skippedNotice(skipped) : null);
      return;
    }
    let selected = diff.map((d) => d.key);
    const boxes = checkboxGroup({
      legend: plural("admin.transfer.legend", diff.length),
      options: diff.map((d) => ({
        value: d.key,
        label: settingLabel(d.key),
        description: t("admin.transfer.change", { old: formatSettingValue(defOf(d.key), d.old), new: formatSettingValue(defOf(d.key), d.new) })
          + (d.lowered ? ` · ${t("ui.diff.lowered")}` : ""),
      })),
      values: selected,
      onChange: (values) => {
        selected = values;
        apply.disabled = !selected.length;
      },
    });
    const apply = button({
      label: t("admin.transfer.review"), variant: "primary", busyLabel: t("admin.transfer.checking"),
      onClick: () => review(doc, selected),
    });
    clear(importZone,
      boxes,
      skipped.length ? skippedNotice(skipped) : null,
      h("div", { class: "l-cluster" }, apply,
        button({ label: t("common.action.cancel"), variant: "quiet", onClick: () => clear(importZone) })));
  }

  const skippedNotice = (keys) => alertCard({ tone: "warn", text: t("admin.transfer.skipped", { keys: keys.map(settingLabel).join(", ") }) });

  /** Revalide la sélection puis ouvre le récapitulatif ; application en une révision. */
  async function review(doc, keys) {
    if (!keys.length) return;
    let validation;
    try {
      validation = await api("POST", "/admin/settings/import?dry_run=true", { ...doc, keys });
    } catch (e) {
      notify({ text: errorText(e), tone: "danger" });
      return;
    }
    if (!validation.ok) {
      notify({ text: plural("admin.transfer.errors", Object.keys(validation.errors || {}).length), tone: "danger" });
      return;
    }
    const settings = await loadSettings({ force: true });
    await openRecap({
      validation,
      title: plural("admin.transfer.recap_title", (validation.diff || []).length),
      confirmLabel: t("admin.transfer.apply"),
      send: (reason, opts) => apiFull("POST", "/admin/settings/import?dry_run=false", { ...doc, keys, reason },
        { ifMatch: settings.revision === null ? undefined : `r${settings.revision}`, ...opts }),
      onSaved: async (res) => {
        await loadSettings({ force: true }).catch(() => {});
        clear(importZone, alertCard({ tone: "ok", text: t("admin.transfer.applied", { revision: res?.data?.revision ?? "" }) }));
        notify({ text: t("admin.transfer.applied", { revision: res?.data?.revision ?? "" }), tone: "ok" });
      },
    });
  }

  return { dispose() {}, isDirty: () => false };
}
