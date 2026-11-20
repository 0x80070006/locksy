// Réglages › Historique (cahier §3.4.6, §4.5) : une carte par révision
// (« Révision 43 · Camille Durand · 2 réglages · il y a 5 min »), motif,
// origine (écran, profil, import…), différences, et « Revenir à cette
// version » pour les propriétaires (confirmation de niveau 2, puis nouvelle
// révision ; confirmation d'identité si un réglage de sécurité baisse).
// Filtre par réglage dans l'adresse (?cle=), pages « Plus anciennes ».
// Repli R11 : serveur sans historique (404) -> explication.

import {
  t, plural, has, h, clear, button, notify, relTime, fmtDate, errorText, diffList, confirm,
  field, selectInput, skeleton, errorState, emptyState, settingLabel,
} from "../../ui/index.js";
import { api, apiFull } from "../../api.js";
import { isOwner, routeMissing, setQuery, withStepUp } from "./shell.js";
import { loadSettings, settingsStore, settingsNav, defOf } from "./settings.js";

const PER_PAGE = 20;

/** Origine d'une révision : « depuis l'écran des réglages », « profil »… */
const sourceText = (source) => (has(`admin.history.source.${source}`) ? t(`admin.history.source.${source}`) : t("admin.history.source.other"));

export async function renderPage(ctx, container, route) {
  let disposed = false;
  let page = 1;
  let revisions = [];
  let total = 0;
  let key = ctx.query?.get("cle") || "";

  const list = h("div", { class: "l-stack", "data-gap": "4" }, skeleton({ lines: 5 }));
  const more = h("div");
  const filter = h("div");
  clear(container,
    h("h1", { tabindex: "-1" }, t("admin.history.title")),
    h("p", { class: "u-muted" }, t("admin.history.intro")),
    filter, list, more);

  try {
    await loadSettings();
  } catch {
    /* sans schéma, les libellés restent lisibles (repli sur les clés du catalogue) */
  }
  if (route.subnav) clear(route.subnav, settingsNav("historique"));
  paintFilter();

  async function load({ append = false } = {}) {
    const p = new URLSearchParams({ page: String(page), per_page: String(PER_PAGE) });
    if (key) p.set("key", key);
    try {
      const res = await api("GET", `/admin/settings/history?${p}`);
      if (disposed) return;
      revisions = append ? [...revisions, ...(res.revisions || [])] : res.revisions || [];
      total = Number(res.total) || revisions.length;
      paint();
    } catch (e) {
      if (disposed) return;
      if (routeMissing(e)) {
        clear(list, emptyState({ icon: "history", title: t("admin.history.unavailable_title"), text: t("admin.history.unavailable_text") }));
        clear(filter);
        return;
      }
      clear(list, errorState({ error: e, onRetry: () => load() }));
    }
  }

  function paintFilter() {
    const defs = [...settingsStore.defs.values()].sort((a, b) => settingLabel(a.key).localeCompare(settingLabel(b.key), "fr"));
    if (!defs.length) return;
    const select = selectInput({
      options: [{ value: "", label: t("admin.history.all_settings") }, ...defs.map((d) => ({ value: d.key, label: settingLabel(d.key) }))],
      value: key,
    });
    select.addEventListener("change", () => {
      key = select.value;
      page = 1;
      setQuery(ctx, { cle: key || null });
      load();
    });
    clear(filter, field({ label: t("admin.history.filter_label"), input: select }));
  }

  function paint() {
    if (!revisions.length) {
      clear(list, emptyState({ icon: "history", title: t("admin.history.empty") }));
      clear(more);
      return;
    }
    clear(list, revisions.map(card));
    clear(more, revisions.length < total
      ? button({ label: t("admin.history.older"), icon: "chevron-down", onClick: () => { page += 1; return load({ append: true }); } })
      : null);
  }

  function card(r) {
    const changes = (r.changes || []).map((c) => ({ key: c.key, def: defOf(c.key), old: c.old, new: c.new }));
    const latest = r.revision === revisions[0]?.revision && page === 1 && !key;
    return h("section", { class: "c-card l-stack", "data-gap": "2", "aria-label": t("admin.history.revision", { revision: r.revision }) },
      h("h2", {}, t("admin.history.entry", { revision: r.revision, by: r.by || r.email || t("admin.history.by_system") })),
      h("p", { class: "u-muted" },
        plural("admin.history.count", changes.length), " · ",
        h("span", { title: fmtDate(r.at, "long") }, relTime(r.at)), " · ", sourceText(r.source)),
      r.reason ? h("p", {}, t("admin.history.reason", { reason: r.reason })) : null,
      diffList({ changes }),
      isOwner(ctx) && !latest ? h("div", { class: "l-cluster" },
        button({ label: t("admin.history.revert"), icon: "restore", busyLabel: t("common.state.saving"), onClick: () => revert(r, changes.length) })) : null);
  }

  async function revert(r, count) {
    const ok = await confirm({
      level: 2,
      title: t("admin.history.revert_title", { revision: r.revision }),
      message: t("admin.history.revert_text"),
      impact: [t("admin.history.revert_impact", { revision: r.revision }), plural("admin.history.count", count)],
      confirmLabel: t("admin.history.revert"),
    });
    if (!ok.confirmed) return;
    try {
      const settings = await loadSettings({ force: true });
      const send = (opts) => apiFull("POST", `/admin/settings/revert/${encodeURIComponent(r.revision)}`, undefined,
        { ifMatch: settings.revision === null ? undefined : `r${settings.revision}`, ...opts });
      const res = await withStepUp("settings", send, { title: t("admin.settings.reauth_title"), message: t("admin.settings.reauth_message") });
      if (res === undefined) return;
      const skipped = res.data?.skipped || [];
      notify({
        text: skipped.length
          ? t("admin.history.reverted_skipped", { revision: res.data?.revision, keys: skipped.map(settingLabel).join(", ") })
          : t("admin.history.reverted", { revision: res.data?.revision }),
        tone: "ok",
      });
      await loadSettings({ force: true }).catch(() => {});
      page = 1;
      await load();
    } catch (e) {
      notify({ text: errorText(e), tone: "danger" });
    }
  }

  await load();
  return {
    dispose() {
      disposed = true;
    },
    isDirty: () => false,
  };
}
