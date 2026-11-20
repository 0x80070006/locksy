// Écran principal du popup (cahier §3.5.1) : comptes du site ouvert en cartes
// (code de vérification mis à jour en continu, « Remplir » ou « Remplir et
// copier le code », menu « Copier »), recherche dans tout le coffre, favoris,
// « Enregistrer le compte saisi sur ce site », Générer et Préférences.

import {
  h, t, iconButton, menuButton, itemList, itemAvatar, totpCode, alertCard, emptyState, searchBox, normalize,
  setDisabled, setPressed, confirm, notify,
} from "../lib/ui/index.js";
import * as V from "../lib/vault.js";
import * as Settings from "../lib/settings-client.js";
import { S, ext, go, screen, showError, action, copyValue } from "./context.js";
import { lock, openVault } from "./session.js";
import { fill, fillRefusal, pageState, siteMatch, currentCode } from "./fill.js";
import { signupCard } from "./signup.js";

const MAX_RESULTS = 50;
let view = "site"; // "site" | "favorites"
const autoFilled = new Set(); // onglets déjà remplis automatiquement depuis l'ouverture du popup

const live = () => [...V.state.items.values()].filter((i) => i.data && !i.deleted_at);
const byName = (a, b) => String(a.data.name).localeCompare(String(b.data.name), "fr");

function collectionLabel(item) {
  const c = V.state.collections.get(item.collection_id);
  return c?.personal ? t("common.glossary.personal_vault") : c?.name || "";
}

/** Comptes du site ouvert : correspondances exactes d'abord, puis même site en http. */
function forSite(items) {
  return items.map((item) => ({ item, m: siteMatch(item) })).filter((x) => x.m.status !== "nomatch")
    .sort((a, b) => (a.m.status === b.m.status ? byName(a.item, b.item) : a.m.status === "match" ? -1 : 1));
}

function search(items, q) {
  const words = normalize(q).split(" ").filter(Boolean);
  return items.filter((i) => {
    const d = i.data;
    const text = normalize([d.name, d.username, ...(d.urls || []), ...(d.tags || [])].join(" "));
    return words.every((w) => text.includes(w));
  }).sort(byName).slice(0, MAX_RESULTS);
}

// ------------------------------------------------------------------ Remplissage

/** Remplit avec l'élément ; compte d'un autre site (si la politique le permet) : confirmation. */
async function fillItem(item) {
  const m = siteMatch(item);
  if (m.status !== "match" && !fillRefusal(item, m)) {
    const { confirmed } = await confirm({
      title: t("extension.fill.mismatch_title"),
      message: t("extension.fill.mismatch_text", { name: item.data.name, site: S.page.hostname }),
      confirmLabel: t("extension.fill.fill_anyway"),
    });
    if (!confirmed) return;
  }
  await fill(item);
}

function fillLabels(item) {
  const name = item.data.name;
  const withCode = !!item.data.totp && item.data.totp_fill !== true && S.rules.copyTotpAfterFill;
  return withCode
    ? { text: t("extension.card.fill_code"), label: t("extension.card.fill_code_named", { name }) }
    : { text: t("extension.card.fill"), label: t("extension.card.fill_named", { name }) };
}

function copyItems(item) {
  const d = item.data;
  return [
    d.username ? { label: t("common.glossary.username"), icon: "user", onSelect: () => copyValue(d.username, "username") } : null,
    d.password ? { label: t("common.glossary.password"), icon: "key", onSelect: () => copyValue(d.password, "password") } : null,
    d.totp ? { label: t("common.glossary.verification_code"), icon: "clock", onSelect: () => { const c = currentCode(d); if (c) copyValue(c, "totp"); } } : null,
  ].filter(Boolean);
}

// ------------------------------------------------------------------ Carte

/** Carte d'un compte : nom, identifiant, code en continu, Remplir, Copier ▾. */
function card(item) {
  const d = item.data;
  const m = siteMatch(item);
  const refusal = fillRefusal(item, m);
  const labels = fillLabels(item);
  const fillBtn = action({
    label: labels.text, icon: "key", variant: "primary", attrs: { "aria-label": labels.label },
    onClick: () => fillItem(item),
  });
  if (refusal) setDisabled(fillBtn, true, t(refusal));
  const copies = copyItems(item);
  const copyBtn = copies.length ? menuButton({ label: t("common.action.copy"), icon: "copy", items: copies }) : null;
  copyBtn?.setAttribute("aria-label", t("extension.card.copy_named", { name: d.name }));
  const code = d.totp ? totpCode({ config: d.totp, onCopy: (c) => copyValue(c, "totp") }) : null;
  return h("li", { class: "x-card" },
    h("div", { class: "x-card__head" },
      itemAvatar({ item: { name: d.name, kind: d.kind } }),
      h("div", { class: "x-card__text" },
        h("p", { class: "x-card__name" }, d.name),
        h("p", { class: "x-card__sub u-muted" }, d.username || collectionLabel(item)))),
    code ? code.el : null,
    m.status === "downgrade" ? h("p", { class: "x-card__note" }, t("extension.fill.downgrade")) : null,
    h("div", { class: "x-card__actions" }, fillBtn, copyBtn));
}

function cards(list, label) {
  return h("ul", { class: "x-cards", "aria-label": label }, list.map(card));
}

// ------------------------------------------------------------------ Liste de résultats

function resultList(items, label) {
  const list = itemList({
    label,
    items,
    render: (item) => ({
      title: item.data.name,
      subtitle: item.data.username || collectionLabel(item),
      avatar: { name: item.data.name, kind: item.data.kind },
      primaryLabel: item.data.password ? t("extension.list.copy_password", { name: item.data.name }) : null,
      menuLabel: t("extension.list.more", { name: item.data.name }),
    }),
    onOpen: (item, e) => { e?.preventDefault?.(); renderItem(item); },
    onPrimary: (item) => copyValue(item.data.password, "password"),
    onMenu: (item) => {
      const m = siteMatch(item);
      return [
        fillRefusal(item, m) ? null : { label: fillLabels(item).text, icon: "key", onSelect: () => fillItem(item).catch(showError) },
        ...copyItems(item).map((c) => ({ ...c, label: t("extension.list.copy_what", { what: c.label.toLowerCase() }) })),
      ].filter(Boolean);
    },
  });
  return list;
}

/** Un élément ouvert depuis la recherche ou les favoris. */
function renderItem(item, back = () => renderMain()) {
  screen({ title: item.data.name, back, session: true }, cards([item], t("extension.list.item")));
}

// ------------------------------------------------------------------ Écran principal

function notices(p) {
  if (!S.page) return h("p", { class: "u-muted" }, t("extension.site.none"));
  return [
    h("p", { class: "x-site" }, t("extension.site.on", { host: S.page.hostname })),
    p.excluded ? alertCard({ tone: "warn", text: t("extension.site.excluded") })
      : p.blocked ? alertCard({ tone: "danger", text: t("extension.site.http_blocked") })
        : p.insecure ? alertCard({ tone: "warn", text: t("extension.site.http_warn") }) : null,
  ];
}

export function renderMain(query = "") {
  const all = live();
  const p = pageState();
  const site = forSite(all);
  const favorites = new Set(Settings.prefs().favorites || []);
  const section = h("section", { class: "l-stack x-section", "aria-labelledby": "x-liste-titre" });
  let lastQuery = query;

  const draw = (q) => {
    lastQuery = q;
    const heading = (key, n) => h("h2", { id: "x-liste-titre", class: "x-section__title" }, n === undefined ? t(key) : t(key, { n }));
    if (q.trim()) {
      const found = search(all, q);
      section.replaceChildren(heading("extension.list.results", found.length),
        found.length ? resultList(found, t("extension.list.results_label")) : emptyState({ title: t("extension.list.no_result"), level: 3 }));
    } else if (view === "favorites") {
      const favs = all.filter((i) => favorites.has(i.id)).sort(byName);
      section.replaceChildren(heading("extension.list.favorites"),
        favs.length ? resultList(favs, t("extension.list.favorites")) : emptyState({ icon: "star", title: t("extension.list.no_favorite"), text: t("extension.list.no_favorite_text"), level: 3 }));
    } else {
      section.replaceChildren(heading("extension.list.for_site"),
        site.length ? cards(site.map((x) => x.item), t("extension.list.for_site"))
          : emptyState({ icon: "key", title: S.page ? t("extension.list.none_for_site", { host: S.page.hostname }) : t("extension.site.none"), level: 3 }));
    }
  };

  const box = searchBox({
    label: t("extension.list.search"), placeholderKey: "extension.list.search_placeholder", value: query, shortcut: null, delay: 40,
    onInput: (_n, raw) => draw(raw),
    // Entrée : remplit le premier compte du site s'il correspond à la page.
    onSubmit: (raw) => {
      const first = (raw.trim() ? search(all, raw) : site.map((x) => x.item)).find((i) => siteMatch(i).status === "match" && !fillRefusal(i, siteMatch(i)));
      if (first) fill(first).catch(showError);
    },
    onArrowDown: () => section.querySelector("button, a")?.focus(),
  });
  const input = box.querySelector("input");
  draw(query);

  const favBtn = action({
    label: t("extension.nav.favorites"), icon: "star", variant: "quiet", attrs: { "aria-pressed": String(view === "favorites") },
    onClick: () => { view = view === "favorites" ? "site" : "favorites"; setPressed(favBtn, view === "favorites"); draw(input.value); },
  });
  // Page d'inscription : détectée après l'affichage (ne retarde pas le popup).
  const signupSlot = h("div", {});
  signupCard().then((card) => { if (card) signupSlot.replaceChildren(card); }, () => {});
  const save = S.page && S.rules.offerSave && !p.excluded
    ? action({ label: t("extension.save.button"), icon: "plus", onClick: () => go("save") })
    : null;

  screen({
    session: true,
    actions: [
      iconButton({ icon: "external", label: t("extension.open"), onClick: () => ext.tabs.create({ url: S.server }) }),
      iconButton({ icon: "lock", label: t("common.action.lock"), onClick: async () => { await lock({ revoke: true }); go("login", { info: t("extension.session.locked") }); } }),
    ],
  },
  notices(p),
  signupSlot,
  box,
  section,
  save,
  h("nav", { class: "x-nav", "aria-label": t("extension.nav.label") },
    action({ label: t("extension.nav.generate"), icon: "generate", variant: "quiet", onClick: () => go("generate") }),
    favBtn,
    action({ label: t("extension.nav.prefs"), icon: "settings", variant: "quiet", onClick: () => go("prefs") }),
    iconButton({
      icon: "refresh", label: t("extension.nav.sync"),
      onClick: async () => {
        try {
          await openVault();
          renderMain(lastQuery);
          notify({ text: t("extension.nav.synced"), tone: "ok" });
        } catch (e) {
          if (e.status !== 401) showError(e);
        }
      },
    })));
  input.focus();

  // Remplissage automatique (préférence extension.autofill) : un seul compte correspond
  // exactement au site, la page est autorisée et rien n'est saisi dans la recherche.
  if (S.rules.autofill && !query && S.tab?.id !== undefined && !autoFilled.has(S.tab.id)) {
    const ready = site.filter((x) => x.m.status === "match" && !fillRefusal(x.item, x.m));
    if (ready.length === 1) {
      autoFilled.add(S.tab.id);
      fill(ready[0].item).catch(showError);
    }
  }
}

