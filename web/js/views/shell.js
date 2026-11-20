// Coquille de l'application déverrouillée (cahier §3.2, contrat C4.3) :
// barre latérale (Tout, Favoris, Coffres, Bilan de sécurité, Corbeille),
// barre du haut (Menu, recherche globale, Générer, Nouveau, menu du compte),
// commutateur « Mon coffre | Administration », préavis de verrouillage et
// bandeau hors ligne.
//
// La coquille est construite UNE fois par déverrouillage (mount) et n'est
// jamais reconstruite : refresh() ne change que les compteurs et la liste des
// coffres, dans les mêmes nœuds (même <nav> avant et après). Elle est détruite
// au verrouillage et à la déconnexion (aucun nom de coffre ne reste affiché).
//
// Sous 900 px, la barre latérale devient un tiroir : fermé, il est `hidden` et
// `inert` (non tabulable) ; le bouton « Menu » porte aria-expanded et
// aria-controls. Sous 600 px, « Générer » et « Nouveau » n'affichent que leur
// icône (même nom accessible).
//
// API (createShell) : mount(appEl, mainEl), unmount(), setCurrent(route, params),
// update(), setSidebarCounts(counts), openGeneratorPanel(opts),
// setSearchScope(collectionId|null), openAccountMenu(), focusSearch(), setOffline(bool),
// showLockWarning(seconds, onStay), hideLockWarning(), isMounted(), api (pour ctx.shell :
// setSidebarCounts, openGeneratorPanel, setSearchScope, openAccountMenu).

import {
  t, plural, h, clear, icon, uid, button, iconButton, openMenu, searchBox, avatar, badge,
  focusSafely, focusables, keepFocus, announce, offlineBanner, HOTKEYS, parseKey, matches,
} from "../ui/index.js";
import * as V from "../vault.js";
import * as S from "../settings-client.js";

/** Pages de la zone « Administration » : adresse, préfixe de correspondance, icône. */
const ADMIN_LINKS = Object.freeze([
  { href: "#/admin", match: "/admin", key: "admin.nav.home", icon: "shield" },
  { href: "#/admin/personnes", match: "/admin/personnes", key: "admin.nav.people", icon: "users" },
  { href: "#/admin/reglages/login", match: "/admin/reglages", key: "admin.nav.settings", icon: "settings" },
  { href: "#/admin/connexion", match: "/admin/connexion", key: "admin.nav.identity", icon: "building" },
  { href: "#/admin/journal", match: "/admin/journal", key: "admin.nav.journal", icon: "history" },
]);

/** Thème affiché : choix explicite, sinon celui du système. */
function isDark() {
  const set = document.documentElement.dataset.theme;
  if (set === "dark" || set === "light") return set === "dark";
  return globalThis.matchMedia?.("(prefers-color-scheme: dark)").matches === true;
}

const DRAWER_QUERY = "(width < 56.25em)";
const COMPACT_QUERY = "(width < 37.5em)";
const MAX_RESULTS = 8;
/** Calcul de la pastille du bilan : délai après l'ouverture, plafond de mots de passe. */
const HEALTH_DELAY_MS = 1500;
const HEALTH_MAX_ITEMS = 2000;

/**
 * createShell({ navigate, lock, logout, newVault, openGenerator })
 *   navigate(path)        : navigation du routeur ;
 *   lock(), logout()      : verrouillage, déconnexion ;
 *   newVault()            : création d'un coffre (fenêtre du coffre) ;
 *   openGenerator(opts)   : panneau du générateur (repli : page « Générateur »).
 */
export function createShell({ navigate, lock, logout, newVault, openGenerator }) {
  let els = null;
  let counts = {};
  let scope = null;
  let current = { nav: null, collectionId: null, admin: false };
  let provider;
  let healthTimer = 0;
  const cleanups = [];

  // ---------------------------------------------------------- Barre latérale

  function navLink(id, href, label, iconName, count, extra) {
    return h("a", { class: "c-sidenav__item", href: `#${href}`, "data-id": id, "data-focus-key": `nav-${id}` },
      icon(iconName), h("span", {}, label), extra || null,
      h("span", { class: "c-sidenav__count", "data-count": id, hidden: typeof count !== "number" }, typeof count === "number" ? String(count) : ""));
  }

  function canCreateVault() {
    const role = V.state.profile?.role;
    return role !== "user" || S.effective("vault.users_can_create_shared").value !== false;
  }

  function collections() {
    return [...V.state.collections.values()].sort((a, b) => (b.personal - a.personal) || String(a.name).localeCompare(String(b.name), "fr"));
  }

  function renderNav() {
    const nav = els.nav;
    keepFocus(nav, () => {
      const healthBadge = counts.health > 0
        ? badge({ tone: "warn", label: plural("shell.nav.health_badge", counts.health) })
        : null;
      clear(nav,
        h("p", { class: "c-sidenav__group" }, t("shell.nav.passwords")),
        navLink("home", "/accueil", t("shell.nav.home"), "home"),
        navLink("all", "/coffre", t("shell.nav.all"), "vault", counts.all),
        navLink("favorites", "/coffre/favoris", t("shell.nav.favorites"), "star", counts.favorites),
        h("p", { class: "c-sidenav__group" }, h("span", {}, t("shell.nav.vaults")),
          canCreateVault()
            ? iconButton({ icon: "plus", label: t("shell.nav.new_vault"), onClick: () => newVault?.(), attrs: { "data-focus-key": "nav-new-vault" } })
            : null),
        collections().map((c) => navLink(`c:${c.id}`, `/coffre/c/${encodeURIComponent(c.id)}`,
          c.personal ? t("shell.nav.personal") : c.name, c.personal ? "lock" : "folder", counts.collections?.[c.id])),
        navLink("health", "/bilan", t("shell.nav.health"), "health", undefined, healthBadge),
        navLink("trash", "/corbeille", t("shell.nav.trash"), "trash", counts.trash));
    });
    markCurrent();
  }

  function markCurrent() {
    if (!els) return;
    const id = current.nav === "collection" ? `c:${current.collectionId}` : current.nav;
    for (const a of els.nav.querySelectorAll("a[data-id]")) {
      if (a.dataset.id === id) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
    const path = String(globalThis.location?.hash || "").replace(/^#/, "").split("?")[0];
    const links = [...(els.switcher?.querySelectorAll("a[data-admin]") || [])];
    const best = current.admin
      ? links.filter((a) => path === a.dataset.admin || path.startsWith(a.dataset.admin + "/"))
        .sort((x, y) => y.dataset.admin.length - x.dataset.admin.length)[0]
      : null;
    for (const a of links) {
      if (a === best) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
  }

  /** Compteurs par défaut, depuis le coffre déchiffré (les vues peuvent les préciser). */
  function defaultCounts() {
    const items = [...V.state.items.values()];
    const live = items.filter((i) => !i.deleted_at);
    const favs = new Set(S.prefs().favorites || []);
    const perCollection = {};
    for (const i of live) perCollection[i.collection_id] = (perCollection[i.collection_id] || 0) + 1;
    return {
      all: live.length,
      favorites: live.filter((i) => favs.has(i.id)).length,
      collections: perCollection,
      trash: items.length - live.length,
    };
  }

  function setSidebarCounts(next = {}) {
    const healthChanged = next.health !== undefined && next.health !== counts.health;
    counts = { ...counts, ...next, collections: { ...(counts.collections || {}), ...(next.collections || {}) } };
    if (!els) return;
    const apply = (id, n) => {
      const span = els.nav.querySelector(`[data-count="${CSS.escape(id)}"]`);
      if (!span) return;
      span.hidden = typeof n !== "number";
      span.textContent = typeof n === "number" ? String(n) : "";
    };
    apply("all", counts.all);
    apply("favorites", counts.favorites);
    apply("trash", counts.trash);
    for (const [cid, n] of Object.entries(counts.collections || {})) apply(`c:${cid}`, n);
    // La pastille du bilan change la structure du lien : rendu de la liste (mÃªme <nav>).
    if (healthChanged) renderNav();
  }

  /**
   * Pastille « N à corriger » du bilan de sécurité : calculée en tâche de
   * fond par le module du bilan (L11), peu après l'ouverture et après chaque
   * synchronisation. Au-delà de HEALTH_MAX_ITEMS mots de passe, le calcul
   * (estimation de force de chacun) attend l'ouverture du bilan, qui envoie
   * lui-même le compte par setSidebarCounts.
   */
  function scheduleHealth() {
    clearTimeout(healthTimer);
    healthTimer = setTimeout(async () => {
      if (!els) return;
      const logins = [...V.state.items.values()].filter((i) => !i.deleted_at && i.data?.password).length;
      if (logins > HEALTH_MAX_ITEMS) return;
      try {
        const m = await import("./tools/health.js");
        if (!els) return;
        setSidebarCounts({ health: m.computeHealth(V.state.items.values(), m.healthThresholds(S)).toFix.length });
      } catch {
        // Module du bilan absent ou en erreur : pas de pastille.
      }
    }, HEALTH_DELAY_MS);
  }

  // ---------------------------------------------------------- Tiroir

  function drawerMode() {
    return window.matchMedia(DRAWER_QUERY).matches;
  }

  function setDrawer(open, { focus = true } = {}) {
    if (!els) return;
    const drawer = drawerMode();
    const visible = !drawer || open;
    els.sidebar.hidden = !visible;
    els.sidebar.inert = !visible;
    els.menuBtn.hidden = !drawer;
    els.menuBtn.setAttribute("aria-expanded", String(drawer && open));
    if (drawer && open && focus) focusSafely(focusables(els.sidebar)[0]);
    else if (drawer && !open && focus && els.sidebar.contains(document.activeElement)) focusSafely(els.menuBtn);
  }

  function compactButtons() {
    const compact = window.matchMedia(COMPACT_QUERY).matches;
    for (const btn of [els.generateBtn, els.newBtn]) {
      const label = btn.querySelector(".c-button__label");
      if (!label) continue;
      label.hidden = compact;
      if (compact) {
        btn.setAttribute("aria-label", label.textContent);
        btn.title = label.textContent;
      } else {
        btn.removeAttribute("aria-label");
        btn.removeAttribute("title");
      }
    }
  }

  // ---------------------------------------------------------- Recherche globale

  async function searchProvider() {
    if (provider !== undefined) return provider;
    try {
      const mod = await import("./vault/search-provider.js");
      provider = typeof mod.search === "function" ? mod : null;
    } catch {
      provider = null;
    }
    return provider;
  }

  function hideResults() {
    if (!els) return;
    els.results.hidden = true;
    els.searchInput.setAttribute("aria-expanded", "false");
  }

  function showResults(children) {
    clear(els.results, children);
    els.results.hidden = false;
    els.searchInput.setAttribute("aria-expanded", "true");
  }

  function resultLink(href, title, subtitle, onPick, itemId) {
    return h("li", {},
      h("a", { class: "c-menu__item", href, "data-item-id": itemId, onclick: (e) => { if (onPick) { e.preventDefault(); onPick(); } hideResults(); } },
        h("span", { class: "l-stack", "data-gap": "1" }, h("span", {}, title), subtitle ? h("span", { class: "u-muted" }, subtitle) : null)));
  }

  function actionsGroup() {
    const role = V.state.profile?.role;
    return h("section", { class: "l-stack", "data-gap": "1", "aria-labelledby": "recherche-actions" },
      h("p", { class: "c-sidenav__group", id: "recherche-actions" }, t("shell.search.actions")),
      h("ul", { class: "l-stack", "data-gap": "1", role: "list" },
        resultLink("#/nouveau", t("shell.top.new"), null),
        resultLink("#/generateur", t("common.action.generate"), null, () => openGeneratorPanel({ anchor: els.generateBtn })),
        resultLink("#/verrouille", t("common.action.lock"), null, () => lock("manual")),
        resultLink("#/parametres/preferences", t("shell.search.preferences"), null),
        resultLink("#/aide", t("shell.account.help"), null),
        role !== "user" ? resultLink("#/admin", t("shell.account.admin"), null) : null));
  }

  let searchSeq = 0;
  async function runSearch(raw) {
    const my = ++searchSeq;
    const q = String(raw || "").trim();
    if (!q) {
      if (document.activeElement === els.searchInput) showResults(actionsGroup());
      else hideResults();
      return;
    }
    // Fournisseur de recherche du coffre absent ou en erreur : aucun résultat.
    const p = await searchProvider();
    if (my !== searchSeq || !els) return;
    let rows = [];
    try {
      rows = (p && (await p.search(q, { collectionId: scope, limit: MAX_RESULTS }))) || [];
    } catch {
      rows = [];
    }
    if (my !== searchSeq || !els) return;
    const shown = rows.slice(0, MAX_RESULTS);
    showResults(shown.length
      ? h("ul", { class: "l-stack", "data-gap": "1", role: "list", "aria-label": t("shell.search.results") },
        shown.map((r) => resultLink(`#/element/${encodeURIComponent(r.id)}`, r.title, [r.subtitle, r.collection].filter(Boolean).join(" · "), null, r.id)))
      : h("p", { class: "u-muted" }, t("common.state.empty_search", { q })));
    const total = rows.total ?? rows.length;
    announce(shown.length ? plural("shell.search.count", total) : t("common.state.empty_search", { q }));
  }

  /**
   * Copie depuis un résultat focalisé (tâche 1 du §3.6 : Ctrl K, saisie, ↓,
   * Ctrl Maj C) : mêmes touches que dans le coffre, quel que soit l'écran.
   * Vrai si la touche a été traitée.
   */
  async function copyFromResult(e) {
    const id = e.target?.closest?.("[data-item-id]")?.dataset.itemId;
    if (!id) return false;
    const hit = ["item.copy_password", "item.copy_username"].find((hk) =>
      HOTKEYS.find((x) => x.id === hk)?.keys.some((k) => matches(e, parseKey(k))));
    if (!hit) return false;
    e.preventDefault();
    e.stopPropagation();
    const item = V.state.items.get(id);
    if (!item) return true;
    const A = await import("./vault/actions.js");
    if (hit === "item.copy_password") await A.copyPrimary(item);
    else await A.copyUsername(item);
    return true;
  }

  function moveInResults(step) {
    const links = [...els.results.querySelectorAll("a")];
    if (!links.length) return;
    const i = links.indexOf(document.activeElement);
    focusSafely(links[i < 0 ? 0 : (i + step + links.length) % links.length]);
  }

  function setSearchScope(collectionId) {
    scope = collectionId || null;
    if (!els) return;
    const c = scope ? V.state.collections.get(scope) : null;
    clear(els.scopeChip, c
      ? h("span", { class: "c-chips__entry" },
        h("span", {}, t("shell.search.scope", { name: c.personal ? t("shell.nav.personal") : c.name })),
        iconButton({ icon: "close", label: t("shell.search.scope_remove"), onClick: () => { setSearchScope(null); focusSearch(); } }))
      : null);
    els.scopeChip.hidden = !c;
  }

  function focusSearch() {
    if (!els) return;
    if (drawerMode()) setDrawer(false, { focus: false });
    focusSafely(els.searchInput);
    els.searchInput.select?.();
  }

  // ---------------------------------------------------------- Générateur

  async function openGeneratorPanel(opts = {}) {
    if (typeof openGenerator === "function") return openGenerator({ anchor: els?.generateBtn, ...opts });
    return undefined;
  }

  // ---------------------------------------------------------- Menu du compte

  function accountItems() {
    const role = V.state.profile?.role;
    return [
      { label: t("shell.account.settings"), icon: "settings", onSelect: () => navigate("/parametres/compte") },
      { label: t("shell.account.links"), icon: "link", onSelect: () => navigate("/liens") },
      { label: t("shell.account.help"), icon: "info", onSelect: () => navigate("/aide") },
      role !== "user" ? { label: t("shell.account.admin"), icon: "shield", onSelect: () => navigate("/admin") } : null,
      "separator",
      { label: t("common.action.logout"), icon: "logout", onSelect: () => logout() },
    ];
  }

  /** Ouvre le menu du compte (bouton de la barre du haut, ou une vue par ctx.shell). */
  function openAccountMenu({ focus = "first" } = {}) {
    if (!els) return undefined;
    return openMenu(els.accountBtn, accountItems(), { focus });
  }

  // ---------------------------------------------------------- Construction

  function mount(appEl, mainEl) {
    if (els) return;
    const p = V.state.profile || {};
    const sidebarId = uid("barre-laterale");
    const nav = h("nav", { class: "c-sidenav", "aria-label": t("shell.nav.label") });
    // Zone « Administration » : seulement pour les administrateurs et propriétaires.
    const switcher = p.role && p.role !== "user"
      ? h("nav", { class: "c-sidenav c-sidenav--admin", "aria-label": t("shell.switch.admin") },
        h("p", { class: "c-sidenav__group" }, t("shell.switch.admin")),
        ADMIN_LINKS.map((l) => h("a", { class: "c-sidenav__item", href: l.href, "data-admin": l.match },
          icon(l.icon), h("span", {}, t(l.key)))))
      : null;
    const org = S.publicSettings()?.branding?.org_name;
    const who = avatar({ name: p.name || p.email || "" });
    const sidebar = h("aside", { class: "l-sidebar l-stack", id: sidebarId, "data-gap": "3", "aria-label": t("shell.sidebar.label") },
      h("p", { class: "l-cluster" }, h("img", { src: S.publicSettings()?.branding?.logo_url || "/favicon.svg", alt: "", width: "32", height: "32" }), h("strong", {}, org ? t("shell.brand_org", { org }) : t("common.app.name"))),
      nav, switcher,
      h("div", { class: "l-stack", "data-gap": "2" },
        h("p", { class: "l-cluster" }, who, h("span", { class: "l-stack", "data-gap": "1" }, h("span", {}, p.name || ""), h("span", { class: "u-muted" }, p.email || ""))),
        button({ label: t("common.action.lock"), icon: "lock", onClick: () => lock("manual") })));

    const menuBtn = iconButton({
      icon: "menu", label: t("shell.top.menu"),
      attrs: { "aria-controls": sidebarId, "aria-expanded": "false" },
      onClick: () => setDrawer(sidebar.hidden),
    });
    const search = searchBox({
      label: t("shell.search.label"), placeholderKey: "shell.search.placeholder",
      onInput: (_norm, raw) => runSearch(raw),
      onSubmit: (raw) => {
        const first = els.results.querySelector("a");
        if (first && raw.trim()) first.click();
      },
      onArrowDown: () => moveInResults(1),
    });
    const searchInput = search.querySelector("input");
    // Liste de résultats sous le champ : modèle « combobox » (aria-expanded, aria-controls).
    searchInput.setAttribute("role", "combobox");
    searchInput.setAttribute("aria-autocomplete", "list");
    searchInput.setAttribute("aria-expanded", "false");
    const results = h("div", { class: "c-popover", hidden: true });
    results.id = uid("resultats");
    searchInput.setAttribute("aria-controls", results.id);
    search.append(results);
    results.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey) {
        copyFromResult(e);
        return;
      }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        moveInResults(e.key === "ArrowDown" ? 1 : -1);
      } else if (e.key === "Escape") {
        e.preventDefault();
        hideResults();
        focusSafely(searchInput);
      }
    });
    searchInput.addEventListener("focus", () => { if (!searchInput.value.trim()) showResults(actionsGroup()); });
    search.addEventListener("focusout", (e) => { if (!search.contains(e.relatedTarget)) hideResults(); });
    const scopeChip = h("div", { class: "c-chips", hidden: true });

    const generateBtn = button({ label: t("common.action.generate"), icon: "generate", onClick: () => openGeneratorPanel({}) });
    const newBtn = button({ label: t("shell.top.new"), icon: "plus", variant: "primary", onClick: () => navigate("/nouveau") });
    const accountBtn = h("button", {
      type: "button", class: "c-button c-button--quiet c-account-btn", "aria-label": t("shell.account.menu"),
      "aria-haspopup": "menu", "aria-expanded": "false", title: p.name || p.email || "",
      onclick: () => openAccountMenu(),
    }, avatar({ name: p.name || p.email || "" }));
    const themeBtn = h("button", { type: "button", class: "c-button c-button--quiet c-button--icon c-theme-btn" });
    const paintTheme = () => {
      const dark = isDark();
      themeBtn.replaceChildren(icon(dark ? "sun" : "moon"));
      themeBtn.setAttribute("aria-label", t(dark ? "shell.theme.to_light" : "shell.theme.to_dark"));
      themeBtn.title = themeBtn.getAttribute("aria-label");
    };
    themeBtn.addEventListener("click", () => {
      const next = isDark() ? "light" : "dark";
      try { S.localOnly("ui.theme", next); } catch { /* stockage indisponible */ }
      S.savePrefs(S.prefPatch("ui.theme", next)).catch(() => { /* gardé sur cet appareil */ });
      document.documentElement.dataset.theme = next;
      paintTheme();
    });
    paintTheme();
    accountBtn.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        openAccountMenu({ focus: e.key === "ArrowDown" ? "first" : "last" });
      }
    });
    const topbar = h("header", { class: "l-topbar" }, menuBtn, search, scopeChip, generateBtn, newBtn, h("span", { class: "l-topbar__end" }, themeBtn, accountBtn));
    const notices = h("div", { class: "l-stack", "data-gap": "2" });
    const column = h("div", { class: "l-main" }, topbar, notices);

    els = { appEl, mainEl, sidebar, nav, switcher, menuBtn, search, searchInput, results, scopeChip, generateBtn, newBtn, accountBtn, topbar, notices, column, offline: null, warning: null };
    mainEl.replaceWith(column);
    column.append(mainEl);
    appEl.classList.add("l-shell");
    appEl.prepend(sidebar);

    // Tiroir : un clic sur un lien le ferme ; Échap aussi ; un clic hors du tiroir également.
    sidebar.addEventListener("click", (e) => { if (drawerMode() && e.target.closest("a[href]")) setDrawer(false, { focus: false }); });
    sidebar.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && drawerMode() && !sidebar.hidden) {
        e.preventDefault();
        setDrawer(false);
      }
    });
    const onOutside = (e) => {
      if (drawerMode() && !sidebar.hidden && !sidebar.contains(e.target) && !menuBtn.contains(e.target)) setDrawer(false, { focus: false });
    };
    document.addEventListener("pointerdown", onOutside, true);
    cleanups.push(() => document.removeEventListener("pointerdown", onOutside, true));
    for (const query of [DRAWER_QUERY, COMPACT_QUERY]) {
      const mq = window.matchMedia(query);
      const on = () => { setDrawer(false, { focus: false }); compactButtons(); };
      mq.addEventListener("change", on);
      cleanups.push(() => mq.removeEventListener("change", on));
    }
    const offSettings = S.subscribe("vault.users_can_create_shared", () => renderNav());
    cleanups.push(offSettings);

    counts = defaultCounts();
    renderNav();
    setDrawer(false, { focus: false });
    compactButtons();
    setOffline(typeof navigator !== "undefined" && navigator.onLine === false);
    scheduleHealth();
  }

  function unmount() {
    if (!els) return;
    clearTimeout(healthTimer);
    while (cleanups.length) cleanups.pop()();
    const { appEl, mainEl, sidebar, column } = els;
    hideLockWarning();
    sidebar.remove();
    column.replaceWith(mainEl);
    appEl.classList.remove("l-shell");
    els = null;
    counts = {};
    scope = null;
    provider = undefined;
  }

  // ---------------------------------------------------------- État

  /** Route affichée : entrée courante de la barre latérale et du commutateur. */
  function setCurrent(route, params = {}) {
    current = {
      nav: route?.nav ?? null,
      collectionId: params.collectionId ?? null,
      admin: !!route?.admin,
    };
    markCurrent();
    if (route?.nav !== "collection" && scope && !route?.pattern?.startsWith("/element")) setSearchScope(null);
    hideResults();
  }

  /** Après une synchronisation : liste des coffres et compteurs, dans les mêmes nœuds. */
  function update() {
    if (!els) return;
    counts = { ...counts, ...defaultCounts() };
    renderNav();
    scheduleHealth();
  }

  function setOffline(offline) {
    if (!els) return;
    if (offline && !els.offline) {
      els.offline = offlineBanner();
      els.notices.prepend(els.offline);
    } else if (!offline && els.offline) {
      els.offline.remove();
      els.offline = null;
    }
  }

  /** Préavis de verrouillage automatique (règle A12) : annoncé par #alert. */
  function showLockWarning(seconds, onStay) {
    if (!els) return;
    hideLockWarning();
    const text = plural("shell.lock.warning", seconds);
    const stay = button({ label: t("shell.lock.stay"), variant: "primary", onClick: () => { hideLockWarning(); onStay?.(); } });
    els.warning = h("div", { class: "c-alert", "data-tone": "warn" }, icon("clock"),
      h("div", { class: "l-cluster", "data-justify": "between" }, h("p", {}, text), stay));
    els.notices.append(els.warning);
    announce(text, { assertive: true });
  }

  function hideLockWarning() {
    els?.warning?.remove();
    if (els) els.warning = null;
  }

  return {
    mount,
    unmount,
    setCurrent,
    update,
    setSidebarCounts,
    openGeneratorPanel,
    setSearchScope,
    openAccountMenu,
    focusSearch,
    setOffline,
    showLockWarning,
    hideLockWarning,
    isMounted: () => !!els,
    /** Sous-ensemble exposé aux vues (ctx.shell, contrat C4.3). */
    api: { setSidebarCounts, openGeneratorPanel, setSearchScope, openAccountMenu },
  };
}

