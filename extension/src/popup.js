// Extension Locksy : déverrouillage, recherche, remplissage et ajout d'identifiants.
// Même noyau cryptographique que l'interface web (WebAssembly), mêmes règles :
// le serveur ne reçoit que des chiffrés.

import { h, clear, icon, logo, toast, colorFor, initials, safeUrl } from "./lib/dom.js";
import { loadCrypto, call, nextFrame } from "./lib/wasm.js";
import { api, setBase, setToken, getToken } from "./lib/api.js";
import * as V from "./lib/vault.js";

const root = document.getElementById("app");
const AUTO_LOCK_MIN = 15;

// --------------------------------------------------------------- Accès au navigateur
// Hors extension (page de test servie par le serveur), on simule les API.
const memory = { local: {}, session: {} };
const fake = {
  storage: {
    local: { get: async (k) => ({ [k]: memory.local[k] }), set: async (o) => Object.assign(memory.local, o), remove: async (k) => delete memory.local[k] },
    session: { get: async (k) => ({ [k]: memory.session[k] }), set: async (o) => Object.assign(memory.session, o), remove: async (k) => delete memory.session[k] },
  },
  permissions: { request: async () => true, contains: async () => true },
  tabs: { query: async () => [{ id: 0, url: new URLSearchParams(location.search).get("page") || location.href }] },
  scripting: null,
};
const ext = globalThis.chrome?.storage?.session ? globalThis.chrome : fake;
const store = {
  get: async (area, k) => (await ext.storage[area].get(k))[k],
  set: (area, k, v) => ext.storage[area].set({ [k]: v }),
  del: (area, k) => ext.storage[area].remove(k),
};

let tab = null;
let pageHost = "";

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

/** Même site : hôtes identiques, ou l'un sous-domaine de l'autre. */
function sameSite(a, b) {
  if (!a || !b) return false;
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

function itemMatches(item) {
  return (item.data.urls || []).some((u) => sameSite(hostOf(safeUrl(u) || ""), pageHost));
}

// --------------------------------------------------------------- Démarrage

async function boot() {
  [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  pageHost = hostOf(tab?.url || "");
  await loadCrypto("lib/locksy.wasm");
  V.setDeviceLabel("Extension");
  const server = await store.get("local", "server");
  if (!server) return renderSetup();
  setBase(server);
  const s = await store.get("session", "vault");
  if (s && s.expires > Date.now()) {
    try {
      setToken(s.token);
      V.restoreSession(s.keys);
      await V.sync();
      await saveSession();
      return renderMain();
    } catch (e) {
      await lock();
      return renderLogin(e.message);
    }
  }
  renderLogin();
}

async function saveSession() {
  await store.set("session", "vault", { token: getToken(), keys: V.exportSession(), expires: Date.now() + AUTO_LOCK_MIN * 60_000 });
}

async function lock() {
  await store.del("session", "vault");
  V.lock();
}

function shell(...content) {
  clear(root, h("div", { class: "pop" },
    h("div", { class: "pop-head" }, h("div", { class: "brand" }, logo(), "Locksy"), ...content.splice(0, 1)),
    ...content));
}

// --------------------------------------------------------------- Écrans

function renderSetup(error) {
  const url = h("input", { class: "input", id: "server", value: "http://localhost:8743", placeholder: "https://coffre.entreprise.fr" });
  const err = h("div", { class: `notice bad ${error ? "" : "hidden"}` }, error || "");
  shell(null,
    h("h2", {}, "Adresse de votre serveur"),
    h("p", { class: "small muted" }, "L'extension ne contactera que ce serveur. Votre navigateur vous demandera de l'autoriser."),
    h("div", { class: "field" }, h("label", { for: "server" }, "Serveur Locksy"), url),
    err,
    h("button", { class: "btn primary block", onclick: async () => {
      let origin;
      try {
        const u = new URL(url.value.trim());
        const local = ["localhost", "127.0.0.1"].includes(u.hostname);
        if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new Error("Utilisez une adresse en https:// (ou http://localhost).");
        origin = u.origin;
      } catch (e) {
        return renderSetup(e.message.startsWith("Utilisez") ? e.message : "Adresse invalide.");
      }
      const granted = await ext.permissions.request({ origins: [`${origin}/*`] });
      if (!granted) return renderSetup("Autorisation refusée : l'extension ne peut pas joindre ce serveur.");
      try {
        const r = await fetch(`${origin}/api/health`, { cache: "no-store" });
        if (!r.ok) throw new Error();
      } catch {
        return renderSetup("Aucun serveur Locksy ne répond à cette adresse.");
      }
      await store.set("local", "server", origin);
      setBase(origin);
      renderLogin();
    } }, "Continuer"));
  url.focus();
}

async function renderLogin(error, pending) {
  const server = await store.get("local", "server");
  const email = h("input", { class: "input", id: "email", type: "email", value: (await store.get("local", "email")) || "" });
  const pw = h("input", { class: "input", id: "pw", type: "password", autocomplete: "current-password" });
  const code = h("input", { class: "input", id: "code", inputmode: "numeric", maxlength: 8, placeholder: "123456" });
  const err = h("div", { class: `notice bad ${error ? "" : "hidden"}` }, error || "");
  const btn = h("button", { class: "btn primary block", type: "submit" }, pending ? "Valider" : "Déverrouiller");
  const health = pending ? null : await fetch(`${server}/api/health`, { cache: "no-store" }).then((r) => r.json()).catch(() => null);
  const sso = health?.sso && ext.identity?.launchWebAuthFlow ? health.sso : null;
  const ssoBtn = sso
    ? h("button", { class: `btn block ${sso.enforced ? "primary" : ""}`, onclick: () => ssoLogin(server) }, icon("shield"), `Se connecter avec ${sso.label}`)
    : null;
  const ldap = pending ? null : health?.ldap;
  const winUser = h("input", { class: "input", id: "win-user", placeholder: "DOMAINE\\identifiant", value: (await store.get("local", "winUser")) || "" });
  const winPw = h("input", { class: "input", id: "win-pw", type: "password", autocomplete: "current-password" });
  const winBtn = h("button", { class: "btn primary block", type: "submit" }, icon("shield"), "Se connecter");
  const winForm = ldap ? h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    winBtn.disabled = true;
    clear(winBtn, h("span", { class: "spinner" }), "Vérification auprès de l'annuaire…");
    try {
      const r = await api("POST", "/ldap/login", { username: winUser.value.trim(), password: winPw.value });
      winPw.value = "";
      await store.set("local", "winUser", winUser.value.trim());
      if (!r.info.registered) return renderLogin(`Identité confirmée (${r.info.email}), mais vous n'avez pas encore de coffre : créez-le depuis l'interface web de Locksy.`);
      renderSsoPassword(r.ticket, r.info);
    } catch (ex) {
      renderLogin(ex.message);
    }
  } },
    h("div", { class: "section-label" }, `Avec votre ${ldap.label.toLowerCase()}`),
    h("div", { class: "field" }, h("label", { for: "win-user" }, "Identifiant Windows"), winUser),
    h("div", { class: "field" }, h("label", { for: "win-pw" }, "Mot de passe Windows"), winPw),
    winBtn) : null;
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true;
    clear(btn, h("span", { class: "spinner" }), pending ? "Vérification…" : "Déchiffrement…");
    await nextFrame();
    try {
      const r = pending ? await V.finishLogin(pending, code.value.trim()) : await V.login({ email: email.value.trim(), password: pw.value });
      pw.value = "";
      if (r.needTotp) return renderLogin(r.error, r.pending);
      await store.set("local", "email", email.value.trim() || (await store.get("local", "email")));
      await V.sync();
      await saveSession();
      renderMain();
    } catch (ex) {
      renderLogin(ex.message, pending);
    }
  } },
    pending
      ? h("div", { class: "field" }, h("label", { for: "code" }, "Code de double authentification"), code)
      : [h("div", { class: "field" }, h("label", { for: "email" }, "Adresse e-mail"), email),
         h("div", { class: "field" }, h("label", { for: "pw" }, "Mot de passe maître"), pw)],
    err, btn);
  shell(h("button", { class: "btn ghost small", title: "Changer de serveur", onclick: async () => { await store.del("local", "server"); renderSetup(); } }, icon("settings")),
    h("div", { class: "site" }, server),
    winForm,
    ssoBtn,
    winForm || ssoBtn ? h("div", { class: "small muted", style: "text-align:center" }, sso?.enforced || ldap?.enforced ? "Accès de secours (propriétaires) :" : "ou avec votre adresse et votre mot de passe maître") : null,
    form);
  (pending ? code : winForm ? (winUser.value ? winPw : winUser) : email.value ? pw : email).focus();
}

// --------------------------------------------------------------- Connexion SSO

async function ssoLogin(server) {
  try {
    const redirect = ext.identity.getRedirectURL("sso");
    const back = await ext.identity.launchWebAuthFlow({
      url: `${server}/api/sso/start?target=extension&redirect=${encodeURIComponent(redirect)}`,
      interactive: true,
    });
    const frag = new URLSearchParams(new URL(back).hash.slice(1));
    if (frag.get("error")) return renderLogin(frag.get("error"));
    const ticket = frag.get("ticket");
    const info = await api("POST", "/sso/redeem", { ticket });
    if (!info.registered) {
      return renderLogin(`Identité confirmée (${info.email}), mais vous n'avez pas encore de coffre : créez-le depuis l'interface web avec la connexion SSO.`);
    }
    renderSsoPassword(ticket, info);
  } catch (e) {
    renderLogin(e.message?.includes("did not approve") ? "Connexion SSO annulée." : e.message);
  }
}

function renderSsoPassword(ticket, info, error) {
  const pw = h("input", { class: "input", id: "pw", type: "password", autocomplete: "current-password" });
  const err = h("div", { class: `notice bad ${error ? "" : "hidden"}` }, error || "");
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Déverrouiller");
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true;
    clear(btn, h("span", { class: "spinner" }), "Déchiffrement…");
    await nextFrame();
    try {
      await V.login({ email: info.email, password: pw.value, ssoTicket: ticket, kdf: info.kdf });
      pw.value = "";
      await store.set("local", "email", info.email);
      await V.sync();
      await saveSession();
      renderMain();
    } catch (ex) {
      // Le ticket a pu être consommé : on recommence le SSO si besoin.
      renderLogin(ex.message);
    }
  } }, h("div", { class: "field" }, h("label", { for: "pw" }, "Mot de passe maître"), pw), err, btn);
  shell(null,
    h("div", { class: "notice small" }, `Identité confirmée par votre entreprise : ${info.email}`),
    h("p", { class: "small muted" }, "Votre mot de passe maître déchiffre le coffre ; l'entreprise ne le connaît pas."),
    form);
  pw.focus();
}

function renderMain(query = "") {
  const all = [...V.state.items.values()].filter((i) => i.data && !i.deleted_at);
  const forSite = all.filter(itemMatches).sort((a, b) => a.data.name.localeCompare(b.data.name, "fr"));
  const search = h("input", { class: "input", type: "search", placeholder: "Rechercher dans le coffre…", value: query, "aria-label": "Rechercher" });
  const results = h("div", { class: "pop-list" });
  const draw = () => {
    const q = search.value.toLowerCase().trim();
    const list = q
      ? all.filter((i) => [i.data.name, i.data.username, ...(i.data.urls || []), ...(i.data.tags || [])].join(" ").toLowerCase().includes(q)).slice(0, 50)
      : forSite;
    clear(results, list.length ? list.map(row) : h("p", { class: "small muted" },
      q ? "Aucun résultat." : pageHost ? `Aucun identifiant enregistré pour ${pageHost}.` : "Ouvrez un site pour voir ses identifiants."));
  };
  search.addEventListener("input", draw);
  draw();
  shell(
    h("button", { class: "btn ghost small", title: "Verrouiller", onclick: async () => { await lock(); renderLogin(); } }, icon("lock")),
    pageHost ? h("div", { class: "site" }, "Site : ", h("strong", {}, pageHost)) : null,
    search,
    h("div", { class: "section-label" }, search.value ? "Résultats" : "Pour ce site"),
    results,
    h("div", { class: "row between" },
      pageHost ? h("button", { class: "btn small", onclick: renderAdd }, icon("plus"), "Enregistrer ce site") : h("span"),
      h("a", { class: "small", href: "#", onclick: async (e) => { e.preventDefault(); const s = await store.get("local", "server"); globalThis.chrome?.tabs?.create ? chrome.tabs.create({ url: s }) : open(s); } }, "Ouvrir Locksy")));
  search.focus();
}

function row(item) {
  const d = item.data;
  const col = V.state.collections.get(item.collection_id);
  const copy = async (value, label) => {
    try { await navigator.clipboard.writeText(value); toast(`${label} copié.`); } catch { toast("Copie refusée.", "bad"); }
  };
  let code = null;
  if (d.totp) { try { code = call("totp", { secret: d.totp, time: Math.floor(Date.now() / 1000) }).code; } catch { code = null; } }
  return h("div", { class: "pop-item" },
    h("div", { class: "icon-tile", style: `background:${colorFor(d.name)}` }, initials(d.name)),
    h("div", { style: "min-width:0" },
      h("div", { class: "t" }, d.name),
      h("div", { class: "s" }, d.username || (col?.personal ? "Personnel" : col?.name) || ""),
      code ? h("div", { class: "totp-mini" }, `Code 2FA : ${code}`) : null),
    h("div", { class: "acts" },
      d.password && pageHost ? h("button", { class: "btn primary small", title: "Remplir la page", onclick: () => fill(item) }, "Remplir") : null,
      d.username ? h("button", { class: "btn ghost small", title: "Copier l'identifiant", onclick: () => copy(d.username, "Identifiant") }, icon("users")) : null,
      d.password ? h("button", { class: "btn ghost small", title: "Copier le mot de passe", onclick: () => copy(d.password, "Mot de passe") }, icon("key")) : null,
      code ? h("button", { class: "btn ghost small", title: "Copier le code 2FA", onclick: () => copy(code, "Code") }, icon("clock")) : null));
}

// --------------------------------------------------------------- Remplissage

/** Exécutée dans la page : remplit identifiant et mot de passe du formulaire visible. */
function fillPage(username, password) {
  const visible = (el) => el.offsetParent !== null && !el.disabled && !el.readOnly && getComputedStyle(el).visibility !== "hidden";
  const pw = [...document.querySelectorAll('input[type="password"]')].find(visible);
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  let user = null;
  const scope = pw?.form || document;
  const candidates = [...scope.querySelectorAll('input[type="email"], input[type="text"], input[type="tel"], input:not([type])')].filter(visible);
  if (pw) {
    const before = candidates.filter((el) => el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING);
    user = before[before.length - 1] || null;
  } else {
    user = candidates.find((el) => /user|login|mail|ident/i.test(`${el.name} ${el.id} ${el.autocomplete}`)) || candidates[0] || null;
  }
  if (user && username) set(user, username);
  if (pw && password) set(pw, password);
  return { user: !!user, password: !!pw };
}

let pendingMismatch = null;

async function fill(item) {
  const d = item.data;
  if (!itemMatches(item) && pendingMismatch !== item.id) {
    pendingMismatch = item.id;
    toast(`Cet identifiant n'est pas enregistré pour ${pageHost}. Cliquez à nouveau sur « Remplir » si vous êtes sûr du site.`, "bad");
    return;
  }
  pendingMismatch = null;
  if (tab?.url?.startsWith("http://") && !["localhost", "127.0.0.1"].includes(pageHost)) {
    toast("Attention : cette page n'est pas chiffrée (http).", "bad");
  }
  if (!ext.scripting) {
    const r = fillPage(d.username, d.password);
    return toast(r.password ? "Formulaire rempli." : "Aucun champ de mot de passe trouvé.", r.password ? "" : "bad");
  }
  try {
    const [res] = await ext.scripting.executeScript({ target: { tabId: tab.id }, func: fillPage, args: [d.username, d.password] });
    if (!res?.result?.password) return toast("Aucun champ de mot de passe visible sur cette page.", "bad");
    window.close();
  } catch {
    toast("Cette page ne peut pas être remplie (page protégée du navigateur).", "bad");
  }
}

// --------------------------------------------------------------- Ajout

function renderAdd() {
  const target = [...V.state.collections.values()].find((c) => c.personal) || [...V.state.collections.values()].find((c) => ["manager", "editor"].includes(c.role));
  const gen = () => call("generate_password", { options: { length: 20, lower: true, upper: true, digits: true, symbols: true, avoid_ambiguous: true } }).value;
  const name = h("input", { class: "input", id: "n", value: pageHost.replace(/^www\./, "") });
  const user = h("input", { class: "input", id: "u" });
  const pw = h("input", { class: "input mono", id: "p", value: gen() });
  shell(h("button", { class: "btn ghost small", title: "Retour", onclick: () => renderMain() }, icon("back")),
    h("h2", {}, "Enregistrer ce site"),
    h("div", { class: "field" }, h("label", { for: "n" }, "Nom"), name),
    h("div", { class: "field" }, h("label", { for: "u" }, "Identifiant"), user),
    h("div", { class: "field" }, h("label", { for: "p" }, "Mot de passe"),
      h("div", { class: "input-row" }, pw, h("button", { class: "btn", title: "Générer", onclick: () => { pw.value = gen(); } }, icon("wand")))),
    h("p", { class: "small muted" }, `Sera enregistré dans « ${target?.personal ? "Personnel" : target?.name || "?"} » avec l'adresse ${tab?.url ? new URL(tab.url).origin : ""}.`),
    h("button", { class: "btn primary block", onclick: async () => {
      if (!name.value.trim()) return toast("Le nom est obligatoire.", "bad");
      try {
        const data = { ...V.emptyItem("login"), name: name.value.trim(), username: user.value.trim(), password: pw.value, urls: [new URL(tab.url).origin], password_changed_at: V.now() };
        await V.createItem(target.id, data);
        await V.sync();
        await saveSession();
        toast("Identifiant enregistré.");
        renderMain();
      } catch (e) {
        toast(e.message, "bad");
      }
    } }, "Enregistrer"));
  user.focus();
}

boot().catch((e) => clear(root, h("div", { class: "pop" }, h("div", { class: "notice bad" }, e.message))));
