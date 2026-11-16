// Point d'entrée : écrans de connexion, coquille principale, verrouillage.

import { h, clear, icon, logo, toast, modal, initials } from "./dom.js";
import { loadCrypto, call, nextFrame } from "./wasm.js";
import { api, hasToken, onSessionExpired, setToken } from "./api.js";
import * as V from "./vault.js";
import { renderVault } from "./views/vaultview.js";
import { renderGenerator, renderHealth, renderShares, renderSettings } from "./views/pages.js";
import { renderAdmin } from "./views/admin.js";
import { prefs } from "./prefs.js";

const root = document.getElementById("app");
export const ui = { view: "vault", filter: { type: "all" }, search: "", selected: null };

// ------------------------------------------------------------ Démarrage

async function boot() {
  clear(root, h("div", { class: "busy" }, h("span", { class: "spinner" }), "Chargement du module de chiffrement…"));
  try {
    await loadCrypto();
  } catch (e) {
    clear(root, authCard("Navigateur non pris en charge", h("p", {}, "Le module de chiffrement n'a pas pu être chargé. Utilisez une version récente de Chrome, Edge, Firefox ou Safari.")));
    return;
  }
  onSessionExpired(() => {
    V.lock();
    toast("Votre session a expiré. Reconnectez-vous.", "bad");
    route();
  });
  window.addEventListener("hashchange", route);
  route();
}

function hashParts() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, query] = raw.split("?");
  return { path: path || "", params: new URLSearchParams(query || "") };
}

export function go(path) {
  if (location.hash === `#/${path}`) route();
  else location.hash = `#/${path}`;
}

async function route() {
  const { path, params } = hashParts();
  if (path === "register") return renderRegister(params.get("token"));
  if (path === "recover") return renderRecover();
  if (path === "sso" && !V.isUnlocked()) return renderSso(params);
  if (!hasToken()) {
    const health = await api("GET", "/health").catch(() => null);
    if (health?.needs_setup) return renderRegister(null, true);
    return renderLogin(health);
  }
  if (!V.isUnlocked()) return renderLock();
  const view = ["vault", "generator", "health", "shares", "settings", "admin"].includes(path) ? path : "vault";
  ui.view = view;
  if (V.state.profile?.must_setup_2fa && view !== "settings") {
    toast("Votre organisation impose la double authentification : activez-la pour continuer.");
    return go("settings");
  }
  renderShell();
}

// ------------------------------------------------------------ Écrans d'accès

function authCard(title, ...content) {
  return h("div", { class: "auth" },
    h("div", { class: "auth-card" },
      h("div", { class: "brand" }, logo(), "Locksy"),
      h("h1", {}, title),
      ...content));
}

function passwordInput(id, placeholder = "", autocomplete = "current-password") {
  const input = h("input", { class: "input", id, type: "password", autocomplete, placeholder, required: true });
  const btn = h("button", { class: "btn icon", type: "button", "aria-label": "Afficher ou masquer", onclick: () => {
    input.type = input.type === "password" ? "text" : "password";
    clear(btn, icon(input.type === "password" ? "eye" : "eyeoff"));
  } }, icon("eye"));
  return { input, row: h("div", { class: "input-row" }, input, btn) };
}

function busyButton(btn, label) {
  btn.disabled = true;
  clear(btn, h("span", { class: "spinner" }), label);
}

function errorBox() {
  return h("div", { class: "notice bad hidden", role: "alert" });
}

function showError(box, msg) {
  box.textContent = msg;
  box.classList.remove("hidden");
}

function ssoButton(sso, primary = false) {
  return h("a", { class: `btn block ${primary ? "primary" : ""}`, href: "/api/sso/start?target=web" }, icon("shield"), `Se connecter avec ${sso.label}`);
}

/** Formulaire « compte Windows » : identifiant et mot de passe Active Directory. */
function windowsForm(ldap, primary) {
  const user = h("input", { class: "input", id: "win-user", autocomplete: "username", required: true, placeholder: "DOMAINE\\identifiant", value: prefs.get("lastWindowsUser", "") });
  const pw = passwordInput("win-pw", "", "current-password");
  const err = errorBox();
  const submit = h("button", { class: `btn block ${primary ? "primary" : ""}`, type: "submit" }, icon("shield"), `Se connecter avec mon ${ldap.label.toLowerCase().startsWith("compte") ? ldap.label.charAt(0).toLowerCase() + ldap.label.slice(1) : ldap.label}`);
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    err.classList.add("hidden");
    busyButton(submit, "Vérification auprès de l'annuaire…");
    try {
      const res = await api("POST", "/ldap/login", { username: user.value.trim(), password: pw.input.value });
      pw.input.value = "";
      prefs.set("lastWindowsUser", user.value.trim());
      renderSso(new URLSearchParams(), res);
    } catch (ex) {
      showError(err, ex.message);
      clear(submit, icon("shield"), "Réessayer");
      submit.disabled = false;
    }
  } },
    h("div", { class: "field" }, h("label", { for: "win-user" }, "Identifiant Windows"), user),
    h("div", { class: "field" }, h("label", { for: "win-pw" }, "Mot de passe Windows"), pw.row),
    err, submit);
  return { form, focus: () => (user.value ? pw.input : user).focus() };
}

function renderLogin(health) {
  const sso = health?.sso;
  const ldap = health?.ldap;
  const email = h("input", { class: "input", id: "email", type: "email", autocomplete: "username", required: true, value: prefs.get("lastEmail", "") });
  const pw = passwordInput("password");
  const err = errorBox();
  const submit = h("button", { class: "btn primary block", type: "submit" }, "Se connecter");
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    err.classList.add("hidden");
    busyButton(submit, "Dérivation de la clé…");
    await nextFrame();
    try {
      const res = await V.login({ email: email.value.trim(), password: pw.input.value });
      pw.input.value = "";
      prefs.set("lastEmail", email.value.trim());
      if (res.needTotp) return renderTotp(res.pending);
      afterUnlock();
    } catch (ex) {
      showError(err, ex.message);
      clear(submit, "Se connecter");
      submit.disabled = false;
    }
  } },
    h("div", { class: "field" }, h("label", { for: "email" }, "Adresse e-mail"), email),
    h("div", { class: "field" }, h("label", { for: "password" }, "Mot de passe maître"), pw.row),
    err, submit);
  const intro = h("p", { class: "muted" }, "Votre mot de passe maître ne quitte jamais cet appareil : il sert à déchiffrer votre coffre localement.");
  const links = h("div", { class: "auth-links" }, h("a", { href: "#/recover" }, "Mot de passe maître oublié ?"));
  const enforced = sso?.enforced || ldap?.enforced;
  const win = ldap ? windowsForm(ldap, true) : null;
  const corporate = [
    win ? h("div", { class: "form" }, h("p", { class: "small muted" }, "Identifiez-vous avec votre session d'entreprise, puis votre mot de passe maître déchiffrera le coffre."), win.form) : null,
    sso ? ssoButton(sso, !win) : null,
  ];
  if (enforced) {
    // Connexion par mot de passe seul réservée aux propriétaires (accès de secours).
    clear(root, authCard("Connexion", corporate,
      h("details", {}, h("summary", { class: "small muted", style: "cursor:pointer" }, "Accès de secours (propriétaire)"), h("div", { style: "margin-top:12px" }, form)),
      links));
    win?.focus();
    return;
  }
  const or = h("div", { class: "row small muted", style: "justify-content:center" }, "ou avec votre adresse et votre mot de passe maître");
  clear(root, authCard("Connexion", win || sso ? [corporate, or] : intro, form, links));
  if (win) win.focus(); else (email.value ? pw.input : email).focus();
}

function renderTotp(pending) {
  const code = h("input", { class: "input", id: "totp", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 8, required: true, style: "font-size:1.4rem;letter-spacing:.3em;text-align:center" });
  const err = errorBox();
  const submit = h("button", { class: "btn primary block", type: "submit" }, "Valider");
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    busyButton(submit, "Vérification…");
    try {
      const res = await V.finishLogin(pending, code.value.trim());
      if (res.needTotp) {
        showError(err, res.error || "Code incorrect.");
        code.value = "";
        clear(submit, "Valider");
        submit.disabled = false;
        return;
      }
      afterUnlock();
    } catch (ex) {
      showError(err, ex.message);
      clear(submit, "Valider");
      submit.disabled = false;
    }
  } }, h("div", { class: "field" }, h("label", { for: "totp" }, "Code à 6 chiffres"), code), err, submit);
  clear(root, authCard("Double authentification", h("p", { class: "muted" }, "Ouvrez votre application d'authentification et saisissez le code affiché pour Locksy."), form,
    h("div", { class: "auth-links" }, h("a", { href: "#/", onclick: () => call("drop_key", { key: pending.encKey }) }, "Annuler"))));
  code.focus();
}

function renderLock() {
  const pw = passwordInput("password");
  const err = errorBox();
  const submit = h("button", { class: "btn primary block", type: "submit" }, "Déverrouiller");
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    busyButton(submit, "Déverrouillage…");
    await nextFrame();
    try {
      await V.unlock(pw.input.value);
      pw.input.value = "";
      afterUnlock();
    } catch (ex) {
      showError(err, ex.message);
      clear(submit, "Déverrouiller");
      submit.disabled = false;
      pw.input.select();
    }
  } }, h("div", { class: "field" }, h("label", { for: "password" }, "Mot de passe maître"), pw.row), err, submit);
  clear(root, authCard("Coffre verrouillé", h("p", { class: "muted" }, "Votre session est ouverte, mais les clés ont été effacées de la mémoire. Saisissez votre mot de passe maître."), form,
    h("div", { class: "auth-links" }, h("a", { href: "#/", onclick: async (e) => { e.preventDefault(); await V.logout(); route(); } }, "Changer de compte"))));
  pw.input.focus();
}

function strengthMeter(input) {
  const bar = h("div", { class: "strength" }, h("span"), h("span"), h("span"), h("span"), h("span"));
  const label = h("span", { class: "small muted" });
  const tips = h("div", { class: "small muted" });
  const update = () => {
    if (!input.value) { bar.className = "strength"; label.textContent = ""; tips.textContent = ""; return; }
    const s = call("strength", { password: input.value });
    bar.className = `strength s${s.score}`;
    label.textContent = `${s.label} · ${Math.round(s.entropy_bits)} bits`;
    tips.textContent = s.warnings.join(" ");
  };
  input.addEventListener("input", update);
  return { el: h("div", { class: "field" }, h("div", { class: "row" }, bar, label), tips), score: () => call("strength", { password: input.value }).score };
}

async function renderRegister(token, firstSetup = false) {
  let invite = null;
  if (token) {
    invite = await api("GET", `/invites/${encodeURIComponent(token)}`).catch((e) => ({ error: e.message }));
    if (invite.error) {
      clear(root, authCard("Invitation invalide", h("p", {}, invite.error), h("a", { class: "btn", href: "#/" }, "Retour à la connexion")));
      return;
    }
  }
  const email = h("input", { class: "input", id: "email", type: "email", autocomplete: "username", required: true, value: invite?.email || "", readonly: !!invite });
  const name = h("input", { class: "input", id: "name", autocomplete: "name", required: true, maxlength: 100 });
  const pw = passwordInput("password", "", "new-password");
  const pw2 = passwordInput("password2", "", "new-password");
  const meter = strengthMeter(pw.input);
  const err = errorBox();
  const submit = h("button", { class: "btn primary block", type: "submit" }, "Créer mon coffre");
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    err.classList.add("hidden");
    if (pw.input.value.length < 12) return showError(err, "Le mot de passe maître doit faire au moins 12 caractères.");
    if (meter.score() < 3) return showError(err, "Mot de passe maître trop faible. Une phrase de plusieurs mots est idéale.");
    if (pw.input.value !== pw2.input.value) return showError(err, "Les deux saisies ne correspondent pas.");
    busyButton(submit, "Génération des clés…");
    await nextFrame();
    try {
      const recovery = await V.register({ email: email.value.trim(), name: name.value.trim(), password: pw.input.value, inviteToken: token });
      pw.input.value = pw2.input.value = "";
      prefs.set("lastEmail", email.value.trim());
      showRecoveryKey(recovery, () => { history.replaceState(null, "", "#/vault"); afterUnlock(); });
    } catch (ex) {
      showError(err, ex.message);
      clear(submit, "Créer mon coffre");
      submit.disabled = false;
    }
  } },
    h("div", { class: "field" }, h("label", { for: "email" }, "Adresse e-mail"), email),
    h("div", { class: "field" }, h("label", { for: "name" }, "Nom affiché"), name),
    h("div", { class: "field" }, h("label", { for: "password" }, "Mot de passe maître"), pw.row),
    meter.el,
    h("div", { class: "field" }, h("label", { for: "password2" }, "Confirmez le mot de passe maître"), pw2.row),
    h("div", { class: "notice warn small" }, "Personne, pas même l'administrateur, ne pourra retrouver ce mot de passe. Une clé de récupération vous sera remise juste après."),
    err, submit);
  const title = firstSetup ? "Installation de Locksy" : "Créer votre compte";
  const intro = firstSetup
    ? "Aucun compte n'existe encore. Le premier compte créé devient propriétaire de l'organisation."
    : `Vous avez été invité${invite?.role === "admin" ? " en tant qu'administrateur" : ""}.`;
  clear(root, authCard(title, h("p", { class: "muted" }, intro), form,
    firstSetup ? null : h("div", { class: "auth-links" }, h("a", { href: "#/" }, "J'ai déjà un compte"))));
  (invite ? name : email).focus();
}

export function showRecoveryKey(display, onDone) {
  const ack = h("input", { type: "checkbox", id: "ack" });
  const btn = h("button", { class: "btn primary block", disabled: true, onclick: () => onDone() }, "Continuer");
  ack.addEventListener("change", () => { btn.disabled = !ack.checked; });
  const copyBtn = h("button", { class: "btn", onclick: async () => {
    try { await navigator.clipboard.writeText(display); toast("Clé copiée. Collez-la dans un endroit sûr puis videz le presse-papiers."); } catch { toast("Copie impossible : recopiez la clé à la main.", "bad"); }
  } }, icon("copy"), "Copier");
  clear(root, authCard("Votre clé de récupération",
    h("p", {}, "C'est le seul moyen de retrouver l'accès à votre coffre si vous oubliez votre mot de passe maître. Imprimez-la ou rangez-la hors de cet ordinateur (coffre physique, autre gestionnaire)."),
    h("div", { class: "recovery-key", tabindex: 0 }, display),
    h("div", { class: "row" }, copyBtn),
    h("label", { class: "check" }, ack, "J'ai mis cette clé en lieu sûr. Elle ne sera plus jamais affichée."),
    btn));
}

async function renderSso(params, preloaded = null) {
  const ticket = preloaded?.ticket || params.get("ticket");
  const error = params.get("error");
  if (!preloaded) history.replaceState(null, "", "#/sso");
  const back = h("div", { class: "auth-links" }, h("a", { href: "#/" }, "Retour à la connexion"));
  if (error || !ticket) {
    clear(root, authCard("Connexion SSO impossible", h("div", { class: "notice bad" }, error || "Ticket manquant."), back));
    return;
  }
  let info = preloaded?.info;
  try {
    if (!info) info = await api("POST", "/sso/redeem", { ticket });
  } catch (e) {
    clear(root, authCard("Connexion SSO impossible", h("div", { class: "notice bad" }, e.message), back));
    return;
  }
  const err = errorBox();
  if (info.registered) {
    const pw = passwordInput("password");
    const submit = h("button", { class: "btn primary block", type: "submit" }, "Déverrouiller");
    const form = h("form", { class: "form", onsubmit: async (e) => {
      e.preventDefault();
      busyButton(submit, "Déchiffrement…");
      await nextFrame();
      try {
        const res = await V.login({ email: info.email, password: pw.input.value, ssoTicket: ticket, kdf: info.kdf });
        pw.input.value = "";
        prefs.set("lastEmail", info.email);
        if (res.needTotp) return renderTotp(res.pending);
        history.replaceState(null, "", "#/vault");
        afterUnlock();
      } catch (ex) {
        showError(err, ex.message);
        clear(submit, "Déverrouiller");
        submit.disabled = false;
      }
    } }, h("div", { class: "field" }, h("label", { for: "password" }, "Mot de passe maître"), pw.row), err, submit);
    clear(root, authCard(`Bonjour ${info.name || info.email}`,
      h("div", { class: "notice small" }, `Identité confirmée par votre entreprise : ${info.email}`),
      h("p", { class: "muted" }, "Saisissez votre mot de passe maître : lui seul peut déchiffrer votre coffre, l'entreprise ne le connaît pas."),
      form, back));
    pw.input.focus();
    return;
  }
  if (!info.can_register) {
    clear(root, authCard("Compte non ouvert", h("p", {}, `Votre identité (${info.email}) est confirmée, mais aucun compte Locksy n'a encore été ouvert pour vous. Demandez à votre administrateur de vous ajouter à l'application Locksy dans l'annuaire, ou de vous envoyer une invitation.`), back));
    return;
  }
  const name = h("input", { class: "input", id: "name", value: info.name || "", required: true, maxlength: 100 });
  const pw = passwordInput("password", "", "new-password");
  const pw2 = passwordInput("password2", "", "new-password");
  const meter = strengthMeter(pw.input);
  const submit = h("button", { class: "btn primary block", type: "submit" }, "Créer mon coffre");
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    err.classList.add("hidden");
    if (pw.input.value.length < 12 || meter.score() < 3) return showError(err, "Mot de passe maître trop faible : 12 caractères minimum, une phrase de plusieurs mots est idéale.");
    if (pw.input.value !== pw2.input.value) return showError(err, "Les deux saisies ne correspondent pas.");
    busyButton(submit, "Génération des clés…");
    await nextFrame();
    try {
      const recovery = await V.register({ email: info.email, name: name.value.trim(), password: pw.input.value, ssoTicket: ticket });
      pw.input.value = pw2.input.value = "";
      prefs.set("lastEmail", info.email);
      showRecoveryKey(recovery, () => { history.replaceState(null, "", "#/vault"); afterUnlock(); });
    } catch (ex) {
      showError(err, ex.message);
      clear(submit, "Créer mon coffre");
      submit.disabled = false;
    }
  } },
    h("div", { class: "field" }, h("span", { class: "label" }, "Adresse e-mail"), h("div", {}, info.email)),
    h("div", { class: "field" }, h("label", { for: "name" }, "Nom affiché"), name),
    h("div", { class: "field" }, h("label", { for: "password" }, "Choisissez votre mot de passe maître"), pw.row),
    meter.el,
    h("div", { class: "field" }, h("label", { for: "password2" }, "Confirmez-le"), pw2.row),
    h("div", { class: "notice warn small" }, "Ce mot de passe chiffre votre coffre. Il est distinct de celui de votre compte d'entreprise, et personne ne pourra le retrouver pour vous : une clé de récupération vous sera remise."),
    err, submit);
  clear(root, authCard("Créer votre coffre", h("div", { class: "notice small" }, `Identité confirmée par votre entreprise : ${info.email}`), form, back));
  pw.input.focus();
}

function renderRecover() {
  const email = h("input", { class: "input", id: "email", type: "email", required: true, value: prefs.get("lastEmail", "") });
  const key = h("textarea", { class: "input mono", id: "rkey", required: true, rows: 3, placeholder: "XXXX-XXXX-XXXX-…", spellcheck: "false" });
  const pw = passwordInput("password", "", "new-password");
  const meter = strengthMeter(pw.input);
  const err = errorBox();
  const submit = h("button", { class: "btn primary block", type: "submit" }, "Définir le nouveau mot de passe");
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    err.classList.add("hidden");
    if (pw.input.value.length < 12 || meter.score() < 3) return showError(err, "Choisissez un mot de passe maître plus robuste (12 caractères minimum).");
    busyButton(submit, "Récupération…");
    await nextFrame();
    try {
      await V.recoverAccount(email.value.trim(), key.value, pw.input.value);
      pw.input.value = "";
      key.value = "";
      toast("Mot de passe maître remplacé. Connectez-vous.");
      setToken(null);
      location.hash = "#/";
    } catch (ex) {
      showError(err, ex.message);
      clear(submit, "Définir le nouveau mot de passe");
      submit.disabled = false;
    }
  } },
    h("div", { class: "field" }, h("label", { for: "email" }, "Adresse e-mail"), email),
    h("div", { class: "field" }, h("label", { for: "rkey" }, "Clé de récupération"), key),
    h("div", { class: "field" }, h("label", { for: "password" }, "Nouveau mot de passe maître"), pw.row),
    meter.el, err, submit);
  clear(root, authCard("Récupérer mon compte", h("p", { class: "muted" }, "Saisissez la clé de récupération reçue à la création de votre compte. Les fautes de frappe courantes (O/0, I/1) sont corrigées."), form,
    h("div", { class: "auth-links" }, h("a", { href: "#/" }, "Retour à la connexion"))));
}

async function afterUnlock() {
  clear(root, h("div", { class: "busy" }, h("span", { class: "spinner" }), "Déchiffrement du coffre…"));
  try {
    await V.sync();
  } catch (e) {
    toast(e.message, "bad");
  }
  startAutoLock();
  if (!location.hash || location.hash === "#/" || /register|recover/.test(location.hash)) location.hash = "#/vault";
  route();
}

// ------------------------------------------------------------ Verrouillage automatique

let idleTimer = null;
function startAutoLock() {
  const reset = () => {
    clearTimeout(idleTimer);
    const minutes = Number(prefs.get("autoLockMinutes", 10));
    if (minutes > 0) idleTimer = setTimeout(lockNow, minutes * 60_000);
  };
  ["mousemove", "keydown", "pointerdown", "scroll", "touchstart"].forEach((ev) => window.addEventListener(ev, reset, { passive: true }));
  reset();
}

export function lockNow() {
  if (!V.isUnlocked()) return;
  V.lock();
  document.querySelectorAll(".overlay").forEach((o) => o.remove());
  renderLock();
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden && prefs.get("lockOnHide", false)) lockNow();
});

// ------------------------------------------------------------ Coquille

export async function refresh(message) {
  try {
    await V.sync();
    if (message) toast(message);
  } catch (e) {
    toast(e.message, "bad");
  }
  renderShell();
}

function navItem(label, iconName, active, onClick, count) {
  return h("button", { class: `nav-item ${active ? "active" : ""}`, onclick: onClick }, icon(iconName), h("span", {}, label),
    count !== undefined ? h("span", { class: "count" }, count) : null);
}

function renderShell() {
  const p = V.state.profile;
  const items = [...V.state.items.values()];
  const live = items.filter((i) => !i.deleted_at);
  const f = ui.filter;
  const shell = h("div", { class: "shell" });
  const closeMenu = () => shell.classList.remove("menu-open");
  const setFilter = (filter) => { ui.filter = filter; ui.selected = null; closeMenu(); if (ui.view !== "vault") go("vault"); else renderShell(); };
  const isVault = ui.view === "vault";

  const collections = [...V.state.collections.values()];
  const nav = h("nav", { class: "nav", "aria-label": "Navigation" },
    navItem("Tous les éléments", "vault", isVault && f.type === "all" && !f.collection && !f.favorites && !f.trash, () => setFilter({ type: "all" }), live.length),
    navItem("Favoris", "star", isVault && f.favorites, () => setFilter({ type: "all", favorites: true }), live.filter((i) => i.data?.favorite).length),
    h("div", { class: "nav-title" }, "Coffres",
      h("button", { class: "btn ghost small", title: "Nouveau coffre partagé", "aria-label": "Nouveau coffre partagé", onclick: () => import("./views/vaultview.js").then((m) => m.newCollectionDialog()) }, icon("plus"))),
    collections.map((c) => navItem(c.personal ? "Personnel" : c.name, c.personal ? "lock" : "folder", isVault && f.collection === c.id,
      () => setFilter({ type: "all", collection: c.id }), live.filter((i) => i.collection_id === c.id).length)),
    navItem("Corbeille", "trash", isVault && f.trash, () => setFilter({ type: "all", trash: true }), items.length - live.length),
    h("div", { class: "nav-title" }, "Outils"),
    navItem("Générateur", "wand", ui.view === "generator", () => { closeMenu(); go("generator"); }),
    navItem("Santé des mots de passe", "heart", ui.view === "health", () => { closeMenu(); go("health"); }),
    navItem("Liens de partage", "link", ui.view === "shares", () => { closeMenu(); go("shares"); }),
    navItem("Paramètres", "settings", ui.view === "settings", () => { closeMenu(); go("settings"); }),
    p.role !== "user" ? navItem("Administration", "users", ui.view === "admin", () => { closeMenu(); go("admin"); }) : null);

  const sidebar = h("aside", { class: "sidebar" },
    h("div", { class: "brand" }, logo(), "Locksy"),
    nav,
    h("div", { class: "sidebar-foot" },
      h("div", { class: "user-badge" }, h("div", { class: "avatar" }, initials(p.name)),
        h("div", { class: "who" }, h("div", { style: "font-weight:600" }, p.name), h("div", { class: "small muted" }, p.email))),
      h("div", { class: "row" },
        h("button", { class: "btn small", onclick: lockNow }, icon("lock"), "Verrouiller"),
        h("button", { class: "btn small ghost", onclick: async () => { await V.logout(); location.hash = "#/"; route(); } }, icon("logout"), "Quitter"))));

  const search = h("input", { class: "input", type: "search", placeholder: "Rechercher (nom, identifiant, site, étiquette)…", value: ui.search, "aria-label": "Rechercher" });
  search.addEventListener("input", () => {
    ui.search = search.value;
    if (ui.view !== "vault") { go("vault"); return; }
    document.dispatchEvent(new CustomEvent("locksy:search"));
  });
  const topbar = h("header", { class: "topbar" },
    h("button", { class: "btn icon menu-toggle", "aria-label": "Menu", onclick: () => shell.classList.toggle("menu-open") }, icon("menu")),
    h("div", { class: "search" }, icon("search"), search),
    h("button", { class: "btn icon", title: "Synchroniser", "aria-label": "Synchroniser", onclick: () => refresh("Coffre synchronisé.") }, icon("refresh")));

  const content = h("div", { class: "content" });
  shell.append(sidebar, h("div", { class: "main" }, topbar, content));
  clear(root, shell);
  const views = { vault: renderVault, generator: renderGenerator, health: renderHealth, shares: renderShares, settings: renderSettings, admin: renderAdmin };
  (views[ui.view] || renderVault)(content);
  if (ui.view === "vault" && ui.search) { search.focus(); search.setSelectionRange(search.value.length, search.value.length); }
}

boot();

// Pour les modules de vues.
export { modal };
