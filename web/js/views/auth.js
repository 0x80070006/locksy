// Écrans d'accès (cahier §3.3.1, annexe C ; contrats C1.3 et C4.3) :
// connexion par la méthode principale de l'organisation (les autres repliées
// sous « Utiliser une autre méthode », absentes si une méthode est imposée,
// sauf l'accès de secours des propriétaires), code de vérification (ou code de
// secours), installation par le jeton, inscription sur invitation, clé de
// récupération (copie, fichier .txt), récupération du compte, retour de la
// connexion d'entreprise, coffre verrouillé, confirmation d'identité pour les
// actions sensibles (reauthUi, branchée sur api.withReauth par app.js).
//
// render(ctx) affiche l'écran ctx.route.screen ∈ login | install | register |
// recover | sso | locked. ctx (app.js) : { root, params, query, extras,
// navigate, setTitle, health, done({ password }), logout() }.
// Le mot de passe saisi n'est gardé que le temps de l'opération ; aucun
// secret n'est écrit hors mémoire (règle R5).

import {
  t, plural, errorText, h, clear, icon, uid, button, field, fieldError, fieldInput, textInput, textArea, passwordField,
  otpInput, normalizeCode, focusSafely, announce, notify, confirm, dialog, copySecret, avatar, busyWhile, fmtDate,
} from "../ui/index.js";
import * as V from "../vault.js";
import { api, ApiError, saveBlob, setToken } from "../api.js";
import * as S from "../settings-client.js";
import { call } from "../wasm.js";
import * as A from "../aad.js";
import { pinKdf } from "../pins.js";

const BACKUP_CODE_MIN = 10;

// ------------------------------------------------------------------ Mise en page

/** Carte centrée d'un écran d'accès : marque, titre (h1), contenu, pied. */
function authPage(ctx, title, ...content) {
  const pub = S.publicSettings();
  const org = pub?.branding?.org_name;
  const logoUrl = pub?.branding?.logo_url;
  const card = h("div", { class: "l-auth__card l-stack", "data-gap": "4" },
    h("p", { class: "l-cluster" },
      h("img", { src: logoUrl || "/favicon.svg", alt: "", width: "36", height: "36" }),
      h("strong", {}, org ? t("shell.brand_org", { org }) : t("common.app.name"))),
    h("h1", {}, title),
    ...content,
    footer());
  clear(ctx.root, h("div", { class: "l-auth" }, card));
  return card;
}

/** Pied des écrans d'accès : bannière, assistance, liens légaux (A20). */
function footer() {
  const pub = S.publicSettings();
  const legal = pub?.legal || {};
  const support = pub?.branding?.support_contact;
  const link = (url, route, label) => (url
    ? h("a", { href: url, rel: "noopener noreferrer", target: "_blank" }, label)
    : h("a", { href: `#${route}` }, label));
  return h("footer", { class: "l-stack u-muted", "data-gap": "2" },
    legal.login_banner ? h("p", {}, legal.login_banner) : null,
    support ? h("p", {}, t("auth.login.support", { contact: support })) : null,
    h("p", { class: "l-cluster" },
      link(legal.notice_url, "/mentions", t("legal.link.notice")),
      legal.privacy_url ? link(legal.privacy_url, "", t("legal.link.privacy")) : null,
      link(legal.accessibility_url, "/accessibilite", t("legal.link.accessibility"))));
}

/** Formulaire avec bouton principal ; onSubmit renvoie une promesse (bouton « en cours »). */
function authForm(children, { label, busyLabel, onSubmit }) {
  const submit = button({ label, variant: "primary", type: "submit" });
  const form = h("form", { class: "l-stack", "data-gap": "4", novalidate: true }, children, submit);
  let running = false;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (running) return;
    running = true;
    busyWhile(submit, Promise.resolve().then(onSubmit), busyLabel)
      .catch((err) => console.error(err))
      .finally(() => { running = false; });
  });
  return { form, submit };
}

const value = (fieldEl) => fieldInput(fieldEl).value;
const clearErrors = (...fields) => fields.forEach((f) => f && fieldError(f, null));

/**
 * Avant un calcul long et bloquant (Argon2, génération des clés) : laisse le
 * navigateur finir de traiter le clic et peindre l'état « en cours » (deux
 * images puis une tâche). Sans cela, sur une machine chargée, le calcul peut
 * démarrer avant la fin du traitement du clic : la page reste figée sans
 * indication. Onglet masqué (aucune image) : délai de secours d'une seconde.
 */
function beforeHeavyWork() {
  return new Promise((resolve) => {
    let done = false;
    const go = () => {
      if (!done) {
        done = true;
        resolve();
      }
    };
    if (document.hidden) return setTimeout(go, 0);
    requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(go, 0)));
    return setTimeout(go, 1000);
  });
}

/** Premier champ vide (focus initial, §3.3.1). */
function focusFirstEmpty(...fields) {
  const target = fields.filter(Boolean).map(fieldInput).find((i) => !i.value && !i.readOnly) || fields.filter(Boolean).map(fieldInput)[0];
  focusSafely(target);
}

/** Phrase d'un blocage : « Trop d'essais. Réessayez dans 15 min. » (délai de Retry-After). */
export function lockedText(retryAfter) {
  const s = Number(retryAfter);
  if (!Number.isFinite(s) || s <= 0) return t("auth.error.locked");
  if (s < 90) return plural("auth.error.locked_seconds", Math.ceil(s));
  return plural("auth.error.locked_minutes", Math.ceil(s / 60));
}

/** Message d'une erreur de connexion, sans jamais dire si le compte existe. */
export function loginErrorText(err, { windows = false } = {}) {
  const support = S.publicSettings()?.branding?.support_contact;
  switch (err?.code) {
    case "invalid_credentials":
    case "wrong_password":
      return t(windows ? "auth.error.windows_credentials" : "auth.error.credentials");
    case "rate_limited":
      return lockedText(err.retryAfter);
    case "account_disabled":
    case "account_expired":
      return support ? `${errorText(err)} ${t("auth.login.support", { contact: support })}` : errorText(err);
    default:
      return errorText(err);
  }
}

function policyProblemText(problem) {
  return t(`auth.policy.${problem.code}`, problem.params);
}

/** Vérifie le nouveau mot de passe maître et sa confirmation ; erreurs sous les champs. */
function checkNewPassword(pwField, confirmField, who) {
  const pw = value(pwField);
  const check = S.checkMasterPolicy(pw, who);
  if (!check.ok) {
    fieldError(pwField, check.problems.map(policyProblemText).join(" "));
    focusSafely(fieldInput(pwField));
    return false;
  }
  if (confirmField && value(confirmField) !== pw) {
    fieldError(confirmField, t("auth.policy.mismatch"));
    focusSafely(fieldInput(confirmField));
    return false;
  }
  return true;
}

function emailField(initial, { readonly = false } = {}) {
  return field({
    label: t("auth.field.email"),
    input: textInput({ name: "email", type: "email", autocomplete: "username", value: initial || "", readonly, spellcheck: false, required: true }),
  });
}

function rememberedEmail() {
  if (S.effective("client.remember_email").value === false) return "";
  return S.localOnly("auth.last_email") || "";
}

function rememberEmail(email, remember) {
  if (remember && S.effective("client.remember_email").value !== false) S.localOnly("auth.last_email", email);
  else S.localOnly("auth.last_email", null);
}

// ------------------------------------------------------------------ Connexion

/** Méthodes de connexion : /settings/public, sinon /health (serveur 1.0). */
function loginMethods(ctx) {
  const pub = S.publicSettings();
  const health = ctx.health || {};
  if (pub?.login?.methods?.length) {
    return {
      primary: pub.login.primary_method,
      methods: pub.login.methods,
      enforced: !!pub.login.enforced,
      ssoLabel: pub.login.sso_label || health.sso?.label || "",
      ldapLabel: pub.login.ldap_label || health.ldap?.label || "",
    };
  }
  const methods = [health.ldap ? "ldap" : null, health.sso ? "sso" : null, "password"].filter(Boolean);
  return {
    primary: methods[0],
    methods,
    enforced: !!(health.sso?.enforced || health.ldap?.enforced),
    ssoLabel: health.sso?.label || "",
    ldapLabel: health.ldap?.label || "",
  };
}

function passwordLogin(ctx) {
  const email = emailField(rememberedEmail());
  const pw = passwordField({ label: t("common.glossary.master_password"), name: "password", autocomplete: "current-password", required: true });
  const remember = h("input", { type: "checkbox", name: "remember", checked: !!rememberedEmail() || S.localOnly("auth.remember_email") !== false });
  const rememberRow = S.effective("client.remember_email").value === false ? null
    : h("label", { class: "l-cluster" }, remember, h("span", {}, t("auth.field.remember")));
  const { form } = authForm([email, pw, rememberRow], {
    label: t("auth.action.login"),
    busyLabel: t("auth.busy.login"),
    onSubmit: async () => {
      clearErrors(email, pw);
      const address = value(email).trim();
      const password = value(pw);
      if (!address) return fieldError(email, t("auth.error.email_required"));
      if (!password) return fieldError(pw, t("auth.error.password_required"));
      await beforeHeavyWork();
      try {
        const res = await V.login({ email: address, password });
        S.localOnly("auth.remember_email", remember.checked);
        rememberEmail(address, remember.checked);
        fieldInput(pw).value = "";
        if (res.needTotp) return totpScreen(ctx, res.pending, password);
        return finishLogin(ctx, password);
      } catch (err) {
        fieldError(pw, loginErrorText(err));
        fieldInput(pw).select();
        return undefined;
      }
    },
  });
  return { form, focus: () => focusFirstEmpty(email, pw) };
}

function windowsLogin(ctx, label) {
  const user = field({
    label: t("auth.field.windows_user"),
    input: textInput({ name: "username", autocomplete: "username", value: S.localOnly("auth.last_windows_user") || "", spellcheck: false, required: true }),
  });
  const pw = passwordField({ label: t("auth.field.windows_password"), name: "windows-password", help: t("auth.field.windows_password_help"), required: true });
  const { form } = authForm([user, pw, h("p", { class: "u-muted" }, t("auth.login.windows_hint"))], {
    label: t("common.action.continue"),
    busyLabel: t("auth.busy.windows"),
    onSubmit: async () => {
      clearErrors(user, pw);
      const username = value(user).trim();
      if (!username) return fieldError(user, t("auth.error.windows_user_required"));
      if (!value(pw)) return fieldError(pw, t("auth.error.password_required"));
      try {
        const res = await api("POST", "/ldap/login", { username, password: value(pw) });
        fieldInput(pw).value = "";
        S.localOnly("auth.last_windows_user", username);
        return ssoScreen(ctx, new URLSearchParams(), res);
      } catch (err) {
        fieldError(pw, loginErrorText(err, { windows: true }));
        return undefined;
      }
    },
  });
  form.dataset.method = label;
  return { form, focus: () => focusFirstEmpty(user, pw) };
}

function ssoLogin(label, primary) {
  const link = h("a", { class: `c-button${primary ? " c-button--primary" : ""}`, href: "/api/sso/start?target=web" },
    icon("shield"), h("span", { class: "c-button__label" }, t("auth.action.sso", { label: label || t("common.glossary.enterprise_login") })));
  return { form: h("div", { class: "l-stack", "data-gap": "2" }, link), focus: () => focusSafely(link) };
}

/** Bloc repliable : bouton (aria-expanded) + région masquée. */
function disclosure(label, content) {
  const region = h("div", { class: "l-stack", "data-gap": "4", hidden: true }, content);
  region.id = uid("replie");
  const toggle = button({
    label, variant: "quiet", icon: "chevron-right",
    attrs: { "aria-expanded": "false", "aria-controls": region.id },
    onClick: () => {
      const open = region.hidden;
      region.hidden = !open;
      toggle.setAttribute("aria-expanded", String(open));
      if (open) focusSafely(region.querySelector("input, a, button"));
    },
  });
  return h("div", { class: "l-stack", "data-gap": "3" }, toggle, region);
}

async function loginScreen(ctx) {
  await S.loadPublic();
  const m = loginMethods(ctx);
  const build = (method, primary) => {
    if (method === "ldap") return windowsLogin(ctx, m.ldapLabel);
    if (method === "sso") return ssoLogin(m.ssoLabel, primary);
    return passwordLogin(ctx);
  };
  const main = build(m.primary, true);
  const titleKey = m.primary === "ldap" ? "auth.title.login_windows" : m.primary === "sso" ? "auth.title.login_sso" : "auth.title.login";
  const message = S.publicSettings()?.branding?.login_message;
  const others = m.methods.filter((x) => x !== m.primary);
  let extra = null;
  if (m.enforced && m.primary !== "password") {
    // Connexion par mot de passe seul : réservée aux propriétaires (accès de secours).
    extra = disclosure(t("auth.action.owner_rescue"), passwordLogin(ctx).form);
  } else if (!m.enforced && others.length) {
    extra = disclosure(t("auth.action.other_method"), others.map((x) => build(x, false).form));
  }
  authPage(ctx, t(titleKey),
    message ? h("p", { class: "u-muted" }, message) : null,
    main.form,
    m.primary === "password" ? h("p", {}, h("a", { href: "#/recuperation" }, t("auth.action.forgot"))) : null,
    extra);
  main.focus();
  return { dispose() {}, isDirty: () => false, focused: true };
}

/** Second facteur : code de l'application (envoi au 6e chiffre) ou code de secours. */
function totpScreen(ctx, pending, password) {
  let backup = false;
  const err = h("p", { class: "c-field__error", role: "alert", hidden: true });
  const area = h("div", { class: "l-stack", "data-gap": "3" });
  let codeField = null;
  let submitBtn = null;

  const submitCode = async (code) => {
    err.hidden = true;
    fieldError(codeField, null);
    if (!backup && normalizeCode(code).length !== 6) return fieldError(codeField, t("auth.error.code_incomplete"));
    if (backup && code.replace(/[\s-]/g, "").length < BACKUP_CODE_MIN) return fieldError(codeField, t("auth.error.backup_incomplete"));
    try {
      const res = await V.finishLogin(pending, backup ? code.trim() : normalizeCode(code));
      if (res.needTotp) {
        fieldError(codeField, t(backup ? "auth.error.backup_invalid" : "errors.invalid_totp"));
        fieldInput(codeField).value = "";
        focusSafely(fieldInput(codeField));
        return undefined;
      }
      if (pending.ssoTicket) history.replaceState(null, "", "#/coffre");
      return finishLogin(ctx, password);
    } catch (ex) {
      // La clé de chiffrement a été effacée : il faut recommencer la connexion.
      const expired = pending.ssoTicket && ex.code === "unauthorized";
      clear(err, expired ? t("auth.error.sso_expired") : loginErrorText(ex));
      err.hidden = false;
      fieldInput(codeField).disabled = true;
      submitBtn.replaceWith(button({ label: t("auth.action.restart"), variant: "primary", onClick: () => ctx.navigate("/connexion", { replace: true }) }));
      return undefined;
    }
  };

  const showMode = () => {
    codeField = backup
      ? field({ label: t("auth.field.backup_code"), help: t("auth.field.backup_code_help"), input: textInput({ name: "backup", autocomplete: "one-time-code", spellcheck: false, maxlength: 24 }) })
      : otpInput({ label: t("common.glossary.verification_code"), onComplete: (code) => { if (!submitBtn.getAttribute("aria-busy")) form.requestSubmit(); } });
    clear(area, h("p", { class: "u-muted" }, t(backup ? "auth.totp.backup_intro" : "auth.totp.intro")), codeField);
    switchBtn.querySelector(".c-button__label").textContent = t(backup ? "auth.action.use_app" : "auth.action.use_backup");
    focusSafely(fieldInput(codeField));
  };
  const switchBtn = button({ label: t("auth.action.use_backup"), variant: "quiet", onClick: () => { backup = !backup; showMode(); } });
  const support = S.publicSettings()?.branding?.support_contact;
  const help = h("p", { class: "u-muted", hidden: true }, t("auth.totp.no_access_help"), support ? ` ${t("auth.login.support", { contact: support })}` : "");
  const noAccess = button({ label: t("auth.action.no_access"), variant: "quiet", attrs: { "aria-expanded": "false" }, onClick: () => { help.hidden = !help.hidden; noAccess.setAttribute("aria-expanded", String(!help.hidden)); } });
  const built = authForm([area, err], { label: t("auth.action.validate"), busyLabel: t("auth.busy.check"), onSubmit: () => submitCode(value(codeField)) });
  const form = built.form;
  submitBtn = built.submit;
  const cancel = h("a", { href: "#/connexion", onclick: (e) => { e.preventDefault(); call("drop_key", { key: pending.encKey }); ctx.navigate("/connexion", { replace: true }); } }, t("common.action.cancel"));
  ctx.setTitle("auth.title.totp");
  authPage(ctx, t("auth.title.totp"),
    pending.ssoTicket ? h("p", { class: "u-muted" }, t("auth.totp.sso_hint")) : null,
    form, h("div", { class: "l-stack", "data-gap": "2" }, switchBtn, noAccess, help), h("p", {}, cancel));
  showMode();
}

/** Après la connexion : montée du KDF si l'organisation l'a renforcé, puis le coffre. */
async function finishLogin(ctx, password) {
  try {
    await upgradeKdf(password);
  } catch {
    // Repli silencieux : la connexion reste valable avec les anciens paramètres.
  }
  return ctx.done({});
}

/**
 * Montée progressive des paramètres de dérivation (POST /me/kdf, #2) quand
 * /settings/public annonce des paramètres plus forts et upgrade_on_login.
 * Serveur sans la route (404) : rien n'est changé.
 */
export async function upgradeKdf(password) {
  const k = S.publicSettings()?.kdf;
  const p = V.state.profile;
  if (!k?.upgrade_on_login || !p?.kdf || !V.state.userKey || !password) return false;
  const target = { m_kib: Number(k.memory_mib) * 1024, t: Number(k.iterations), p: Number(k.parallelism) || 1 };
  if (!(target.m_kib > 0 && target.t > 0)) return false;
  if (p.kdf.m_kib >= target.m_kib && p.kdf.t >= target.t) return false;
  const kdf = { alg: "argon2id", m_kib: Math.max(p.kdf.m_kib, target.m_kib), t: Math.max(p.kdf.t, target.t), p: target.p, salt: call("new_kdf").salt };
  const current = call("derive_master", { password, kdf: p.kdf });
  call("drop_key", { key: current.enc_key });
  const next = call("derive_master", { password, kdf });
  try {
    await api("POST", "/me/kdf", {
      current_auth_key: current.auth_key,
      kdf,
      auth_key: next.auth_key,
      wrapped_user_key: call("wrap", { wrapping: next.enc_key, key: V.state.userKey, aad: A.userKey() }),
    }, { retry: false });
  } catch (e) {
    // Serveur sans la route (404, ou 405 : chemin connu pour une autre méthode) : rien ne change.
    if (e instanceof ApiError && (e.status === 404 || e.status === 405)) return false;
    throw e;
  } finally {
    call("drop_key", { key: next.enc_key });
  }
  pinKdf(p.email, kdf, { replace: true });
  V.state.profile = { ...p, kdf };
  return true;
}

// ------------------------------------------------------------------ Installation et inscription

async function registerScreen(ctx, { install = false } = {}) {
  await S.loadPublic();
  const token = ctx.params.jeton;
  let invite = null;
  if (token) {
    try {
      invite = await api("GET", `/invites/${encodeURIComponent(token)}`);
    } catch (err) {
      authPage(ctx, t("auth.register.invalid_invite_title"),
        h("p", {}, err?.status === 404 || err?.status === 410 ? t("auth.register.invalid_invite_text") : errorText(err)),
        h("p", {}, h("a", { href: "#/connexion" }, t("auth.action.back_to_login"))));
      return { dispose() {}, isDirty: () => false };
    }
  }
  const setup = install
    ? field({
      label: t("auth.field.setup_token"), help: t("auth.field.setup_token_help"),
      input: textInput({ name: "setup", autocomplete: "off", spellcheck: false, value: ctx.extras?.setupToken || "", required: true }),
    })
    : null;
  if (setup) fieldInput(setup).classList.add("u-mono");
  const email = emailField(invite?.email || "", { readonly: !!invite });
  const name = field({ label: t("auth.field.name"), input: textInput({ name: "name", autocomplete: "name", maxlength: 100, value: invite?.name || "", required: true }) });
  const pw = passwordField({ label: t("common.glossary.master_password"), name: "new-password", autocomplete: "new-password", withStrength: true, required: true });
  const pw2 = passwordField({ label: t("auth.field.confirm"), name: "confirm-password", autocomplete: "new-password", capsLockHint: false, required: true });
  const { form } = authForm([setup, email, name, pw, pw2, h("div", { class: "c-alert", "data-tone": "warn" }, icon("warn"), h("p", {}, t("auth.register.warning")))], {
    label: t("auth.action.create"),
    busyLabel: t("auth.busy.create"),
    onSubmit: async () => {
      clearErrors(setup, email, name, pw, pw2);
      if (setup && !value(setup).trim()) return fieldError(setup, t("errors.setup_token_required"));
      const address = value(email).trim();
      if (!address) return fieldError(email, t("auth.error.email_required"));
      if (!value(name).trim()) return fieldError(name, t("auth.error.name_required"));
      if (!checkNewPassword(pw, pw2, { email: address, name: value(name) })) return undefined;
      const password = value(pw);
      await beforeHeavyWork();
      try {
        const recovery = await V.register({
          email: address, name: value(name).trim(), password, inviteToken: token || null,
          setupToken: setup ? value(setup).trim() : null,
        });
        fieldInput(pw).value = "";
        fieldInput(pw2).value = "";
        if (setup) fieldInput(setup).value = "";
        S.localOnly("auth.remember_email", true);
        rememberEmail(address, true);
        return recoveryKeyScreen(ctx.root, recovery, {
          email: address,
          onDone: () => finishLogin(ctx, password),
        });
      } catch (err) {
        if (setup && (err.code === "setup_token_required" || err.code === "invalid_setup_token")) {
          fieldError(setup, errorText(err));
          fieldInput(setup).select();
        } else if (err.code === "domain_not_allowed") {
          fieldError(email, errorText(err));
        } else if (err.code === "kdf_too_weak") {
          fieldError(pw, errorText(err));
        } else if (install && err.status === 403) {
          // Installation faite entre-temps (autre onglet, autre administrateur).
          notify({ text: t("auth.register.already_installed"), tone: "info" });
          return ctx.navigate("/connexion", { replace: true });
        } else {
          fieldError(pw2, errorText(err));
        }
        return undefined;
      }
    },
  });
  const intro = install
    ? t("auth.register.install_intro")
    : t(invite?.role === "admin" ? "auth.register.invite_admin" : invite?.role === "owner" ? "auth.register.invite_owner" : "auth.register.invite_intro");
  authPage(ctx, t(install ? "auth.title.install" : "auth.title.register"),
    h("p", { class: "u-muted" }, intro), form,
    install ? null : h("p", {}, h("a", { href: "#/connexion" }, t("auth.action.have_account"))));
  focusFirstEmpty(setup, email, name, pw);
  return { dispose() {}, isDirty: () => false, focused: true };
}

/**
 * Clé de récupération affichée une seule fois (#4) : copie, téléchargement
 * en .txt (fichier créé dans le navigateur, rien n'est stocké), case « J'ai
 * conservé ma clé de récupération » obligatoire avant « Continuer ».
 */
export function recoveryKeyScreen(root, display, { email, onDone }) {
  const ack = h("input", { type: "checkbox", name: "ack" });
  const next = button({ label: t("common.action.continue"), variant: "primary", disabled: true, busyLabel: t("auth.busy.open"), onClick: () => onDone?.() });
  ack.addEventListener("change", () => {
    next.disabled = !ack.checked;
    next.removeAttribute("aria-disabled");
  });
  const download = button({
    label: t("auth.action.download_key"), icon: "download",
    onClick: () => {
      const lines = [
        t("auth.recovery_key.file_title"),
        "",
        email ? t("auth.recovery_key.file_account", { email }) : null,
        t("auth.recovery_key.file_server", { url: location.origin }),
        t("auth.recovery_key.file_date", { date: fmtDate(Date.now() / 1000, "long") }),
        "",
        display,
        "",
        t("auth.recovery_key.file_warning"),
        "",
      ].filter((l) => l !== null);
      saveBlob(new Blob([lines.join("\r\n")], { type: "text/plain;charset=utf-8" }), t("auth.recovery_key.file_name"));
      announce(t("auth.recovery_key.downloaded"));
    },
  });
  const copy = button({ label: t("auth.action.copy_key"), icon: "copy", onClick: () => copySecret(display, { kind: "secret" }) });
  const card = h("div", { class: "l-auth__card l-stack", "data-gap": "4" },
    h("h1", {}, t("auth.title.recovery_key")),
    h("p", {}, t("auth.recovery_key.intro")),
    h("div", { class: "c-card" }, h("p", { class: "u-mono" }, display)),
    h("div", { class: "l-cluster" }, download, copy),
    h("label", { class: "l-cluster" }, ack, h("span", {}, t("auth.recovery_key.ack"))),
    h("p", { class: "u-muted" }, t("auth.recovery_key.ack_help")),
    next);
  clear(root, h("div", { class: "l-auth" }, card));
  focusSafely(card.querySelector("h1"), { preventScroll: false });
}

// ------------------------------------------------------------------ Récupération

function recoverScreen(ctx) {
  const email = emailField(rememberedEmail());
  const key = field({ label: t("common.glossary.recovery_key"), help: t("auth.field.recovery_key_help"), input: textArea({ name: "recovery", rows: 3 }) });
  fieldInput(key).classList.add("u-mono");
  fieldInput(key).setAttribute("spellcheck", "false");
  fieldInput(key).setAttribute("autocomplete", "off");
  const pw = passwordField({ label: t("auth.field.new_password"), name: "new-password", autocomplete: "new-password", withStrength: true, required: true });
  const pw2 = passwordField({ label: t("auth.field.new_confirm"), name: "confirm-password", autocomplete: "new-password", capsLockHint: false, required: true });
  const { form } = authForm([email, key, pw, pw2], {
    label: t("auth.action.recover"),
    busyLabel: t("auth.busy.recover"),
    onSubmit: async () => {
      clearErrors(email, key, pw, pw2);
      const address = value(email).trim();
      if (!address) return fieldError(email, t("auth.error.email_required"));
      if (!value(key).trim()) return fieldError(key, t("auth.error.recovery_key_required"));
      if (!checkNewPassword(pw, pw2, { email: address })) return undefined;
      await beforeHeavyWork();
      try {
        await V.recoverAccount(address, value(key), value(pw));
        fieldInput(pw).value = "";
        fieldInput(pw2).value = "";
        fieldInput(key).value = "";
        setToken(null);
        notify({ text: t("auth.recover.done"), tone: "ok" });
        return ctx.navigate("/connexion", { replace: true });
      } catch (err) {
        if (!(err instanceof ApiError) && !err?.code) fieldError(key, t("auth.error.recovery_key_format"));
        else if (err.code === "invalid_credentials" || err.code === "not_found") fieldError(key, t("auth.error.recovery_key"));
        else if (err.code === "rate_limited") fieldError(key, lockedText(err.retryAfter));
        else fieldError(pw2, errorText(err));
        return undefined;
      }
    },
  });
  authPage(ctx, t("auth.title.recover"), h("p", { class: "u-muted" }, t("auth.recover.intro")), form,
    h("p", {}, h("a", { href: "#/connexion" }, t("auth.action.back_to_login"))));
  focusFirstEmpty(email, key, pw);
  return { dispose() {}, isDirty: () => false, focused: true };
}

// ------------------------------------------------------------------ Connexion d'entreprise (retour)

async function ssoScreen(ctx, query, preloaded = null) {
  await S.loadPublic();
  const ticket = preloaded?.ticket || query.get("ticket");
  // Le texte de « error » vient de l'adresse : jamais affiché (un tiers pourrait y glisser un faux message).
  if (!preloaded) history.replaceState(null, "", "#/sso");
  const back = h("p", {}, h("a", { href: "#/connexion" }, t("auth.action.back_to_login")));
  const fail = (text) => {
    authPage(ctx, t("auth.title.sso_failed"), h("div", { class: "c-alert", "data-tone": "danger" }, icon("error"), h("p", {}, text)), back);
    return { dispose() {}, isDirty: () => false };
  };
  if (query.has("error") || !ticket) return fail(t("auth.error.sso_failed"));
  let info = preloaded?.info;
  try {
    info ??= await api("POST", "/sso/redeem", { ticket });
  } catch (err) {
    return fail(err.code === "unauthorized" ? t("auth.error.sso_expired") : loginErrorText(err));
  }
  const confirmed = h("p", { class: "c-alert", "data-tone": "info" }, icon("shield"), h("span", {}, t("auth.sso.confirmed", { email: info.email })));
  if (info.registered) {
    const pw = passwordField({ label: t("common.glossary.master_password"), name: "password", autocomplete: "current-password", required: true });
    const { form } = authForm([pw], {
      label: t("auth.action.unlock"),
      busyLabel: t("auth.busy.unlock"),
      onSubmit: async () => {
        clearErrors(pw);
        const password = value(pw);
        if (!password) return fieldError(pw, t("auth.error.password_required"));
        await beforeHeavyWork();
        try {
          // info.kdf est vérifié contre l'épinglage local avant tout calcul Argon2.
          const res = await V.login({ email: info.email, password, ssoTicket: ticket, kdf: info.kdf });
          fieldInput(pw).value = "";
          rememberEmail(info.email, S.localOnly("auth.remember_email") !== false);
          if (res.needTotp) return totpScreen(ctx, res.pending, password);
          history.replaceState(null, "", "#/coffre");
          return finishLogin(ctx, password);
        } catch (err) {
          fieldError(pw, err.code === "unauthorized" ? t("auth.error.sso_expired") : loginErrorText(err));
          return undefined;
        }
      },
    });
    authPage(ctx, t("auth.sso.hello", { name: info.name || info.email }), confirmed, h("p", { class: "u-muted" }, t("auth.sso.unlock_intro")), form, back);
    focusSafely(fieldInput(pw));
    return { dispose() {}, isDirty: () => false, focused: true };
  }
  if (!info.can_register) {
    return fail(t("auth.error.no_account", { email: info.email }));
  }
  const name = field({ label: t("auth.field.name"), input: textInput({ name: "name", autocomplete: "name", maxlength: 100, value: info.name || "", required: true }) });
  const pw = passwordField({ label: t("common.glossary.master_password"), name: "new-password", autocomplete: "new-password", withStrength: true, required: true });
  const pw2 = passwordField({ label: t("auth.field.confirm"), name: "confirm-password", autocomplete: "new-password", capsLockHint: false, required: true });
  const { form } = authForm([name, pw, pw2, h("div", { class: "c-alert", "data-tone": "warn" }, icon("warn"), h("p", {}, t("auth.register.sso_warning")))], {
    label: t("auth.action.create"),
    busyLabel: t("auth.busy.create"),
    onSubmit: async () => {
      clearErrors(name, pw, pw2);
      if (!value(name).trim()) return fieldError(name, t("auth.error.name_required"));
      if (!checkNewPassword(pw, pw2, { email: info.email, name: value(name) })) return undefined;
      const password = value(pw);
      await beforeHeavyWork();
      try {
        const recovery = await V.register({ email: info.email, name: value(name).trim(), password, ssoTicket: ticket });
        fieldInput(pw).value = "";
        fieldInput(pw2).value = "";
        rememberEmail(info.email, true);
        return recoveryKeyScreen(ctx.root, recovery, {
          email: info.email,
          onDone: () => { history.replaceState(null, "", "#/coffre"); return finishLogin(ctx, password); },
        });
      } catch (err) {
        fieldError(pw2, err.code === "unauthorized" ? t("auth.error.sso_expired") : errorText(err));
        return undefined;
      }
    },
  });
  authPage(ctx, t("auth.title.register"), confirmed, form, back);
  focusFirstEmpty(name, pw);
  return { dispose() {}, isDirty: () => false, focused: true };
}

// ------------------------------------------------------------------ Coffre verrouillé

const LOCK_REASONS = new Set(["idle", "manual", "hidden", "os", "reload"]);

function lockedScreen(ctx) {
  const p = V.state.profile || {};
  const reason = LOCK_REASONS.has(ctx.extras?.lockReason) ? ctx.extras.lockReason : "reload";
  const pw = passwordField({ label: t("common.glossary.master_password"), name: "password", autocomplete: "current-password", required: true });
  const { form } = authForm([pw], {
    label: t("auth.action.unlock"),
    busyLabel: t("auth.busy.unlock"),
    onSubmit: async () => {
      clearErrors(pw);
      if (!value(pw)) return fieldError(pw, t("auth.error.password_required"));
      await beforeHeavyWork();
      try {
        await V.unlock(value(pw));
        fieldInput(pw).value = "";
        return ctx.done({});
      } catch (err) {
        fieldError(pw, err.code === "wrong_password" || err.code === "invalid_credentials" ? t("errors.wrong_password") : loginErrorText(err));
        if (err.code === "wrong_password") fieldInput(pw).select();
        else if (err.code === "kdf_downgrade" || err.code === "key_mismatch") fieldInput(pw).value = "";
        return undefined;
      }
    },
  });
  const logout = h("a", { href: "#/connexion", onclick: (e) => { e.preventDefault(); ctx.logout(); } }, t("common.action.logout"));
  authPage(ctx, t("auth.title.locked"),
    p.name || p.email ? h("p", { class: "l-cluster" }, avatar({ name: p.name || p.email }), h("strong", {}, p.name || p.email)) : null,
    h("p", {}, t(`auth.locked.reason.${reason}`)),
    form,
    h("p", {}, `${t("auth.locked.not_you")} `, logout));
  focusSafely(fieldInput(pw));
  return { dispose() {}, isDirty: () => false, focused: true };
}

// ------------------------------------------------------------------ Point d'entrée

export async function render(ctx) {
  switch (ctx.route?.screen) {
    case "install":
      return registerScreen(ctx, { install: true });
    case "register":
      return registerScreen(ctx);
    case "recover":
      return recoverScreen(ctx);
    case "sso":
      return ssoScreen(ctx, ctx.query);
    case "locked":
      return lockedScreen(ctx);
    default:
      return loginScreen(ctx);
  }
}

// ------------------------------------------------------------------ Confirmation d'identité

const NEED_CODE = Symbol("code");

/** Preuve du mot de passe maître (auth_key en b64) : vault.authProof, sinon dérivation locale. */
async function proof(password) {
  if (typeof V.authProof === "function") return V.authProof(password);
  const kdf = V.state.profile?.kdf;
  if (!kdf) throw new ApiError(0, "error", t("errors.error"));
  await beforeHeavyWork();
  const mk = call("derive_master", { password, kdf });
  call("drop_key", { key: mk.enc_key });
  return mk.auth_key;
}

/** Seconde fenêtre : code de vérification ou code de secours (après la première, jamais empilée). */
function askCode(exchange) {
  return new Promise((resolve) => {
    let token = null;
    let backup = false;
    const area = h("div", { class: "l-stack", "data-gap": "3" });
    let codeField = null;
    let dlg = null;
    const show = () => {
      codeField = backup
        ? field({ label: t("auth.field.backup_code"), help: t("auth.field.backup_code_help"), input: textInput({ name: "backup", autocomplete: "one-time-code", spellcheck: false, maxlength: 24 }) })
        : otpInput({ label: t("common.glossary.verification_code"), onComplete: () => dlg?.querySelector("button[type=submit]")?.click() });
      clear(area, codeField);
      toggle.querySelector(".c-button__label").textContent = t(backup ? "auth.action.use_app" : "auth.action.use_backup");
      focusSafely(fieldInput(codeField));
    };
    const toggle = button({ label: t("auth.action.use_backup"), variant: "quiet", onClick: () => { backup = !backup; show(); } });
    dlg = dialog({
      title: t("auth.reauth.totp_title"),
      description: t("auth.reauth.totp_message"),
      body: h("div", { class: "l-stack", "data-gap": "3" }, area, toggle),
      size: "sm",
      actions: [
        { label: t("common.action.cancel"), value: "cancel" },
        {
          label: t("auth.action.validate"), variant: "primary", busyLabel: t("auth.busy.check"),
          onClick: async () => {
            const raw = value(codeField);
            const code = backup ? raw.trim() : normalizeCode(raw);
            if (!backup && code.length !== 6) { fieldError(codeField, t("auth.error.code_incomplete")); return false; }
            try {
              token = await exchange(null, code);
              return true;
            } catch (err) {
              fieldError(codeField, err.code === "invalid_totp" ? t(backup ? "auth.error.backup_invalid" : "errors.invalid_totp") : errorText(err));
              return false;
            }
          },
        },
      ],
      onClose: () => resolve(token),
    });
    show();
  });
}

/** Interface de api.withReauth (contrat C4.1). */
export const reauthUi = {
  proof,
  async ask({ title, message, objectName, exchange }) {
    const res = await confirm({
      level: 3,
      title: title || t("auth.reauth.title"),
      message: message || t("auth.reauth.message"),
      objectName,
      confirmLabel: t("auth.reauth.confirm"),
      reauth: async (password) => {
        try {
          return await exchange(password);
        } catch (err) {
          if (err?.code === "totp_required") return NEED_CODE;
          throw err;
        }
      },
    });
    if (!res.confirmed) return null;
    if (res.reauth !== NEED_CODE) return res.reauth;
    return askCode(exchange);
  },
};
