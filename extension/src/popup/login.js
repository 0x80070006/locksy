// Écrans d'accès : adresse du serveur, autorisation d'accès au serveur imposé,
// extension non autorisée, connexion (mot de passe maître, compte Windows,
// connexion d'entreprise) et double authentification.

import {
  h, t, announce, iconButton, field, textInput, passwordField, fieldInput, otpInput, alertCard, errorText,
} from "../lib/ui/index.js";
import { nextFrame } from "../lib/wasm.js";
import { api, setBase } from "../lib/api.js";
import * as V from "../lib/vault.js";
import { DEV, TEST } from "../lib/build-flags.js";
import { normalizeServer } from "../settings.js";
import { S, ext, store, go, screen, showError, action as button, form, submitButton as submit } from "./context.js";
import { lock, openVault, touch } from "./session.js";

const health = (server) => fetch(`${server}/api/health`, { cache: "no-store", credentials: "omit", signal: AbortSignal.timeout(5000) })
  .then((r) => (r.ok ? r.json() : null)).catch(() => null);

export async function hasHostPermission(origin) {
  try { return await ext.permissions.contains({ origins: [`${origin}/*`] }); } catch { return false; }
}

async function requestHost(origin) {
  try { return await ext.permissions.request({ origins: [`${origin}/*`] }); } catch { return false; }
}

// ------------------------------------------------------------------ Serveur

export function renderSetup(error) {
  const url = textInput({
    name: "serveur", type: "url", value: S.server || (DEV ? "http://localhost:8743" : ""), autocomplete: "url",
    placeholder: t("extension.setup.placeholder"), spellcheck: false,
  });
  const f = form(async () => {
    const origin = normalizeServer(url.value, { allowHttp: TEST });
    if (!origin) return showError(t("extension.setup.invalid"));
    if (!(await requestHost(origin))) return showError(t("extension.server.denied"));
    if (!(await health(origin))) return showError(t("extension.setup.unreachable"));
    const previous = await store.get("local", "server");
    if (previous && previous !== origin) await lock({ revoke: true });
    await store.set("local", "server", origin);
    S.server = origin;
    setBase(origin);
    go("boot");
  },
  h("p", { class: "u-muted" }, t("extension.setup.intro")),
  field({ label: t("extension.setup.label"), input: url }),
  submit(t("common.action.continue")));
  screen({ title: t("extension.setup.title"), back: S.server ? () => go("boot") : null }, f);
  if (error) showError(error);
  url.focus();
}

/** Serveur imposé par le poste : il ne manque que l'autorisation d'accès. */
export function renderGrant() {
  screen({ title: t("extension.server.title") },
    h("p", { class: "u-muted" }, t("extension.server.intro")),
    h("p", { class: "x-site" }, S.server),
    h("p", { class: "c-policy-hint" }, t("ui.policy.machine")),
    button({
      label: t("extension.server.grant"), variant: "primary",
      onClick: async () => {
        if (!(await requestHost(S.server))) return showError(t("extension.server.denied"));
        go("boot");
      },
    }));
}

/** Extension refusée par l'organisation (GET /extension/allowed). */
export function renderBlocked() {
  const id = ext.runtime?.id || "";
  screen({},
    alertCard({ tone: "danger", title: t("extension.blocked.title"), text: t("errors.extension_not_allowed") }),
    h("p", {}, t("extension.blocked.give_id")),
    h("p", { class: "u-mono x-site" }, id));
}

// ------------------------------------------------------------------ Connexion

/**
 * Écran de connexion.
 * @param {object} o  info : message d'état ; error : erreur à afficher ;
 *   pending : 2FA en attente (opaque) ; viaTicket : connexion d'entreprise
 *   (ticket de 5 min) ; email : adresse à mémoriser après succès.
 */
export async function renderLogin(o = {}) {
  const { error, info, pending, viaTicket, email: pendingEmail } = o;
  if (pending) return renderCode(o);
  const remembered = (await store.get("local", "email")) || "";
  const email = textInput({ name: "email", type: "email", autocomplete: "username", value: remembered, spellcheck: false });
  const pw = passwordField({ label: t("common.glossary.master_password"), name: "mdp", autocomplete: "current-password" });
  const pwInput = fieldInput(pw);
  const status = await health(S.server);
  const sso = status?.sso && ext.identity?.launchWebAuthFlow ? status.sso : null;
  const ldap = status?.ldap || null;

  const winUser = textInput({ name: "windows", autocomplete: "username", value: (await store.get("local", "winUser")) || "", placeholder: t("extension.login.windows_placeholder"), spellcheck: false });
  const winPw = passwordField({ label: t("extension.login.windows_password"), name: "mdp-windows", autocomplete: "current-password" });
  const winForm = ldap ? form(async () => {
    const r = await api("POST", "/ldap/login", { username: winUser.value.trim(), password: fieldInput(winPw).value });
    fieldInput(winPw).value = "";
    await store.set("local", "winUser", winUser.value.trim());
    if (!r.info.registered) return showError(t("extension.login.no_vault", { email: r.info.email }));
    renderSsoPassword(r.ticket, r.info);
  },
  h("h3", {}, t("extension.login.with_windows")),
  field({ label: t("extension.login.windows_user"), input: winUser }),
  winPw,
  submit(t("extension.login.submit"))) : null;

  const ssoBtn = sso ? button({
    label: t("extension.login.with_sso", { label: sso.label }), icon: "shield", variant: sso.enforced ? "primary" : "secondary",
    onClick: () => ssoLogin(),
  }) : null;

  const main = form(async () => {
    await nextFrame();
    const address = email.value.trim();
    let r;
    try {
      r = await V.login({ email: address, password: pwInput.value });
    } finally {
      pwInput.value = "";
    }
    if (r.needTotp) return renderLogin({ pending: r.pending, email: address, error: r.error ? t("errors.invalid_totp") : null });
    await afterLogin(address);
  },
  field({ label: t("extension.login.email"), input: email }),
  pw,
  submit(t("extension.login.unlock")));

  const alt = winForm || ssoBtn
    ? h("p", { class: "u-muted" }, sso?.enforced || ldap?.enforced ? t("extension.login.rescue") : t("extension.login.or_password"))
    : null;
  screen({ actions: [settingsButton()] },
    h("p", { class: "x-site" }, S.server),
    info ? h("p", {}, info) : null,
    winForm, ssoBtn, alt, main);
  if (error) showError(error);
  else if (info) announce(info);
  (winForm ? (winUser.value ? fieldInput(winPw) : winUser) : email.value ? pwInput : email).focus();
}

function settingsButton() {
  return iconButton({ icon: "settings", label: t("extension.prefs.title"), onClick: () => go("prefs", () => go("boot")) });
}

/** Double authentification (après mot de passe maître ou connexion d'entreprise). */
function renderCode({ error, info, pending, viaTicket, email }) {
  const code = otpInput({ label: t("common.glossary.verification_code"), onComplete: () => f.requestSubmit() });
  const input = fieldInput(code);
  const f = form(async () => {
    await nextFrame();
    let r;
    try {
      r = await V.finishLogin(pending, input.value.trim());
    } catch (ex) {
      // finishLogin a effacé la clé de chiffrement : on repart du formulaire complet.
      return renderLogin({ error: viaTicket && ex.code === "unauthorized" ? t("extension.sso.expired") : errorText(ex) });
    }
    if (r.needTotp) return renderLogin({ pending: r.pending, viaTicket, email, error: t("errors.invalid_totp") });
    await afterLogin(email);
  },
  code,
  viaTicket ? h("p", { class: "u-muted" }, t("extension.sso.ticket_hint")) : null,
  submit(t("extension.login.validate")),
  button({ label: t("common.action.cancel"), variant: "quiet", onClick: () => renderLogin() }));
  screen({ title: t("common.glossary.two_factor") },
    h("p", {}, info || t("extension.login.code_hint")), f);
  if (error) showError(error);
  input.focus();
}

async function afterLogin(address) {
  try {
    if (address) await store.set("local", "email", address);
    await openVault({ incremental: false });
    await touch();
    go("main");
  } catch (ex) {
    await lock();
    if (ex.status !== 401) return renderLogin({ error: errorText(ex) });
  }
}

// ------------------------------------------------------------------ Connexion d'entreprise

async function ssoLogin() {
  try {
    const redirect = ext.identity.getRedirectURL("sso");
    const startUrl = `${S.server}/api/sso/start?target=extension&redirect=${encodeURIComponent(redirect)}`;
    // Vérification préalable : un refus du serveur (extension non déclarée,
    // SSO saturé…) s'afficherait sinon comme une page JSON dans la fenêtre de
    // connexion. Une redirection (opaque) signifie « accepté ».
    const pre = await fetch(startUrl, { redirect: "manual", cache: "no-store", credentials: "omit" }).catch(() => null);
    if (pre && pre.type !== "opaqueredirect" && !pre.ok) {
      const data = await pre.json().catch(() => ({}));
      if (data.error === "extension_not_allowed") return renderBlocked();
      return showError({ code: data.error, status: pre.status });
    }
    const back = await ext.identity.launchWebAuthFlow({ url: startUrl, interactive: true });
    const frag = new URLSearchParams(new URL(back).hash.slice(1));
    // Le texte d'erreur renvoyé n'est jamais affiché tel quel (il viendrait de
    // l'adresse de retour) : message générique.
    const ticket = frag.get("ticket");
    if (frag.get("error") || !ticket) return showError(t("extension.sso.refused"));
    const info = await api("POST", "/sso/redeem", { ticket });
    if (!info.registered) return showError(t("extension.login.no_vault", { email: info.email }));
    renderSsoPassword(ticket, info);
  } catch (e) {
    if (e.code === "unauthorized") return showError(t("extension.sso.expired"));
    showError(/did not approve|canceled|cancelled/i.test(e.message || "") ? t("extension.sso.cancelled") : e);
  }
}

function renderSsoPassword(ticket, info) {
  const pw = passwordField({ label: t("common.glossary.master_password"), name: "mdp", autocomplete: "current-password" });
  const input = fieldInput(pw);
  const f = form(async () => {
    await nextFrame();
    let r;
    try {
      r = await V.login({ email: info.email, password: input.value, ssoTicket: ticket, kdf: info.kdf });
    } catch (ex) {
      if (ex.code === "unauthorized") return renderLogin({ error: t("extension.sso.expired") });
      throw ex; // mot de passe faux : le ticket n'est consommé qu'au succès, on peut réessayer
    } finally {
      input.value = "";
    }
    // 2FA Locksy active : demandée même après le SSO, sans consommer le ticket.
    if (r.needTotp) {
      return renderLogin({ pending: r.pending, viaTicket: true, email: info.email, error: r.error ? t("errors.invalid_totp") : null, info: t("extension.sso.code_hint") });
    }
    await afterLogin(info.email);
  },
  pw,
  submit(t("extension.login.unlock")),
  button({ label: t("common.action.cancel"), variant: "quiet", onClick: () => renderLogin() }));
  screen({},
    h("p", {}, t("extension.sso.confirmed", { email: info.email })),
    h("p", { class: "u-muted" }, t("extension.sso.master_hint")),
    f);
  input.focus();
}
