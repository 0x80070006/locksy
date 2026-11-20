// Paramètres › Mon compte : nom affiché, mot de passe maître (changement
// avec confirmation et politique de l'organisation), double authentification
// (activation par QR code, désactivation confirmée, codes de secours affichés
// une fois, comptés et régénérés), clé de récupération (nouvelle clé,
// téléchargement .txt) et empreinte de la clé du compte.
//
// Les secrets affichés (codes de secours, clé de récupération) ne sont jamais
// annoncés, journalisés ni gardés : ils ne vivent que dans la fenêtre qui les
// montre, et dans le fichier que la personne choisit de télécharger.

import {
  t, plural, h, clear, button, dialog, field, fieldError, fieldInput, textInput, passwordField, notify, badge,
  alertCard, keepFocus, copySecret, technicalDetails, fmtDate, errorText, uid, dirtyGuard,
} from "../../ui/index.js";
import { api, apiFull, saveBlob, withReauth } from "../../api.js";
import { nextFrame } from "../../wasm.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";

const EOL = "\r\n";

/** Champ du second facteur : code à 6 chiffres ou code de secours (lettres et tiret). */
function codeField() {
  const input = textInput({ name: "code", autocomplete: "one-time-code", spellcheck: false, maxlength: 24 });
  input.setAttribute("autocapitalize", "characters");
  return field({ label: t("common.glossary.verification_code"), help: t("settings_user.account.code_help"), input });
}

/** Erreur d'une action confirmée : rattachée au bon champ, sinon au bloc d'alerte. */
function showError(err, { passwordEl, codeEl, alertEl }) {
  const code = err?.code;
  if (passwordEl && (code === "wrong_password" || code === "invalid_credentials")) {
    fieldError(passwordEl, t("errors.wrong_password"));
  } else if (codeEl && (code === "invalid_totp" || code === "totp_required" || code === "recovery_code_invalid")) {
    fieldError(codeEl, errorText(err));
  } else {
    clear(alertEl, alertCard({ tone: "danger", text: errorText(err) }));
  }
}

/** Erreur de champ ; renvoie false (la fenêtre reste ouverte). */
function fail(fieldEl, message) {
  fieldError(fieldEl, message);
  return false;
}

/** Texte d'un fichier .txt (lignes jointes en CRLF pour le Bloc-notes). */
const textFile = (lines) => new Blob([lines.join(EOL) + EOL], { type: "text/plain;charset=utf-8" });

/**
 * Fenêtre d'affichage unique d'un secret de compte (codes de secours ou clé
 * de récupération) : copie, téléchargement .txt, case de confirmation.
 */
function showSecrets({ title, intro, values, fileName, fileLines, keptLabel, copyKey }) {
  return new Promise((resolve) => {
    const kept = h("input", { type: "checkbox", id: uid("garde") });
    const keptField = h("div", { class: "c-field" },
      h("label", { class: "l-cluster" }, kept, h("span", {}, keptLabel)),
      h("p", { class: "c-field__error", hidden: true }, t("settings_user.secrets.kept_required")));
    const list = h("ul", { class: "c-card l-stack u-mono", "data-gap": "1", translate: "no" }, values.map((v) => h("li", {}, v)));
    dialog({
      title,
      body: h("div", { class: "l-stack", "data-gap": "4" },
        h("p", {}, intro),
        list,
        h("div", { class: "l-cluster" },
          button({ label: t("settings_user.secrets.copy"), icon: "copy", onClick: () => copySecret(values.join("\n"), { kind: "secret", labelKey: copyKey }) }),
          button({
            label: t("settings_user.secrets.download"), icon: "download",
            onClick: () => {
              saveBlob(textFile(fileLines), fileName);
              notify({ text: t("settings_user.secrets.downloaded"), tone: "ok" });
            },
          })),
        keptField),
      actions: [{
        label: t("settings_user.secrets.done"), variant: "primary",
        onClick: () => {
          const ok = kept.checked;
          keptField.querySelector(".c-field__error").hidden = ok;
          if (!ok) kept.focus();
          return ok;
        },
      }],
      onClose: () => resolve(),
    });
  });
}

/** Codes de secours : affichage unique. */
function showRecoveryCodes(codes) {
  const profile = V.state.profile || {};
  return showSecrets({
    title: t("settings_user.codes.title"),
    intro: t("settings_user.codes.intro"),
    values: codes,
    fileName: "locksy-codes-de-secours.txt",
    fileLines: [
      t("settings_user.codes.file_title"),
      t("settings_user.secrets.file_account", { email: profile.email || "" }),
      t("settings_user.secrets.file_date", { date: fmtDate(Date.now() / 1000, "long") }),
      "",
      ...codes,
      "",
      t("settings_user.codes.file_help"),
    ],
    keptLabel: t("settings_user.codes.kept"),
    copyKey: "settings_user.codes.copied",
  });
}

/** Clé de récupération : affichage unique. */
function showRecoveryKey(display) {
  const profile = V.state.profile || {};
  return showSecrets({
    title: t("settings_user.recovery.title_new"),
    intro: t("settings_user.recovery.intro_new"),
    values: [display],
    fileName: "locksy-cle-de-recuperation.txt",
    fileLines: [
      t("settings_user.recovery.file_title"),
      t("settings_user.secrets.file_account", { email: profile.email || "" }),
      t("settings_user.secrets.file_date", { date: fmtDate(Date.now() / 1000, "long") }),
      "",
      display,
      "",
      t("settings_user.recovery.file_help"),
    ],
    keptLabel: t("settings_user.recovery.kept"),
    copyKey: "settings_user.recovery.copied",
  });
}

// ------------------------------------------------------------ Mot de passe maître

function changePasswordDialog(settings) {
  const profile = V.state.profile;
  const current = passwordField({ label: t("settings_user.password.current"), autocomplete: "current-password", required: true });
  const next = passwordField({
    label: t("settings_user.password.new"), autocomplete: "new-password", withStrength: true, required: true,
    help: t("settings_user.password.rules", { min: settings.publicSettings?.()?.master_password?.min_length ?? 12 }),
  });
  const again = passwordField({ label: t("settings_user.password.confirm"), autocomplete: "new-password", required: true, capsLockHint: false });
  const code = profile.totp_enabled ? codeField() : null;
  const alertEl = h("div", {});
  const value = (el) => fieldInput(el).value;
  dialog({
    title: t("settings_user.password.dialog_title"),
    description: t("settings_user.password.dialog_intro"),
    body: h("div", { class: "l-stack", "data-gap": "3" }, alertEl, current, next, again, code),
    dirty: () => [current, next, again].some((el) => value(el) !== ""),
    actions: [
      { label: t("common.action.cancel"), cancel: true },
      {
        label: t("settings_user.password.submit"), variant: "primary", busyLabel: t("settings_user.password.busy"),
        onClick: async () => {
          clear(alertEl);
          for (const el of [current, next, again, code]) if (el) fieldError(el, null, { announce: false });
          if (!value(current)) return fail(current, t("settings_user.password.current_required"));
          const policy = settings.checkMasterPolicy(value(next), { email: profile.email, name: profile.name });
          if (!policy.ok) {
            const p = policy.problems[0];
            fieldError(next, t(`settings_user.password.problem.${p.code}`, p.params));
            return false;
          }
          if (value(next) === value(current)) return fail(next, t("settings_user.password.same"));
          if (value(next) !== value(again)) return fail(again, t("settings_user.password.mismatch"));
          if (code && !value(code).trim()) return fail(code, t("errors.totp_required"));
          await nextFrame();
          try {
            await V.changePassword(value(current), value(next), code ? { totp: value(code).trim() } : {});
          } catch (e) {
            showError(e, { passwordEl: current, codeEl: code, alertEl });
            return false;
          }
          notify({ text: t("settings_user.password.changed"), tone: "ok" });
          return true;
        },
      },
    ],
  });
}

// ------------------------------------------------------------ Clé de récupération

function rotateRecoveryDialog() {
  const profile = V.state.profile;
  const current = passwordField({ label: t("common.glossary.master_password"), autocomplete: "current-password", required: true });
  const code = profile.totp_enabled ? codeField() : null;
  const alertEl = h("div", {});
  let display = null;
  dialog({
    title: t("settings_user.recovery.dialog_title"),
    description: t("settings_user.recovery.dialog_intro"),
    body: h("div", { class: "l-stack", "data-gap": "3" }, alertEl, current, code),
    actions: [
      { label: t("common.action.cancel"), cancel: true },
      {
        label: t("settings_user.recovery.submit"), variant: "primary", busyLabel: t("settings_user.recovery.busy"),
        onClick: async () => {
          clear(alertEl);
          const password = fieldInput(current).value;
          if (!password) return fail(current, t("settings_user.password.current_required"));
          if (code && !fieldInput(code).value.trim()) return fail(code, t("errors.totp_required"));
          await nextFrame();
          try {
            display = await V.rotateRecovery(password, code ? { totp: fieldInput(code).value.trim() } : {});
          } catch (e) {
            showError(e, { passwordEl: current, codeEl: code, alertEl });
            return false;
          }
          return true;
        },
      },
    ],
    // La fenêtre de saisie fermée, la nouvelle clé s'affiche une seule fois.
    onClose: async () => {
      if (!display) return;
      await showRecoveryKey(display);
      display = null;
      notify({ text: t("settings_user.recovery.saved"), tone: "ok" });
    },
  });
}

// ------------------------------------------------------------ Double authentification

async function enableTwoFactor(redraw, ctx) {
  let setup;
  try {
    setup = await api("POST", "/me/2fa/setup");
  } catch (e) {
    notify({ text: errorText(e), tone: "danger" });
    return;
  }
  const codeInput = textInput({ name: "code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 7, spellcheck: false });
  const code = field({ label: t("settings_user.twofa.code_label"), input: codeInput });
  let after = null;
  const qr = h("img", { class: "c-card", alt: t("settings_user.twofa.qr_alt"), src: `data:image/svg+xml;base64,${btoa(setup.qr_svg)}`, width: 200, height: 200 });
  dialog({
    title: t("settings_user.twofa.enable_title"),
    body: h("ol", { class: "l-stack", "data-gap": "4" },
      h("li", { class: "l-stack", "data-gap": "2" }, h("p", {}, t("settings_user.twofa.step_scan")), qr,
        h("details", {}, h("summary", {}, t("settings_user.twofa.manual")),
          h("p", { class: "u-mono", translate: "no" }, setup.secret))),
      h("li", {}, code)),
    actions: [
      { label: t("common.action.cancel"), cancel: true },
      {
        label: t("settings_user.twofa.enable_submit"), variant: "primary", busyLabel: t("common.state.saving"),
        onClick: async () => {
          const value = codeInput.value.replace(/\D+/g, "");
          if (value.length !== 6) return fail(code, t("settings_user.twofa.code_invalid"));
          let res;
          try {
            res = await api("POST", "/me/2fa/enable", { code: value });
          } catch (e) {
            fieldError(code, errorText(e));
            return false;
          }
          const { recovery_codes: codes, ...profile } = res || {};
          const wasRequired = V.state.profile?.must_setup_2fa;
          V.state.profile = { ...V.state.profile, ...profile, totp_enabled: true, must_setup_2fa: false };
          notify({ text: t("settings_user.twofa.enabled"), tone: "ok" });
          after = async () => {
            if (Array.isArray(codes) && codes.length) await showRecoveryCodes(codes);
            await redraw();
            if (wasRequired) ctx.refresh?.();
          };
          return true;
        },
      },
    ],
    // Codes de secours montrés une fois la fenêtre d'activation fermée.
    onClose: () => after?.(),
  });
}

async function disableTwoFactor(redraw) {
  let done;
  try {
    done = await withReauth("totp.disable", ({ reauth }) => api("POST", "/me/2fa/disable", {}, { reauth }), {
      title: t("settings_user.twofa.disable_title"),
      message: t("settings_user.twofa.disable_message"),
    });
  } catch (e) {
    notify({ text: t("settings_user.twofa.disable_failed", { reason: errorText(e) }), tone: "danger" });
    return;
  }
  if (!done) return;
  V.state.profile = { ...V.state.profile, ...done, totp_enabled: false };
  notify({ text: t("settings_user.twofa.disabled"), tone: "ok" });
  await redraw();
}

async function regenerateCodes(redraw) {
  let res;
  try {
    res = await withReauth("totp.recovery_codes", ({ reauth }) => api("POST", "/me/2fa/recovery-codes", undefined, { reauth }), {
      title: t("settings_user.codes.regenerate_title"),
      message: t("settings_user.codes.regenerate_message"),
    });
  } catch (e) {
    notify({ text: t("settings_user.codes.regenerate_failed", { reason: errorText(e) }), tone: "danger" });
    return;
  }
  if (!res) return;
  await showRecoveryCodes(res.codes || []);
  await redraw();
}

/** Compteur des codes de secours ; null si le serveur ne les gère pas. */
async function codesStatus() {
  try {
    return (await apiFull("GET", "/me/2fa/recovery-codes")).data;
  } catch (e) {
    if (e?.status === 404) return null;
    throw e;
  }
}

// ------------------------------------------------------------ Vue

export async function render(container, ctx) {
  const settings = ctx.settings || S;
  let disposed = false;
  // Nom affiché en cours de saisie : garde au changement d'écran et à la
  // fermeture de l'onglet (G35), avec « Enregistrer » dans la demande.
  let nameInput = null;
  let saveNameNow = null;
  const guard = dirtyGuard(() => !disposed && !!nameInput && nameInput.value.trim() !== (V.state.profile?.name || ""), {
    onSave: () => saveNameNow?.(),
  });

  async function draw() {
    const p = V.state.profile || {};
    let status = null;
    let statusError = null;
    if (p.totp_enabled) {
      try {
        status = await codesStatus();
      } catch (e) {
        statusError = e;
      }
    }
    if (disposed) return;

    const name = textInput({ name: "name", value: p.name || "", maxlength: 100, autocomplete: "name" });
    const nameField = field({ label: t("settings_user.account.name"), input: name, count: true });
    nameInput = name;
    /** Enregistre le nom ; faux si la saisie reste à corriger. */
    saveNameNow = async () => {
      const value = name.value.trim();
      if (!value) {
        fieldError(nameField, t("settings_user.account.name_required"));
        return false;
      }
      try {
        const profile = await api("PUT", "/me", { name: value });
        V.state.profile = { ...V.state.profile, ...profile };
        fieldError(nameField, null);
        notify({ text: t("settings_user.account.name_saved"), tone: "ok" });
        return true;
      } catch (e) {
        fieldError(nameField, errorText(e));
        return false;
      }
    };
    const saveName = button({
      label: t("settings_user.account.save_name"), busyLabel: t("common.state.saving"),
      onClick: () => saveNameNow(),
    });

    const twofa = [];
    if (!p.totp_enabled) {
      twofa.push(
        p.must_setup_2fa ? alertCard({ tone: "warn", text: t("settings_user.account.twofa_required") }) : null,
        h("p", { class: "l-cluster" }, badge({ tone: "neutral", label: t("common.state.disabled") }), h("span", { class: "u-muted" }, t("settings_user.twofa.off_help"))),
        h("div", { class: "l-cluster" }, button({ label: t("settings_user.twofa.enable"), icon: "shield", variant: "primary", onClick: () => enableTwoFactor(redraw, ctx) })),
      );
    } else {
      let codesLine = null;
      if (statusError) codesLine = alertCard({ tone: "danger", text: errorText(statusError) });
      else if (status) {
        const low = status.remaining <= 3;
        codesLine = h("div", { class: "l-stack", "data-gap": "2" },
          h("p", {}, status.total
            ? plural("settings_user.codes.remaining", status.remaining, { total: status.total })
            : t("settings_user.codes.none")),
          status.generated_at ? h("p", { class: "u-muted" }, t("settings_user.codes.generated_at", { date: fmtDate(status.generated_at) })) : null,
          low ? alertCard({ tone: "warn", text: t("settings_user.codes.low") }) : null);
      }
      twofa.push(
        h("p", { class: "l-cluster" }, badge({ tone: "ok", icon: "check", label: t("common.state.enabled") }), h("span", { class: "u-muted" }, t("settings_user.twofa.on_help"))),
        h("h3", {}, t("settings_user.codes.heading")),
        h("p", { class: "u-muted" }, t("settings_user.codes.help")),
        codesLine,
        h("div", { class: "l-cluster" },
          status ? button({ label: t("settings_user.codes.regenerate"), icon: "refresh", onClick: () => regenerateCodes(redraw) }) : null,
          button({ label: t("settings_user.twofa.disable"), variant: "danger", onClick: () => disableTwoFactor(redraw) })),
      );
    }

    let fingerprint = null;
    try {
      fingerprint = p.public_key ? V.fingerprint(p.public_key) : null;
    } catch { /* module de chiffrement indisponible : section masquée */ }

    const section = (titleKey, ...content) => {
      const id = uid("section");
      return h("section", { class: "c-card", "aria-labelledby": id }, h("h2", { id }, t(titleKey)), ...content);
    };

    clear(container,
      section("settings_user.account.profile",
        nameField,
        h("p", {}, t("settings_user.account.email", { email: p.email || "" })),
        h("p", { class: "l-cluster" }, badge({ tone: "info", label: t(`ui.role.${p.role || "user"}`) }),
          p.created_at ? h("span", { class: "u-muted" }, t("settings_user.account.created", { date: fmtDate(p.created_at, "date") })) : null),
        h("div", { class: "l-cluster" }, saveName)),
      section("settings_user.password.heading",
        h("p", { class: "u-muted" }, t("settings_user.password.help")),
        h("div", { class: "l-cluster" }, button({ label: t("settings_user.password.open"), icon: "key", onClick: () => changePasswordDialog(settings) }))),
      section("common.glossary.two_factor", ...twofa),
      section("settings_user.recovery.heading",
        h("p", { class: "u-muted" }, t("settings_user.recovery.help")),
        h("div", { class: "l-cluster" }, button({ label: t("settings_user.recovery.open"), icon: "key", onClick: () => rotateRecoveryDialog() }))),
      fingerprint ? section("settings_user.account.fingerprint",
        h("p", { class: "u-muted" }, t("settings_user.account.fingerprint_help")),
        technicalDetails({ summary: t("settings_user.account.fingerprint_show"), body: h("p", { class: "u-mono" }, fingerprint) })) : null);
  }

  const redraw = () => keepFocus(container, draw);
  await draw();
  return {
    dispose() {
      disposed = true;
      guard.destroy();
    },
    isDirty: guard.isDirty,
    save: () => saveNameNow?.(),
  };
}
