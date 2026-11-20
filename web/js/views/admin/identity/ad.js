// Compte Windows (Active Directory) : assistant en 4 étapes (serveur et
// compte de service, personnes autorisées avec synchronisation à blanc, test
// avec le compte Windows de l'administrateur, activation) et page d'état
// (synchronisation, test, historique des synchronisations).

import { api } from "../../../api.js";
import {
  alertCard, announce, button, clear, confirm, dataTable, dirtyGuard, field, fieldError, fieldInput, fmtDate, focusSafely, h,
  passwordField, plural, relTime, t, technicalDetails, textArea, textInput, toggle, wizard,
} from "../../../ui/index.js";
import {
  backLink, changeTracker, errorBlock, getOrNull, modeChoice, modeOf, pageHeader, reasonText, relatedSettings, resultArea,
  testLines, testedRecently, toggleState,
} from "./common.js";
import { loadIdentityStatus } from "./status-cards.js";

/** Raisons d'un compte ignoré connues de l'interface (identity.ad.ignored_reason.*). */
const REASONS = new Set(["no_email", "invalid_email", "domain_not_allowed", "not_in_group", "disabled_in_directory", "duplicate_email", "last_owner"]);
const ATTRIBUTE_RE = /^[A-Za-z0-9-]+$/;
const URL_RE = /^ldaps?:\/\/\S+$/i;

const reasonLabel = (r) => t(`identity.ad.ignored_reason.${REASONS.has(r) ? r : "other"}`);

/** Résumé d'une synchronisation : « 42 comptes trouvés, 3 ignorés ». */
function foundLine(r) {
  const ignored = Array.isArray(r.ignored) ? r.ignored.length : Number(r.ignored_count) || 0;
  return t("identity.ad.summary", { found: plural("identity.ad.count.found", Number(r.found) || 0), ignored: plural("identity.ad.count.ignored", ignored) });
}

/** Effet (prévu à blanc, ou réel) d'une synchronisation. */
function effectLine(r) {
  return t(r.dry_run ? "identity.ad.effect.dry" : "identity.ad.effect.real", {
    created: plural("identity.ad.count.created", Number(r.created) || 0),
    updated: plural("identity.ad.count.updated", Number(r.updated) || 0),
    disabled: plural("identity.ad.count.disabled", Number(r.disabled) || 0),
  });
}

/** Tableau des comptes ignorés et de leur raison, replié derrière « Voir pourquoi ». */
function ignoredDetails(ignored) {
  if (!ignored?.length) return null;
  const table = dataTable({
    caption: t("identity.ad.ignored.caption"),
    columns: [
      { key: "login", label: t("identity.ad.col.login") },
      { key: "email", label: t("identity.ad.col.email"), render: (r) => r.email || "—" },
      { key: "reason", label: t("identity.ad.col.reason"), render: (r) => reasonLabel(r.reason) },
    ],
    rows: ignored,
    rowKey: (r) => `${r.login}:${r.reason}`,
    pageSize: 500,
  });
  return h("details", { class: "c-card" }, h("summary", {}, t("identity.ad.ignored.why")), table.el);
}

/** Bloc de résultat d'une synchronisation (à blanc ou réelle). */
function syncReport(r) {
  return h("div", { class: "l-stack", "data-gap": "2" },
    alertCard({ tone: "ok", title: foundLine(r), text: effectLine(r) }),
    ignoredDetails(r.ignored));
}

/** Champs de l'assistant, construits une fois : la saisie survit aux changements d'étape. */
function buildForm(cfg) {
  // Première configuration : synchronisation et connexion « Proposé » présélectionnées
  // (l'assistant sert à les activer) ; ensuite, l'état enregistré.
  const first = !cfg.url;
  const form = {
    starttls: !!cfg.starttls,
    enabled: first || !!cfg.enabled,
    mode: first ? "offered" : modeOf(cfg.allow_login, cfg.enforce),
  };
  const text = (labelKey, value, { help, placeholderKey, mono = true, maxlength } = {}) => {
    const input = textInput({ value, autocomplete: "off", spellcheck: false, maxlength, placeholder: placeholderKey ? t(placeholderKey) : undefined });
    if (mono) input.classList.add("u-mono");
    return field({ label: t(labelKey), help: help ? t(help) : undefined, input });
  };
  const ca = textArea({ value: cfg.ca_pem, rows: 5, placeholder: t("identity.ad.ca.placeholder") });
  ca.classList.add("u-mono");
  ca.setAttribute("spellcheck", "false");
  const minutes = textInput({ type: "number", value: String(cfg.sync_minutes ?? 15), min: 0, max: 1440, inputmode: "numeric" });

  const f = {
    form,
    url: text("identity.ad.url.label", cfg.url, { help: "identity.ad.url.help", placeholderKey: "identity.ad.url.placeholder" }),
    starttls: toggle({ label: t("identity.ad.starttls.label"), checked: form.starttls, onChange: (v) => { form.starttls = v; } }),
    ca: field({ label: t("identity.ad.ca.label"), help: t("identity.ad.ca.help"), input: ca }),
    bindDn: text("identity.ad.bind_dn.label", cfg.bind_dn, { help: "identity.ad.bind_dn.help", placeholderKey: "identity.ad.bind_dn.placeholder" }),
    bindPw: passwordField({
      label: t("identity.ad.bind_password.label"), autocomplete: "new-password", capsLockHint: false,
      help: t(cfg.has_password ? "identity.secret.help_saved" : "identity.secret.help_new"),
    }),
    baseDn: text("identity.ad.base_dn.label", cfg.base_dn, { help: "identity.ad.base_dn.help", placeholderKey: "identity.ad.base_dn.placeholder" }),
    group: text("identity.ad.group.label", cfg.group_dn, { help: "identity.ad.group.help", placeholderKey: "identity.ad.group.placeholder" }),
    loginAttr: text("identity.ad.login_attribute.label", cfg.login_attribute),
    mailAttr: text("identity.ad.email_attribute.label", cfg.email_attribute, { help: "identity.ad.email_attribute.help" }),
    minutes: field({ label: t("identity.ad.sync_minutes.label"), help: t("identity.ad.sync_minutes.help"), input: minutes, suffix: t("identity.ad.sync_minutes.suffix") }),
    label: text("identity.ad.button_label.label", cfg.label, { help: "identity.ad.button_label.help", mono: false, maxlength: 60 }),
    sync: toggle({
      label: t("identity.ad.sync.label"), help: t("identity.ad.sync.help"),
      checked: form.enabled, onChange: (v) => { form.enabled = v; },
    }),
  };
  f.advanced = h("details", { class: "c-card" },
    h("summary", {}, t("identity.options")),
    h("div", { class: "l-stack", "data-gap": "3" }, f.loginAttr, f.mailAttr, f.minutes, f.label));
  f.values = () => ({
    url: fieldInput(f.url).value.trim(),
    starttls: toggleState(f.starttls),
    ca_pem: fieldInput(f.ca).value.trim(),
    bind_dn: fieldInput(f.bindDn).value.trim(),
    bind_password: fieldInput(f.bindPw).value,
    base_dn: fieldInput(f.baseDn).value.trim(),
    group_dn: fieldInput(f.group).value.trim(),
    login_attribute: fieldInput(f.loginAttr).value.trim(),
    email_attribute: fieldInput(f.mailAttr).value.trim(),
    sync_minutes: Math.max(0, Math.min(1440, Math.round(Number(fieldInput(f.minutes).value) || 0))),
    label: fieldInput(f.label).value.trim(),
    enabled: toggleState(f.sync),
    mode: form.mode,
  });
  f.tracker = changeTracker(f.values);
  return f;
}

/** Corps de PUT /admin/ldap et POST /admin/ldap/test (mot de passe vide = conserver l'actuel). */
function payload(cfg, v, { enabled, allowLogin, enforce }) {
  const { mode: _mode, ...fields } = v;
  return { ...cfg, ...fields, enabled, allow_login: allowLogin, enforce };
}

/** Vérifie les champs obligatoires ; renvoie le premier champ en erreur (focalisé) ou null. */
function checkFields(list) {
  let first = null;
  for (const [el, key] of list) {
    fieldError(el, key ? t(key) : null, { announce: false });
    if (key && !first) first = el;
  }
  if (first) focusSafely(fieldInput(first));
  return first;
}

/** Page « Compte Windows (Active Directory) ». */
export async function adPage(container) {
  let [status, cfg] = await Promise.all([loadIdentityStatus(), api("GET", "/admin/ldap")]);
  let mode = status.ldap?.configured ? "state" : "wizard";
  let f = buildForm(cfg);
  const body = h("div", { class: "l-stack", "data-gap": "4" });
  clear(container,
    backLink(),
    ...pageHeader("identity.ad.title", "identity.ad.intro"),
    status.partial ? alertCard({ tone: "info", text: t("identity.partial") }) : null,
    body,
    relatedSettings(["directory.deprovision", "directory.delete_after_days", "directory.max_deprovision_percent"], "ad-reglages"));

  const canEnforce = () => testedRecently(status.ldap) || (cfg.allow_login && cfg.enforce);
  const refresh = async () => { status = await loadIdentityStatus(); };
  /** Configuration actuelle, sans changer l'activation. */
  const keep = () => ({ enabled: cfg.enabled, allowLogin: cfg.allow_login, enforce: cfg.enforce });

  /** Enregistre la saisie sans changer l'activation (avant une synchronisation à blanc). */
  async function saveDraft() {
    cfg = await api("PUT", "/admin/ldap", payload(cfg, f.values(), keep()));
    fieldInput(f.bindPw).value = "";
    f.bindPw.querySelector(".c-field__help").textContent = t("identity.secret.help_saved");
    f.tracker.reset();
  }

  /**
   * Bouton de synchronisation (à blanc ou réelle) et affichage du rapport dans
   * `area`. Un serveur sans /admin/identity/status ignore ?dry_run et ferait
   * une vraie synchronisation : le bouton « à blanc » y est désactivé, avec la raison.
   */
  function syncButton({ dry, area, beforeRun, onDone }) {
    const unsafe = dry && status.partial;
    return button({
      label: t(dry ? "identity.ad.dry_run.start" : "identity.ad.sync_now"),
      disabled: unsafe, reason: unsafe ? t("identity.ad.dry_run.unavailable") : undefined,
      icon: "refresh", busyLabel: t("identity.ad.sync.running"), variant: dry ? "secondary" : "primary",
      onClick: async () => {
        if (!dry) {
          const { confirmed } = await confirm({
            level: 1, title: t("identity.ad.sync_now.title"), message: t("identity.ad.sync_now.message"),
            confirmLabel: t("identity.ad.sync_now"),
          });
          if (!confirmed) return;
        }
        area.clear();
        try {
          await beforeRun?.();
          const r = await api("POST", `/admin/ldap/sync?dry_run=${dry ? "true" : "false"}`);
          clear(area.el, syncReport({ ...r, dry_run: dry }));
          announce(`${t(dry ? "identity.ad.dry_run.done" : "identity.ad.sync.done")} ${foundLine(r)}`);
        } catch (e) {
          area.error(e);
        }
        await onDone?.();
      },
    });
  }

  /** Formulaire de test avec le compte Windows de l'administrateur. */
  function testForm(area, onDone) {
    const user = field({ label: t("identity.ad.test.username"), input: textInput({ autocomplete: "off", spellcheck: false }) });
    const pw = passwordField({ label: t("identity.ad.test.password"), autocomplete: "off" });
    const run = button({
      label: t("identity.action.test_with_my_account"), icon: "user", busyLabel: t("identity.test.running"),
      onClick: async () => {
        const username = fieldInput(user).value.trim();
        const password = fieldInput(pw).value;
        if (checkFields([[user, username ? null : "identity.ad.test.username_required"], [pw, password ? null : "identity.ad.test.password_required"]])) return;
        area.clear();
        let r;
        try {
          r = await api("POST", "/admin/ldap/test-login", { username, password });
        } catch (e) {
          area.error(e);
          return;
        } finally {
          // Le mot de passe Windows n'est gardé nulle part.
          fieldInput(pw).value = "";
        }
        if (r.ok) area.ok(t("identity.ad.test.ok"));
        else area.error({ code: r.error_code, params: r.technical ? { technical: r.technical } : undefined });
        await refresh().catch(() => {});
        onDone?.();
      },
    });
    return h("div", { class: "l-stack", "data-gap": "3" }, h("p", {}, t("identity.ad.test.intro")), user, pw, h("div", { class: "l-cluster" }, run), area.el);
  }

  async function historySection() {
    let rows;
    try {
      rows = await getOrNull("/admin/ldap/history?limit=20");
    } catch (e) {
      return errorBlock(e);
    }
    if (!Array.isArray(rows)) {
      const tech = status.ldap?.last_sync?.technical;
      return tech ? technicalDetails({ body: h("p", {}, tech) }) : null;
    }
    const table = dataTable({
      caption: t("identity.ad.history.title"),
      columns: [
        { key: "at", label: t("identity.ad.history.col.date"), render: (r) => fmtDate(r.at) },
        { key: "dry_run", label: t("identity.ad.history.col.kind"), render: (r) => t(r.dry_run ? "identity.ad.history.kind.dry" : "identity.ad.history.kind.real") },
        { key: "result", label: t("identity.ad.history.col.result"), render: (r) => (r.error_code ? t("identity.ad.history.failed", { reason: reasonText(r.error_code) }) : foundLine(r)) },
        { key: "by", label: t("identity.ad.history.col.by"), render: (r) => t(r.triggered_by ? "identity.ad.history.by.manual" : "identity.ad.history.by.auto") },
      ],
      rows,
      rowKey: (r) => r.id,
      pageSize: 50,
      empty: t("identity.ad.history.empty"),
    });
    return h("section", { class: "l-stack", "data-gap": "2" }, table.el);
  }

  /** Page d'état ; `saved` : confirmation affichée dans la page (un toast recouvrirait ses boutons). */
  async function showState(saved) {
    mode = "state";
    const area = resultArea();
    if (saved) area.ok(saved);
    const testArea = resultArea();
    const lines = h("div", { class: "l-stack", "data-gap": "1" });
    const fillLines = () => {
      const sync = status.ldap?.last_sync;
      clear(lines,
        h("p", {}, h("strong", {}, t(`identity.ad.state.${cfg.allow_login ? modeOf(true, cfg.enforce) : cfg.enabled ? "sync_only" : "off"}`))),
        sync ? h("p", {}, sync.ok ? t("identity.ad.detail.synced_at", { when: relTime(sync.at) }) : t("identity.ad.detail.sync_failed", { when: relTime(sync.at), reason: reasonText(sync.error_code) })) : null,
        ...testLines(status.ldap).map((line) => h("p", {}, line)));
    };
    fillLines();
    const history = h("div", {});
    const reloadHistory = async () => {
      await refresh().catch(() => {});
      fillLines();
      clear(history, await historySection());
    };
    const tester = h("details", { class: "c-card" },
      h("summary", {}, t("identity.action.test_now")),
      testForm(testArea, fillLines));
    clear(body,
      h("section", { class: "c-card l-stack", "data-gap": "3", "aria-labelledby": "ad-etat" },
        h("h2", { id: "ad-etat" }, t("identity.state.title")),
        lines,
        h("div", { class: "l-cluster" },
          cfg.enabled ? syncButton({ dry: false, area, onDone: reloadHistory }) : null,
          syncButton({ dry: true, area, onDone: reloadHistory })),
        area.el,
        tester,
        h("div", { class: "l-cluster" },
          button({ label: t("identity.action.change_mode"), onClick: () => showWizard("activation") }),
          button({ label: t("identity.action.edit_config"), icon: "edit", onClick: () => showWizard("server") }))),
      h("section", { class: "l-stack", "data-gap": "2", "aria-labelledby": "ad-historique" },
        h("h2", { id: "ad-historique" }, t("identity.ad.history.title")),
        history));
    clear(history, await historySection());
  }

  function showWizard(step = "server", { focus = true } = {}) {
    mode = "wizard";
    // saved : confirmation de l'étape précédente, affichée en tête de l'étape
    // suivante (un toast recouvrirait les boutons de l'assistant).
    const areas = { server: resultArea(), saved: resultArea(), group: resultArea(), dry: resultArea(), test: resultArea(), activation: resultArea() };
    const modeBox = h("div", {});
    const renderMode = () => clear(modeBox, modeChoice({
      kind: "ad", value: f.form.mode, canEnforce: canEnforce(),
      onChange: (v) => { f.form.mode = v; },
    }));
    const tester = testForm(areas.test, () => renderMode());
    const dryRun = syncButton({ dry: true, area: areas.dry, beforeRun: saveDraft });

    const steps = [
      {
        id: "server", title: t("identity.ad.step.server"),
        render: (c) => clear(c, f.url, f.starttls, f.ca, f.bindDn, f.bindPw, f.baseDn, areas.server.el),
        validate: async () => {
          const v = f.values();
          if (checkFields([
            [f.url, !v.url ? "identity.ad.url.required" : URL_RE.test(v.url) ? null : "identity.ad.url.invalid"],
            [f.bindDn, v.bind_dn ? null : "identity.ad.bind_dn.required"],
            [f.bindPw, v.bind_password || cfg.has_password ? null : "identity.ad.bind_password.required"],
            [f.baseDn, v.base_dn ? null : "identity.ad.base_dn.required"],
          ])) {
            areas.server.clear();
            return false;
          }
          let found;
          try {
            found = await api("POST", "/admin/ldap/test", payload(cfg, v, keep()));
            await saveDraft();
          } catch (e) {
            areas.server.error(e);
            return false;
          }
          areas.server.clear();
          areas.saved.ok(plural("identity.ad.server.ok", Number(found?.users) || 0));
          return true;
        },
      },
      {
        id: "group", title: t("identity.ad.step.group"),
        render: (c) => clear(c, areas.saved.el, f.group, f.advanced,
          h("p", {}, t(status.partial ? "identity.ad.dry_run.unavailable" : "identity.ad.dry_run.intro")),
          h("div", { class: "l-cluster" }, dryRun), areas.dry.el, areas.group.el),
        validate: async () => {
          const v = f.values();
          if (checkFields([
            [f.loginAttr, ATTRIBUTE_RE.test(v.login_attribute) ? null : "identity.ad.attribute.invalid"],
            [f.mailAttr, ATTRIBUTE_RE.test(v.email_attribute) ? null : "identity.ad.attribute.invalid"],
          ])) {
            f.advanced.open = true;
            return false;
          }
          if (!f.tracker.isDirty()) return true;
          try {
            await saveDraft();
          } catch (e) {
            areas.group.error(e);
            return false;
          }
          return true;
        },
      },
      {
        id: "test", title: t("identity.ad.step.test"),
        render: (c) => clear(c, tester),
      },
      {
        id: "activation", title: t("identity.ad.step.activation"),
        render: (c) => { renderMode(); clear(c, f.sync, modeBox, areas.activation.el); },
      },
    ];

    const w = wizard({
      label: t("identity.ad.wizard.label"), steps, current: step, finishLabel: t("common.action.save"),
      onFinish: async () => {
        const v = f.values();
        try {
          cfg = await api("PUT", "/admin/ldap", payload(cfg, v, { enabled: v.enabled, allowLogin: v.mode !== "off", enforce: v.mode === "enforced" }));
        } catch (e) {
          if (e?.code === "test_required") {
            status = { ...status, ldap: { ...status.ldap, last_ok_by_me_at: null } };
            f.form.mode = "offered";
            renderMode();
          }
          areas.activation.error(e);
          return;
        }
        await refresh().catch(() => {});
        f = buildForm(cfg);
        await showState(t("identity.saved"));
        focusSafely(container.querySelector("h1"));
      },
    });
    const cancel = status.ldap?.configured
      ? button({
        label: t("common.action.cancel"), variant: "quiet",
        onClick: async () => {
          const choice = await dirtyGuard(() => f.tracker.isDirty(), { unload: false }).confirmLeave();
          if (choice === "stay") return;
          f = buildForm(cfg);
          await showState();
          focusSafely(container.querySelector("h1"));
        },
      })
      : null;
    clear(body, w.el, cancel ? h("div", { class: "l-cluster", "data-justify": "end" }, cancel) : null);
    if (focus) focusSafely(w.el.querySelector("h2"));
  }

  // Premier affichage : pas de focus forcé, le routeur le pose sur le h1.
  if (mode === "state") await showState();
  else showWizard("server", { focus: false });

  return { isDirty: () => mode === "wizard" && f.tracker.isDirty() };
}
