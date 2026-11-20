// Connexion d'entreprise (SSO) : assistant en 4 étapes (fournisseur,
// identifiants de l'application, test avec le compte de l'administrateur,
// activation) et page d'état (dernière réussite, dernière erreur, « Tester
// maintenant », détails techniques repliés). « Imposé » n'est proposé
// qu'après un test réussi de moins de 24 h par l'administrateur (G-14).

import { api } from "../../../api.js";
import {
  alertCard, button, chipsInput, clear, dirtyGuard, field, fieldError, fieldInput, focusSafely, h,
  passwordField, radioCards, setToggle, t, technicalDetails, textInput, toggle, wizard,
} from "../../../ui/index.js";
import {
  backLink, changeTracker, copyField, hrefOf, modeChoice, modeOf, pageHeader, reasonText, resultArea,
  testLines, testedRecently, toggleState,
} from "./common.js";
import { loadIdentityStatus } from "./status-cards.js";

/** Préréglages des fournisseurs : émetteur pré-rempli et adresse e-mail non vérifiée acceptée. */
const PROVIDERS = Object.freeze({
  entra: { issuer: "", trustUnverified: true },
  google: { issuer: "https://accounts.google.com", trustUnverified: false },
  okta: { issuer: "", trustUnverified: false },
  keycloak: { issuer: "", trustUnverified: false },
  other: { issuer: "", trustUnverified: false },
});

/** Fournisseurs dont le nom sert de texte du bouton de connexion par défaut. */
const PRESET_LABELS = ["entra", "google", "okta", "keycloak"];

/** Fournisseur probable d'une configuration enregistrée. */
function guessProvider(issuer) {
  const i = String(issuer || "").toLowerCase();
  if (!i) return "";
  if (i.includes("microsoftonline") || i.includes("login.microsoft")) return "entra";
  if (i.includes("accounts.google.com")) return "google";
  if (i.includes("okta")) return "okta";
  if (i.includes("/realms/")) return "keycloak";
  return "other";
}

const DOMAIN_RE = /^\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;
const EXTENSION_RE = /^[a-p]{32}$/i;

/** Délai entre deux lectures de l'état pendant un test dans une autre fenêtre. */
const POLL_MS = 4000;
const POLL_MAX = 75;

/** Résultat d'un test lu dans l'adresse (?test=ok | ?test=erreur&code=…). */
function readTestResult(query) {
  const value = query?.get("test");
  if (value !== "ok" && value !== "erreur") return null;
  return { ok: value === "ok", code: query.get("code") || "unknown" };
}

/**
 * Lance un vrai parcours SSO de test dans une nouvelle fenêtre, ouverte dans
 * le geste de l'utilisateur (sinon bloquée). Fenêtre refusée : le test se
 * poursuit dans cet onglet. Renvoie vrai si le test est en cours ailleurs.
 */
async function startTest() {
  const win = window.open("", "_blank");
  let url;
  try {
    ({ url } = await api("POST", "/admin/sso/test-start"));
  } catch (e) {
    win?.close();
    throw e;
  }
  if (!win) {
    location.assign(url);
    return false;
  }
  win.opener = null;
  win.location.href = url;
  return true;
}

/**
 * Surveille le résultat d'un test lancé dans une autre fenêtre : lecture de
 * l'état au retour sur l'onglet et toutes les 4 s. onResult(status) quand un
 * nouveau test SSO est enregistré. Renvoie la fonction d'arrêt.
 */
function watchTest(before, onResult) {
  let n = 0;
  let stopped = false;
  const check = async () => {
    if (stopped) return;
    n += 1;
    if (n > POLL_MAX) return stop();
    try {
      const status = await loadIdentityStatus();
      const last = status.sso?.last_test;
      if (!stopped && last && last.at !== before && last.by_me !== false) {
        stop();
        onResult(status);
      }
    } catch {
      /* lecture impossible : nouvel essai au prochain passage */
    }
  };
  const onVisible = () => { if (document.visibilityState === "visible") check(); };
  const timer = setInterval(check, POLL_MS);
  window.addEventListener("focus", check);
  document.addEventListener("visibilitychange", onVisible);
  function stop() {
    stopped = true;
    clearInterval(timer);
    window.removeEventListener("focus", check);
    document.removeEventListener("visibilitychange", onVisible);
  }
  return { stop, check };
}

/** Champs de l'assistant, construits une fois : la saisie survit aux changements d'étape. */
function buildForm(cfg) {
  const form = {
    provider: guessProvider(cfg.issuer),
    autoProvision: !!cfg.auto_provision,
    trustUnverified: !!cfg.trust_unverified_email,
    domains: [...(cfg.allowed_domains || [])],
    extensions: [...(cfg.allowed_extension_ids || [])],
    // Première configuration : « Proposé » est présélectionné (l'assistant sert à l'activer).
    mode: cfg.issuer ? modeOf(cfg.enabled, cfg.enforce) : "offered",
  };

  const providerHelp = h("p", { class: "u-muted" });
  const issuer = field({
    label: t("identity.sso.issuer.label"), help: t("identity.sso.issuer.help"),
    input: textInput({ value: cfg.issuer, autocomplete: "off", spellcheck: false, inputmode: "url" }),
  });
  const clientId = field({
    label: t("identity.sso.client_id.label"), help: t("identity.sso.client_id.help"),
    input: textInput({ value: cfg.client_id, autocomplete: "off", spellcheck: false }),
  });
  const secret = passwordField({
    label: t("identity.sso.secret.label"), autocomplete: "new-password", capsLockHint: false,
    help: t(cfg.has_secret ? "identity.secret.help_saved" : "identity.secret.help_new"),
  });
  const buttonLabel = field({
    label: t("identity.sso.button_label.label"), help: t("identity.sso.button_label.help"),
    input: textInput({ value: cfg.label, maxlength: 60, autocomplete: "off" }),
  });
  const unverified = toggle({
    label: t("identity.sso.unverified.label"), help: t("identity.sso.unverified.help"),
    checked: form.trustUnverified, onChange: (v) => { form.trustUnverified = v; },
  });
  const options = h("details", { class: "c-card" },
    h("summary", {}, t("identity.options")),
    h("div", { class: "l-stack", "data-gap": "3" },
      toggle({
        label: t("identity.sso.auto_provision.label"), help: t("identity.sso.auto_provision.help"),
        checked: form.autoProvision, onChange: (v) => { form.autoProvision = v; },
      }),
      chipsInput({
        label: t("identity.sso.domains.label"), help: t("identity.sso.domains.help"), values: form.domains,
        placeholderKey: "identity.sso.domains.placeholder",
        validate: (v) => (DOMAIN_RE.test(v) ? null : t("identity.sso.domains.invalid", { value: v })),
        onChange: (v) => { form.domains = v; },
      }),
      unverified,
      chipsInput({
        label: t("identity.sso.extensions.label"), help: t("identity.sso.extensions.help"), values: form.extensions,
        validate: (v) => (EXTENSION_RE.test(v) ? null : t("errors.field.invalid_extension_id", { value: v })),
        onChange: (v) => { form.extensions = v; },
      })));

  const setProvider = (p) => {
    const before = PROVIDERS[form.provider];
    form.provider = p;
    providerHelp.textContent = p ? t(`identity.sso.help.${p}`) : "";
    const input = fieldInput(issuer);
    input.placeholder = p ? t(`identity.sso.issuer.placeholder.${p}`) : "";
    // Valeur pré-remplie seulement si l'émetteur est vide ou vient du préréglage précédent.
    if (!input.value.trim() || input.value === before?.issuer) input.value = PROVIDERS[p]?.issuer || "";
    const label = fieldInput(buttonLabel);
    if (!label.value.trim() || PRESET_LABELS.some((k) => label.value === t(`identity.sso.preset.${k}`))) {
      label.value = p === "other" ? "" : t(`identity.sso.preset.${p}`);
    }
    if (!cfg.has_secret && PROVIDERS[p]) {
      form.trustUnverified = PROVIDERS[p].trustUnverified;
      setToggle(unverified, form.trustUnverified);
    }
  };
  const provider = radioCards({
    legend: t("identity.sso.provider.legend"),
    options: Object.keys(PROVIDERS).map((p) => ({ value: p, label: t(`identity.sso.provider.${p}`) })),
    value: form.provider,
    onChange: setProvider,
  });
  if (form.provider) {
    providerHelp.textContent = t(`identity.sso.help.${form.provider}`);
    fieldInput(issuer).placeholder = t(`identity.sso.issuer.placeholder.${form.provider}`);
  }

  const values = () => ({
    provider: form.provider,
    issuer: fieldInput(issuer).value.trim(),
    client_id: fieldInput(clientId).value.trim(),
    secret: fieldInput(secret).value,
    label: fieldInput(buttonLabel).value.trim(),
    auto_provision: form.autoProvision,
    trust_unverified_email: toggleState(unverified),
    allowed_domains: form.domains,
    allowed_extension_ids: form.extensions,
    mode: form.mode,
  });
  return { form, provider, providerHelp, issuer, clientId, secret, buttonLabel, options, values, tracker: changeTracker(values) };
}

/** Corps de PUT /admin/sso : configuration complète (le secret vide conserve l'actuel). */
function payload(cfg, v, { enabled, enforce }) {
  return {
    ...cfg,
    enabled, enforce,
    issuer: v.issuer, client_id: v.client_id, client_secret: v.secret, label: v.label,
    auto_provision: v.auto_provision, trust_unverified_email: v.trust_unverified_email,
    allowed_domains: v.allowed_domains, allowed_extension_ids: v.allowed_extension_ids,
    redirect_uri: "", has_secret: false,
  };
}

/** Page « Connexion d'entreprise (SSO) ». */
export async function ssoPage(container, { query, setQuery }) {
  let [status, cfg] = await Promise.all([loadIdentityStatus(), api("GET", "/admin/sso")]);
  const fromUrl = readTestResult(query);
  // Le résultat est lu une fois : l'adresse est nettoyée sans recharger la vue.
  if (fromUrl) {
    if (typeof setQuery === "function") setQuery({ test: null, code: null });
    else history.replaceState(history.state, "", hrefOf("sso"));
  }

  let mode = status.sso?.configured ? "state" : "wizard";
  let f = buildForm(cfg);
  let watcher = null;
  const body = h("div", { class: "l-stack", "data-gap": "4" });
  const banner = fromUrl
    ? alertCard({
      tone: fromUrl.ok ? "ok" : "danger",
      text: fromUrl.ok ? t("identity.sso.test.ok") : t("identity.test.failed", { reason: reasonText(fromUrl.code) }),
    })
    : null;
  clear(container,
    backLink(),
    ...pageHeader("identity.sso.title", "identity.sso.intro"),
    status.partial ? alertCard({ tone: "info", text: t("identity.partial") }) : null,
    banner,
    body);

  const canEnforce = () => testedRecently(status.sso) || (cfg.enabled && cfg.enforce);
  const refresh = async () => { status = await loadIdentityStatus(); };
  const stopWatch = () => { watcher?.stop(); watcher = null; };

  /** Bouton « Tester … » et sa zone de résultat ; onDone() après un nouveau résultat. */
  function testControls(label, area, onDone) {
    const check = button({ label: t("identity.sso.test.check"), variant: "quiet", onClick: () => watcher?.check() });
    check.hidden = true;
    const start = button({
      label, icon: "external", busyLabel: t("identity.test.starting"),
      onClick: async () => {
        stopWatch();
        const before = status.sso?.last_test?.at ?? null;
        try {
          if (!(await startTest())) return;
        } catch (e) {
          area.error(e);
          return;
        }
        area.info(t("identity.sso.test.pending"));
        check.hidden = false;
        watcher = watchTest(before, (next) => {
          status = next;
          check.hidden = true;
          const last = next.sso.last_test;
          if (last.ok) area.ok(t("identity.sso.test.ok"));
          else area.error({ code: last.error_code });
          onDone?.();
        });
      },
    });
    return h("div", { class: "l-cluster" }, start, check);
  }

  /** Page d'état ; `saved` : confirmation affichée dans la page (un toast recouvrirait ses boutons). */
  function showState(saved) {
    stopWatch();
    mode = "state";
    const s = status.sso || {};
    const area = resultArea();
    if (saved) area.ok(saved);
    const lines = h("div", { class: "l-stack", "data-gap": "1" });
    const fillLines = () => clear(lines,
      h("p", {}, h("strong", {}, t(`identity.sso.state.${modeOf(cfg.enabled, cfg.enforce)}`))),
      ...testLines(status.sso).map((line) => h("p", {}, line)));
    fillLines();
    clear(body,
      h("section", { class: "c-card l-stack", "data-gap": "3", "aria-labelledby": "sso-etat" },
        h("h2", { id: "sso-etat" }, t("identity.state.title")),
        lines,
        testControls(t("identity.action.test_now"), area, fillLines),
        area.el,
        h("div", { class: "l-cluster" },
          button({ label: t("identity.action.change_mode"), onClick: () => showWizard("activation") }),
          button({ label: t("identity.action.edit_config"), icon: "edit", onClick: () => showWizard("provider") })),
        technicalDetails({
          body: h("dl", {},
            h("dt", {}, t("identity.tech.issuer")), h("dd", {}, cfg.issuer || "—"),
            h("dt", {}, t("identity.tech.client_id")), h("dd", {}, cfg.client_id || "—"),
            h("dt", {}, t("identity.tech.redirect_uri")), h("dd", {}, cfg.redirect_uri || "—"),
            s.last_error ? h("dt", {}, t("identity.tech.last_error_code")) : null,
            s.last_error ? h("dd", {}, s.last_error.code) : null),
        })));
  }

  function showWizard(step = "provider", { focus = true } = {}) {
    stopWatch();
    mode = "wizard";
    // saved : confirmation de l'étape précédente, affichée en tête de l'étape
    // suivante (un toast recouvrirait les boutons de l'assistant).
    const areas = { provider: resultArea(), credentials: resultArea(), saved: resultArea(), test: resultArea(), activation: resultArea() };
    const modeBox = h("div", {});
    const renderMode = () => clear(modeBox, modeChoice({
      kind: "sso", value: f.form.mode, canEnforce: canEnforce(),
      onChange: (v) => { f.form.mode = v; },
    }));
    renderMode();
    const testState = h("p", {});
    const fillTestState = () => {
      testState.textContent = testedRecently(status.sso) ? testLines(status.sso)[0] : t("identity.sso.test.optional");
    };
    fillTestState();
    // Le test continue pendant qu'on change d'étape : son résultat met à jour l'activation.
    const tester = testControls(t("identity.action.test_with_my_account"), areas.test, () => { fillTestState(); renderMode(); });
    const redirect = copyField({
      label: t("identity.sso.redirect.label"), help: t("identity.sso.redirect.help"),
      value: cfg.redirect_uri, copyLabel: t("identity.sso.redirect.copy"),
    });

    const steps = [
      {
        id: "provider", title: t("identity.sso.step.provider"),
        render: (c) => clear(c, f.provider, f.providerHelp, redirect,
          cfg.public_url ? null : alertCard({ tone: "info", text: t("identity.sso.redirect.no_public_url") }),
          areas.provider.el),
        validate: () => {
          if (f.form.provider) {
            areas.provider.clear();
            return true;
          }
          areas.provider.warn(t("identity.sso.provider.required"));
          f.provider.querySelector("input")?.focus();
          return false;
        },
      },
      {
        id: "credentials", title: t("identity.sso.step.credentials"),
        render: (c) => clear(c, f.issuer, f.clientId, f.secret, f.buttonLabel, f.options, areas.credentials.el),
        validate: async () => {
          const v = f.values();
          const checks = [
            [f.issuer, !v.issuer ? "identity.sso.issuer.required" : !/^https:\/\//i.test(v.issuer) ? "identity.sso.issuer.https" : null],
            [f.clientId, v.client_id ? null : "identity.sso.client_id.required"],
            [f.secret, v.secret || cfg.has_secret ? null : "identity.sso.secret.required"],
          ];
          let first = null;
          for (const [el, key] of checks) {
            fieldError(el, key ? t(key) : null, { announce: false });
            if (key && !first) first = el;
          }
          if (first) {
            areas.credentials.clear();
            focusSafely(fieldInput(first));
            return false;
          }
          try {
            await api("POST", "/admin/sso/test", payload(cfg, v, { enabled: cfg.enabled, enforce: cfg.enforce }));
            cfg = await api("PUT", "/admin/sso", payload(cfg, v, { enabled: cfg.enabled, enforce: cfg.enforce }));
          } catch (e) {
            areas.credentials.error(e);
            return false;
          }
          // Secret enregistré : le champ se vide et le dit.
          fieldInput(f.secret).value = "";
          f.secret.querySelector(".c-field__help").textContent = t("identity.secret.help_saved");
          f.tracker.reset();
          await refresh().catch(() => {});
          areas.credentials.clear();
          areas.saved.ok(t(cfg.enabled ? "identity.saved" : "identity.sso.saved_inactive"));
          return true;
        },
      },
      {
        id: "test", title: t("identity.sso.step.test"),
        render: (c) => clear(c, areas.saved.el, h("p", {}, t("identity.sso.test.intro")), testState, tester, areas.test.el),
      },
      {
        id: "activation", title: t("identity.sso.step.activation"),
        render: (c) => { renderMode(); clear(c, modeBox, areas.activation.el); },
      },
    ];

    const w = wizard({
      label: t("identity.sso.wizard.label"), steps, current: step, finishLabel: t("common.action.save"),
      onFinish: async () => {
        const v = f.values();
        try {
          cfg = await api("PUT", "/admin/sso", payload(cfg, v, { enabled: v.mode !== "off", enforce: v.mode === "enforced" }));
        } catch (e) {
          if (e?.code === "test_required") {
            status = { ...status, sso: { ...status.sso, last_ok_by_me_at: null } };
            f.form.mode = "offered";
            renderMode();
          }
          areas.activation.error(e);
          return;
        }
        await refresh().catch(() => {});
        f = buildForm(cfg);
        showState(t("identity.sso.saved"));
        focusSafely(container.querySelector("h1"));
      },
    });
    const cancel = status.sso?.configured
      ? button({
        label: t("common.action.cancel"), variant: "quiet",
        onClick: async () => {
          const choice = await dirtyGuard(() => f.tracker.isDirty(), { unload: false }).confirmLeave();
          if (choice === "stay") return;
          f = buildForm(cfg);
          showState();
          focusSafely(container.querySelector("h1"));
        },
      })
      : null;
    clear(body, w.el, cancel ? h("div", { class: "l-cluster", "data-justify": "end" }, cancel) : null);
    if (focus) focusSafely(w.el.querySelector("h2"));
  }

  // Premier affichage : pas de focus forcé, le routeur le pose sur le h1.
  if (mode === "state") showState();
  else showWizard("provider", { focus: false });

  return {
    isDirty: () => mode === "wizard" && f.tracker.isDirty(),
    dispose: () => stopWatch(),
  };
}
