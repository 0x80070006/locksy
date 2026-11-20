// « Enregistrer le compte saisi sur ce site » : lit l'identifiant et le mot de
// passe PRÉSENTS DANS LA PAGE (correctif P0 de l'audit 01 : jamais un mot de
// passe généré à la place de celui de l'utilisateur). Sans saisie dans la
// page, « Créer un mot de passe pour ce site » génère explicitement.
// Un compte déjà enregistré pour ce site et cet identifiant est mis à jour
// (l'ancien mot de passe va dans l'historique) au lieu d'être dupliqué.

import { h, t, field, textInput, selectInput, passwordField, fieldInput, alertCard, notify } from "../lib/ui/index.js";
import * as V from "../lib/vault.js";
import * as Settings from "../lib/settings-client.js";
import { isInsecurePage, urlMatches } from "../match.js";
import { S, ext, go, screen, showError, action, form, submitButton } from "./context.js";
import { touch } from "./session.js";
import { pageState } from "./fill.js";
import { generate, generateFresh } from "./generate.js";

/**
 * Exécutée dans la page (cadre principal) : identifiant et mot de passe saisis.
 * Fonction autonome (sérialisée par executeScript). Préfère un champ « nouveau
 * mot de passe » rempli (inscription, changement), sinon le premier rempli.
 */
export function readPage(expectedOrigin) {
  if (location.origin !== expectedOrigin) return { error: "origin" };
  const filled = (el) => el.value !== "" && el.getClientRects().length > 0;
  const pws = [...document.querySelectorAll('input[type="password"]')].filter(filled);
  const pw = pws.find((el) => el.autocomplete === "new-password") || pws[0] || null;
  const texts = [...document.querySelectorAll('input[type="email"], input[type="text"], input[type="tel"], input:not([type])')].filter(filled);
  const isUser = (el) => /user|login|mail|ident/i.test(`${el.name} ${el.id} ${el.autocomplete}`) || el.type === "email";
  let user = null;
  if (pw) {
    const scope = texts.filter((el) => (!pw.form || el.form === pw.form) && el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING);
    user = scope.filter(isUser).pop() || scope.pop() || null;
  } else {
    user = texts.find(isUser) || null;
  }
  return { username: user ? user.value.trim() : "", password: pw ? pw.value : "" };
}

/** Valeurs saisies dans l'onglet actif ({ username, password }), ou null si illisible. */
async function captured() {
  if (!ext.scripting) return readPage(location.origin);
  try {
    const [{ result } = {}] = await ext.scripting.executeScript({
      target: { tabId: S.tab.id, frameIds: [0] }, func: readPage, args: [S.page.origin],
    });
    return result?.error ? null : result;
  } catch {
    return null;
  }
}

export function writableCollections() {
  return [...V.state.collections.values()]
    .filter((c) => !c.error && (c.personal || ["manager", "editor"].includes(c.role)))
    .sort((a, b) => (a.personal ? -1 : b.personal ? 1 : String(a.name).localeCompare(String(b.name), "fr")));
}

/** Compte déjà enregistré pour cette page et cet identifiant. */
function existing(username) {
  if (!username) return null;
  return [...V.state.items.values()].find((i) => i.data && !i.deleted_at && (i.data.kind || "login") === "login"
    && i.data.username === username && (i.data.urls || []).some((u) => urlMatches(u, S.page.href))) || null;
}

/** Point d'entrée : lit la page puis propose l'enregistrement. */
export async function renderSave() {
  if (!S.page) return go("main");
  if (pageState().excluded) return showError(t("extension.fill.excluded"));
  const found = await captured();
  if (found?.password) return renderForm({ username: found.username, password: found.password, origin: "page" });
  screen({ title: t("extension.save.title"), back: () => go("main"), session: true },
    alertCard({ tone: "info", title: t("extension.save.nothing_title"), text: t("extension.save.nothing_text") }),
    action({ label: t("extension.save.create"), icon: "generate", variant: "primary", onClick: async () => renderForm({ username: found?.username || "", password: await generateFresh(), origin: "generated" }) }));
}

/**
 * Formulaire d'enregistrement. origin : "page" (valeurs lues dans la page)
 * ou "generated" (mot de passe créé ici, à saisir ensuite sur le site).
 */
function renderForm({ username, password, origin }) {
  const targets = writableCollections();
  const back = () => go("main");
  if (!targets.length) {
    screen({ title: t("extension.save.title"), back, session: true });
    return showError(t("extension.save.read_only"));
  }
  const match = existing(username);
  const name = textInput({ name: "nom", value: match?.data.name || S.page.hostname.replace(/^www\./, ""), required: true });
  const user = textInput({ name: "identifiant", value: username, autocomplete: "off", spellcheck: false });
  const pwField = passwordField({
    label: t("common.glossary.password"), name: "mot-de-passe", value: password, autocomplete: "off", capsLockHint: false,
    withGenerate: origin === "generated", onGenerate: generate,
  });
  const pw = fieldInput(pwField);
  const preferred = Settings.prefs().ui?.default_collection;
  const target = selectInput({
    name: "coffre",
    options: targets.map((c) => ({ value: c.id, label: c.personal ? t("common.glossary.personal_vault") : c.name })),
    value: targets.some((c) => c.id === preferred) ? preferred : targets[0].id,
  });

  const save = async () => {
    if (!name.value.trim()) return showError(t("extension.save.name_required"));
    if (!pw.value) return showError(t("extension.save.password_required"));
    if (match) {
      const data = { ...V.applyPassword(match.data, pw.value), name: name.value.trim(), username: user.value.trim() };
      await V.updateItem(match, data);
    } else {
      const data = {
        ...V.emptyItem("login"), name: name.value.trim(), username: user.value.trim(), password: pw.value,
        urls: [S.page.origin], password_changed_at: V.now(),
      };
      await V.createItem(target.value, data);
    }
    await V.sync();
    await touch();
    notify({ text: t(match ? "extension.save.updated" : "extension.save.saved"), tone: "ok" });
    go("main");
  };

  screen({ title: t("extension.save.title"), back, session: true }, form(save,
    h("p", { class: "u-muted" }, t(origin === "page" ? "extension.save.from_page" : "extension.save.generated_hint")),
    match ? alertCard({ tone: "info", text: t("extension.save.will_update", { name: match.data.name }) }) : null,
    field({ label: t("extension.save.name"), input: name }),
    field({ label: t("common.glossary.username"), input: user }),
    pwField,
    match || targets.length < 2 ? null : field({ label: t("extension.save.target"), input: target }),
    h("p", { class: "u-muted" }, t("extension.save.address", { origin: S.page.origin })),
    isInsecurePage(S.page.href) ? alertCard({ tone: "warn", text: t("extension.save.insecure") }) : null,
    submitButton(t(match ? "extension.save.update" : "common.action.save"))));
  (origin === "page" ? name : user).focus();
}
