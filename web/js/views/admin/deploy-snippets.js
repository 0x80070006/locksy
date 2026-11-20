// Déploiement sur les postes (cahier §4.10) : extraits générés depuis le
// registre des réglages (clés client.*, extension.* et l'adresse du serveur),
// avec les valeurs effectives actuelles et les MÊMES noms de clés que le
// serveur (contrats C4.7 et C4.8) :
//   - registre Windows (.reg, HKLM\SOFTWARE\Policies\Locksy) ;
//   - modèles d'administration ADMX / ADML (fr-FR) ;
//   - Intune : OMA-URI de l'ADMX ingéré, une ligne par stratégie ;
//   - Chrome et Edge : ExtensionSettings, ExtensionInstallForcelist et
//     3rdparty.extensions.<id> (stockage géré de l'extension).
// Chaque bloc a « Copier » et « Télécharger » (Blob, aucun réseau).
//
// Les extraits sont du code : ils sont marqués data-technical (seul endroit où
// les termes techniques sont permis à l'écran).

import { t, h, clear, button, copySecret, field, textInput, settingLabel, has } from "../../ui/index.js";
import { saveBlob } from "../../api.js";

const POLICY_KEY = "SOFTWARE\\Policies\\Locksy";
const CHROME_UPDATE_URL = "https://clients2.google.com/service/update2/crx";
const EDGE_UPDATE_URL = "https://edge.microsoft.com/extensionwebstorebase/v1/crx";
const ADMX_NS = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions";
const OMA_INGEST = "./Device/Vendor/MSFT/Policy/ConfigOperationalADMX/Locksy/Policy/LocksyAdmx";
const OMA_POLICY = "./Device/Vendor/MSFT/Policy/Config/Locksy~Policy~Locksy/";
const EXTENSION_ID_RE = /^[a-p]{32}$/;
/** En-tête imposé d'un fichier .reg (format de l'éditeur du registre). */
const REG = Object.freeze({ format: "Windows Registry Editor Version 5.00" });
/** Catégorie et préfixe des stratégies : dernier segment de la clé (« Locksy »). */
const CATEGORY = POLICY_KEY.split("\\").pop();

/** Clés déployées : { key, def, value } triées, pour les postes (client.*) et l'extension. */
function deployableSettings(values, defs) {
  const out = [];
  for (const [key, def] of defs) {
    if (!key.startsWith("client.") && !key.startsWith("extension.")) continue;
    if (key === "extension.allowed_ids") continue;
    const value = values?.values?.[key]?.value;
    if (value === undefined || value === null) continue;
    out.push({ key, def, value });
  }
  return out.sort((a, b) => a.key.localeCompare(b.key));
}

const policyName = (key) => key.replace(/[^A-Za-z0-9]/g, "_");
const xml = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const regString = (s) => String(s).replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
const dword = (n) => `dword:${(Number(n) >>> 0).toString(16).padStart(8, "0")}`;
const typeOf = (def) => def?.kind?.type || typeof def?.default;

/** Fichier .reg (stratégies machine) : adresse du serveur et clés client.*. */
function regFile(serverUrl, settings) {
  const lines = [REG.format, "", `[HKEY_LOCAL_MACHINE\\${POLICY_KEY}]`];
  if (serverUrl) lines.push(`"server_url"="${regString(serverUrl)}"`);
  for (const s of settings.filter((x) => x.key.startsWith("client."))) {
    const type = typeOf(s.def);
    if (type === "bool" || typeof s.value === "boolean") lines.push(`"${s.key}"=${dword(s.value ? 1 : 0)}`);
    else if (type === "int" || typeof s.value === "number") lines.push(`"${s.key}"=${dword(s.value)}`);
    else if (!Array.isArray(s.value)) lines.push(`"${s.key}"="${regString(s.value)}"`);
  }
  return `${lines.join("\r\n")}\r\n`;
}

/** Modèle ADMX (stratégies) et ressources ADML françaises. */
function admxFiles(settings, revision = 1) {
  const rev = `${Math.max(1, Number(revision) || 1)}.0`;
  const client = settings.filter((x) => x.key.startsWith("client."));
  const policy = (name, valueName, inner, presentation) => [
    `    <policy name="${name}" class="Machine" displayName="$(string.${name})" explainText="$(string.${name}_Help)"`
      + `${presentation ? ` presentation="$(presentation.${name})"` : ""} key="${POLICY_KEY}"${inner.bool ? ` valueName="${xml(valueName)}"` : ""}>`,
    "      <parentCategory ref=\"Locksy\" />",
    "      <supportedOn ref=\"SUPPORTED_Locksy\" />",
    inner.body,
    "    </policy>",
  ].join("\n");
  const policies = [policy("server_url", "server_url", {
    body: "      <elements><text id=\"server_url\" valueName=\"server_url\" required=\"true\" /></elements>",
  }, true)];
  const strings = [
    [CATEGORY, t("common.app.name")],
    ["SUPPORTED_Locksy", t("admin.deploy.admx.supported")],
    ["server_url", t("admin.deploy.server_url")],
    ["server_url_Help", t("admin.deploy.server_url_help")],
  ];
  const presentations = [`      <presentation id="server_url"><textBox refId="server_url"><label>${xml(t("admin.deploy.server_url"))}</label></textBox></presentation>`];
  for (const s of client) {
    const name = policyName(s.key);
    const type = typeOf(s.def);
    strings.push([name, settingLabel(s.key)], [`${name}_Help`, has(`settings.${s.key}.help`) ? t(`settings.${s.key}.help`) : settingLabel(s.key)]);
    if (type === "bool") {
      policies.push(policy(name, s.key, {
        bool: true,
        body: "      <enabledValue><decimal value=\"1\" /></enabledValue>\n      <disabledValue><decimal value=\"0\" /></disabledValue>",
      }, false));
    } else if (type === "int") {
      const k = s.def.kind || {};
      policies.push(policy(name, s.key, {
        body: `      <elements><decimal id="${name}" valueName="${xml(s.key)}" minValue="${Number(k.min) || 0}" maxValue="${Number(k.max) || 4294967295}" /></elements>`,
      }, true));
      presentations.push(`      <presentation id="${name}"><decimalTextBox refId="${name}" defaultValue="${Number(s.value) || 0}">${xml(settingLabel(s.key))}</decimalTextBox></presentation>`);
    }
  }
  const admx = [
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
    `<policyDefinitions revision="${rev}" schemaVersion="1.0" xmlns="${ADMX_NS}">`,
    "  <policyNamespaces>",
    "    <target prefix=\"locksy\" namespace=\"Locksy.Policies.Locksy\" />",
    "    <using prefix=\"windows\" namespace=\"Microsoft.Policies.Windows\" />",
    "  </policyNamespaces>",
    `  <resources minRequiredRevision="${rev}" />`,
    "  <supportedOn><definitions><definition name=\"SUPPORTED_Locksy\" displayName=\"$(string.SUPPORTED_Locksy)\" /></definitions></supportedOn>",
    "  <categories><category name=\"Locksy\" displayName=\"$(string.Locksy)\" /></categories>",
    "  <policies>",
    ...policies,
    "  </policies>",
    "</policyDefinitions>",
    "",
  ].join("\n");
  const adml = [
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
    `<policyDefinitionResources revision="${rev}" schemaVersion="1.0" xmlns="${ADMX_NS}">`,
    `  <displayName>${xml(t("common.app.name"))}</displayName>`,
    `  <description>${xml(t("admin.deploy.admx.description"))}</description>`,
    "  <resources>",
    "    <stringTable>",
    ...strings.map(([id, text]) => `      <string id="${id}">${xml(text)}</string>`),
    "    </stringTable>",
    "    <presentationTable>",
    ...presentations,
    "    </presentationTable>",
    "  </resources>",
    "</policyDefinitionResources>",
    "",
  ].join("\n");
  return { admx, adml };
}

/** OMA-URI Intune : ingestion de l'ADMX puis une ligne par stratégie. */
function intuneLines(serverUrl, settings) {
  const lines = [`${OMA_INGEST}  (String : ${t("admin.deploy.intune.admx_content")})`];
  if (serverUrl) lines.push(`${OMA_POLICY}server_url  <enabled/><data id="server_url" value="${xml(serverUrl)}"/>`);
  for (const s of settings.filter((x) => x.key.startsWith("client."))) {
    const name = policyName(s.key);
    const type = typeOf(s.def);
    if (type === "bool") lines.push(`${OMA_POLICY}${name}  ${s.value ? "<enabled/>" : "<disabled/>"}`);
    else if (type === "int") lines.push(`${OMA_POLICY}${name}  <enabled/><data id="${name}" value="${Number(s.value)}"/>`);
  }
  return `${lines.join("\n")}\n`;
}

/** Politique Chrome ou Edge : installation imposée et stockage géré de l'extension. */
function browserPolicy(extensionId, serverUrl, settings, updateUrl) {
  const managed = {};
  if (serverUrl) managed.server_url = serverUrl;
  for (const s of settings) managed[s.key] = s.value;
  return `${JSON.stringify({
    ExtensionInstallForcelist: [`${extensionId};${updateUrl}`],
    ExtensionSettings: { [extensionId]: { installation_mode: "force_installed", update_url: updateUrl } },
    "3rdparty": { extensions: { [extensionId]: managed } },
  }, null, 2)}\n`;
}

/** Fichier .reg en UTF-16 LE avec BOM (format attendu par l'éditeur du registre). */
function utf16(text) {
  const buf = new Uint16Array(text.length + 1);
  buf[0] = 0xfeff;
  for (let i = 0; i < text.length; i++) buf[i + 1] = text.charCodeAt(i);
  return new Blob([buf], { type: "text/plain" });
}

/** Bloc de code : titre, explication, code, « Copier » et « Télécharger ». */
function block({ title, help, code, filename, blob }) {
  return h("section", { class: "l-stack", "data-gap": "2" },
    h("h3", {}, title),
    help ? h("p", { class: "u-muted" }, help) : null,
    h("div", { class: "c-table__scroll", role: "region", "aria-label": title, tabindex: "0" },
      h("pre", { class: "u-mono", "data-technical": "", translate: "no" }, code)),
    h("div", { class: "l-cluster" },
      // Copie partagée (message d'échec commun) ; « text » : jamais effacé ensuite.
      button({ label: t("admin.deploy.copy"), icon: "copy", onClick: () => copySecret(code, { kind: "text", labelKey: "admin.deploy.copied" }) }),
      filename ? button({
        label: t("admin.deploy.download_file", { file: filename }), icon: "download", variant: "quiet",
        onClick: () => saveBlob(blob || new Blob([code], { type: "text/plain" }), filename),
      }) : null));
}

/**
 * Remplit `container` avec les extraits de déploiement.
 * values : réponse de GET /admin/settings ; defs : Map clé -> définition du schéma.
 */
export function renderDeploySnippets(container, { values, defs }) {
  const settings = deployableSettings(values, defs);
  const serverUrl = values?.values?.["instance.public_url"]?.value || location.origin;
  const ids = values?.values?.["extension.allowed_ids"]?.value || [];
  const idInput = textInput({ value: ids[0] || "", maxlength: 32, spellcheck: false, autocomplete: "off" });
  const blocks = h("div", { class: "l-stack", "data-gap": "4" });

  const paint = () => {
    const raw = idInput.value.trim();
    const id = EXTENSION_ID_RE.test(raw) ? raw : t("admin.deploy.id_placeholder");
    const reg = regFile(serverUrl, settings);
    const { admx, adml } = admxFiles(settings, values?.schema_version);
    clear(blocks,
      block({ title: t("admin.deploy.reg.title"), help: t("admin.deploy.reg.help"), code: reg, filename: "locksy-postes.reg", blob: utf16(reg) }),
      block({ title: t("admin.deploy.admx.title"), help: t("admin.deploy.admx.help"), code: admx, filename: "Locksy.admx", blob: new Blob([admx], { type: "application/xml" }) }),
      block({ title: t("admin.deploy.adml.title"), help: t("admin.deploy.adml.help"), code: adml, filename: "Locksy.adml", blob: new Blob([adml], { type: "application/xml" }) }),
      block({ title: t("admin.deploy.intune.title"), help: t("admin.deploy.intune.help"), code: intuneLines(serverUrl, settings) }),
      block({ title: t("admin.deploy.chrome.title"), help: t("admin.deploy.chrome.help"), code: browserPolicy(id, serverUrl, settings, CHROME_UPDATE_URL), filename: "locksy-chrome.json" }),
      block({ title: t("admin.deploy.edge.title"), help: t("admin.deploy.edge.help"), code: browserPolicy(id, serverUrl, settings, EDGE_UPDATE_URL), filename: "locksy-edge.json" }));
  };
  idInput.addEventListener("input", paint);
  paint();
  clear(container,
    h("h2", {}, t("admin.deploy.title")),
    h("p", {}, t("admin.deploy.intro")),
    field({ label: t("admin.deploy.extension_id"), help: t("admin.deploy.extension_id_help"), input: idInput }),
    blocks);
}
