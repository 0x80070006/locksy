// Import dans le coffre : lecture des fichiers CSV (tableurs, autres
// gestionnaires de mots de passe), des sauvegardes chiffrées Locksy et des
// bases chiffrées KeePass / Bitwarden (déchiffrées hors du fil principal par
// import-worker.js). Tout se passe dans le navigateur : le fichier en clair
// n'est jamais envoyé au serveur.
//
// Exports (contrat C4.5) :
//   parseCsv(text) -> { rows, lines, separator, errors: [{ line, code }] }
//     UN seul séparateur (« , », « ; » ou tabulation), détecté sur la ligne
//     d'en-tête hors guillemets (ou imposé par une première ligne « sep=; ») ;
//     guillemets RFC 4180 (« "" » échappé, retours à la ligne dans un champ) :
//     un mot de passe « a;b » n'est jamais coupé. lines[i] = numéro de la
//     ligne du fichier où commence rows[i].
//   detectMapping(header) -> [{ index, header, target }] (colonne -> champ)
//   csvToItems(rows, mapping?, { lines, folderMode }) -> { items: [{ data, folder, line }], errors }
//   importFile(file, { format, password, keyfile, onProgress, maxBytes, unprotect })
//     -> { items: [{ data, folder, source_id }], folders, warnings, errors }
//   importInBatches(entries, { send, start, size, onProgress }) -> { done, failedAt, error }
//   ImportFailure : erreur portant `code` (libellé t("import.error.<code>")
//     ou t("settings_user.import.error.<code>")).
//
// Codes de rapport CSV (libellés settings_user.import.csv_error.<code>) :
//   unterminated_quote, extra_columns, empty_entry, no_header, no_data.

import { emptyItem, now } from "./vault.js";

export const CSV_SEPARATORS = Object.freeze([",", ";", "\t"]);
/** Taille d'un lot envoyé à POST /items/batch. */
export const BATCH_SIZE = 500;
/** Formats acceptés par importFile. */
export const FORMATS = Object.freeze(["csv", "locksy", "kdbx", "bitwarden_json"]);
const WORKER_FORMATS = new Set(["kdbx", "bitwarden_json"]);

export class ImportFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

// ------------------------------------------------------------ CSV

/** Retire l'indicateur d'ordre des octets (BOM) laissé par les tableurs. */
const stripBom = (text) => (text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);

/**
 * Séparateur de la ligne d'en-tête : le plus fréquent hors guillemets parmi
 * « , », « ; » et la tabulation (à égalité : tabulation, puis « ; », puis
 * « , »). Aucun : virgule (fichier à une seule colonne).
 */
export function detectSeparator(text) {
  const counts = { ",": 0, ";": 0, "\t": 0 };
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "\"") {
      if (quoted && text[i + 1] === "\"") i++;
      else quoted = !quoted;
    } else if (!quoted && (c === "\n" || c === "\r")) {
      break;
    } else if (!quoted && Object.hasOwn(counts, c)) {
      counts[c] += 1;
    }
  }
  let best = ",";
  for (const sep of ["\t", ";", ","]) if (counts[sep] > counts[best]) best = sep;
  return counts[best] > 0 ? best : ",";
}

/**
 * Lit un fichier CSV avec un séparateur unique. Les lignes vides sont
 * ignorées ; un guillemet jamais fermé est rapporté (la fin du fichier,
 * illisible, n'est pas importée).
 */
export function parseCsv(input) {
  let text = stripBom(String(input ?? ""));
  let lineNo = 1;
  let separator;
  // Indication d'Excel : première ligne « sep=; ».
  const hint = /^sep=(.)\r?\n/i.exec(text);
  if (hint && CSV_SEPARATORS.includes(hint[1])) {
    separator = hint[1];
    text = text.slice(hint[0].length);
    lineNo = 2;
  } else {
    separator = detectSeparator(text);
  }
  const rows = [];
  const lines = [];
  const errors = [];
  let row = [];
  let field = "";
  let quoted = false;
  let fieldStarted = false;
  let rowLine = lineNo;
  let quoteLine = lineNo;
  const endField = () => {
    row.push(field);
    field = "";
    fieldStarted = false;
  };
  const endRow = () => {
    endField();
    if (row.some((v) => v.trim() !== "")) {
      rows.push(row);
      lines.push(rowLine);
    }
    row = [];
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === "\"") {
        if (text[i + 1] === "\"") {
          field += "\"";
          i++;
        } else {
          quoted = false;
        }
      } else if (c === "\r") {
        // Fin de ligne dans un champ ramenée à « \n » (le « \n » d'un « \r\n » compte la ligne).
        if (text[i + 1] !== "\n") {
          lineNo += 1;
          field += "\n";
        }
      } else {
        if (c === "\n") lineNo += 1;
        field += c;
      }
      continue;
    }
    if (c === "\"" && !fieldStarted) {
      quoted = true;
      fieldStarted = true;
      quoteLine = lineNo;
    } else if (c === separator) {
      endField();
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      endRow();
      lineNo += 1;
      rowLine = lineNo;
    } else {
      // Guillemet au milieu d'un champ non entouré : gardé tel quel.
      field += c;
      fieldStarted = true;
    }
  }
  if (quoted) {
    errors.push({ line: quoteLine, code: "unterminated_quote" });
    row = [];
    field = "";
  } else if (field !== "" || row.length) {
    endRow();
  }
  return { rows, lines, separator, errors };
}

// ------------------------------------------------------------ Colonnes

/** Texte comparable : sans accents, minuscules, séparateurs ramenés à une espace. */
function fold(text) {
  return String(text ?? "").normalize("NFD").replace(/\p{M}+/gu, "").toLowerCase()
    .replace(/[_\-.:/]+/g, " ").replace(/\s+/g, " ").trim();
}

/**
 * Noms de colonnes reconnus (exports courants, en français et en anglais),
 * comparés après fold() : « _ », « - », « . » valent une espace
 * (« mot_de_passe » reconnaît « Mot de passe » et « mot-de-passe »).
 */
const SYNONYMS = Object.freeze({
  name: ["name", "title", "nom", "titre", "account", "entry", "libelle", "label", "nom du compte", "intitule"],
  url: ["url", "login uri", "website", "site", "site web", "uri", "web site", "adresse", "adresse du site", "lien", "url du site", "login url"],
  domain: ["domain", "domaine", "hostname", "nom_de_domaine"],
  username: ["username", "login username", "user", "login", "identifiant", "user name", "utilisateur", "nom d utilisateur", "login name"],
  email: ["email", "e mail", "courriel", "adresse e mail", "mail"],
  password: ["password", "login password", "pass", "mot_de_passe", "motdepasse", "pwd", "mdp"],
  notes: ["notes", "note", "extra", "comments", "comment", "commentaire", "commentaires", "remarques"],
  description: ["description", "desc"],
  totp: ["totp", "login totp", "otp", "otpauth", "one time password", "otpsecret", "otp secret", "2fa", "mfa", "code_de_verification"],
  folder: ["folder", "grouping", "group", "dossier", "category", "categorie", "collection", "chemin", "path", "groupe", "coffre", "vault"],
  tags: ["tags", "tag", "etiquettes", "etiquette", "labels"],
  first_name: ["first name", "firstname", "prenom", "given name"],
  last_name: ["last name", "lastname", "nom_de_famille", "surname", "family name"],
  type: ["type", "kind"],
  bw_fields: ["fields"],
  skip: ["id", "guid", "uuid", "favorite", "fav", "favori", "reprompt", "icon", "icone", "httprealm", "formactionorigin",
    "timecreated", "timelastused", "timepasswordchanged", "created", "modified", "last modified", "creation", "modification",
    "login fido2credentials", "password changed", "last used"],
});
const LOOKUP = new Map(Object.entries(SYNONYMS).flatMap(([target, names]) => names.map((n) => [fold(n), target])));
const KINDS = new Set(["login", "note", "card", "identity", "ssh"]);

/**
 * Correspondance des colonnes d'un en-tête : une entrée par colonne
 * { index, header, target } ; target ∈ name, url, domain, username, email,
 * password, notes, description, totp, folder, tags, first_name, last_name,
 * type, bw_fields, skip, field (champ libre). Chaque champ connu n'est pris
 * qu'une fois : une deuxième colonne « url » devient un champ libre. Sans
 * colonne d'identifiant, la colonne e-mail en tient lieu.
 */
export function detectMapping(header = []) {
  const taken = new Set();
  const out = header.map((raw, index) => {
    const label = String(raw ?? "").trim();
    let target = LOOKUP.get(fold(label)) ?? (label ? "field" : "skip");
    if (target !== "field" && target !== "skip") {
      if (taken.has(target)) target = "field";
      else taken.add(target);
    }
    return { index, header: label, target };
  });
  if (!taken.has("username")) {
    const email = out.find((c) => c.target === "email");
    if (email) email.target = "username";
  }
  return out;
}

/** Champs libres d'une colonne « fields » (exports Bitwarden) : « nom: valeur » par ligne. */
function parseFieldsCell(value) {
  return String(value).split(/\r?\n/).map((line) => {
    const at = line.indexOf(":");
    if (at <= 0) return line.trim() ? { label: "", value: line.trim(), hidden: false } : null;
    return { label: line.slice(0, at).trim(), value: line.slice(at + 1).trim(), hidden: false };
  }).filter(Boolean);
}

/** Chemin de dossier normalisé : « A\B / C » -> « A/B/C ». */
export function normalizeFolder(path) {
  return String(path ?? "").split(/[\\/]+/).map((s) => s.trim()).filter(Boolean).join("/");
}

/** Hôte d'une adresse, pour nommer un élément sans nom. */
function hostOf(url) {
  return String(url ?? "").replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split(/[/?#]/)[0].replace(/^www\./i, "");
}

/**
 * Convertit les lignes d'un CSV (en-tête compris, en premier) en éléments.
 * opts.lines : numéros de ligne (parseCsv) ; opts.folderMode : "tags" (le
 * dossier devient des étiquettes) ou "vaults" (il est gardé dans `folder`
 * pour choisir le coffre de destination ; ses étiquettes ne sont pas posées).
 * Une ligne inexploitable est rapportée { line, code } et n'est pas importée.
 */
export function csvToItems(rows, mapping, { lines, folderMode = "tags" } = {}) {
  const items = [];
  const errors = [];
  if (!Array.isArray(rows) || rows.length === 0) return { items, errors: [{ line: 1, code: "no_header" }] };
  const map = mapping || detectMapping(rows[0]);
  const lineOf = (i) => (Array.isArray(lines) && lines[i] !== undefined ? lines[i] : i + 1);
  if (rows.length < 2) return { items, errors: [{ line: lineOf(0), code: "no_data" }] };
  const width = map.length;
  const at = new Map(map.filter((c) => c.target !== "field" && c.target !== "skip").map((c) => [c.target, c.index]));
  const changedAt = now();

  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    const line = lineOf(r);
    // Cellules au-delà de l'en-tête : séparateur dans un champ non entouré de
    // guillemets ; la ligne est décalée, ses valeurs ne sont pas fiables.
    if (row.slice(width).some((v) => String(v).trim() !== "")) {
      errors.push({ line, code: "extra_columns" });
      continue;
    }
    const raw = (target) => (at.has(target) ? String(row[at.get(target)] ?? "") : "");
    const get = (target) => raw(target).trim();
    const password = raw("password");
    const username = get("username");
    let urls = raw("url").split(/\r?\n/).map((u) => u.trim()).filter(Boolean);
    const domain = get("domain");
    if (!urls.length && domain) urls = [/^[a-z][a-z0-9+.-]*:\/\//i.test(domain) ? domain : `https://${domain}`];
    const firstName = get("first_name");
    const lastName = get("last_name");
    const notes = [raw("description").trim(), raw("notes").replace(/\s+$/, "")].filter(Boolean).join("\n\n");
    const fields = [];
    for (const c of map) {
      const value = String(row[c.index] ?? "");
      if (c.target === "field" && value.trim()) fields.push({ label: c.header, value: value.trim(), hidden: false });
      if (c.target === "email" && value.trim()) fields.push({ label: c.header, value: value.trim(), hidden: false });
      if (c.target === "bw_fields" && value.trim()) fields.push(...parseFieldsCell(value));
    }
    const declared = get("type").toLowerCase();
    let kind;
    if (KINDS.has(declared)) kind = declared;
    else if (password || username || urls.length) kind = "login";
    else if (firstName || lastName) kind = "identity";
    else if (notes || fields.length) kind = "note";
    if (!kind) {
      errors.push({ line, code: "empty_entry" });
      continue;
    }
    const data = emptyItem(kind);
    const person = [firstName, lastName].filter(Boolean).join(" ");
    data.name = get("name") || (urls.length ? hostOf(urls[0]) : "") || person || username;
    data.username = username;
    data.password = password;
    data.urls = urls;
    data.notes = notes;
    data.totp = get("totp");
    data.fields = fields;
    if (kind === "identity" || firstName || lastName) {
      data.identity = { ...data.identity, first_name: firstName, last_name: lastName };
    }
    const folder = normalizeFolder(raw("folder"));
    const tags = raw("tags").split(/[,;]/).map((s) => s.trim()).filter(Boolean);
    if (folderMode === "tags" && folder) tags.unshift(...folder.split("/"));
    data.tags = [...new Set(tags)];
    if (password) data.password_changed_at = changedAt;
    items.push({ data, folder, line });
  }
  return { items, errors };
}

// ------------------------------------------------------------ Lots

/**
 * Envoie les éléments par lots de `size` (500) : send(lot) -> promesse. Au
 * premier échec, s'arrête et renvoie { done, failedAt, error } ; relancer
 * avec start = failedAt reprend au lot refusé (rien n'est envoyé deux fois).
 * onProgress(done, total) après chaque lot.
 */
export async function importInBatches(entries, { send, start = 0, size = BATCH_SIZE, onProgress } = {}) {
  let done = start;
  while (done < entries.length) {
    const chunk = entries.slice(done, done + size);
    try {
      await send(chunk);
    } catch (error) {
      return { done, failedAt: done, error };
    }
    done += chunk.length;
    onProgress?.(done, entries.length);
  }
  return { done, failedAt: null, error: null };
}

// ------------------------------------------------------------ Fichiers

/** Lecture d'un fichier (File, Blob) en texte ou en tampon. */
const readText = (file) => (typeof file.text === "function" ? file.text() : new Response(file).text());
const readBuffer = (file) => (typeof file.arrayBuffer === "function" ? file.arrayBuffer() : new Response(file).arrayBuffer());

/** Déchiffrement par le worker (KeePass, Bitwarden). */
let nextId = 0;
function parseInWorker(format, file, keyfile, password, onProgress, signal) {
  let worker;
  try {
    worker = new Worker(new URL("./import-worker.js", import.meta.url), { type: "module" });
  } catch {
    return Promise.reject(new ImportFailure("format_unavailable"));
  }
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    const finish = (fn, value) => {
      signal?.removeEventListener("abort", abort);
      worker.postMessage({ type: "dispose" });
      setTimeout(() => worker.terminate(), 1000);
      fn(value);
    };
    const abort = () => {
      worker.terminate();
      reject(new ImportFailure("aborted"));
    };
    signal?.addEventListener("abort", abort, { once: true });
    worker.addEventListener("message", (e) => {
      const m = e.data;
      if (!m || m.id !== id) return;
      if (m.type === "progress") onProgress?.(m.phase, m.ratio);
      else if (m.type === "result") finish(resolve, { items: m.items || [], folders: m.folders || [], warnings: m.warnings || [], errors: [] });
      else if (m.type === "error") finish(reject, new ImportFailure(m.code || "worker_failed"));
    });
    // Module introuvable ou erreur de chargement du worker.
    worker.addEventListener("error", (e) => {
      e.preventDefault?.();
      finish(reject, new ImportFailure("format_unavailable"));
    });
    const transfer = [file];
    if (keyfile) transfer.push(keyfile);
    worker.postMessage({ type: "parse", id, format, file, password, keyfile }, transfer);
  });
}

/**
 * Lit un fichier d'import. format ∈ csv | locksy | kdbx | bitwarden_json.
 * maxBytes : taille maximale (import.max_file_mib) ; unprotect(mdp, texte)
 * -> texte déchiffré d'une sauvegarde Locksy (opération du noyau). Lève une
 * ImportFailure (code) en cas d'échec.
 */
export async function importFile(file, { format, password = "", keyfile, onProgress, maxBytes, unprotect, folderMode, signal } = {}) {
  if (!file) throw new ImportFailure("no_file");
  if (!FORMATS.includes(format)) throw new ImportFailure("unsupported_format");
  if (maxBytes && file.size > maxBytes) throw new ImportFailure("too_large");
  if (format === "csv") {
    onProgress?.("parse", 0);
    const parsed = parseCsv(await readText(file));
    const { items, errors } = csvToItems(parsed.rows, undefined, { lines: parsed.lines, folderMode });
    onProgress?.("map", 1);
    return {
      items: items.map((it) => ({ data: it.data, folder: it.folder, source_id: `ligne-${it.line}` })),
      folders: [...new Set(items.map((it) => it.folder).filter(Boolean))],
      warnings: [],
      errors: [...parsed.errors, ...errors].sort((a, b) => a.line - b.line),
      separator: parsed.separator,
    };
  }
  if (format === "locksy") {
    if (typeof unprotect !== "function") throw new ImportFailure("format_unavailable");
    onProgress?.("kdf", 0);
    let doc;
    try {
      doc = JSON.parse(unprotect(password, await readText(file)));
    } catch {
      throw new ImportFailure("wrong_password");
    }
    const list = Array.isArray(doc?.items) ? doc.items : [];
    onProgress?.("map", 1);
    return { items: list.map((data, i) => ({ data, folder: "", source_id: String(i) })), folders: [], warnings: [], errors: [] };
  }
  if (!WORKER_FORMATS.has(format) || typeof Worker === "undefined") throw new ImportFailure("format_unavailable");
  const buffer = await readBuffer(file);
  const key = keyfile ? await readBuffer(keyfile) : undefined;
  return parseInWorker(format, buffer, key, password, onProgress, signal);
}
