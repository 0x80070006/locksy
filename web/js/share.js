// Page publique d'un lien sécurisé (/s/<id>#<clé>), pour une personne qui
// n'a pas Locksy (cahier §3.3.5, contrat C5).
//
// La clé est dans le fragment (#) de l'adresse : le navigateur ne l'envoie
// jamais au serveur, et la page la retire aussitôt de la barre d'adresse et
// de l'historique. Le serveur reçoit seulement une preuve de possession
// (SHA-256 de la clé, calculée par le noyau WebAssembly : WebCrypto manque en
// HTTP clair) : sans elle, il ne lit pas le contenu chiffré et ne décompte
// aucune ouverture.
//
// Parcours : aperçu (POST …/peek : état, expiration, ouvertures restantes),
// puis « Afficher le secret » (POST …/open, avec un identifiant de
// consultation gardé dans sessionStorage : rouvrir le même lien dans cet
// onglet ne décompte pas deux fois ; cet identifiant n'a aucune valeur sans
// la clé). Lien inconnu ou preuve fausse : « Lien introuvable » ; lien
// terminé (410) : état lisible selon le motif. Module sans preuve, ou lien
// créé sans vérificateur : lecture historique (GET, une ouverture par appel).
//
// Le nom de l'élément n'est affiché que s'il est dans le contenu chiffré
// (l'expéditeur a coché « Inclure le nom ») ; il n'apparaît jamais dans le
// titre de la page.

import {
  t, plural, h, clear, icon, button, secretRow, totpCode, alertCard, focusHeading, fmtDate, formatDuration,
} from "./ui/index.js";
import { loadCrypto, call } from "./wasm.js";
import { loadPublic } from "./settings-client.js";
import * as A from "./aad.js";

const NONCE_PREFIX = "locksy.share.nonce.";
/** Motifs de fin connus (shares.ended_reason) ; libellés tools.share.ended.<motif>. */
const REASONS = new Set(["revoked", "revoked_admin", "expired", "exhausted", "item_deleted", "access_lost", "owner_disabled", "rotated"]);

const root = document.getElementById("app");
const id = decodeURIComponent(location.pathname.split("/").filter(Boolean).pop() || "");
const keyText = location.hash.slice(1);
// Retire la clé de la barre d'adresse et de l'historique.
history.replaceState(null, "", location.pathname);
document.title = t("tools.share.page_title");

let brand = null;
let keyHandle = null;

// ------------------------------------------------------------ Réseau

/** Requête publique, sans jeton de session ni cookie : { status, data, retryAfter }. */
async function request(method, path, body) {
  let res;
  try {
    res = await fetch(`/api${path}`, {
      method,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
  } catch {
    return { status: 0, data: null };
  }
  let data = null;
  try {
    data = await res.json();
  } catch { /* corps vide ou illisible */ }
  const header = Number(res.headers.get("retry-after"));
  const retryAfter = Number.isFinite(header) && header > 0 ? header : Number(data?.retry_after) || null;
  return { status: res.status, data, retryAfter };
}

/** Base64 URL sans bourrage. */
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Identifiant de consultation de ce lien dans cet onglet (créé une fois). */
function nonceFor(shareId) {
  const key = NONCE_PREFIX + shareId;
  try {
    const kept = sessionStorage.getItem(key);
    if (kept && /^[A-Za-z0-9_-]{22}$/.test(kept)) return kept;
  } catch { /* stockage indisponible : identifiant de cette page seulement */ }
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(16)));
  try {
    sessionStorage.setItem(key, nonce);
  } catch { /* idem */ }
  return nonce;
}

/** Preuve de possession de la clé ; null si le module n'a pas l'opération (version antérieure). */
function proofOf(key) {
  try {
    const p = call("share_proof", { key })?.proof;
    return typeof p === "string" && p ? p : null;
  } catch {
    return null;
  }
}

function dropKey() {
  if (!keyHandle) return;
  try {
    call("drop_key", { key: keyHandle });
  } catch { /* module déjà déchargé */ }
  keyHandle = null;
}

// ------------------------------------------------------------ Mise en page

/** Carte centrée : marque de l'organisation, titre, contenu, pied. */
function page(title, ...content) {
  const org = brand?.branding?.org_name;
  const logo = brand?.branding?.logo_url;
  clear(root, h("div", { class: "l-auth" }, h("div", { class: "l-auth__card l-stack", "data-gap": "4" },
    h("p", { class: "l-cluster" },
      logo ? h("img", { src: logo, alt: "", width: "32", height: "32" }) : icon("lock", { size: "lg" }),
      h("strong", {}, org ? t("tools.share.brand_org", { org }) : t("common.app.name"))),
    h("h1", { tabindex: "-1" }, title),
    ...content,
    footer())));
  focusHeading(root);
}

function footer() {
  const legal = brand?.legal || {};
  const support = brand?.branding?.support_contact;
  const link = (url, labelKey) => (/^https:\/\//i.test(url || "")
    ? h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, t(labelKey))
    : null);
  const links = [link(legal.notice_url, "tools.share.legal_notice"), link(legal.privacy_url, "tools.share.legal_privacy"),
    link(legal.accessibility_url, "tools.share.legal_accessibility")].filter(Boolean);
  return h("footer", { class: "l-stack u-muted", "data-gap": "2" },
    h("p", {}, t("tools.share.e2e")),
    support ? h("p", {}, t("tools.share.support", { contact: support })) : null,
    links.length ? h("p", { class: "l-cluster" }, links) : null);
}

// ------------------------------------------------------------ États

function incomplete() {
  page(t("tools.share.incomplete_title"), h("p", {}, t("tools.share.incomplete_text")));
}

function notFound() {
  dropKey();
  page(t("tools.share.not_found_title"), h("p", {}, t("tools.share.not_found_text")));
}

/** Lien terminé : motif lisible et date de fin. */
function ended(reason, endedAt) {
  dropKey();
  const why = REASONS.has(reason) ? reason : "revoked";
  page(t("tools.share.ended_title"),
    h("p", {}, t(`tools.share.ended.${why}`)),
    endedAt ? h("p", { class: "u-muted" }, t("tools.share.ended_at", { date: fmtDate(endedAt) })) : null,
    h("p", {}, t("tools.share.ended_help")));
}

function failure(res, retry) {
  if (res.status === 429) {
    const wait = res.retryAfter ? formatDuration(res.retryAfter, "seconds") : null;
    page(t("tools.share.busy_title"),
      h("p", {}, wait ? t("tools.share.rate_limited", { wait }) : t("tools.share.rate_limited_soon")),
      h("div", { class: "l-cluster" }, button({ label: t("common.action.retry"), icon: "refresh", onClick: retry })));
    return;
  }
  page(t("tools.share.error_title"),
    h("p", {}, res.status === 0 ? t("tools.share.offline") : t("tools.share.server_error")),
    h("div", { class: "l-cluster" }, button({ label: t("common.action.retry"), icon: "refresh", onClick: retry })));
}

/** Réponse d'une ouverture ou d'un aperçu : vrai si elle a été traitée comme un échec. */
function handledFailure(res, retry) {
  if (res.status === 404) {
    notFound();
    return true;
  }
  if (res.status === 410) {
    ended(res.data?.reason, res.data?.ended_at);
    return true;
  }
  if (res.status !== 200 || !res.data) {
    failure(res, retry);
    return true;
  }
  return false;
}

/** Accueil avant l'affichage : expiration et ouvertures restantes si connues. */
function intro(info, onReveal) {
  const btn = button({ label: t("tools.share.reveal"), icon: "eye", variant: "primary", busyLabel: t("tools.share.revealing"), onClick: onReveal });
  page(t("tools.share.intro_title"),
    h("p", {}, t("tools.share.intro_text")),
    info ? h("p", {}, plural("tools.share.intro_state", info.views_left, { date: fmtDate(info.expires_at) })) : null,
    alertCard({ tone: "warn", text: t("tools.share.intro_warning") }),
    h("div", { class: "l-cluster" }, btn));
}

/** Contenu déchiffré : seuls les champs présents dans la charge sont montrés. */
function revealed(d, meta) {
  const urls = (Array.isArray(d.urls) ? d.urls : []).map((u) => String(u || "").trim()).filter(Boolean);
  const links = urls.map((u) => (/^https?:\/\//i.test(u)
    ? h("li", {}, h("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, u))
    : h("li", {}, u)));
  const fields = (Array.isArray(d.fields) ? d.fields : []).filter((f) => f && f.value);
  const notes = String(d.notes || "");
  let status;
  if (meta.views_left > 0) status = plural("tools.share.views_left", meta.views_left, { date: fmtDate(meta.expires_at) });
  else status = t("tools.share.last_view");
  const totp = d.totp ? totpCode({ config: d.totp }) : null;
  page(d.name ? String(d.name) : t("tools.share.secret_title"),
    h("div", { class: "c-card l-stack", "data-gap": "3" },
      d.username ? secretRow({ label: t("common.glossary.username"), value: String(d.username), kind: "username", masked: false }) : null,
      d.password ? secretRow({ label: t("common.glossary.password"), value: String(d.password), kind: "password" }) : null,
      totp ? h("div", { class: "l-stack", "data-gap": "1" }, h("p", { class: "c-field__label" }, t("common.glossary.verification_code")), totp.el) : null,
      links.length ? h("div", { class: "l-stack", "data-gap": "1" }, h("p", { class: "c-field__label" }, plural("tools.share.sites", links.length)), h("ul", {}, links)) : null,
      fields.map((f) => secretRow({ label: String(f.label || t("tools.share.field")), value: String(f.value), kind: f.hidden ? "secret" : "text", masked: !!f.hidden })),
      notes ? h("div", { class: "l-stack", "data-gap": "1" }, h("p", { class: "c-field__label" }, t("tools.share.notes")),
        h("p", {}, notes.split(/\r?\n/).flatMap((line, i) => (i ? [h("br"), line] : [line])))) : null),
    meta.replayed ? h("p", { class: "u-muted" }, t("tools.share.replayed")) : null,
    alertCard({ tone: meta.views_left > 0 ? "info" : "warn", text: status }));
}

// ------------------------------------------------------------ Parcours

/** Déchiffre la charge reçue ; null si la clé ne correspond pas. */
function decrypt(data) {
  try {
    return JSON.parse(call("decrypt", { key: keyHandle, data, aad: A.share() }));
  } catch {
    return null;
  } finally {
    dropKey();
  }
}

function show(res) {
  const d = decrypt(res.data.data);
  if (!d || typeof d !== "object") {
    page(t("tools.share.decrypt_title"), h("p", {}, t("tools.share.decrypt_text")));
    return;
  }
  revealed(d, res.data);
}

/** Lien avec preuve : aperçu puis ouverture idempotente. */
async function withProof(proof) {
  const peek = await request("POST", `/public/shares/${encodeURIComponent(id)}/peek`, { proof });
  // 404 : lien inconnu, preuve fausse, ou lien créé sans vérificateur (avant
  // la preuve de possession) : seule la lecture historique peut trancher.
  if (peek.status === 404) return legacy();
  if (handledFailure(peek, () => withProof(proof))) return undefined;
  const open = async () => {
    const res = await request("POST", `/public/shares/${encodeURIComponent(id)}/open`, { proof, nonce: nonceFor(id) });
    if (handledFailure(res, () => intro(null, open))) return;
    show(res);
  };
  intro(peek.data, open);
  return undefined;
}

/** Lien sans preuve : chaque lecture compte une ouverture, d'où le bouton avant. */
function legacy() {
  const open = async () => {
    const res = await request("GET", `/public/shares/${encodeURIComponent(id)}`);
    if (handledFailure(res, () => intro(null, open))) return;
    show(res);
  };
  intro(null, open);
}

async function start() {
  brand = await loadPublic().catch(() => null);
  if (!id || !keyText) return incomplete();
  try {
    await loadCrypto();
  } catch {
    return page(t("tools.share.unsupported_title"), h("p", {}, t("tools.share.unsupported_text")));
  }
  try {
    keyHandle = call("import_key", { key: keyText });
  } catch {
    return incomplete();
  }
  const proof = proofOf(keyText);
  return proof ? withProof(proof) : legacy();
}

window.addEventListener("pagehide", dropKey);
// Erreur imprévue : une page lisible avec « Réessayer », jamais une page vide
// (la clé, retirée de l'adresse, reste en mémoire : pas de rechargement).
function run() {
  start().catch(() => {
    dropKey();
    failure({ status: -1 }, run);
  });
}
run();
