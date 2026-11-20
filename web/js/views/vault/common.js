// Outils partagés des écrans du coffre : types d'élément, droits, coffres,
// favoris personnels, sous-titres et valeurs à copier. Aucun DOM ici, sauf
// le message d'erreur commun (errorNotice).

import { t, errorText, notify } from "../../ui/index.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";

/** Types d'élément, dans l'ordre du choix « Que voulez-vous enregistrer ? ». */
export const KINDS = Object.freeze(["login", "note", "card", "identity", "ssh"]);
export const KIND_ICONS = Object.freeze({ login: "key", note: "note", card: "card", identity: "id", ssh: "ssh" });

export const kindLabel = (kind) => t(`vault.kind.${KINDS.includes(kind) ? kind : "login"}`);

/** Rôles dans un coffre, du plus au moins étendu. */
export const ROLES = Object.freeze(["manager", "editor", "reader"]);
export const roleLabel = (role) => t(`vault.role.${ROLES.includes(role) ? role : "reader"}`);

export const collectionOf = (id) => V.state.collections.get(id) || null;
export const canWrite = (collectionId) => ["manager", "editor"].includes(collectionOf(collectionId)?.role);
export const canManage = (collectionId) => collectionOf(collectionId)?.role === "manager";

/** Nom affiché d'un coffre (« Coffre personnel » pour l'espace personnel). */
export function collectionLabel(c) {
  if (!c) return t("vault.collection.unknown");
  return c.personal ? t("common.glossary.personal_vault") : c.name;
}

/** Coffres où l'on peut écrire, le personnel d'abord (s'il est permis). */
export function writableCollections() {
  const personalAllowed = policy("vault.personal_enabled", true) !== false;
  return [...V.state.collections.values()]
    .filter((c) => canWrite(c.id) && !c.error && (personalAllowed || !c.personal))
    .sort((a, b) => (b.personal - a.personal) || collectionLabel(a).localeCompare(collectionLabel(b), "fr"));
}

/** Coffre proposé pour un nouvel élément : préférence, coffre filtré, puis le premier permis. */
export function defaultCollection(preferredId) {
  const list = writableCollections();
  const pref = S.prefs().ui?.default_collection;
  return list.find((c) => c.id === preferredId)?.id ?? list.find((c) => c.id === pref)?.id ?? list[0]?.id ?? null;
}

/** Valeur effective d'une clé de politique (défaut si la politique ne la donne pas). */
export function policy(key, fallback) {
  try {
    const v = S.effective(key).value;
    return v === undefined || v === null ? fallback : v;
  } catch {
    return fallback;
  }
}

/** Ensemble des favoris personnels (préférences chiffrées). */
export const favorites = () => new Set(S.prefs().favorites || []);

/** Éléments lisibles, hors corbeille. */
export const liveItems = () => [...V.state.items.values()].filter((i) => i.data && !i.deleted_at);

/** Sous-titre d'une ligne : identifiant, 4 derniers chiffres, hôte, début de note. */
export function subtitle(d) {
  if (!d) return "";
  switch (d.kind) {
    case "login": return d.username || (d.urls || [])[0] || "";
    case "card": {
      const n = String(d.card?.number || "").replace(/\D/g, "");
      return n.length >= 4 ? t("vault.list.card_end", { last: n.slice(-4) }) : d.card?.holder || "";
    }
    case "identity": return [d.identity?.first_name, d.identity?.last_name].filter(Boolean).join(" ") || d.identity?.email || "";
    case "ssh": {
      const host = d.ssh?.host || "";
      const user = d.ssh?.username || "";
      if (host) return user ? `${user}@${host}` : host;
      return String(d.ssh?.public_key || "").trim().split(/\s+/).slice(2).join(" ");
    }
    default: return String(d.notes || "").split("\n")[0].slice(0, 60);
  }
}

/** Secret principal d'un élément (bouton de la ligne) : { value, kind, labelKey } ou null. */
export function primarySecret(d) {
  if (!d) return null;
  if (d.kind === "card" && d.card?.number) return { value: d.card.number, kind: "secret", labelKey: "vault.list.copy_number" };
  const pw = d.kind === "ssh" ? d.ssh?.password : d.password;
  if (pw) return { value: pw, kind: "password", labelKey: "vault.list.copy_password" };
  return null;
}

/** Identifiant à copier (connexion, SSH, identité). */
export function usernameOf(d) {
  if (!d) return "";
  if (d.kind === "ssh") return d.ssh?.username || "";
  if (d.kind === "identity") return d.identity?.email || "";
  return d.username || "";
}

/** Adresse ouvrable sans risque (http ou https seulement), ou null. */
export function safeUrl(raw) {
  const s = String(raw || "").trim();
  if (!s) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(s) ? s : `https://${s}`);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch {
    return null;
  }
}

/** Hors ligne : écritures désactivées avec la raison (§2.12). */
export const offline = () => typeof navigator !== "undefined" && navigator.onLine === false;

/** Erreur d'une action : message français, l'objet reste dans son état initial. */
export function errorNotice(err) {
  notify({ text: errorText(err), tone: "danger" });
}
