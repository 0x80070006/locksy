// Recherche dans tout le coffre (contrat C4.4, consommé par la recherche
// globale de la coquille et par la liste) : sans accents ni casse, sur le nom,
// l'identifiant, les sites, les étiquettes et le début des notes ; tous les
// mots doivent être trouvés. Les éléments de la corbeille sont exclus.

import { normalize } from "../../ui/index.js";
import * as V from "../../vault.js";
import { collectionLabel, subtitle } from "./common.js";

const NOTES_PREFIX = 200;

/** Texte cherchable d'un élément (normalisé, mis en cache tant que l'élément ne change pas). */
const cache = new WeakMap();
export function haystack(item) {
  let text = cache.get(item);
  if (text !== undefined) return text;
  const d = item.data || {};
  text = normalize([
    d.name, d.username, ...(d.urls || []), ...(d.tags || []), String(d.notes || "").slice(0, NOTES_PREFIX),
    d.card?.holder, d.identity?.email, d.identity?.first_name, d.identity?.last_name, d.identity?.company,
    d.ssh?.host, d.ssh?.username,
  ].filter(Boolean).join(" "));
  cache.set(item, text);
  return text;
}

/** Mots de la requête (normalisés) ; vide si la requête l'est. */
export const terms = (query) => normalize(query).split(/\s+/).filter(Boolean);

/** Vrai si l'élément contient tous les mots. */
export function matches(item, words) {
  if (!words.length) return true;
  const hay = haystack(item);
  return words.every((w) => hay.includes(w));
}

/** Tri des noms à la française, sans casse ni accents (un seul collateur). */
const COLLATOR = new Intl.Collator("fr", { sensitivity: "base" });

/** Les `k` premiers de `rows` selon `cmp`, triés, sans trier le reste. */
function firstK(rows, k, cmp) {
  const out = [];
  for (const r of rows) {
    if (out.length >= k && cmp(r, out[k - 1]) >= 0) continue;
    let lo = 0;
    let hi = out.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (cmp(r, out[mid]) < 0) hi = mid;
      else lo = mid + 1;
    }
    out.splice(lo, 0, r);
    if (out.length > k) out.pop();
  }
  return out;
}

/**
 * search(query, { collectionId, limit }) -> [{ id, title, subtitle, collection, kind }]
 * Les éléments dont le nom commence par la requête viennent en premier, puis
 * l'ordre alphabétique. Avec `limit`, seuls les `limit` premiers sont triés
 * et décrits (frappe fluide à 10 000 éléments) ; le tableau porte alors
 * `total`, le nombre de correspondances.
 */
export function search(query, { collectionId = null, limit = Infinity } = {}) {
  const words = terms(query);
  if (!words.length) return [];
  const first = words.join(" ");
  const rows = [];
  for (const item of V.state.items.values()) {
    if (!item.data || item.deleted_at) continue;
    if (collectionId && item.collection_id !== collectionId) continue;
    if (!matches(item, words)) continue;
    rows.push({ item, name: String(item.data.name ?? ""), starts: normalize(item.data.name).startsWith(first) ? 0 : 1 });
  }
  const cmp = (a, b) => (a.starts - b.starts) || COLLATOR.compare(a.name, b.name);
  const chosen = limit < rows.length ? firstK(rows, limit, cmp) : rows.sort(cmp);
  const out = chosen.map(({ item: i }) => ({
    id: i.id,
    title: i.data.name,
    subtitle: subtitle(i.data),
    collection: collectionLabel(V.state.collections.get(i.collection_id)),
    kind: i.data.kind,
  }));
  out.total = rows.length;
  return out;
}
