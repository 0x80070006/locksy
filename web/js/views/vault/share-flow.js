// Partage avec des collègues (cahier §3.3.4, D7) : enchaînement des
// opérations existantes de vault.js, avec retour arrière complet.
//
//   destinations(item, people)  -> { existing: [coffre], canCreate, suggestedName }
//       coffres que l'on gère et dont les membres (hors soi) sont EXACTEMENT les
//       personnes choisies, le plus récent d'abord ; création permise ou non ;
//   shareWithPeople({ item, people, role, collectionId, newName })
//       -> { collectionId, created }
//       1. createCollection(nom) si nouveau coffre ;
//       2. addMember(coffre, personne, rôle) pour chaque personne pas encore membre ;
//       3. updateItem(élément, données, coffre) : l'élément y est rangé (ses pièces
//          jointes le suivent : leur clé est dans l'élément chiffré).
//       Une étape échoue : le coffre créé est supprimé (il est vide), ou les
//       membres ajoutés pendant CETTE exécution sont retirés (retrait = clé
//       renouvelée, seule voie du serveur) ; l'élément reste où il était.
//       L'erreur levée porte `rolledBack` (vrai si tout a été défait).
//
// Aucun DOM ici (seul le nom proposé passe par t()) : l'interface est dans share-dialog.js.

import { t } from "../../ui/index.js";
import { api } from "../../api.js";
import * as V from "../../vault.js";
import { policy } from "./common.js";

/** Rôle dans le coffre pour « Voir et copier » / « Voir, copier et modifier ». */
export const SHARE_ROLES = Object.freeze({ read: "reader", write: "editor" });

/** Prénom d'une personne (premier mot du nom, sinon partie locale de l'adresse). */
export function firstName(person) {
  const name = String(person?.name || "").trim();
  if (name) return name.split(/\s+/)[0];
  return String(person?.email || "").split("@")[0];
}

/** Le rôle de l'utilisateur lui permet-il de créer un coffre partagé ? */
export function canCreateShared() {
  const role = V.state.profile?.role;
  return role !== "user" || policy("vault.users_can_create_shared", true) !== false;
}

const sameSet = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));

/**
 * Destinations possibles pour partager `item` avec `people` ([{ id, name, email }]).
 * Seuls les coffres partagés que l'on gère et dont le nombre de membres
 * correspond sont interrogés (un appel par coffre candidat).
 */
export async function destinations(item, people) {
  const me = V.state.profile?.id;
  const wanted = new Set(people.map((p) => p.id));
  const candidates = [...V.state.collections.values()].filter((c) =>
    !c.personal && !c.error && c.role === "manager" && c.id !== item.collection_id && (c.member_count || 0) === wanted.size + 1);
  const existing = [];
  for (const c of candidates) {
    let members;
    try {
      members = await api("GET", `/collections/${encodeURIComponent(c.id)}/members`);
    } catch {
      continue; // coffre illisible pour l'instant : il n'est simplement pas proposé
    }
    const others = new Set((members || []).map((m) => m.user_id).filter((id) => id !== me));
    if (sameSet(others, wanted)) existing.push(c);
  }
  existing.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
  const names = [firstName(V.state.profile), ...people.map(firstName)].filter(Boolean);
  return {
    existing,
    canCreate: canCreateShared(),
    suggestedName: names.length > 1 ? t("vault.share.vault_name", { first: names.slice(0, -1).join(", "), last: names.at(-1) }) : names.join(""),
  };
}

/**
 * Exécute le partage. `collectionId` (coffre existant) ou `newName` (nouveau
 * coffre). `onStep(étape)` reçoit "create" | "members" | "move" (avancement).
 */
export async function shareWithPeople({ item, people, role = SHARE_ROLES.read, collectionId = null, newName = "", onStep }) {
  let target = collectionId;
  let created = false;
  const added = [];
  try {
    if (!target) {
      onStep?.("create");
      target = await V.createCollection(newName.trim());
      created = true;
      // La clé du nouveau coffre n'est connue qu'après synchronisation.
      await V.sync();
    }
    onStep?.("members");
    const current = await api("GET", `/collections/${encodeURIComponent(target)}/members`);
    const already = new Set((current || []).map((m) => m.user_id));
    for (const person of people) {
      if (already.has(person.id)) continue;
      await V.addMember(target, person, role);
      added.push(person.id);
    }
    onStep?.("move");
    const fresh = V.state.items.get(item.id) || item;
    await V.updateItem(fresh, fresh.data, target);
    return { collectionId: target, created };
  } catch (e) {
    e.rolledBack = await rollback({ target, created, added });
    throw e;
  }
}

/** Défait ce que cette exécution a fait ; vrai si tout a été défait. */
async function rollback({ target, created, added }) {
  if (!target) return true;
  try {
    if (created) {
      // Jamais de suppression d'un coffre qui contiendrait déjà l'élément
      // (réponse perdue après un enregistrement réussi) : on vérifie d'abord.
      await V.sync();
      if ([...V.state.items.values()].some((i) => i.collection_id === target)) return false;
      await api("DELETE", `/collections/${encodeURIComponent(target)}`);
    } else if (added.length) {
      // Le serveur ne retire un autre membre qu'en renouvelant la clé du coffre.
      await V.sync();
      await V.rotateCollection(target, added);
    }
    return true;
  } catch {
    return false;
  }
}
