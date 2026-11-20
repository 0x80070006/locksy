// Corbeille (écart #6) : chaque ligne dit qui a mis l'élément à la corbeille
// et dans combien de temps il sera supprimé définitivement ; vues « Tous »,
// « Coffre personnel », « Coffres partagés ». Les actions (Restaurer,
// Supprimer définitivement) passent par actions.js.

import { t, relTime, segmented } from "../../ui/index.js";
import { api } from "../../api.js";
import * as V from "../../vault.js";
import { collectionOf, collectionLabel, kindLabel } from "./common.js";
import { purgeAt } from "./detail.js";

const SCOPES = ["all", "personal", "shared"];

/** Noms de l'annuaire (id -> nom), chargés une fois par session. */
let names = null;
let namesFor = null;
let loading = null;

/** Charge l'annuaire si besoin ; renvoie vrai si de nouveaux noms sont disponibles. */
export function trashNames() {
  const me = V.state.profile?.id || null;
  if (names && namesFor === me) return Promise.resolve(false);
  loading ??= api("GET", "/directory")
    .then((list) => {
      names = new Map((list || []).map((u) => [u.id, u.name || u.email]));
      namesFor = me;
      return true;
    })
    .catch(() => false)
    .finally(() => { loading = null; });
  return loading;
}

/** Auteur de la mise à la corbeille : « vous », un nom, ou une mention neutre. */
export function deletedBy(item) {
  if (!item.deleted_by) return null;
  if (item.deleted_by === V.state.profile?.id) return t("vault.trash.by_you");
  return names?.get(item.deleted_by) || t("vault.trash.by_member");
}

export function inTrashScope(item, scope) {
  if (!scope || scope === "all") return true;
  const personal = !!collectionOf(item.collection_id)?.personal;
  return scope === "personal" ? personal : !personal;
}

/** Ligne de la corbeille pour itemList. */
export function trashRow(item, name) {
  const col = collectionOf(item.collection_id);
  const who = deletedBy(item);
  const when = relTime(purgeAt(item));
  const parts = [
    who ? t("vault.trash.row_by", { who, when: relTime(item.deleted_at) }) : t("vault.trash.row", { when: relTime(item.deleted_at) }),
    t("vault.trash.row_purge", { when }),
  ];
  if (col && !col.personal) parts.push(collectionLabel(col));
  return {
    title: name,
    subtitle: parts.join(" · ") || kindLabel(item.data.kind),
    href: `#/element/${encodeURIComponent(item.id)}`,
    avatar: { name: item.data.name, kind: item.data.kind },
    menuLabel: t("vault.list.more", { name }),
  };
}

/** Choix de la vue de la corbeille. */
export function trashScopes(value, onChange) {
  return segmented({
    label: t("vault.trash.scope.label"),
    name: "corbeille",
    value: SCOPES.includes(value) ? value : "all",
    options: SCOPES.map((s) => ({ value: s, label: t(`vault.trash.scope.${s}`) })),
    onChange,
  });
}
