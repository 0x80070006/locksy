// Actions sur un élément, chacune avec sa gestion d'erreur (correctif P0
// 01-2) : en cas d'échec, un message français s'affiche et l'élément reste
// dans son état initial ; aucun état optimiste n'est laissé sans annulation.
//
// `env` = { reload(), navigate(path, opts) } fourni par l'écran du coffre :
// reload() resynchronise puis redessine la liste et la fiche.

import { t, h, confirm, copySecret, dialog, field, selectInput, fieldInput, audienceLine, icon, notify } from "../../ui/index.js";
import { api } from "../../api.js";
import { call } from "../../wasm.js";
import * as V from "../../vault.js";
import * as S from "../../settings-client.js";
import {
  primarySecret, usernameOf, safeUrl, errorNotice, favorites, writableCollections, collectionLabel, collectionOf,
} from "./common.js";

/** Fenêtre « Nouveau coffre » (bouton « + » de la barre latérale, app.js). */
export { newCollectionDialog } from "./collections.js";

// ------------------------------------------------------------ Copies

export async function copyPrimary(item) {
  const s = primarySecret(item?.data);
  if (!s) return false;
  return copySecret(s.value, { kind: s.kind });
}

export async function copyUsername(item) {
  const u = usernameOf(item?.data);
  if (!u) return false;
  return copySecret(u, { kind: "username" });
}

/** Code de vérification courant (null si la clé est absente ou invalide). */
export function currentCode(secret) {
  if (!secret) return null;
  try {
    return call("totp", { secret, time: Math.floor(Date.now() / 1000) }).code || null;
  } catch {
    return null;
  }
}

export async function copyCode(item) {
  const code = currentCode(item?.data?.totp);
  if (!code) return false;
  return copySecret(code, { kind: "totp" });
}

export function openSite(item) {
  const url = safeUrl((item?.data?.urls || [])[0]);
  if (url) window.open(url, "_blank", "noopener,noreferrer");
}

// ------------------------------------------------------------ Favoris personnels

/**
 * Ajoute ou retire un favori personnel (préférences chiffrées, jamais dans
 * l'élément : le favori de l'un ne change pas celui des autres). Renvoie le
 * nouvel état, ou l'ancien si l'enregistrement a échoué.
 */
export async function toggleFavorite(item) {
  const set = favorites();
  const was = set.has(item.id);
  if (was) set.delete(item.id);
  else set.add(item.id);
  try {
    await S.savePrefs({ favorites: [...set] });
  } catch (e) {
    errorNotice(e);
    return was;
  }
  return !was;
}

/**
 * Reprise unique des anciens favoris (champ `favorite` des éléments) dans les
 * préférences, à la première ouverture du coffre neuf (§4.9). Marquée dans
 * onboarding.done (« favorites ») pour ne jamais se répéter.
 */
export async function migrateLegacyFavorites() {
  const p = S.prefs();
  const done = p.onboarding?.done || [];
  if (done.includes("favorites")) return false;
  const legacy = [...V.state.items.values()].filter((i) => i.data?.favorite === true).map((i) => i.id);
  const merged = [...new Set([...(p.favorites || []), ...legacy])];
  try {
    await S.savePrefs({ favorites: merged, onboarding: { done: [...done, "favorites"] } });
    return true;
  } catch {
    // Nouvel essai à la prochaine ouverture ; rien n'est perdu.
    return false;
  }
}

// ------------------------------------------------------------ Corbeille

/**
 * Met à la corbeille (niveau 0) : action immédiate puis toast « … mis à la
 * corbeille · Annuler » pendant 8 s ; « Annuler » restaure l'élément.
 */
export async function moveToTrash(item, env) {
  const name = item.data?.name || "";
  try {
    await api("DELETE", `/items/${encodeURIComponent(item.id)}`);
  } catch (e) {
    errorNotice(e);
    return false;
  }
  await env.reload();
  await confirm({
    level: 0,
    message: t("vault.trash.moved", { name }),
    undoText: t("vault.trash.restored", { name }),
    undo: async () => {
      if (await restore(item, env, { quiet: true })) env.navigate?.(`/element/${encodeURIComponent(item.id)}`);
    },
  });
  return true;
}

export async function restore(item, env, { quiet = false } = {}) {
  try {
    await api("POST", `/items/${encodeURIComponent(item.id)}/restore`);
  } catch (e) {
    errorNotice(e);
    return false;
  }
  await env.reload();
  if (!quiet) notifyDone(t("vault.trash.restored", { name: item.data?.name || "" }));
  return true;
}

/** Suppression définitive (niveau 1 : la fenêtre nomme l'élément). */
export async function purge(item, env) {
  const name = item.data?.name || "";
  const { confirmed } = await confirm({
    level: 1,
    title: t("vault.trash.purge_title"),
    message: t("vault.trash.purge_text"),
    objectName: name,
    confirmLabel: t("common.action.delete_forever"),
    danger: true,
  });
  if (!confirmed) return false;
  try {
    await api("DELETE", `/items/${encodeURIComponent(item.id)}/purge`);
  } catch (e) {
    errorNotice(e);
    return false;
  }
  await env.reload();
  notifyDone(t("vault.trash.purged", { name }));
  return true;
}

function notifyDone(text) {
  notify({ text, tone: "ok" });
}

// ------------------------------------------------------------ Déplacer vers…

/**
 * Déplace l'élément vers un autre coffre où l'on peut écrire. La fenêtre dit
 * qui y aura accès ; les pièces jointes suivent l'élément (leur clé est dans
 * l'élément chiffré).
 */
export function moveDialog(item, env) {
  const targets = writableCollections().filter((c) => c.id !== item.collection_id);
  if (!targets.length) {
    dialog({
      title: t("vault.move.title"),
      body: h("p", {}, t("vault.move.none")),
      actions: [{ label: t("common.action.close"), variant: "primary" }],
    });
    return;
  }
  const select = selectInput({ options: targets.map((c) => ({ value: c.id, label: collectionLabel(c) })), value: targets[0].id });
  const impact = h("div", {});
  const paint = () => {
    const c = collectionOf(select.value);
    impact.replaceChildren(audienceLine({ collection: { name: collectionLabel(c), personal: c?.personal }, members: c?.member_count || 0 }));
  };
  select.addEventListener("change", paint);
  paint();
  dialog({
    title: t("vault.move.title"),
    description: t("vault.move.text", { name: item.data?.name || "" }),
    body: h("div", { class: "l-stack", "data-gap": "3" }, field({ label: t("vault.editor.collection"), input: select }), impact,
      (item.data?.attachments || []).length ? h("p", { class: "u-muted" }, icon("attachment", { size: "sm" }), " ", t("vault.move.attachments")) : null),
    actions: [
      { label: t("common.action.cancel"), value: "cancel" },
      {
        label: t("vault.move.confirm"), variant: "primary", busyLabel: t("common.state.saving"),
        onClick: async () => {
          const target = fieldInput(select.closest(".c-field")).value;
          try {
            await V.updateItem(item, item.data, target);
          } catch (e) {
            errorNotice(e);
            return false;
          }
          await env.reload();
          notifyDone(t("vault.move.done", { name: item.data?.name || "", vault: collectionLabel(collectionOf(target)) }));
          return true;
        },
      },
    ],
  });
}
