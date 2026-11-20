// Coffres partagés (cahier §3.3.4, « Gérer le coffre ») : membres avec leur
// rôle en mots, ajout par recherche, retrait (niveau 1) avec renouvellement de
// la clé, proposition de changer les mots de passe connus de la personne
// retirée selon vault.rotate_on_member_removal, empreintes repliées sous
// « Vérifier l'identité des membres (avancé) », renommage, renouvellement de
// la clé, suppression (niveau 3), départ du coffre. Création d'un coffre.
//
//   manageCollection(id, { env, rotate })  fenêtre « Gérer le coffre »
//   newCollectionDialog({ navigate, refresh })  fenêtre « Nouveau coffre »

import {
  t, plural, fmtDate, h, clear, icon, button, dialog, confirm, field, textInput, selectInput, menuButton, avatar, badge,
  notify, errorText, normalize, focusSafely,
} from "../../ui/index.js";
import { api } from "../../api.js";
import { keyPinStatus, pinKey } from "../../pins.js";
import * as V from "../../vault.js";
import { ROLES, roleLabel, collectionOf, collectionLabel, canManage, policy, offline } from "./common.js";
import { canCreateShared } from "./share-flow.js";

/** Libellé d'un rôle en mots (« Peut voir », « Peut modifier », « Gère le coffre »). */
const roleWords = (role) => t(`vault.members.role.${ROLES.includes(role) ? role : "reader"}`);

/** Erreur d'une opération sur le coffre ; 409 = la liste des membres a changé entre-temps. */
function failed(e) {
  notify({ text: e?.status === 409 ? t("vault.members.changed") : errorText(e), tone: "danger" });
}

/** Éléments du coffre qui ont un mot de passe (à changer après un départ). */
function secretsIn(collectionId) {
  return [...V.state.items.values()].filter((i) => i.collection_id === collectionId && !i.deleted_at
    && (i.data?.password || i.data?.ssh?.password || i.data?.card?.number)).length;
}

/**
 * Confirme un renouvellement de clé : la nouvelle clé n'est remise qu'aux
 * personnes du plan ; une clé publique changée depuis le dernier partage doit
 * être vérifiée explicitement (case à cocher) avant de continuer.
 */
async function confirmRotation(collectionId, removeIds, { title, message, confirmLabel, danger }) {
  // Le rechiffrement exige de lire chaque élément : refus expliqué avant toute demande.
  if ([...V.state.items.values()].some((i) => i.collection_id === collectionId && !i.data)) {
    notify({ text: t("vault.members.unreadable"), tone: "danger" });
    return null;
  }
  let plan;
  try {
    plan = await V.planRotation(collectionId, removeIds);
  } catch (e) {
    failed(e);
    return null;
  }
  const changed = plan.members.filter((m) => m.pin === "changed");
  const impact = [
    t("vault.members.rotation_recipients", { names: plan.members.map((m) => m.name || m.email).join(", ") }),
    ...changed.map((m) => t("vault.members.key_changed", { name: m.name || m.email, fingerprint: m.fingerprint })),
  ];
  const { confirmed } = await confirm({ level: changed.length ? 2 : 1, title, message, impact, confirmLabel, danger });
  return confirmed ? plan : null;
}

export function manageCollection(collectionId, { env, rotate = false } = {}) {
  const col = collectionOf(collectionId);
  if (!col) {
    notify({ text: t("vault.collection.not_found"), tone: "danger" });
    return null;
  }
  const manager = canManage(collectionId);
  const me = V.state.profile?.id;
  const body = h("div", { class: "l-stack", "data-gap": "4" }, h("p", { class: "u-muted" }, t("common.state.loading")));
  let members = [];
  let directory = null;

  const dlg = dialog({
    title: t("vault.members.title", { vault: collectionLabel(col) }),
    body,
    size: "lg",
    actions: [{ label: t("common.action.close"), value: "done", variant: "primary" }],
  });

  async function reload() {
    try {
      await V.sync();
    } catch { /* la liste des membres sera relue quand même */ }
    await draw();
    env?.countsChanged?.();
  }

  async function removeMember(m) {
    const plan = await confirmRotation(collectionId, [m.user_id], {
      title: t("vault.members.remove_title", { name: m.name || m.email }),
      message: t("vault.members.remove_text", { name: m.name || m.email }),
      confirmLabel: t("vault.members.remove_confirm"),
      danger: true,
    });
    if (!plan) return;
    try {
      await V.rotateCollection(collectionId, [m.user_id], plan);
    } catch (e) {
      failed(e);
      return;
    }
    notify({ text: t("vault.members.removed", { name: m.name || m.email }), tone: "ok" });
    await reload();
    // Proposition de changer les mots de passe que la personne connaissait.
    const n = secretsIn(collectionId);
    if (n && policy("vault.rotate_on_member_removal", "suggest") !== "off") {
      body.prepend(h("div", { class: "c-alert", "data-tone": "warn" }, icon("warn"),
        h("div", { class: "l-stack", "data-gap": "2" },
          h("p", {}, plural("vault.members.change_passwords", n, { name: m.name || m.email })),
          h("div", {}, h("a", { class: "c-button", href: `#/coffre/c/${encodeURIComponent(collectionId)}`, onclick: () => dlg.close("done") },
            t("vault.members.change_passwords_action"))))));
    }
  }

  async function rotateKey() {
    const plan = await confirmRotation(collectionId, [], {
      title: t("vault.members.rotate_title"),
      message: t("vault.members.rotate_text"),
      confirmLabel: t("vault.members.rotate_confirm"),
    });
    if (!plan) return;
    try {
      await V.rotateCollection(collectionId, [], plan);
    } catch (e) {
      failed(e);
      return;
    }
    notify({ text: t("vault.members.rotated"), tone: "ok" });
    await reload();
  }

  async function changeRole(m, select) {
    const before = m.role;
    try {
      await api("PUT", `/collections/${encodeURIComponent(collectionId)}/members/${encodeURIComponent(m.user_id)}`, { role: select.value });
    } catch (e) {
      select.value = before;
      failed(e);
      return;
    }
    m.role = select.value;
    notify({ text: t("vault.members.role_changed", { name: m.name || m.email, role: roleWords(select.value) }), tone: "ok" });
  }

  async function addMember(u, role) {
    const pin = keyPinStatus(u.id, u.public_key);
    if (pin === "changed") {
      const { confirmed } = await confirm({
        level: 2,
        title: t("vault.members.add_title", { name: u.name || u.email }),
        message: t("vault.members.add_changed_text"),
        impact: t("vault.members.key_changed", { name: u.name || u.email, fingerprint: V.fingerprint(u.public_key) }),
        confirmLabel: t("vault.members.add_confirm"),
      });
      if (!confirmed) return;
    }
    try {
      await V.addMember(collectionId, u, role);
    } catch (e) {
      failed(e);
      return;
    }
    notify({ text: t("vault.members.added", { name: u.name || u.email }), tone: "ok" });
    await reload();
  }

  async function rename() {
    const input = textInput({ name: "nom", value: collectionLabel(col), maxlength: 80, autocomplete: "off" });
    dialog({
      title: t("vault.members.rename_title"),
      body: field({ label: t("vault.members.rename_label"), input }),
      actions: [
        { label: t("common.action.cancel"), value: "cancel", cancel: true },
        {
          label: t("vault.members.rename_confirm"), variant: "primary", busyLabel: t("common.state.saving"),
          onClick: async () => {
            const name = input.value.trim();
            if (!name) {
              focusSafely(input);
              return false;
            }
            try {
              await V.renameCollection(collectionId, name);
            } catch (e) {
              failed(e);
              return false;
            }
            notify({ text: t("vault.members.renamed"), tone: "ok" });
            await env?.reload?.();
            dlg.close("done");
            return true;
          },
        },
      ],
    });
  }

  async function remove() {
    const { confirmed } = await confirm({
      level: 3,
      title: t("vault.members.delete_title"),
      message: t("vault.members.delete_text"),
      objectName: collectionLabel(col),
      impact: plural("vault.members.delete_impact", [...V.state.items.values()].filter((i) => i.collection_id === collectionId).length),
      confirmLabel: t("vault.members.delete_confirm"),
      danger: true,
      // Mot de passe maître vérifié localement avant l'action définitive.
      reauth: (password) => V.authProof(password),
    });
    if (!confirmed) return;
    try {
      await api("DELETE", `/collections/${encodeURIComponent(collectionId)}`);
    } catch (e) {
      failed(e);
      return;
    }
    dlg.close("done");
    notify({ text: t("vault.members.deleted"), tone: "ok" });
    await env?.reload?.();
    env?.navigate?.("/coffre", { replace: true });
  }

  async function leave() {
    const { confirmed } = await confirm({
      level: 1, title: t("vault.members.leave_title"), message: t("vault.members.leave_text"),
      objectName: collectionLabel(col), confirmLabel: t("vault.members.leave_confirm"), danger: true,
    });
    if (!confirmed) return;
    try {
      await api("DELETE", `/collections/${encodeURIComponent(collectionId)}/members/${encodeURIComponent(me)}`);
    } catch (e) {
      failed(e);
      return;
    }
    dlg.close("done");
    notify({ text: t("vault.members.left"), tone: "ok" });
    await env?.reload?.();
    env?.navigate?.("/coffre", { replace: true });
  }

  function memberRow(m) {
    const self = m.user_id === me;
    let roleEl;
    if (manager && !self) {
      const select = selectInput({ name: `role-${m.user_id}`, value: m.role, options: ROLES.map((r) => ({ value: r, label: roleWords(r) })) });
      select.setAttribute("aria-label", t("vault.members.role_of", { name: m.name || m.email }));
      select.addEventListener("change", () => changeRole(m, select));
      roleEl = select;
    } else {
      roleEl = h("span", {}, roleWords(m.role));
    }
    return h("li", { class: "l-cluster", "data-justify": "between" },
      h("span", { class: "l-cluster" }, avatar({ name: m.name || m.email }),
        h("span", { class: "l-stack", "data-gap": "1" },
          h("span", {}, self ? t("vault.members.you", { name: m.name || m.email }) : (m.name || m.email)),
          h("span", { class: "u-muted" }, m.email))),
      h("span", { class: "l-cluster" }, roleEl,
        manager && !self ? button({ label: t("vault.members.remove", { name: m.name || m.email }), icon: "close", variant: "quiet",
          disabled: offline(), reason: offline() ? t("vault.offline_reason") : undefined, onClick: () => removeMember(m) }) : null));
  }

  function fingerprints() {
    return h("details", { class: "c-card" },
      h("summary", {}, t("vault.members.verify")),
      h("p", { class: "u-muted" }, t("vault.members.verify_help")),
      h("dl", { class: "c-hotkeys" }, members.flatMap((m) => {
        const pin = m.user_id === me ? "same" : keyPinStatus(m.user_id, m.public_key);
        // Première rencontre sur cet appareil : la clé vue devient la référence.
        if (pin === "new") pinKey(m.user_id, m.public_key, m.email);
        return [
          h("dt", {}, m.name || m.email, pin === "changed" ? badge({ tone: "danger", label: t("vault.members.pin_changed") }) : null),
          h("dd", { class: "u-mono" }, V.fingerprint(m.public_key)),
        ];
      })));
  }

  function addSection() {
    const input = textInput({ name: "ajouter", autocomplete: "off" });
    const role = selectInput({ name: "role", value: "reader", options: ROLES.map((r) => ({ value: r, label: roleWords(r) })) });
    const results = h("ul", { class: "l-stack", "data-gap": "1", role: "list", "aria-label": t("vault.share.results") });
    const paint = () => {
      const q = normalize(input.value);
      if (!q || !directory) return results.replaceChildren();
      const found = directory.filter((u) => !members.some((m) => m.user_id === u.id) && normalize(`${u.name} ${u.email}`).includes(q)).slice(0, 6);
      results.replaceChildren(...(found.length
        ? found.map((u) => h("li", { class: "l-cluster", "data-justify": "between" },
          h("span", { class: "l-cluster" }, avatar({ name: u.name || u.email }), h("span", {}, u.name), h("span", { class: "u-muted" }, u.email)),
          button({ label: t("vault.share.add_person", { name: u.name || u.email }), icon: "plus", onClick: () => addMember(u, role.value) })))
        : [h("li", { class: "u-muted" }, t("vault.share.nobody", { q: input.value.trim() }))]));
    };
    input.addEventListener("input", paint);
    input.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      e.preventDefault();
      results.querySelector("button")?.click();
    });
    return h("section", { class: "l-stack", "data-gap": "2" },
      h("h3", {}, t("vault.members.add")),
      h("div", { class: "l-cluster" }, field({ label: t("vault.share.who"), input }), field({ label: t("vault.members.add_role"), input: role })),
      results);
  }

  async function draw() {
    try {
      [members, directory] = await Promise.all([
        api("GET", `/collections/${encodeURIComponent(collectionId)}/members`),
        directory ? Promise.resolve(directory) : api("GET", "/directory").then((l) => (l || []).filter((u) => u.public_key)).catch(() => []),
      ]);
    } catch (e) {
      body.replaceChildren(h("div", { class: "c-alert", "data-tone": "danger" }, icon("error"), h("p", {}, errorText(e))),
        h("div", {}, button({ label: t("common.action.retry"), icon: "refresh", onClick: () => draw() })));
      return;
    }
    const fresh = collectionOf(collectionId) || col;
    const menu = manager ? menuButton({
      label: t("common.action.more_actions"), icon: "more", iconOnly: true, variant: "quiet",
      items: [
        { label: t("vault.members.rename"), icon: "edit", onSelect: rename },
        { label: t("vault.members.rotate"), icon: "refresh", onSelect: rotateKey },
        "separator",
        { label: t("vault.members.delete"), icon: "trash", danger: true, onSelect: remove },
      ],
    }) : null;
    const suggested = fresh.rotation_suggested_at && manager
      ? h("div", { class: "c-alert", "data-tone": "warn" }, icon("warn"), h("div", { class: "l-stack", "data-gap": "2" },
        h("p", {}, t("vault.collection.rotation_suggested", { date: fmtDate(fresh.rotation_suggested_at, "date") })),
        h("div", {}, button({ label: t("vault.collection.rotate"), icon: "refresh", onClick: rotateKey }))))
      : null;
    clear(body,
      h("div", { class: "l-cluster", "data-justify": "between" },
        h("p", { class: "u-muted" }, plural("vault.collection.members", members.length), " · ",
          t("vault.collection.your_role", { role: roleLabel(fresh.role).toLowerCase() })),
        menu),
      suggested,
      h("section", { class: "l-stack", "data-gap": "2" },
        h("h3", {}, t("vault.members.list")),
        h("ul", { class: "l-stack", "data-gap": "2", role: "list", "aria-label": t("vault.members.list") }, members.map(memberRow))),
      manager ? addSection() : h("p", { class: "c-policy-hint" }, icon("info", { size: "sm" }), t("vault.members.managers_only")),
      fingerprints(),
      fresh.personal ? null : h("div", {}, button({ label: t("vault.members.leave"), icon: "logout", variant: "quiet", onClick: leave })));
    if (rotate && manager) {
      rotate = false;
      rotateKey();
    }
  }

  draw();
  return dlg;
}

/** Fenêtre « Nouveau coffre » : création, puis ouverture du coffre et de ses membres. */
export function newCollectionDialog({ navigate, refresh } = {}) {
  // vault.users_can_create_shared : refus expliqué avant toute saisie (le serveur refuse aussi).
  if (!canCreateShared()) {
    return dialog({
      title: t("vault.collection.new_title"),
      body: h("p", { class: "c-policy-hint" }, icon("lock", { size: "sm" }), t("vault.share.creation_admins")),
      actions: [{ label: t("common.action.close"), value: "cancel", variant: "primary" }],
    });
  }
  let created = null;
  const input = textInput({ name: "nom", maxlength: 80, autocomplete: "off" });
  const nameField = field({ label: t("vault.collection.new_name"), help: t("vault.collection.new_help"), input });
  return dialog({
    title: t("vault.collection.new_title"),
    body: nameField,
    dirty: () => input.value.trim() !== "",
    // Membres à ajouter : fenêtre ouverte après la fermeture de celle-ci (le focus y va).
    onClose: () => { if (created) manageCollection(created, { env: { reload: refresh, navigate } }); },
    actions: [
      { label: t("common.action.cancel"), value: "cancel", cancel: true },
      {
        label: t("common.action.create"), variant: "primary", busyLabel: t("vault.collection.creating"),
        onClick: async () => {
          const name = input.value.trim();
          if (!name) {
            notify({ text: t("vault.collection.name_required"), tone: "danger" });
            focusSafely(input);
            return false;
          }
          let id;
          try {
            id = await V.createCollection(name);
          } catch (e) {
            failed(e);
            return false;
          }
          try {
            await refresh?.();
          } catch (e) {
            failed(e);
          }
          notify({ text: t("vault.collection.created"), tone: "ok" });
          await navigate?.(`/coffre/c/${encodeURIComponent(id)}`);
          created = id;
          return true;
        },
      },
    ],
  });
}
