// Fenêtre « Partager <nom> » (cahier §3.3.4) : un seul bouton « Partager »
// sur la fiche, deux onglets. « Avec des collègues » : choix des personnes,
// des droits et du coffre (existant avec exactement ces personnes, ou
// nouveau), puis partage enchaîné avec retour arrière (share-flow.js).
// « Par lien sécurisé » : link-tab.js.
//
// openShareDialog(item, env) -> HTMLDialogElement

import {
  t, plural, h, clear, icon, button, dialog, tabs, field, textInput, segmented, radioCards, avatar, notify, errorText,
  setDisabled, normalize, iconButton, announce,
} from "../../ui/index.js";
import { api } from "../../api.js";
import { keyPinStatus } from "../../pins.js";
import * as V from "../../vault.js";
import { collectionOf, collectionLabel, canManage, offline } from "./common.js";
import { destinations, shareWithPeople, SHARE_ROLES } from "./share-flow.js";
import { renderLinkTab } from "./link-tab.js";

const MAX_RESULTS = 6;

/** Annuaire de l'organisation (personnes actives, avec leur clé publique), sans soi. */
async function directory() {
  const me = V.state.profile?.id;
  const list = await api("GET", "/directory");
  return (list || []).filter((u) => u.id !== me && u.public_key);
}

export function openShareDialog(item, env) {
  const name = item.data?.name || "";
  let colleagues = null;
  const tabsEl = tabs({
    label: t("vault.share.tabs"),
    tabs: [
      { id: "collegues", label: t("vault.share.tab_people"), render: (p) => { colleagues = renderPeopleTab(p, item, env, () => dlg); } },
      { id: "lien", label: t("vault.share.tab_link"), render: (p) => renderLinkTab(p, item, env) },
    ],
  });
  const dlg = dialog({
    title: t("vault.share.title", { name }),
    body: tabsEl.el,
    size: "lg",
    dirty: () => !!colleagues?.isDirty(),
    actions: [{ label: t("common.action.close"), value: "cancel", cancel: true }],
    onClose: () => tabsEl.destroy?.(),
  });
  return dlg;
}

/** Onglet « Avec des collègues ». Renvoie { isDirty(), focus() }. */
function renderPeopleTab(panel, item, env, getDialog) {
  const col = collectionOf(item.collection_id);
  const name = item.data?.name || "";

  // Élément déjà dans un coffre partagé : qui y a accès, et gestion du coffre.
  if (col && !col.personal) {
    const who = h("p", { class: "u-muted" }, t("common.state.loading"));
    api("GET", `/collections/${encodeURIComponent(col.id)}/members`)
      .then((members) => {
        const me = V.state.profile?.id;
        const others = (members || []).filter((m) => m.user_id !== me).map((m) => m.name || m.email);
        who.textContent = others.length ? t("vault.share.shared_with", { names: others.join(", ") }) : t("vault.share.shared_alone");
      })
      .catch((e) => { who.textContent = errorText(e); });
    panel.replaceChildren(h("div", { class: "l-stack", "data-gap": "3" },
      h("p", {}, t("vault.share.already_in", { vault: collectionLabel(col) })),
      who,
      h("div", { class: "l-cluster" }, button({
        label: t(canManage(col.id) ? "vault.share.manage" : "vault.share.view_members", { vault: collectionLabel(col) }),
        icon: "users", variant: "primary",
        onClick: () => {
          getDialog()?.close("cancel");
          env.manageCollection(col.id);
        },
      }))));
    return { isDirty: () => false, focus() {} };
  }

  let people = [];
  let all = null;
  let role = SHARE_ROLES.read;
  let choice = null; // id d'un coffre existant ou "nouveau"
  let options = null;
  let seq = 0;

  const searchInput = textInput({ name: "avec_qui", autocomplete: "off" });
  const searchField = field({ label: t("vault.share.who"), help: t("vault.share.who_help"), input: searchInput });
  const results = h("ul", { class: "l-stack", "data-gap": "1", role: "list", "aria-label": t("vault.share.results") });
  // Personnes choisies ; l'ajout et le retrait sont annoncés par #status (A1).
  const chosenBox = h("div", { class: "l-cluster" });
  const rights = segmented({
    label: t("vault.share.rights"), name: "droits", value: role,
    options: [{ value: SHARE_ROLES.read, label: t("vault.share.right_read") }, { value: SHARE_ROLES.write, label: t("vault.share.right_write") }],
    onChange: (v) => { role = v; },
  });
  const whereBox = h("div", { class: "l-stack", "data-gap": "2" });
  const warnBox = h("div", { class: "l-stack", "data-gap": "2" });
  const errorBox = h("div", {});
  const ack = h("input", { type: "checkbox", name: "empreintes_verifiees" });
  const leaving = col?.personal ? h("p", { class: "c-policy-hint" }, icon("info", { size: "sm" }), t("vault.share.leaves_personal", { name })) : null;
  const attachments = (item.data?.attachments || []).length
    ? h("p", { class: "u-muted" }, icon("attachment", { size: "sm" }), " ", t("vault.share.attachments_follow")) : null;

  const shareBtn = button({ label: t("common.action.share"), icon: "share", variant: "primary", busyLabel: t("vault.share.busy"), onClick: () => run() });
  const refreshButton = () => {
    const changed = people.some((p) => p.pin === "changed");
    let reason = null;
    if (offline()) reason = t("vault.offline_reason");
    else if (!people.length) reason = t("vault.share.pick_someone");
    else if (!choice) reason = t("vault.share.pick_vault");
    else if (changed && !ack.checked) reason = t("vault.share.ack_required");
    setDisabled(shareBtn, !!reason, reason || undefined);
  };
  ack.addEventListener("change", refreshButton);

  function paintChosen() {
    chosenBox.replaceChildren(...(people.length ? [h("span", { class: "u-muted" }, t("vault.share.added"))] : []),
      ...people.map((p) => h("span", { class: "c-chips__entry" }, avatar({ name: p.name || p.email }), h("span", {}, p.name || p.email),
        iconButton({ icon: "close", label: t("vault.share.remove_person", { name: p.name || p.email }), onClick: () => removePerson(p.id) }))));
  }

  function paintWarnings() {
    const changed = people.filter((p) => p.pin === "changed");
    warnBox.replaceChildren(...(changed.length ? [h("div", { class: "c-alert", "data-tone": "danger", role: "alert" }, icon("warn"),
      h("div", { class: "l-stack", "data-gap": "2" },
        h("p", {}, plural("vault.share.key_changed", changed.length, { names: changed.map((p) => p.name || p.email).join(", ") })),
        h("label", { class: "l-cluster" }, ack, t("vault.share.key_changed_ack"))))] : []));
  }

  async function paintWhere() {
    const my = ++seq;
    choice = null;
    options = null;
    errorBox.replaceChildren();
    if (!people.length) {
      whereBox.replaceChildren();
      refreshButton();
      return;
    }
    whereBox.replaceChildren(h("p", { class: "u-muted" }, t("common.state.loading")));
    refreshButton();
    let found;
    try {
      found = await destinations(item, people);
    } catch (e) {
      if (my === seq) whereBox.replaceChildren(h("p", { class: "c-field__error" }, errorText(e)));
      return;
    }
    if (my !== seq) return;
    options = found;
    const cards = found.existing.map((c) => ({
      value: c.id, label: collectionLabel(c),
      description: t("vault.share.same_people", { names: people.map((p) => p.name || p.email).join(", ") }),
      icon: "folder",
    }));
    const nameInput = textInput({ name: "nom_coffre", value: found.suggestedName, maxlength: 80, autocomplete: "off" });
    const nameField = field({ label: t("vault.share.new_name"), input: nameInput });
    if (found.canCreate) cards.push({ value: "nouveau", label: t("vault.share.new_vault"), description: t("vault.share.new_vault_help"), icon: "plus" });
    choice = cards[0]?.value ?? null;
    nameField.hidden = choice !== "nouveau";
    options.nameInput = nameInput;
    const managed = !found.canCreate && !found.existing.length
      ? [...V.state.collections.values()].filter((c) => !c.personal && c.role === "manager" && c.id !== item.collection_id) : [];
    if (!found.canCreate && managed.length) {
      for (const c of managed) cards.push({ value: c.id, label: collectionLabel(c), description: plural("vault.collection.members", c.member_count || 0), icon: "folder" });
      choice = cards[0]?.value ?? null;
    }
    // clear() ignore les null (replaceChildren les écrirait en texte).
    clear(whereBox,
      cards.length
        ? radioCards({
          legend: t("vault.share.where"), name: "destination", value: choice, options: cards,
          onChange: (v) => { choice = v; nameField.hidden = v !== "nouveau"; refreshButton(); },
        })
        : null,
      nameField,
      !found.canCreate ? h("p", { class: "c-policy-hint" }, icon("lock", { size: "sm" }), t("vault.share.creation_admins")) : null,
      !cards.length ? h("p", {}, t("vault.share.no_destination")) : null);
    refreshButton();
  }

  function addPerson(u) {
    if (people.some((p) => p.id === u.id)) return;
    people = [...people, { ...u, pin: keyPinStatus(u.id, u.public_key) }];
    announce(t("vault.share.person_added", { name: u.name || u.email }));
    searchInput.value = "";
    results.replaceChildren();
    paintChosen();
    paintWarnings();
    paintWhere();
    searchInput.focus();
  }

  function removePerson(id) {
    const gone = people.find((p) => p.id === id);
    people = people.filter((p) => p.id !== id);
    if (gone) announce(t("vault.share.person_removed", { name: gone.name || gone.email }));
    paintChosen();
    paintWarnings();
    paintWhere();
    searchInput.focus();
  }

  async function search() {
    const q = normalize(searchInput.value).trim();
    if (!q) {
      results.replaceChildren();
      return;
    }
    if (!all) {
      try {
        all = await directory();
      } catch (e) {
        results.replaceChildren(h("li", { class: "c-field__error" }, errorText(e)));
        return;
      }
    }
    const found = all.filter((u) => !people.some((p) => p.id === u.id) && normalize(`${u.name} ${u.email}`).includes(q)).slice(0, MAX_RESULTS);
    results.replaceChildren(...(found.length ? found.map((u) => h("li", { class: "l-cluster", "data-justify": "between" },
      h("span", { class: "l-cluster" }, avatar({ name: u.name || u.email }), h("span", {}, u.name), h("span", { class: "u-muted" }, u.email)),
      button({ label: t("vault.share.add_person", { name: u.name || u.email }), icon: "plus", onClick: () => addPerson(u) })))
      : [h("li", { class: "u-muted" }, t("vault.share.nobody", { q: searchInput.value.trim() }))]));
  }
  searchInput.addEventListener("input", search);
  searchInput.addEventListener("keydown", (e) => {
    // Entrée : ajoute la première personne trouvée (et n'envoie pas le formulaire).
    if (e.key !== "Enter") return;
    e.preventDefault();
    results.querySelector("button")?.click();
  });

  async function run() {
    errorBox.replaceChildren();
    const target = choice === "nouveau" ? null : choice;
    const newName = choice === "nouveau" ? options?.nameInput?.value.trim() : "";
    if (choice === "nouveau" && !newName) {
      errorBox.replaceChildren(h("p", { class: "c-field__error", role: "alert" }, t("vault.share.name_required")));
      return;
    }
    let res;
    try {
      res = await shareWithPeople({ item, people, role, collectionId: target, newName });
    } catch (e) {
      const text = t(e.rolledBack === false ? "vault.share.failed_partial" : "vault.share.failed", { reason: errorText(e) });
      errorBox.replaceChildren(h("div", { class: "c-alert", "data-tone": "danger", role: "alert" }, icon("error"), h("p", {}, text)));
      await env.reload();
      return;
    }
    people = [];
    await env.reload();
    const vault = collectionLabel(collectionOf(res.collectionId)) || newName;
    notify({ text: t("vault.share.done", { name, vault }), tone: "ok" });
    getDialog()?.close("ok");
    env.navigate(`/element/${encodeURIComponent(item.id)}`, { replace: true });
  }

  panel.replaceChildren(h("div", { class: "l-stack", "data-gap": "3" },
    searchField, results, chosenBox, rights, whereBox, warnBox, leaving, attachments, errorBox,
    h("div", { class: "l-cluster", "data-justify": "end" }, shareBtn)));
  refreshButton();
  return {
    isDirty: () => people.length > 0,
    focus: () => searchInput.focus(),
  };
}
