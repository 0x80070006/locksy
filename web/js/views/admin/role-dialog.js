// Fenêtre « Changer le rôle » (cahier §3.4.4, correctif P0 de l'audit 02) :
// jamais déclenchée par le changement d'une liste ; trois cartes de choix avec
// ce que chaque rôle permet ; rétrogradation = confirmation simple (niveau 1),
// élévation vers Administrateur ou Propriétaire = mot de passe maître exigé
// dans la même fenêtre (niveau 3, jeton « admin.role »). Rien n'est envoyé
// tant que la fenêtre n'est pas confirmée.
//
// openRoleDialog(ctx, people, { onDone }) -> Promise<résultat | undefined>
//   people : une ou plusieurs lignes { id, name, email, role } ;
//   une personne : PUT /admin/users/:id { role } ;
//   plusieurs : POST /admin/users/bulk { action: "set_role", role }, avec
//   repli personne par personne sur un serveur plus ancien.

import {
  t, plural, h, dialog, radioCards, alertCard, passwordField, fieldInput, fieldError, errorText, notify, clear,
} from "../../ui/index.js";
import { api } from "../../api.js";
import { isOwner, personName, roleRank, routeMissing, stepUpToken } from "./shell.js";

const ROLES = Object.freeze(["user", "admin", "owner"]);

/** Le rôle choisi élève-t-il au moins une des personnes ? */
const elevates = (people, role) => people.some((p) => roleRank(role) > roleRank(p.role));

export function openRoleDialog(ctx, people, { onDone } = {}) {
  const list = (people || []).filter(Boolean);
  if (!list.length) return Promise.resolve(undefined);
  const single = list.length === 1;
  const current = single ? list[0].role : null;
  const owner = isOwner(ctx);
  let choice = current || "user";

  return new Promise((resolve) => {
    let outcome;
    const pw = passwordField({ label: t("common.glossary.master_password"), autocomplete: "current-password" });
    const pwBlock = h("div", { class: "l-stack", "data-gap": "2" },
      h("p", {}, t("admin.role.password_intro")), pw);
    const problem = h("div");
    const cards = radioCards({
      legend: t("admin.role.legend"),
      options: ROLES.map((r) => ({
        value: r,
        label: t(`ui.role.${r}`),
        description: t(`admin.role.describe.${r}`),
        disabled: r === "owner" && !owner,
      })),
      value: choice,
      onChange: (v) => {
        choice = v;
        sync();
      },
    });
    const sync = () => {
      pwBlock.hidden = !elevates(list, choice);
      clear(problem);
    };
    sync();

    const title = single
      ? t("admin.role.title", { name: personName(list[0]) })
      : plural("admin.role.title_many", list.length);
    dialog({
      title,
      body: h("div", { class: "l-stack", "data-gap": "3" },
        cards,
        alertCard({ tone: "info", text: t("admin.role.no_vault_access") }),
        owner ? null : h("p", { class: "u-muted" }, t("admin.role.owner_reserved")),
        pwBlock,
        problem),
      actions: [
        { label: t("common.action.cancel"), value: "cancel" },
        {
          label: t("admin.role.confirm"), variant: "primary", busyLabel: t("common.state.saving"),
          onClick: async () => {
            if (single && choice === current) {
              clear(problem, alertCard({ tone: "info", text: t("admin.role.unchanged") }));
              return false;
            }
            let reauth;
            if (elevates(list, choice)) {
              const password = fieldInput(pw).value;
              if (!password) {
                fieldError(pw, t("ui.confirm.password_required"));
                return false;
              }
              try {
                reauth = await stepUpToken("admin.role", password);
              } catch (e) {
                fieldError(pw, errorText(e));
                return false;
              }
            }
            try {
              outcome = single ? await setOne(list[0], choice, reauth) : await setMany(list, choice, reauth);
            } catch (e) {
              clear(problem, alertCard({ tone: "danger", text: errorText(e) }));
              return false;
            }
            return true;
          },
        },
      ],
      onClose: async () => {
        if (outcome) {
          if (single) notify({ text: t("admin.role.done", { name: personName(list[0]), role: t(`ui.role.${choice}`) }), tone: "ok" });
          await onDone?.(outcome);
        }
        resolve(outcome);
      },
    });
  });
}

async function setOne(person, role, reauth) {
  await api("PUT", `/admin/users/${encodeURIComponent(person.id)}`, { role }, { reauth, retry: false });
  return { done: [person.id], skipped: [] };
}

/** Changement de rôle en masse ; repli personne par personne (serveur plus ancien). */
async function setMany(people, role, reauth) {
  const ids = people.map((p) => p.id);
  try {
    return await api("POST", "/admin/users/bulk", { ids, action: "set_role", role }, { reauth, retry: false });
  } catch (e) {
    if (!routeMissing(e)) throw e;
  }
  const out = { done: [], skipped: [] };
  for (const p of people) {
    if (p.role === role) {
      out.skipped.push({ id: p.id, reason: "unchanged" });
      continue;
    }
    try {
      await setOne(p, role, reauth);
      out.done.push(p.id);
    } catch (err) {
      out.skipped.push({ id: p.id, reason: skipReason(err) });
    }
  }
  return out;
}

/** Raison d'une ligne ignorée à partir d'une erreur (repli personne par personne). */
export function skipReason(err) {
  const map = { self_action: "self", last_owner: "last_owner", owner_only: "owner_only", forbidden: "owner_only", not_found: "not_found" };
  return map[err?.code] || "error";
}
