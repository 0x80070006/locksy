// Assistant « Départ de l'entreprise » (cahier §3.4.5, parcours A3 en
// 6 gestes au plus quel que soit le nombre de coffres, contrat C1.1) :
//   1. Accès : désactiver le compte et fermer ses sessions (cochés) ;
//   2. Coffres dont la personne est le seul gestionnaire : un membre existant
//      est proposé comme repreneur (promotion de rôle, aucune clé transmise) ;
//      coffre sans autre membre : illisible après le départ, supprimé avec le
//      compte (aucune récupération possible) ;
//   3. Mots de passe connus : « rotation conseillée » sur les coffres partagés ;
//   4. Rapport : simulation (dry_run, aucune écriture) affichée avant de
//      confirmer, suppression programmée (directory.delete_after_days) ou
//      immédiate ; confirmation par mot de passe maître (jeton
//      « admin.offboard », ou « admin.delete_user » pour une suppression
//      immédiate) ; rapport CSV téléchargeable.
// Repli R11 : serveur sans offboard-plan -> désactivation et fermeture des
// sessions par les routes historiques.

import {
  t, plural, h, clear, button, wizard, checkboxGroup, field, selectInput, radioCards, alertCard, skeleton, errorState,
  notify, errorText, fmtDate, fmtNumber, badge,
} from "../../ui/index.js";
import { api, download as downloadFile } from "../../api.js";
import { go, personName, reauthThen, roleLabel, routeMissing } from "./shell.js";

/**
 * Délai de suppression proposé quand l'organisation a choisi la suppression
 * immédiate (directory.delete_after_days = 0) : défaut du registre. Le serveur
 * n'a pas de « jamais » : un départ désactive puis supprime toujours.
 */
const FALLBACK_DELETE_DAYS = 30;

export async function renderPage(ctx, container, route) {
  const id = route.id;
  const head = h("div", { class: "l-stack", "data-gap": "2" }, h("h1", { tabindex: "-1" }, t("admin.offboard.title")));
  const body = h("div", { class: "l-stack", "data-gap": "4" }, skeleton({ lines: 6 }));
  clear(container, head, body);

  let plan;
  let legacy = false;
  try {
    plan = await api("GET", `/admin/users/${encodeURIComponent(id)}/offboard-plan`);
  } catch (e) {
    if (!routeMissing(e)) {
      clear(body, errorState({ error: e, onRetry: () => renderPage(ctx, container, route) }));
      return { dispose() {}, isDirty: () => false };
    }
    legacy = true;
    plan = await legacyPlan(id).catch(() => null);
    if (!plan) {
      clear(body, errorState({ error: e }));
      return { dispose() {}, isDirty: () => false };
    }
  }

  const user = plan.user;
  clear(head,
    h("h1", { tabindex: "-1" }, t("admin.offboard.title_named", { name: personName(user) })),
    h("p", { class: "u-muted" }, t("admin.offboard.intro", { email: user.email, role: roleLabel(user.role) })));

  const state = {
    disable: true,
    revoke_sessions: true,
    suggest_rotation: true,
    transfers: new Map(),
    deleteMode: "scheduled",
    started: false,
    done: false,
  };
  const sole = (plan.collections || []).filter((c) => c.sole_manager && !c.personal);
  const transferable = sole.filter((c) => (c.members || []).length > 0);
  const orphans = (plan.collections || []).filter((c) => !(c.members || []).length);
  const shared = (plan.collections || []).filter((c) => c.shared && !c.personal);
  for (const c of transferable) state.transfers.set(c.id, defaultHeir(c.members).user_id);
  const days = Number(plan.delete_after_days) > 0 ? Number(plan.delete_after_days) : FALLBACK_DELETE_DAYS;
  /** Suppression immédiate demandée (elle n'a lieu que si le compte est désactivé). */
  const immediate = () => !legacy && state.disable && state.deleteMode === "now";

  const request = () => ({
    disable: state.disable,
    revoke_sessions: state.revoke_sessions,
    transfers: [...state.transfers].filter(([, uid]) => uid).map(([collection_id, new_manager_id]) => ({ collection_id, new_manager_id })),
    suggest_rotation: state.suggest_rotation,
    delete_after_days: state.deleteMode === "now" ? 0 : days,
  });

  const preview = h("div", { class: "l-stack", "data-gap": "3" });

  const steps = [
    {
      id: "acces", title: t("admin.offboard.step.access"),
      render: (el) => clear(el,
        checkboxGroup({
          legend: t("admin.offboard.access.legend"),
          options: [
            { value: "disable", label: t("admin.offboard.access.disable"), description: t("admin.offboard.access.disable_help") },
            { value: "revoke_sessions", label: t("admin.offboard.access.revoke"), description: plural("admin.offboard.access.revoke_help", Number(plan.sessions) || 0) },
          ],
          values: ["disable", "revoke_sessions"].filter((k) => state[k]),
          onChange: (values) => {
            state.disable = values.includes("disable");
            state.revoke_sessions = values.includes("revoke_sessions");
          },
        })),
    },
    {
      id: "coffres", title: t("admin.offboard.step.vaults"),
      render: (el) => clear(el, legacy ? alertCard({ tone: "info", text: t("admin.offboard.legacy_vaults") }) : vaultsStep()),
    },
    {
      id: "mots-de-passe", title: t("admin.offboard.step.passwords"),
      render: (el) => clear(el,
        h("p", {}, shared.length ? plural("admin.offboard.passwords.intro", shared.length) : t("admin.offboard.passwords.none")),
        shared.length ? checkboxGroup({
          legend: t("admin.offboard.passwords.legend"),
          options: [{ value: "rotation", label: t("admin.offboard.passwords.suggest"), description: t("admin.offboard.passwords.suggest_help", { name: personName(user) }) }],
          values: state.suggest_rotation ? ["rotation"] : [],
          onChange: (values) => { state.suggest_rotation = values.includes("rotation"); },
        }) : null),
    },
    {
      id: "rapport", title: t("admin.offboard.step.report"),
      render: (el) => {
        // Serveur plus ancien : le départ ne supprime pas le compte.
        clear(el, legacy ? null : deleteChoice(), preview);
        simulate();
      },
    },
  ];

  function vaultsStep() {
    if (!sole.length && !orphans.length) return h("p", {}, t("admin.offboard.vaults.none"));
    return h("div", { class: "l-stack", "data-gap": "3" },
      sole.length ? h("p", {}, plural("admin.offboard.vaults.intro", sole.length)) : null,
      transferable.map((c, i) => {
        const select = selectInput({
          options: c.members.map((m) => ({ value: m.user_id, label: t("admin.offboard.vaults.member", { name: personName(m), role: t(`admin.person.vault_role.${["manager", "editor", "reader"].includes(m.role) ? m.role : "reader"}`) }) })),
          value: state.transfers.get(c.id),
        });
        select.addEventListener("change", () => state.transfers.set(c.id, select.value));
        return h("div", { class: "c-card l-stack", "data-gap": "2" },
          h("strong", {}, t("admin.offboard.vaults.vault", { n: i + 1, items: plural("admin.person.vault_items", Number(c.items_count) || 0) })),
          field({ label: t("admin.offboard.vaults.heir"), help: t("admin.offboard.vaults.heir_help"), input: select }));
      }),
      orphans.length ? alertCard({ tone: "warn", text: plural("admin.offboard.vaults.orphans", orphans.length, { items: fmtNumber(orphans.reduce((n, c) => n + (Number(c.items_count) || 0), 0)) }) }) : null);
  }

  function deleteChoice() {
    return radioCards({
      legend: t("admin.offboard.delete.legend"),
      options: [
        { value: "scheduled", label: plural("admin.offboard.delete.scheduled", days), description: t("admin.offboard.delete.scheduled_help") },
        { value: "now", label: t("admin.offboard.delete.now"), description: t("admin.offboard.delete.now_help") },
      ],
      value: state.deleteMode,
      onChange: (v) => {
        state.deleteMode = v;
        simulate();
      },
    });
  }

  /** Simulation (aucune écriture) : ce qui va se passer, avant de confirmer. */
  async function simulate() {
    clear(preview, skeleton({ lines: 3 }));
    if (legacy) {
      clear(preview, summary({
        disabled: state.disable, sessions_closed: state.revoke_sessions ? Number(plan.sessions) || 0 : 0,
        transferred: 0, orphaned: [], rotation_suggested: 0, shares_revoked: 0, deprovision_at: null,
      }, true));
      return;
    }
    try {
      const res = await api("POST", `/admin/users/${encodeURIComponent(id)}/offboard?dry_run=true`, request());
      clear(preview, summary(res.report || {}, true));
    } catch (e) {
      clear(preview, alertCard({ tone: "danger", text: errorText(e), action: { label: t("common.action.retry"), onClick: simulate } }));
    }
  }

  /** Récapitulatif d'une simulation ou du départ effectué. */
  function summary(r, simulation) {
    const lines = [
      r.disabled ? t("admin.offboard.report.disabled") : t("admin.offboard.report.not_disabled"),
      plural("admin.offboard.report.sessions", Number(r.sessions_closed) || 0),
      plural("admin.offboard.report.transferred", Number(r.transferred) || 0),
      plural("admin.offboard.report.rotation", Number(r.rotation_suggested) || 0),
      plural("admin.offboard.report.shares", Number(r.shares_revoked) || 0),
      (r.orphaned || []).length ? plural("admin.offboard.report.orphaned", r.orphaned.length) : null,
      r.deprovision_at
        ? (immediate() ? t("admin.offboard.report.deleted_now") : t("admin.offboard.report.deprovision", { date: fmtDate(r.deprovision_at, "date") }))
        : t("admin.offboard.report.no_deletion"),
    ].filter(Boolean);
    return h("section", { class: "c-card l-stack", "data-gap": "2", "aria-label": simulation ? t("admin.offboard.report.simulation") : t("admin.offboard.report.done_title") },
      h("p", { class: "l-cluster" },
        badge({ tone: simulation ? "info" : "ok", label: simulation ? t("admin.offboard.report.simulation") : t("admin.offboard.report.done_badge") }),
        simulation ? h("span", { class: "u-muted" }, t("admin.offboard.report.simulation_help")) : null),
      h("ul", { class: "l-stack", "data-gap": "1" }, lines.map((l) => h("li", {}, l))));
  }

  async function finish() {
    const req = request();
    const now = immediate();
    const action = now ? "admin.delete_user" : "admin.offboard";
    try {
      const res = await reauthThen(action, (opts) => (legacy ? legacyOffboard(id, req) : api("POST",
        `/admin/users/${encodeURIComponent(id)}/offboard?dry_run=false`, req, { ...opts, retry: false })), {
        title: t("admin.offboard.confirm_title", { name: personName(user) }),
        message: now ? t("admin.offboard.confirm_now") : t("admin.offboard.confirm_text"),
        confirmLabel: t("admin.offboard.confirm"),
        danger: now,
      });
      if (res === undefined) return;
      state.done = true;
      notify({ text: t("admin.offboard.done", { name: personName(user) }), tone: "ok" });
      clear(body,
        summary(res.report || {}, false),
        h("div", { class: "l-cluster" },
          res.report_csv ? button({
            label: t("admin.offboard.download"), icon: "download", variant: "primary",
            onClick: async () => {
              try {
                await downloadFile(String(res.report_csv).replace(/^\/api/, ""), `locksy-depart-${new Date().toISOString().slice(0, 10)}.csv`);
              } catch (e) {
                notify({ text: errorText(e), tone: "danger" });
              }
            },
          }) : null,
          button({ label: t("admin.offboard.back"), onClick: () => go(ctx, "/admin/personnes") })));
    } catch (e) {
      notify({ text: errorText(e), tone: "danger" });
    }
  }

  const wiz = wizard({
    label: t("admin.offboard.steps_label"),
    steps,
    finishLabel: t("admin.offboard.finish"),
    onStep: () => { state.started = true; },
    onFinish: finish,
  });
  clear(body, wiz.el);
  return {
    dispose() {},
    isDirty: () => state.started && !state.done,
  };
}

/** Repreneur proposé : un gestionnaire, sinon un éditeur, sinon le premier membre. */
function defaultHeir(members) {
  return members.find((m) => m.role === "manager") || members.find((m) => m.role === "editor") || members[0];
}

/** Plan réduit depuis les routes historiques (aucun détail des coffres). */
async function legacyPlan(id) {
  const users = await api("GET", "/admin/users");
  const u = (Array.isArray(users) ? users : []).find((x) => x.id === id);
  if (!u) return null;
  return {
    user: { id: u.id, name: u.name, email: u.email, role: u.role, status: u.disabled ? "disabled" : "active" },
    sessions: 0, collections: [], delete_after_days: 0,
  };
}

/** Départ sur un serveur plus ancien : désactivation et fermeture des sessions. */
async function legacyOffboard(id, req) {
  if (req.revoke_sessions) await api("POST", `/admin/users/${encodeURIComponent(id)}/revoke-sessions`);
  if (req.disable) await api("PUT", `/admin/users/${encodeURIComponent(id)}`, { disabled: true });
  return {
    report: { disabled: req.disable, sessions_closed: 0, transferred: 0, orphaned: [], rotation_suggested: 0, shares_revoked: 0, deprovision_at: null },
    report_csv: null,
  };
}
