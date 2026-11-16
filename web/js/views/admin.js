// Administration : vue d'ensemble, comptes, invitations, journal, réglages.

import { h, clear, icon, toast, modal, confirmDialog, fmtDate, relTime } from "../dom.js";
import { api, download } from "../api.js";
import * as V from "../vault.js";
import { ui } from "../app.js";
import { sso, scim } from "./admin-sso.js";
import { ad } from "./admin-ad.js";

const ROLE = { owner: "Propriétaire", admin: "Administrateur", user: "Utilisateur" };

export function renderAdmin(container) {
  const tabs = [["overview", "Vue d'ensemble"], ["users", "Utilisateurs"], ["invites", "Invitations"], ["audit", "Journal d'audit"], ["settings", "Règles de sécurité"], ["ad", "Active Directory"], ["sso", "Authentification unique"], ["scim", "Annuaire (SCIM)"]];
  const tab = ui.adminTab || "overview";
  const body = h("div", { style: "display:grid;gap:16px" });
  container.append(h("div", { class: "page" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Administration"),
      h("p", { class: "muted" }, "Vous gérez les accès, pas les secrets : aucun administrateur ne peut lire le contenu des coffres."))),
    h("div", { class: "tabs" }, tabs.map(([k, l]) => h("button", { class: `tab ${tab === k ? "on" : ""}`, onclick: () => { ui.adminTab = k; renderAdmin(clear(container)); } }, l))),
    body));
  const rerender = () => renderAdmin(clear(container));
  body.append(h("div", { class: "busy" }, h("span", { class: "spinner" })));
  ({ overview, users, invites, audit, settings, ad, sso, scim })[tab](body, rerender).catch((e) => clear(body, h("div", { class: "notice bad" }, e.message)));
}

async function overview(body) {
  const [s, events] = await Promise.all([api("GET", "/admin/stats"), api("GET", "/admin/audit?limit=8")]);
  const pct = s.active_users ? Math.round((100 * s.users_with_2fa) / s.active_users) : 0;
  const stat = (n, l, tone) => h("div", { class: "stat" }, h("div", { class: "n", style: tone ? `color:var(--${tone})` : "" }, n), h("div", { class: "l" }, l));
  clear(body,
    h("div", { class: "stats" },
      stat(s.active_users, `utilisateurs actifs (${s.users} au total)`),
      stat(`${pct} %`, "ont activé la double authentification", pct >= 90 ? "ok" : pct >= 50 ? "warn" : "bad"),
      stat(s.items, "éléments stockés"),
      stat(s.shared_collections, `coffres partagés (${s.collections} au total)`),
      stat(s.active_shares, "liens de partage actifs"),
      stat(s.failed_logins_24h, "échecs de connexion sur 24 h", s.failed_logins_24h > 20 ? "bad" : s.failed_logins_24h > 5 ? "warn" : null)),
    h("div", { class: "card" }, h("div", { class: "section" }, h("h3", {}, "Derniers événements"), auditTable(events.entries))));
}

function auditTable(entries) {
  if (!entries.length) return h("p", { class: "muted" }, "Aucun événement.");
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Date"), h("th", {}, "Utilisateur"), h("th", {}, "Action"), h("th", {}, "Cible"), h("th", {}, "Détails"), h("th", {}, "IP"))),
    h("tbody", {}, entries.map((e) => h("tr", {},
      h("td", { class: "small", style: "white-space:nowrap" }, fmtDate(e.at)),
      h("td", { class: "small" }, e.email || "—"),
      h("td", {}, h("span", { class: `chip ${/failed|refused/.test(e.action) ? "bad" : /deleted|disabled|revoked|reset/.test(e.action) ? "warn" : ""}` }, e.action)),
      h("td", { class: "small mono" }, e.target),
      h("td", { class: "small" }, e.details),
      h("td", { class: "small mono" }, e.ip))))));
}

async function users(body, rerender) {
  const list = await api("GET", "/admin/users");
  const me = V.state.profile;
  const canManage = (u) => u.id !== me.id && (me.role === "owner" || u.role === "user");
  const act = async (fn, ok) => { try { await fn(); toast(ok); rerender(); } catch (e) { toast(e.message, "bad"); } };
  clear(body, h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Personne"), h("th", {}, "Rôle"), h("th", {}, "2FA"), h("th", {}, "Coffres"), h("th", {}, "Dernière connexion"), h("th", {}, "Actions"))),
    h("tbody", {}, list.map((u) => {
      const role = h("select", { class: "input", disabled: !canManage(u) || me.role !== "owner", "aria-label": `Rôle de ${u.name}` },
        Object.entries(ROLE).map(([k, l]) => h("option", { value: k, selected: u.role === k }, l)));
      role.addEventListener("change", () => act(() => api("PUT", `/admin/users/${u.id}`, { role: role.value }), "Rôle modifié."));
      return h("tr", { style: u.disabled ? "opacity:.6" : "" },
        h("td", {}, h("strong", {}, u.name, u.id === me.id ? " (vous)" : ""), h("div", { class: "small muted" }, u.email), u.disabled ? h("span", { class: "chip bad" }, "Désactivé") : null),
        h("td", {}, role),
        h("td", {}, h("span", { class: `chip ${u.totp_enabled ? "ok" : "warn"}` }, u.totp_enabled ? "Activée" : "Non")),
        h("td", { class: "num" }, u.collections),
        h("td", { class: "small" }, u.last_login_at ? relTime(u.last_login_at) : "Jamais"),
        h("td", {}, canManage(u) ? h("div", { class: "row" },
          h("button", { class: "btn small", onclick: () => act(() => api("PUT", `/admin/users/${u.id}`, { disabled: !u.disabled }), u.disabled ? "Compte réactivé." : "Compte désactivé et déconnecté de tous ses appareils.") }, u.disabled ? "Réactiver" : "Désactiver"),
          h("button", { class: "btn small", onclick: () => act(() => api("POST", `/admin/users/${u.id}/revoke-sessions`), "Toutes ses sessions ont été fermées.") }, "Déconnecter"),
          u.totp_enabled ? h("button", { class: "btn small", onclick: async () => {
            if (await confirmDialog({ title: "Réinitialiser la 2FA ?", message: `${u.name} pourra se reconnecter avec son seul mot de passe maître puis réactiver la double authentification. À utiliser en cas de téléphone perdu, après avoir vérifié son identité.`, confirmLabel: "Réinitialiser" }))
              act(() => api("POST", `/admin/users/${u.id}/reset-2fa`), "Double authentification réinitialisée.");
          } }, "Réinit. 2FA") : null,
          h("button", { class: "btn small danger", onclick: async () => {
            if (await confirmDialog({ title: `Supprimer ${u.name} ?`, message: "Son coffre personnel sera détruit (personne ne peut le déchiffrer). Les coffres partagés restent accessibles à leurs autres membres ; s'il en était le seul gestionnaire, le membre le plus ancien le devient.", confirmLabel: "Supprimer le compte", danger: true }))
              act(() => api("DELETE", `/admin/users/${u.id}`), "Compte supprimé.");
          } }, "Supprimer")) : null));
    })))),
    h("p", { class: "small muted" }, "Désactiver un compte coupe immédiatement l'accès sur tous ses appareils."));
}

async function invites(body, rerender) {
  const list = await api("GET", "/admin/invites");
  const me = V.state.profile;
  const email = h("input", { class: "input", id: "inv-email", type: "email", placeholder: "prenom.nom@entreprise.fr" });
  const role = h("select", { class: "input", id: "inv-role" }, h("option", { value: "user" }, "Utilisateur"), me.role === "owner" ? h("option", { value: "admin" }, "Administrateur") : null);
  const status = (i) => i.used_at ? h("span", { class: "chip ok" }, "Utilisée") : i.expires_at < V.now() ? h("span", { class: "chip" }, "Expirée") : h("span", { class: "chip accent" }, "En attente");
  clear(body,
    h("div", { class: "card section" }, h("h3", {}, "Inviter une personne"),
      h("div", { class: "grid2" }, h("div", { class: "field" }, h("label", { for: "inv-email" }, "Adresse e-mail"), email), h("div", { class: "field" }, h("label", { for: "inv-role" }, "Rôle"), role)),
      h("div", {}, h("button", { class: "btn primary", onclick: async () => {
        try {
          const r = await api("POST", "/admin/invites", { email: email.value.trim(), role: role.value });
          const link = `${location.origin}/#/register?token=${encodeURIComponent(r.token)}`;
          const box = h("input", { class: "input mono", readonly: true, value: link });
          modal({ title: "Invitation créée", body: h("div", { class: "form" },
            h("p", {}, `Envoyez ce lien à ${email.value.trim()}. Il est valable 7 jours, pour cette adresse uniquement, et ne sera plus affiché.`),
            h("div", { class: "input-row" }, box, h("button", { class: "btn", onclick: async () => { try { await navigator.clipboard.writeText(link); toast("Lien copié."); } catch { box.select(); } } }, icon("copy"), "Copier"))),
            actions: [{ label: "Terminé", kind: "primary" }], onClose: rerender });
        } catch (e) { toast(e.message, "bad"); }
      } }, icon("plus"), "Créer le lien d'invitation"))),
    list.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Adresse"), h("th", {}, "Rôle"), h("th", {}, "État"), h("th", {}, "Expire"), h("th", {}, ""))),
      h("tbody", {}, list.map((i) => h("tr", {}, h("td", {}, i.email), h("td", {}, ROLE[i.role]), h("td", {}, status(i)), h("td", { class: "small" }, fmtDate(i.expires_at)),
        h("td", {}, !i.used_at ? h("button", { class: "btn small danger", onclick: async () => {
          try { await api("DELETE", `/admin/invites/${i.id}`); toast("Invitation révoquée."); rerender(); } catch (e) { toast(e.message, "bad"); }
        } }, "Révoquer") : null)))))) : null);
}

async function audit(body) {
  const q = h("input", { class: "input", id: "a-q", type: "search", placeholder: "Utilisateur, cible, IP…", value: ui.auditQ || "" });
  const action = h("select", { class: "input", id: "a-action" },
    [["", "Toutes les actions"], ["login", "Connexions"], ["login.failed", "Échecs de connexion"], ["item", "Éléments"], ["collection", "Coffres et partages"], ["share", "Liens de partage"], ["admin", "Administration"], ["2fa", "Double authentification"], ["recovery", "Récupérations"]]
      .map(([v, l]) => h("option", { value: v, selected: (ui.auditAction || "") === v }, l)));
  const from = h("input", { class: "input", id: "a-from", type: "date" });
  const to = h("input", { class: "input", id: "a-to", type: "date" });
  const result = h("div");
  let offset = 0;
  const params = () => {
    const p = new URLSearchParams({ q: q.value, action: action.value, limit: "100", offset: String(offset) });
    if (from.value) p.set("from", String(Math.floor(new Date(from.value + "T00:00:00").getTime() / 1000)));
    if (to.value) p.set("to", String(Math.floor(new Date(to.value + "T23:59:59").getTime() / 1000)));
    return p;
  };
  const load = async () => {
    ui.auditQ = q.value; ui.auditAction = action.value;
    try {
      const page = await api("GET", `/admin/audit?${params()}`);
      clear(result, auditTable(page.entries),
        h("div", { class: "row between", style: "margin-top:10px" }, h("span", { class: "small muted" }, `${page.total} événement(s)`),
          h("div", { class: "row" },
            h("button", { class: "btn small", disabled: offset === 0, onclick: () => { offset = Math.max(0, offset - 100); load(); } }, "Précédents"),
            h("button", { class: "btn small", disabled: offset + 100 >= page.total, onclick: () => { offset += 100; load(); } }, "Suivants"))));
    } catch (e) { clear(result, h("div", { class: "notice bad" }, e.message)); }
  };
  [q, action, from, to].forEach((el) => el.addEventListener("change", () => { offset = 0; load(); }));
  clear(body,
    h("div", { class: "card section" },
      h("div", { class: "grid2" }, h("div", { class: "field" }, h("label", { for: "a-q" }, "Recherche"), q), h("div", { class: "field" }, h("label", { for: "a-action" }, "Type"), action),
        h("div", { class: "field" }, h("label", { for: "a-from" }, "Du"), from), h("div", { class: "field" }, h("label", { for: "a-to" }, "Au"), to)),
      h("div", { class: "row" }, h("button", { class: "btn", onclick: async () => {
        const p = params(); p.delete("limit"); p.delete("offset");
        try { await download(`/admin/audit.csv?${p}`, "locksy-journal.csv"); } catch (e) { toast(e.message, "bad"); }
      } }, "Exporter en CSV"), h("span", { class: "small muted" }, "Pour vos audits NIS2, ISO 27001 ou DORA. Les exports sont eux-mêmes journalisés."))),
    result);
  load();
}

async function settings(body) {
  const s = await api("GET", "/admin/settings");
  const req = h("input", { type: "checkbox", checked: s.require_2fa });
  const num = (id, v, min, max) => h("input", { class: "input", id, type: "number", min, max, value: v });
  const idle = num("s-idle", s.session_idle_minutes, 5, 1440);
  const maxh = num("s-max", s.session_max_hours, 1, 720);
  const audit = num("s-audit", s.audit_retention_days, 30, 3650);
  const trash = num("s-trash", s.trash_retention_days, 1, 365);
  clear(body, h("div", { class: "card section" },
    h("label", { class: "check" }, req, h("span", {}, h("strong", {}, "Imposer la double authentification à tous"), h("div", { class: "small muted" }, "Les personnes sans 2FA devront l'activer avant d'accéder à leur coffre."))),
    h("div", { class: "grid2" },
      h("div", { class: "field" }, h("label", { for: "s-idle" }, "Déconnexion après inactivité (minutes)"), idle),
      h("div", { class: "field" }, h("label", { for: "s-max" }, "Durée maximale d'une session (heures)"), maxh),
      h("div", { class: "field" }, h("label", { for: "s-audit" }, "Conservation du journal d'audit (jours)"), audit),
      h("div", { class: "field" }, h("label", { for: "s-trash" }, "Conservation de la corbeille (jours)"), trash)),
    h("div", {}, h("button", { class: "btn primary", onclick: async () => {
      try {
        await api("PUT", "/admin/settings", { require_2fa: req.checked, session_idle_minutes: Number(idle.value), session_max_hours: Number(maxh.value), audit_retention_days: Number(audit.value), trash_retention_days: Number(trash.value) });
        toast("Règles enregistrées.");
      } catch (e) { toast(e.message, "bad"); }
    } }, "Enregistrer"))));
}
