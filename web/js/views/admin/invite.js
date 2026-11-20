// « Inviter des personnes » (cahier §3.4.3, parcours A1 en 3 clics, contrat
// C1.1 POST /admin/invites/batch) : coller une ou plusieurs adresses
// (virgule, point-virgule, tabulation ou retour à la ligne), ou déposer un
// fichier CSV « adresse;prénom;nom;rôle » ; rôle par défaut ; date de fin d'accès
// facultative. Rapport : invitations créées, adresses ignorées avec leur
// raison en clair, et « Copier toutes les invitations » pour les liens qui
// ne sont pas partis par e-mail.
// Repli : serveur sans envoi groupé -> POST /admin/invites adresse par adresse.
//
// Export : openInviteDialog.

import {
  t, plural, has, h, clear, dialog, field, textArea, textInput, segmented, alertCard, button, copySecret,
  errorText, fmtDate,
} from "../../ui/index.js";
import { api } from "../../api.js";
import { dateInputToTs, isOwner, routeMissing } from "./shell.js";

const EMAIL_RE = /^[^\s@;,<>"]+@[^\s@;,<>"]+\.[^\s@;,<>"]+$/;
const ROLE_WORDS = Object.freeze({
  user: "user", utilisateur: "user", utilisatrice: "user",
  admin: "admin", administrateur: "admin", administratrice: "admin",
  owner: "owner", proprietaire: "owner",
});
const MAX_BATCH = 200;

const plain = (s) => String(s || "").normalize("NFD").replace(/\p{M}/gu, "").trim().toLowerCase();

/**
 * Adresses d'un texte collé ou d'un CSV « adresse;prénom;nom;rôle » :
 * -> { people: [{ email, role|null, name }], invalid: [texte], duplicates: n }.
 * Le nom (prénom puis nom) est repris des cellules qui ne sont ni l'adresse ni le rôle.
 * Une ligne d'en-tête (sans adresse) est ignorée.
 */
function parseInvitees(text) {
  const people = [];
  const invalid = [];
  const seen = new Set();
  let duplicates = 0;
  for (const line of String(text || "").split(/\r?\n/)) {
    const cells = line.split(/[;,\t]/).map((c) => c.trim().replace(/^"|"$/g, "").trim()).filter(Boolean);
    if (!cells.length) continue;
    const emails = cells.filter((c) => c.includes("@"));
    if (!emails.length) {
      // En-tête CSV (« email;nom;rôle ») ou texte sans adresse.
      if (!cells.some((c) => ["email", "e-mail", "adresse", "courriel"].includes(plain(c)))) invalid.push(line.trim());
      continue;
    }
    const role = cells.map((c) => ROLE_WORDS[plain(c)]).find(Boolean) || null;
    const name = cells.filter((c) => !c.includes("@") && !ROLE_WORDS[plain(c)]).join(" ").slice(0, 100);
    for (const raw of emails.length === 1 ? emails : cells.filter((c) => c.includes("@"))) {
      const email = raw.replace(/^<|>$/g, "").toLowerCase();
      if (!EMAIL_RE.test(email)) {
        invalid.push(raw);
        continue;
      }
      if (seen.has(email)) {
        duplicates++;
        continue;
      }
      seen.add(email);
      people.push({ email, role: emails.length === 1 ? role : null, name: emails.length === 1 ? name : "" });
    }
  }
  return { people, invalid, duplicates };
}

/**
 * Fenêtre d'invitation. onDone() après au moins une invitation créée.
 * Résout le rapport { created, skipped } ou undefined (annulation).
 */
export function openInviteDialog(ctx, { onDone } = {}) {
  const owner = isOwner(ctx);
  let role = "user";
  let report;
  const text = textArea({ rows: 6, placeholder: t("admin.invite.placeholder") });
  const until = textInput({ type: "date" });
  const firstName = textInput({ name: "prenom", autocomplete: "off", maxlength: 50 });
  const lastName = textInput({ name: "nom", autocomplete: "off", maxlength: 50 });
  const summary = h("p", { class: "u-muted", "aria-live": "off" });
  const problem = h("div");
  const file = h("input", { type: "file", accept: ".csv,text/csv,text/plain", class: "u-sr-only", id: "invitation-csv" });
  const pick = h("label", { for: "invitation-csv", class: "c-button" }, t("admin.invite.csv"));

  const refresh = () => {
    const { people, invalid } = parseInvitees(text.value);
    summary.textContent = people.length || invalid.length
      ? [plural("admin.invite.recognized", people.length), invalid.length ? plural("admin.invite.invalid", invalid.length) : ""].filter(Boolean).join(" · ")
      : "";
  };
  text.addEventListener("input", refresh);
  file.addEventListener("change", async () => {
    const f = file.files?.[0];
    file.value = "";
    if (!f) return;
    try {
      const content = await f.text();
      text.value = [text.value.trim(), content.trim()].filter(Boolean).join("\n");
      refresh();
    } catch {
      clear(problem, alertCard({ tone: "danger", text: t("admin.invite.csv_unreadable") }));
    }
  });

  const roles = segmented({
    label: t("admin.invite.role"),
    options: [
      { value: "user", label: t("ui.role.user") },
      { value: "admin", label: t("ui.role.admin") },
      ...(owner ? [{ value: "owner", label: t("ui.role.owner") }] : []),
    ],
    value: role,
    onChange: (v) => { role = v; },
  });

  const body = h("div", { class: "l-stack", "data-gap": "3" },
    h("div", { class: "l-grid" },
      field({ label: t("admin.invite.first_name"), optional: true, input: firstName }),
      field({ label: t("admin.invite.last_name"), optional: true, input: lastName })),
    h("p", { class: "u-muted" }, t("admin.invite.names_help")),
    field({ label: t("admin.invite.emails"), help: t("admin.invite.emails_help"), input: text }),
    summary,
    h("div", { class: "l-cluster" }, file, pick, h("span", { class: "u-muted" }, t("admin.invite.csv_help"))),
    roles,
    field({ label: t("admin.invite.until"), help: t("admin.invite.until_help"), optional: true, input: until }),
    problem);

  return new Promise((resolve) => {
    const dlg = dialog({
      title: t("admin.invite.title"),
      body,
      size: "lg",
      dirty: () => !report && text.value.trim() !== "",
      actions: [
        { label: t("common.action.cancel"), cancel: true, value: "cancel" },
        {
          label: t("admin.invite.submit"), variant: "primary", busyLabel: t("admin.invite.sending"),
          onClick: async () => {
            if (report) return true;
            const { people, invalid } = parseInvitees(text.value);
            if (!people.length) {
              clear(problem, alertCard({ tone: "danger", text: invalid.length ? t("admin.invite.none_valid") : t("admin.invite.empty") }));
              return false;
            }
            if (people.length > MAX_BATCH) {
              clear(problem, alertCard({ tone: "danger", text: t("admin.invite.too_many", { max: MAX_BATCH }) }));
              return false;
            }
            try {
              // Prénom et nom saisis : pour la seule adresse indiquée (sans nom déjà lu dans le CSV).
              const typed = [firstName.value, lastName.value].map((x) => x.trim()).filter(Boolean).join(" ");
              if (typed && people.length === 1 && !people[0].name) people[0].name = typed;
              report = await sendInvites(people, role, dateInputToTs(until.value), owner);
            } catch (e) {
              clear(problem, alertCard({ tone: "danger", text: errorText(e) }));
              return false;
            }
            report.invalid = invalid;
            showReport(dlg, report);
            if (report.created.length) await onDone?.(report);
            return false;
          },
        },
      ],
      onClose: () => resolve(report),
    });
  });
}

/** Envoi groupé par rôle ; repli adresse par adresse. */
async function sendInvites(people, defaultRole, accessUntil, owner) {
  const groups = new Map();
  for (const p of people) {
    let r = p.role || defaultRole;
    if (r === "owner" && !owner) r = "admin";
    if (!groups.has(r)) groups.set(r, []);
    groups.get(r).push(p);
  }
  const out = { created: [], skipped: [] };
  for (const [role, group] of groups) {
    const emails = group.map((p) => p.email);
    const names = group.map((p) => p.name || "");
    let res;
    try {
      res = await api("POST", "/admin/invites/batch", { emails, names, role, access_until: accessUntil ?? undefined }, { retry: false });
    } catch (e) {
      if (!routeMissing(e)) throw e;
      res = await legacyInvites(group, role);
    }
    out.created.push(...(res.created || []).map((c) => ({ ...c, role })));
    out.skipped.push(...(res.skipped || []));
  }
  return out;
}

/** Serveur sans envoi groupé : une invitation à la fois (lien à transmettre). */
async function legacyInvites(group, role) {
  const res = { created: [], skipped: [] };
  for (const { email, name } of group) {
    try {
      const r = await api("POST", "/admin/invites", { email, role, name: name || "" }, { retry: false });
      res.created.push({ id: r.id, email, link: `${location.origin}/#/inscription/${encodeURIComponent(r.token)}`, mailed: false, expires_at: r.expires_at });
    } catch (e) {
      // Panne du serveur, réseau coupé ou trop de demandes : ce n'est pas
      // l'adresse qui est en cause. L'erreur remonte (message, saisie gardée).
      if (!(e?.status >= 400 && e.status < 500) || e.status === 429) throw e;
      const reason = { conflict: "exists", email_taken: "exists", domain_not_allowed: "domain_not_allowed", bad_request: "invalid" }[e?.code] || "invalid";
      res.skipped.push({ email, reason });
    }
  }
  return res;
}

/** Rapport dans la même fenêtre (créées, ignorées avec raison, liens à copier). */
function showReport(dlg, report) {
  const pending = report.created.filter((c) => !c.mailed && c.link);
  const mailed = report.created.length - pending.length;
  const allText = pending.map((c) => t("admin.invite.copy_line", { email: c.email, link: c.link, date: fmtDate(c.expires_at, "date") })).join("\n");
  const body = dlg.querySelector(".c-dialog__form > .l-stack");
  const skipped = [...report.skipped.map((s) => t("admin.invite.skipped_line", {
    email: s.email,
    reason: has(`admin.people.skip_reason.${s.reason}`) ? t(`admin.people.skip_reason.${s.reason}`) : t("admin.people.skip_reason.invalid"),
  })), ...(report.invalid || []).map((x) => t("admin.invite.skipped_line", { email: x, reason: t("admin.people.skip_reason.invalid") }))];
  clear(body,
    alertCard({
      tone: report.created.length ? "ok" : "warn",
      title: plural("admin.invite.created", report.created.length),
      text: report.created.length ? [mailed ? plural("admin.invite.mailed", mailed) : "", pending.length ? plural("admin.invite.to_copy", pending.length) : ""].filter(Boolean).join(" ") : null,
    }),
    skipped.length ? h("div", { class: "l-stack", "data-gap": "1" },
      h("p", {}, plural("admin.invite.skipped", skipped.length)),
      h("ul", {}, skipped.map((s) => h("li", {}, s)))) : null,
    pending.length ? h("div", { class: "l-cluster" },
      button({
        label: t("admin.invite.copy_all"), icon: "copy", variant: "primary",
        onClick: () => copySecret(allText, { kind: "text", labelKey: "admin.invite.copied" }),
      })) : null);
  // Après l'envoi, une seule action : fermer.
  const actions = dlg.querySelector(".c-dialog__actions");
  if (actions) {
    clear(actions, button({ label: t("common.action.close"), variant: pending.length ? "secondary" : "primary", onClick: () => dlg.close("done") }));
  }
}
