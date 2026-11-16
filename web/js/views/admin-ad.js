// Administration : connecteur Active Directory sur site (LDAPS).

import { h, clear, toast, fmtDate } from "../dom.js";
import { api } from "../api.js";

export async function ad(body, rerender) {
  const cfg = await api("GET", "/admin/ldap");
  const field = (id, label, value, opts = {}) => {
    const el = opts.multiline
      ? h("textarea", { class: "input mono", id, rows: 5, spellcheck: "false", placeholder: opts.placeholder || "" })
      : h("input", { class: `input ${opts.mono ? "mono" : ""}`, id, type: opts.type || "text", autocomplete: "off", placeholder: opts.placeholder || "" });
    el.value = value ?? "";
    return { el, f: h("div", { class: "field" }, h("label", { for: id }, label), el, opts.help ? h("span", { class: "small muted" }, opts.help) : null) };
  };
  const url = field("ad-url", "Contrôleur de domaine", cfg.url, { mono: true, placeholder: "ldaps://dc1.entreprise.local:636", help: "LDAPS (636) recommandé. Avec ldap:// (389), cochez STARTTLS." });
  const bindDn = field("ad-bind", "Compte de service (lecture seule)", cfg.bind_dn, { mono: true, placeholder: "svc_locksy@entreprise.local" });
  const bindPw = field("ad-pw", "Mot de passe du compte de service", "", { type: "password", placeholder: cfg.has_password ? "•••••••• (enregistré, laissez vide pour le conserver)" : "", help: "Chiffré par le serveur, jamais réaffiché." });
  const base = field("ad-base", "Racine de recherche (base DN)", cfg.base_dn, { mono: true, placeholder: "DC=entreprise,DC=local" });
  const group = field("ad-group", "Groupe d'accès à Locksy", cfg.group_dn, { mono: true, placeholder: "CN=GG_Locksy_Utilisateurs,OU=Groupes,DC=entreprise,DC=local", help: "Les membres, y compris via des groupes imbriqués, obtiennent un compte. Vide = tous les utilisateurs de la racine." });
  const loginAttr = field("ad-login", "Attribut d'identifiant", cfg.login_attribute, { mono: true });
  const mailAttr = field("ad-mail", "Attribut d'adresse e-mail", cfg.email_attribute, { mono: true, help: "À défaut : userPrincipalName." });
  const ca = field("ad-ca", "Certificat de l'autorité (AD CS), format PEM", cfg.ca_pem, { multiline: true, placeholder: "-----BEGIN CERTIFICATE-----\n…", help: "L'autorité racine qui a signé le certificat des contrôleurs (doit contenir le nom DNS du DC en « autre nom de l'objet »)." });
  const minutes = field("ad-min", "Synchronisation toutes les (minutes)", String(cfg.sync_minutes), { type: "number" });
  const label = field("ad-label", "Libellé sur l'écran de connexion", cfg.label);
  const starttls = h("input", { type: "checkbox", checked: cfg.starttls });
  const enabled = h("input", { type: "checkbox", checked: cfg.enabled });
  const allowLogin = h("input", { type: "checkbox", checked: cfg.allow_login });
  const enforce = h("input", { type: "checkbox", checked: cfg.enforce });
  const out = h("div");
  const values = () => ({
    enabled: enabled.checked, allow_login: allowLogin.checked, enforce: enforce.checked, starttls: starttls.checked,
    url: url.el.value, bind_dn: bindDn.el.value, bind_password: bindPw.el.value, base_dn: base.el.value, group_dn: group.el.value,
    login_attribute: loginAttr.el.value, email_attribute: mailAttr.el.value, ca_pem: ca.el.value,
    sync_minutes: Number(minutes.el.value) || 15, label: label.el.value,
  });
  const run = async (fn) => { clear(out, h("span", { class: "spinner" })); try { await fn(); } catch (e) { clear(out, h("div", { class: "notice bad" }, e.message)); } };
  clear(body,
    h("div", { class: "card section" },
      h("h3", {}, "Active Directory sur site"),
      h("p", { class: "small muted" }, "Locksy lit votre annuaire en LDAPS, sans aucun service cloud. Ajouter quelqu'un au groupe lui ouvre un compte ; le désactiver dans l'AD ou le retirer du groupe coupe son accès sur tous ses appareils."),
      cfg.last_sync ? h("div", { class: `notice small ${cfg.last_result.startsWith("Échec") ? "bad" : ""}` }, `Dernière synchronisation le ${fmtDate(cfg.last_sync)} : ${cfg.last_result}`) : null,
      h("div", { class: "grid2" }, url.f, bindDn.f, bindPw.f, base.f, group.f, loginAttr.f, mailAttr.f, minutes.f, label.f),
      ca.f,
      h("label", { class: "check" }, starttls, "Utiliser STARTTLS (adresse ldap://)"),
      h("label", { class: "check" }, enabled, h("strong", {}, "Synchroniser les comptes depuis l'annuaire")),
      h("label", { class: "check" }, allowLogin, h("span", {}, h("strong", {}, "Connexion avec le compte Windows"),
        h("div", { class: "small muted" }, "Identifiant et mot de passe Windows vérifiés par un contrôleur de domaine ; le mot de passe maître reste demandé pour déchiffrer le coffre."))),
      h("label", { class: "check" }, enforce, h("span", {}, h("strong", {}, "Imposer la connexion Windows"),
        h("div", { class: "small muted" }, "Sauf pour les propriétaires (accès de secours si l'annuaire est indisponible)."))),
      h("div", { class: "row" },
        h("button", { class: "btn", onclick: () => run(async () => {
          const r = await api("POST", "/admin/ldap/test", values());
          clear(out, h("div", { class: "notice" }, h("strong", {}, `Connexion réussie : ${r.users} compte(s) trouvé(s).`),
            r.sample.length ? h("ul", { style: "margin:6px 0 0;padding-left:20px" }, r.sample.map((s) => h("li", {}, s))) : null));
        }) }, "Tester la connexion"),
        h("button", { class: "btn primary", onclick: () => run(async () => {
          await api("PUT", "/admin/ldap", values());
          toast("Configuration enregistrée.");
          rerender();
        }) }, "Enregistrer"),
        cfg.enabled ? h("button", { class: "btn", onclick: () => run(async () => {
          const r = await api("POST", "/admin/ldap/sync");
          toast(`${r.found} compte(s) lu(s) : ${r.created} créé(s), ${r.updated} mis à jour, ${r.disabled} désactivé(s), ${r.enabled} réactivé(s).`);
          rerender();
        }) }, "Synchroniser maintenant") : null),
      out),
    h("div", { class: "card section" },
      h("h3", {}, "Préparer l'annuaire"),
      h("ol", { class: "small", style: "margin:0;padding-left:20px;display:grid;gap:4px" },
        h("li", {}, "Créez un compte de service sans droits particuliers (un utilisateur du domaine suffit : il lit l'annuaire), mot de passe sans expiration."),
        h("li", {}, "Créez un groupe de sécurité, par exemple GG_Locksy_Utilisateurs, et ajoutez-y les personnes (ou des groupes)."),
        h("li", {}, "Vérifiez que les contrôleurs ont un certificat LDAPS émis par votre AD CS (modèle « Authentification Kerberos » ou « Contrôleur de domaine »)."),
        h("li", {}, "Exportez le certificat de l'autorité racine en Base 64 (.cer) et collez son contenu ci-dessus."))),
  );
}
