// Administration : authentification unique (OpenID Connect) et provisionnement SCIM.

import { h, clear, icon, toast, confirmDialog, fmtDate, relTime } from "../dom.js";
import { api } from "../api.js";

function copyRow(value) {
  const box = h("input", { class: "input mono", readonly: true, value });
  return h("div", { class: "input-row" }, box, h("button", { class: "btn", onclick: async () => {
    try { await navigator.clipboard.writeText(value); toast("Copié."); } catch { box.select(); }
  } }, icon("copy"), "Copier"));
}

export async function sso(body, rerender) {
  const cfg = await api("GET", "/admin/sso");
  const field = (id, label, value, opts = {}) => {
    const el = h("input", { class: `input ${opts.mono ? "mono" : ""}`, id, value: value ?? "", placeholder: opts.placeholder || "", type: opts.type || "text", autocomplete: "off" });
    return { el, f: h("div", { class: "field" }, h("label", { for: id }, label), el, opts.help ? h("span", { class: "small muted" }, opts.help) : null) };
  };
  const enabled = h("input", { type: "checkbox", checked: cfg.enabled });
  const enforce = h("input", { type: "checkbox", checked: cfg.enforce });
  const auto = h("input", { type: "checkbox", checked: cfg.auto_provision });
  const label = field("sso-label", "Libellé du bouton", cfg.label, { placeholder: "Microsoft, Okta, Google…" });
  const publicUrl = field("sso-url", "Adresse publique de Locksy", cfg.public_url, { mono: true, help: "Celle que tapent vos utilisateurs, par exemple https://coffre.entreprise.fr" });
  const issuer = field("sso-issuer", "Émetteur (issuer)", cfg.issuer, { mono: true, placeholder: "https://login.microsoftonline.com/<tenant>/v2.0" });
  const clientId = field("sso-client", "Identifiant client (client ID)", cfg.client_id, { mono: true });
  const secret = field("sso-secret", "Secret client", "", { type: "password", placeholder: cfg.has_secret ? "•••••••• (enregistré, laissez vide pour le conserver)" : "", help: "Chiffré par le serveur, jamais réaffiché." });
  const domains = field("sso-domains", "Domaines e-mail autorisés (facultatif)", (cfg.allowed_domains || []).join(", "), { placeholder: "entreprise.fr, filiale.fr" });
  const testOut = h("div");
  const values = () => ({
    enabled: enabled.checked, enforce: enforce.checked, auto_provision: auto.checked, label: label.el.value,
    public_url: publicUrl.el.value, issuer: issuer.el.value, client_id: clientId.el.value, client_secret: secret.el.value,
    allowed_domains: domains.el.value.split(",").map((d) => d.trim()).filter(Boolean),
  });
  clear(body,
    h("div", { class: "card section" },
      h("h3", {}, "Connexion unique OpenID Connect"),
      h("p", { class: "small muted" }, "Compatible Microsoft Entra ID, Okta, Google Workspace, Keycloak, ADFS 2016+, Auth0… Le SSO confirme l'identité ; le mot de passe maître reste demandé, car lui seul déchiffre le coffre."),
      h("div", { class: "field" }, h("span", { class: "label" }, "URI de redirection à déclarer chez votre fournisseur"), copyRow(cfg.redirect_uri)),
      h("div", { class: "grid2" }, label.f, publicUrl.f, issuer.f, clientId.f, secret.f, domains.f),
      h("label", { class: "check" }, enabled, h("strong", {}, "Activer la connexion unique")),
      h("label", { class: "check" }, auto, h("span", {}, h("strong", {}, "Création de compte à la première connexion"),
        h("div", { class: "small muted" }, "Sinon, seules les personnes poussées par l'annuaire (SCIM) ou invitées peuvent créer leur coffre."))),
      h("label", { class: "check" }, enforce, h("span", {}, h("strong", {}, "Imposer le SSO"),
        h("div", { class: "small muted" }, "La connexion par mot de passe seul est refusée, sauf pour les propriétaires (accès de secours si le fournisseur est en panne)."))),
      h("div", { class: "row" },
        h("button", { class: "btn", onclick: async () => {
          clear(testOut, h("span", { class: "spinner" }));
          try {
            const r = await api("POST", "/admin/sso/test", values());
            clear(testOut, h("div", { class: "notice" }, `Fournisseur joignable : ${r.issuer} · ${r.keys} clé(s) de signature publiée(s).`));
          } catch (e) { clear(testOut, h("div", { class: "notice bad" }, e.message)); }
        } }, "Tester le fournisseur"),
        h("button", { class: "btn primary", onclick: async () => {
          try { await api("PUT", "/admin/sso", values()); toast("Configuration SSO enregistrée."); rerender(); } catch (e) { toast(e.message, "bad"); }
        } }, "Enregistrer")),
      testOut),
    h("div", { class: "card section" },
      h("h3", {}, "Exemple : Microsoft Entra ID"),
      h("ol", { class: "small", style: "margin:0;padding-left:20px;display:grid;gap:4px" },
        h("li", {}, "Entra ID > Inscriptions d'applications > Nouvelle inscription, plateforme « Web », avec l'URI de redirection ci-dessus."),
        h("li", {}, "Certificats et secrets > Nouveau secret client : copiez sa valeur dans « Secret client »."),
        h("li", {}, "Émetteur : https://login.microsoftonline.com/<ID de l'annuaire>/v2.0 ; identifiant client : « ID d'application (client) »."),
        h("li", {}, "Autorisations API : openid, email, profile (Microsoft Graph, déléguées)."))));
}

export async function scim(body, rerender) {
  const [st, dir] = await Promise.all([api("GET", "/admin/scim"), api("GET", "/admin/directory")]);
  const tokenBox = h("div");
  const status = (d) => !d.active ? h("span", { class: "chip bad" }, "Désactivé")
    : d.registered ? h("span", { class: "chip ok" }, "Actif")
    : h("span", { class: "chip accent" }, "En attente de 1re connexion");
  clear(body,
    h("div", { class: "card section" },
      h("h3", {}, "Provisionnement automatique (SCIM 2.0)"),
      h("p", { class: "small muted" }, "Votre annuaire (Entra ID, Okta, OneLogin…) crée, renomme, désactive et supprime les comptes Locksy. Une désactivation dans l'annuaire coupe immédiatement l'accès sur tous les appareils."),
      h("div", { class: "field" }, h("span", { class: "label" }, "URL du locataire (Tenant URL)"), copyRow(st.base_url)),
      h("div", { class: "row" },
        st.enabled ? h("span", { class: "chip ok" }, `Jeton actif depuis le ${fmtDate(st.created_at)}`) : h("span", { class: "chip" }, "Aucun jeton : provisionnement désactivé"),
        h("button", { class: "btn primary", onclick: async () => {
          if (st.enabled && !(await confirmDialog({ title: "Remplacer le jeton ?", message: "L'ancien jeton cessera immédiatement de fonctionner : pensez à mettre le nouveau dans votre annuaire.", confirmLabel: "Générer" }))) return;
          try {
            const r = await api("POST", "/admin/scim/token");
            clear(tokenBox, h("div", { class: "notice" }, h("div", { class: "field" },
              h("span", { class: "label" }, "Jeton secret (Secret Token) : copiez-le maintenant, il ne sera plus affiché"), copyRow(r.token))));
            toast("Jeton SCIM généré.");
          } catch (e) { toast(e.message, "bad"); }
        } }, st.enabled ? "Remplacer le jeton" : "Générer un jeton"),
        st.enabled ? h("button", { class: "btn danger", onclick: async () => {
          if (!(await confirmDialog({ title: "Révoquer le jeton ?", message: "L'annuaire ne pourra plus modifier les comptes.", confirmLabel: "Révoquer", danger: true }))) return;
          await api("DELETE", "/admin/scim/token");
          toast("Jeton révoqué.");
          rerender();
        } }, "Révoquer") : null),
      tokenBox,
      h("p", { class: "small muted" }, "Les groupes ne sont pas synchronisés : l'accès aux coffres partagés se donne depuis Locksy, car il faut sceller la clé du coffre pour chaque membre.")),
    h("div", { class: "card section" },
      h("h3", {}, `Comptes poussés par l'annuaire (${dir.length})`),
      dir.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Personne"), h("th", {}, "État"), h("th", {}, "Identifiant annuaire"), h("th", {}, "Mis à jour"))),
        h("tbody", {}, dir.map((d) => h("tr", {},
          h("td", {}, h("strong", {}, d.display_name || d.email), h("div", { class: "small muted" }, d.email)),
          h("td", {}, status(d)),
          h("td", { class: "mono small" }, d.external_id || "—"),
          h("td", { class: "small" }, relTime(d.updated_at)))))))
        : h("p", { class: "muted" }, "Aucun compte provisionné pour l'instant.")));
}
