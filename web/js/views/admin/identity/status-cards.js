// Cartes d'état de la connexion d'entreprise (SSO, Active Directory, SCIM),
// réutilisables par l'accueil de l'administration :
//
//   const { loadIdentityStatus, identityStatusCards } = await import("./identity/status-cards.js");
//   const status = await loadIdentityStatus();
//   container.append(...identityStatusCards(status));
//
// loadIdentityStatus() lit GET /admin/identity/status ; sur un serveur qui ne
// la fournit pas encore (404), l'état est reconstitué depuis les routes
// historiques (/admin/sso, /admin/ldap, /admin/scim) et marqué `partial`.

import { api } from "../../../api.js";
import { plural, relTime, statusCard, t } from "../../../ui/index.js";
import { getOrNull, hrefOf, nowSecs, reasonText } from "./common.js";

/** État reconstitué depuis les routes historiques (serveur sans /admin/identity/status). */
async function legacyStatus() {
  const [sso, ldap, scim] = await Promise.all([getOrNull("/admin/sso"), getOrNull("/admin/ldap"), getOrNull("/admin/scim")]);
  const lastSync = Number(ldap?.last_sync) > 0
    ? {
      at: ldap.last_sync, dry_run: false, ok: !/^échec/i.test(String(ldap.last_result || "")),
      found: null, created: null, updated: null, disabled: null, ignored_count: 0, error_code: null,
      technical: ldap.last_result || "",
    }
    : null;
  return {
    partial: true,
    sso: {
      configured: !!(sso?.issuer && sso?.client_id), enabled: !!sso?.enabled, enforce: !!sso?.enforce,
      last_test: null, last_ok_by_me_at: null, last_error: null,
    },
    ldap: {
      configured: !!(ldap?.url && ldap?.bind_dn && ldap?.has_password && ldap?.base_dn),
      enabled: !!ldap?.enabled, allow_login: !!ldap?.allow_login, enforce: !!ldap?.enforce,
      last_test: null, last_ok_by_me_at: null, last_sync: lastSync,
    },
    scim: {
      token_set: !!scim?.enabled, token_created_at: scim?.created_at ?? null,
      token_expires_at: scim?.expires_at ?? null, last_used_at: scim?.last_used_at ?? null, base_url: scim?.base_url || "",
    },
  };
}

/** État des trois méthodes de connexion d'entreprise. */
export async function loadIdentityStatus() {
  try {
    const status = await api("GET", "/admin/identity/status");
    return { ...status, partial: false };
  } catch (e) {
    if (e?.status !== 404) throw e;
  }
  return legacyStatus();
}

/** Vrai si au moins une méthode est configurée. */
export function anyConfigured(status) {
  return !!(status?.sso?.configured || status?.ldap?.configured || status?.scim?.token_set);
}

function ssoCard(s, href) {
  if (!s?.configured) {
    return statusCard({
      tone: "neutral", title: t("common.glossary.enterprise_sso"), detail: t("identity.state.not_configured"),
      action: { label: t("identity.action.configure"), href },
    });
  }
  const mode = s.enabled ? (s.enforce ? "enforced" : "offered") : "off";
  const failed = s.last_test && !s.last_test.ok;
  const details = [t(`identity.sso.state.${mode}`)];
  if (failed) details.push(t("identity.test.last_error", { when: relTime(s.last_test.at), reason: reasonText(s.last_test.error_code) }));
  else if (s.last_test?.ok) details.push(t("identity.test.last_ok", { when: relTime(s.last_test.at) }));
  return statusCard({
    tone: failed ? "warn" : mode === "off" ? "info" : "ok",
    title: t("common.glossary.enterprise_sso"),
    detail: details.join(" "),
    action: { label: t("identity.action.manage"), href },
  });
}

function adCard(s, href) {
  if (!s?.configured) {
    return statusCard({
      tone: "neutral", title: t("common.glossary.enterprise_directory"), detail: t("identity.state.not_configured"),
      action: { label: t("identity.action.configure"), href },
    });
  }
  const mode = s.allow_login ? (s.enforce ? "enforced" : "offered") : s.enabled ? "sync_only" : "off";
  const details = [t(`identity.ad.state.${mode}`)];
  const sync = s.last_sync;
  let tone = mode === "off" ? "info" : "ok";
  if (sync && !sync.ok) {
    tone = "warn";
    details.push(t("identity.ad.detail.sync_failed", { when: relTime(sync.at), reason: reasonText(sync.error_code) }));
  } else if (sync && Number.isFinite(sync.found)) {
    details.push(plural("identity.ad.detail.synced", sync.found, { when: relTime(sync.at) }));
  } else if (sync) {
    details.push(t("identity.ad.detail.synced_at", { when: relTime(sync.at) }));
  } else if (s.enabled) {
    details.push(t("identity.ad.detail.never_synced"));
  }
  return statusCard({
    tone, title: t("common.glossary.enterprise_directory"), detail: details.join(" "),
    action: { label: t("identity.action.manage"), href },
  });
}

function scimCard(s, href) {
  if (!s?.token_set) {
    return statusCard({
      tone: "neutral", title: t("common.glossary.enterprise_provisioning"), detail: t("identity.scim.state.none"),
      action: { label: t("identity.action.configure"), href },
    });
  }
  const expired = Number(s.token_expires_at) > 0 && s.token_expires_at <= nowSecs();
  const details = [t(expired ? "identity.scim.state.expired" : "identity.scim.state.active")];
  if (!expired && s.token_expires_at) details.push(t("identity.scim.detail.expires", { when: relTime(s.token_expires_at) }));
  details.push(s.last_used_at ? t("identity.scim.detail.used", { when: relTime(s.last_used_at) }) : t("identity.scim.detail.never_used"));
  const soon = !expired && s.token_expires_at && s.token_expires_at - nowSecs() < 7 * 86400;
  return statusCard({
    tone: expired ? "danger" : soon ? "warn" : "ok",
    title: t("common.glossary.enterprise_provisioning"),
    detail: details.join(" "),
    action: { label: t("identity.action.manage"), href },
  });
}

/**
 * Cartes d'état SSO, Active Directory et SCIM (HTMLElement[]), chacune avec
 * un lien vers sa page. `href(section)` remplace l'adresse par défaut
 * (« #/admin/connexion/sso »…).
 */
export function identityStatusCards(status, { href = hrefOf } = {}) {
  return [
    ssoCard(status?.sso, href("sso")),
    adCard(status?.ldap, href("ad")),
    scimCard(status?.scim, href("scim")),
  ];
}
