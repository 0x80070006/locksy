// Connexion d'entreprise contre les vrais fournisseurs de test (profils
// « sso » : Dex, « ldap » : Samba AD), par l'API d'administration du serveur
// de la vague 2 : découverte OpenID permise sur le réseau interne
// (LOCKSY_SSO_ALLOW_HTTP l'implique), test de l'annuaire en LDAPS,
// synchronisation à blanc sans écriture et historique. Ignorés si le profil
// n'a pas été démarré :
//   bash e2e/tools/run.sh -p <cle> --fast-server --profile sso --profile ldap -- --project=chromium tests/identity/reel.spec.ts

import { readFileSync } from "node:fs";
import { test, expect } from "../../fixtures/index.ts";
import { dex, ldap } from "../../fixtures/annuaires.ts";
import { PROFILES } from "../../fixtures/env.ts";

test.describe.configure({ mode: "serial" });

test("sso réel : configuration testée contre Dex (découverte, clés publiées)", async ({ apiAs }) => {
  test.skip(!PROFILES.has("sso"), "Profil sso non démarré.");
  const api = await apiAs("owner");
  const res = await api.post("/api/admin/sso/test", {
    data: {
      enabled: true, label: "Dex", issuer: dex.issuer, client_id: dex.clientId, client_secret: dex.clientSecret,
      has_secret: false, public_url: "", enforce: false, auto_provision: false, allowed_domains: [], redirect_uri: "",
    },
  });
  expect(res.status(), await res.text()).toBe(200);
  const body = await res.json();
  expect(body.issuer).toBe(dex.issuer);
  expect(body.keys).toBeGreaterThan(0);
});

test("ldap réel : test LDAPS, synchronisation à blanc sans écriture, historique", async ({ apiAs }) => {
  test.skip(!PROFILES.has("ldap"), "Profil ldap non démarré.");
  // Le certificat LDAPS généré par Samba n'a aucun nom alternatif (SAN) :
  // le client TLS du serveur le refuse pour « samba ». À rétablir quand
  // fixtures/ldap/start.sh posera un certificat signé pour ce nom.
  test.fixme(true, "certificat LDAPS de Samba sans nom alternatif (fixture à compléter)");
  const api = await apiAs("owner");
  const config = {
    enabled: true, url: ldap.ldapsUrl, starttls: false, bind_dn: ldap.bindDn, bind_password: ldap.bindPassword,
    has_password: false, base_dn: ldap.usersDn, group_dn: "", login_attribute: "sAMAccountName", email_attribute: "mail",
    ca_pem: readFileSync(ldap.caFile, "utf8"), sync_minutes: 0, allow_login: false, enforce: false, label: "Annuaire de test",
    last_sync: 0, last_result: "",
  };
  const test1 = await api.post("/api/admin/ldap/test", { data: config });
  expect(test1.status(), await test1.text()).toBe(200);

  const saved = await api.put("/api/admin/ldap", { data: config });
  expect(saved.status(), await saved.text()).toBe(200);
  try {
    const before = await (await api.get("/api/admin/people?origine=ldap&par_page=100")).json();
    const dry = await api.post("/api/admin/ldap/sync?dry_run=true");
    expect(dry.status(), await dry.text()).toBe(200);
    const report = await dry.json();
    expect(report.dry_run).toBe(true);
    // Les comptes actifs de l'annuaire de test, avec une adresse : trouvés.
    expect(report.found).toBeGreaterThanOrEqual(ldap.accounts.filter((a) => a.enabled).length);
    expect(Array.isArray(report.ignored)).toBe(true);
    // À blanc : aucun compte créé.
    const after = await (await api.get("/api/admin/people?origine=ldap&par_page=100")).json();
    expect(after.total).toBe(before.total);
    const history = await (await api.get("/api/admin/ldap/history?limit=5")).json();
    expect(history[0]).toMatchObject({ dry_run: true });
  } finally {
    // L'organisation de test est partagée : l'annuaire est désactivé ensuite.
    const off = await api.put("/api/admin/ldap", { data: { ...config, enabled: false } });
    expect(off.status()).toBe(200);
  }
});
