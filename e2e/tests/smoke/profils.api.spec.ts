// Les services des profils (run.sh --profile sso|ldap|mail) répondent depuis
// le lanceur. Chaque test est ignoré si son profil n'a pas été démarré.

import { existsSync, readFileSync } from "node:fs";
import { test, expect } from "../../fixtures/index.ts";
import { dex, ldap } from "../../fixtures/annuaires.ts";
import { MAILPIT_URL, PROFILES } from "../../fixtures/env.ts";

test.describe("Profils de l'environnement de test", { tag: "@smoke" }, () => {
  test("sso : Dex publie sa configuration OIDC", async ({ request }) => {
    test.skip(!PROFILES.has("sso"), "Profil sso non démarré.");
    const res = await request.get(`${dex.issuer}/.well-known/openid-configuration`);
    expect(res.status()).toBe(200);
    expect(await res.json()).toMatchObject({ issuer: dex.issuer });
  });

  test("ldap : l'annuaire est prêt et son autorité LDAPS est publiée", async () => {
    test.skip(!PROFILES.has("ldap"), "Profil ldap non démarré.");
    expect(existsSync(ldap.caFile), ldap.caFile).toBe(true);
    expect(readFileSync(ldap.caFile, "utf8")).toContain("BEGIN CERTIFICATE");
    expect(ldap.accounts.filter((a) => a.enabled)).toHaveLength(2);
  });

  test("mail : mailpit expose sa boîte de réception", async ({ request }) => {
    test.skip(!PROFILES.has("mail"), "Profil mail non démarré.");
    const res = await request.get(`${MAILPIT_URL}/api/v1/messages`);
    expect(res.status()).toBe(200);
    expect(await res.json()).toHaveProperty("messages");
  });
});
