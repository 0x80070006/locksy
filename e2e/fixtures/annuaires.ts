// Comptes des fournisseurs d'identité de test (profils « sso » et « ldap »).
// Valeurs de TEST uniquement, jamais réutilisées ailleurs.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DEX_URL, LDAP_CA_FILE, LDAP_URL, LDAPS_URL } from "./env.ts";

/** Dex (fixtures/dex/config.yaml) : client OIDC et deux utilisateurs statiques. */
export const dex = {
  issuer: DEX_URL,
  clientId: "locksy-e2e",
  clientSecret: "e2e-secret-dex-locksy-0123456789",
  redirectUri: "http://locksy:8743/api/sso/callback",
  users: [
    { email: "marie.curie@e2e.test", password: "Dex-Marie-2026-essai", username: "marie.curie" },
    { email: "paul.durand@e2e.test", password: "Dex-Paul-2026-essai", username: "paul.durand" },
  ],
} as const;

export interface LdapAccount {
  login: string;
  password: string;
  givenName: string;
  surname: string;
  mail: string;
  enabled: boolean;
}

/** Samba AD (fixtures/ldap/comptes.tsv, lu aussi par fixtures/ldap/start.sh). */
export const ldap = {
  url: LDAP_URL,
  ldapsUrl: LDAPS_URL,
  domain: "E2E.LOCAL",
  netbios: "E2E",
  baseDn: "dc=e2e,dc=local",
  usersDn: "cn=Users,dc=e2e,dc=local",
  bindDn: "cn=Administrator,cn=Users,dc=e2e,dc=local",
  bindPassword: "E2e-Annuaire-Admin-2026",
  /** Certificat de l'autorité LDAPS (auto-signé, publié au démarrage de Samba). */
  caFile: LDAP_CA_FILE,
  accounts: readFileSync(fileURLToPath(new URL("./ldap/comptes.tsv", import.meta.url)), "utf8")
    .split(/\r?\n/)
    .filter((l) => l.trim() && !l.startsWith("#"))
    .map((l): LdapAccount => {
      const [login, password, givenName, surname, mail, state] = l.split("\t");
      return { login, password, givenName, surname, mail, enabled: state === "actif" };
    }),
};
