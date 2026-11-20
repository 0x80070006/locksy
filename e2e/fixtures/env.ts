// Environnement d'exécution des tests : adresses vues du lanceur, clé et
// dossier d'état propres à l'exécution (voir tools/run.sh).

import { mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const KEY = process.env.E2E_KEY || "local";
/** Serveur amorcé par la fixture `org` (propriétaire, admin, utilisateur). */
export const BASE_URL = (process.env.BASE_URL || "http://locksy:8743").replace(/\/+$/, "");
/** Serveur neuf, réservé à l'installation (suite smoke). */
export const FRESH_URL = (process.env.FRESH_URL || "http://locksy-fresh:8743").replace(/\/+$/, "");
export const DEX_URL = process.env.DEX_URL || "http://dex:5556/dex";
export const MAILPIT_URL = process.env.MAILPIT_URL || "http://mailpit:8025";
export const LDAP_URL = process.env.LDAP_URL || "ldap://samba:389";
export const LDAPS_URL = process.env.LDAPS_URL || "ldaps://samba:636";
export const LDAP_CA_FILE = process.env.LDAP_CA_FILE || "/ldap-ca/ca.pem";
/** Profils démarrés par run.sh (« sso », « ldap », « mail »). */
export const PROFILES = new Set((process.env.E2E_PROFILES || "").split(",").map((p) => p.trim()).filter(Boolean));
/** Jeton d'installation imposé par docker-compose.e2e.yml. */
export const SETUP_TOKEN = "e2e-jeton-installation-0123456789";

/** Dossier d'état de l'exécution (jamais commité) : org.json, verrous. */
export function stateDir(): string {
  const dir = join(E2E_DIR, ".state", KEY);
  mkdirSync(dir, { recursive: true });
  return dir;
}

export const statePath = (name: string) => join(stateDir(), name);
