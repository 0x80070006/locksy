// Amorçage de l'organisation de test sur BASE_URL, PAR L'INTERFACE, une seule
// fois par exécution (verrou dans e2e/.state/<cle>/) :
//   1. le propriétaire installe Locksy avec le jeton d'installation ;
//   2. son jeton de session (sessionStorage « locksy.session ») sert à inviter
//      admin@e2e.test (rôle admin) et alice@e2e.test (rôle user) par l'API ;
//   3. chaque invité s'inscrit par son lien, dans l'interface.
// Résultat : e2e/.state/<cle>/org.json (mots de passe générés, jamais commités).

import { request, type Browser, type BrowserContextOptions } from "@playwright/test";
import { existsSync, rmSync } from "node:fs";
import { BASE_URL, FRESH_URL, SETUP_TOKEN, statePath } from "./env.ts";
import { once } from "./lock.ts";
import { installOwner, registerInvite, sessionToken, testPassword, type Account } from "./ui.ts";

export type Role = "owner" | "admin" | "user";

export interface Org {
  baseURL: string;
  freshURL: string;
  accounts: Record<Role, Account>;
}

export const ORG_FILE = "org.json";

const PEOPLE: Record<Role, { email: string; name: string }> = {
  owner: { email: "proprietaire@e2e.test", name: "Paule Propriétaire" },
  admin: { email: "admin@e2e.test", name: "Adam Administrateur" },
  user: { email: "alice@e2e.test", name: "Alice Martin" },
};

/** Santé du serveur (null s'il ne répond pas). */
export async function health(url: string): Promise<{ needs_setup: boolean } | null> {
  const ctx = await request.newContext();
  try {
    const res = await ctx.get(`${url}/api/health`, { timeout: 5_000 });
    return res.ok() ? await res.json() : null;
  } catch {
    return null;
  } finally {
    await ctx.dispose();
  }
}

/** Oublie un org.json qui ne correspond plus au serveur (serveur recréé). */
export async function forgetStaleOrg() {
  const file = statePath(ORG_FILE);
  if (existsSync(file) && (await health(BASE_URL))?.needs_setup) rmSync(file);
}

async function bootstrap(browser: Browser, contextOptions: BrowserContextOptions): Promise<Org> {
  const h = await health(BASE_URL);
  if (!h) throw new Error(`Serveur ${BASE_URL} injoignable.`);
  if (!h.needs_setup) {
    throw new Error(
      `${BASE_URL} est déjà installé mais ${statePath(ORG_FILE)} est absent : ` +
        "relancez sans --keep, ou supprimez l'environnement (docker compose -p <cle> … down -v).",
    );
  }
  const accounts = {} as Record<Role, Account>;
  // Adresse IP propre à l'amorçage (plage 10.250.x.x, hors de celles des tests).
  let ip = 0;
  const newPage = async () => {
    ip++;
    const ctx = await browser.newContext({
      ...contextOptions,
      baseURL: BASE_URL,
      extraHTTPHeaders: { "X-Forwarded-For": `10.250.${ip >> 8}.${ip & 255}` },
    });
    return { ctx, page: await ctx.newPage() };
  };

  const { ctx, page } = await newPage();
  const owner = { ...PEOPLE.owner, password: testPassword() };
  await installOwner(page, SETUP_TOKEN, owner);
  const ownerToken = await sessionToken(page);
  await ctx.close();

  const api = await request.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${ownerToken}`, "X-Forwarded-For": "10.250.255.1" },
  });
  try {
    for (const role of ["admin", "user"] as const) {
      const res = await api.post("/api/admin/invites", { data: { email: PEOPLE[role].email, role } });
      if (!res.ok()) throw new Error(`Invitation de ${PEOPLE[role].email} refusée : ${res.status()} ${await res.text()}`);
      const { token } = await res.json();
      const { ctx: c, page: p } = await newPage();
      const password = testPassword();
      await registerInvite(p, token, { name: PEOPLE[role].name, password });
      await c.close();
      accounts[role] = { ...PEOPLE[role], password, id: "" };
    }
    accounts.owner = { ...owner, id: "" };
    const res = await api.get("/api/admin/users");
    if (!res.ok()) throw new Error(`Liste des comptes refusée : ${res.status()}`);
    const users: { id: string; email: string; role: string }[] = await res.json();
    for (const role of Object.keys(accounts) as Role[]) {
      const u = users.find((x) => x.email === accounts[role].email);
      if (!u) throw new Error(`Compte ${accounts[role].email} introuvable après inscription.`);
      if (u.role !== role) throw new Error(`Compte ${u.email} : rôle ${u.role} au lieu de ${role}.`);
      accounts[role].id = u.id;
    }
  } finally {
    await api.dispose();
  }
  return { baseURL: BASE_URL, freshURL: FRESH_URL, accounts };
}

/** Organisation amorcée (une fois par exécution, partagée par tous les workers). */
export async function ensureOrg(browser: Browser, contextOptions: BrowserContextOptions): Promise<Org> {
  return (await once(statePath(ORG_FILE), () => bootstrap(browser, contextOptions))).value;
}
