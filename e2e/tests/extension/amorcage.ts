// Organisation de test pour les tests de l'extension, SANS l'interface web :
// les comptes sont créés avec le module du coffre embarqué dans l'extension
// (même cryptographie que le web), puis décrits dans e2e/.state/<cle>/org.json
// au format de la fixture « org » (même fichier, même verrou : une exécution
// qui combine plusieurs projets ne crée l'organisation qu'une fois).
//
// Raison : l'extension se teste avec le serveur seul ; une interface web en
// cours de refonte ne doit pas empêcher de vérifier le popup.

import type { BrowserContext } from "@playwright/test";
import { request } from "@playwright/test";
import { BASE_URL, FRESH_URL, SETUP_TOKEN, statePath } from "../../fixtures/env.ts";
import { once } from "../../fixtures/lock.ts";
import { ORG_FILE, health, type Org, type Role } from "../../fixtures/org.ts";
import { testPassword, type Account } from "../../fixtures/ui.ts";

const PEOPLE: Record<Role, { email: string; name: string }> = {
  owner: { email: "proprietaire@e2e.test", name: "Paule Propriétaire" },
  admin: { email: "admin@e2e.test", name: "Adam Administrateur" },
  user: { email: "alice@e2e.test", name: "Alice Martin" },
};

/** Inscription par le module du coffre d'une page de l'extension ; renvoie le jeton de session. */
async function register(ctx: BrowserContext, id: string, a: { email: string; name: string; password: string }, token: { setup?: string; invite?: string }): Promise<string> {
  const page = await ctx.newPage();
  try {
    await page.goto(`chrome-extension://${id}/offscreen.html`);
    return await page.evaluate(async ({ a, base, token }) => {
      const W = await import("./lib/wasm.js");
      await W.loadCrypto("lib/locksy.wasm");
      const api = await import("./lib/api.js");
      api.setBase(base);
      const V = await import("./lib/vault.js");
      await V.register({ email: a.email, name: a.name, password: a.password, setupToken: token.setup, inviteToken: token.invite });
      return api.getToken();
    }, { a, base: BASE_URL, token });
  } finally {
    await page.close();
  }
}

async function bootstrap(ctx: BrowserContext, id: string): Promise<Org> {
  const h = await health(BASE_URL);
  if (!h) throw new Error(`Serveur ${BASE_URL} injoignable.`);
  if (!h.needs_setup) throw new Error(`${BASE_URL} est déjà installé mais ${statePath(ORG_FILE)} est absent : relancez sans --keep.`);
  const accounts = {} as Record<Role, Account>;
  const owner = { ...PEOPLE.owner, password: testPassword() };
  const ownerToken = await register(ctx, id, owner, { setup: SETUP_TOKEN });
  accounts.owner = { ...owner, id: "" };
  const api = await request.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${ownerToken}`, "X-Forwarded-For": "10.251.255.1" },
  });
  try {
    for (const role of ["admin", "user"] as const) {
      const res = await api.post("/api/admin/invites", { data: { email: PEOPLE[role].email, role } });
      if (!res.ok()) throw new Error(`Invitation de ${PEOPLE[role].email} refusée : ${res.status()} ${await res.text()}`);
      const { token } = await res.json();
      const account = { ...PEOPLE[role], password: testPassword() };
      await register(ctx, id, account, { invite: token });
      accounts[role] = { ...account, id: "" };
    }
    const res = await api.get("/api/admin/users");
    if (!res.ok()) throw new Error(`Liste des comptes refusée : ${res.status()}`);
    const users: { id: string; email: string; role: string }[] = await res.json();
    for (const role of Object.keys(accounts) as Role[]) {
      const u = users.find((x) => x.email === accounts[role].email);
      if (!u || u.role !== role) throw new Error(`Compte ${accounts[role].email} absent ou de mauvais rôle après inscription.`);
      accounts[role].id = u.id;
    }
  } finally {
    await api.dispose();
  }
  return { baseURL: BASE_URL, freshURL: FRESH_URL, accounts };
}

/** Extensions déjà autorisées dans ce processus (identifiant de l'extension non empaquetée). */
const authorized = new Set<string>();

/**
 * Autorise l'extension de test auprès du serveur (réglage
 * extension.allowed_ids, GET /api/extension/allowed) : son identifiant
 * dépend du chemin de chargement et ne figure pas parmi les identifiants
 * officiels. Ajouter un identifiant abaisse la sécurité : le propriétaire
 * confirme son identité (POST /auth/reauth, action « settings »). Idempotent.
 */
async function authorizeExtension(ctx: BrowserContext, id: string, org: Org) {
  if (authorized.has(id)) return;
  const page = await ctx.newPage();
  try {
    await page.goto(`chrome-extension://${id}/offscreen.html`);
    await page.evaluate(async ({ base, owner, id }) => {
      const W = await import("./lib/wasm.js");
      await W.loadCrypto("lib/locksy.wasm");
      const api = await import("./lib/api.js");
      api.setBase(base);
      const V = await import("./lib/vault.js");
      await V.login({ email: owner.email, password: owner.password });
      const proof = await V.authProof(owner.password);
      const { data: current, etag } = await api.apiFull("GET", "/admin/settings");
      // Valeur brute ou { value, mode… } selon le réglage.
      const raw = current.values?.["extension.allowed_ids"];
      const ids: string[] = Array.isArray(raw) ? raw : Array.isArray(raw?.value) ? raw.value : [];
      if (ids.includes(id)) return;
      const { token } = await api.api("POST", "/auth/reauth", { action: "settings", auth_key: proof });
      await api.apiFull("PATCH", "/admin/settings", { changes: { "extension.allowed_ids": [...ids, id] } }, { ifMatch: etag.replace(/"/g, ""), reauth: token });
      await api.api("POST", "/auth/logout");
    }, { base: BASE_URL, owner: org.accounts.owner, id });
    authorized.add(id);
  } finally {
    await page.close();
  }
}

/** Organisation de test (créée par l'extension si personne ne l'a encore fait), extension autorisée. */
export async function organisation(ctx: BrowserContext, id: string): Promise<Org> {
  const org = (await once(statePath(ORG_FILE), () => bootstrap(ctx, id))).value;
  await authorizeExtension(ctx, id, org);
  return org;
}
