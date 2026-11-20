// Tests de vault.js avec le vrai module WebAssembly (dist/release/locksy.wasm)
// et un serveur simulé : épinglage KDF avant Argon2, codes wrong_password et
// key_mismatch, plan de rotation et épinglage des clés. Ignorés si le module
// n'a pas été compilé.
import { test, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const WASM = fileURLToPath(new URL("../../dist/release/locksy.wasm", import.meta.url));
const skip = existsSync(WASM) ? false : "dist/release/locksy.wasm absent (compiler locksy-wasm)";

let W, A, V, P;
let routes;
let calls;

/** Serveur simulé : routes « MÉTHODE /chemin » → (corps) => [statut, réponse]. */
async function fakeFetch(url, opts = {}) {
  if (String(url).endsWith("/locksy.wasm")) {
    return new Response(readFileSync(WASM), { headers: { "content-type": "application/wasm" } });
  }
  const path = String(url).replace(/^.*\/api/, "");
  const key = `${opts.method || "GET"} ${path}`;
  calls.push(key);
  const handler = routes[key];
  if (!handler) return new Response(JSON.stringify({ error: "not_found", message: key }), { status: 404 });
  const [status, body] = await handler(opts.body ? JSON.parse(opts.body) : undefined);
  if (status === 204) return new Response(null, { status });
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
}

// Paramètres minimaux acceptés par le noyau : tests rapides.
const salt = Buffer.alloc(16, 7).toString("base64url");
const WEAK = { alg: "argon2id", m_kib: 19 * 1024, t: 2, p: 1, salt };
const STRONG = { alg: "argon2id", m_kib: 64 * 1024, t: 3, p: 1, salt };
const EMAIL = "alice@exemple.fr";
const PASSWORD = "cheval agrafe batterie correct";
let account;

before(async () => {
  if (skip) return;
  globalThis.fetch = fakeFetch;
  W = await import("../js/wasm.js");
  A = await import("../js/aad.js");
  P = await import("../js/pins.js");
  V = await import("../js/vault.js");
  await W.loadCrypto("/locksy.wasm");
  // Compte de test chiffré comme le ferait register().
  const mk = W.call("derive_master", { password: PASSWORD, kdf: WEAK });
  const id = W.call("new_uuid");
  const userKey = W.call("generate_key");
  const kp = W.call("generate_keypair");
  account = {
    profile: {
      id, email: EMAIL, name: "Alice", role: "owner", kdf: WEAK, public_key: kp.public_key,
      wrapped_user_key: W.call("wrap", { wrapping: mk.enc_key, key: userKey, aad: A.userKey() }),
      wrapped_private_key: W.call("wrap", { wrapping: userKey, key: kp.private_key, aad: A.privateKey(id) }),
    },
    authKey: mk.auth_key,
  };
  W.call("drop_key", { key: mk.enc_key });
});

beforeEach(() => {
  if (skip) return;
  calls = [];
  P.setPinStorage(memoryStorage());
  routes = {
    "POST /auth/prelogin": () => [200, { kdf: account.profile.kdf }],
    "POST /auth/login": (b) => (b.auth_key === account.authKey ? [200, { token: "jeton", profile: account.profile }] : [401, { error: "invalid_credentials", message: "Identifiants incorrects." }]),
    "GET /me": () => [200, account.profile],
  };
});

test("connexion réussie : paramètres KDF épinglés", { skip }, async () => {
  const r = await V.login({ email: EMAIL, password: PASSWORD });
  assert.equal(r.needTotp, false);
  assert.ok(V.isUnlocked());
  // Le même compte annoncé plus faible est désormais refusé.
  assert.throws(() => P.checkKdf(EMAIL, { ...WEAK, t: 1 }), (e) => e.code === "kdf_downgrade");
  V.lock();
});

test("rétrogradation annoncée au prelogin : refus avant Argon2 et sans envoi", { skip }, async () => {
  P.pinKdf(EMAIL, STRONG);
  const t0 = Date.now();
  await assert.rejects(V.login({ email: EMAIL, password: PASSWORD }), (e) => e.code === "kdf_downgrade" && e.status === 0);
  assert.deepEqual(calls, ["POST /auth/prelogin"], "aucune preuve d'authentification envoyée");
  assert.ok(Date.now() - t0 < 2000);
});

test("rétrogradation après SSO (kdf fourni) : refus sans prelogin", { skip }, async () => {
  P.pinKdf(EMAIL, STRONG);
  await assert.rejects(V.login({ email: EMAIL, password: PASSWORD, ssoTicket: "t", kdf: WEAK }), (e) => e.code === "kdf_downgrade");
  assert.deepEqual(calls, []);
});

test("2FA demandée : kdf transmis dans pending, épinglé après finishLogin", { skip }, async () => {
  let n = 0;
  routes["POST /auth/login"] = (b) => (n++ === 0
    ? [401, { error: "totp_required", message: "Code requis." }]
    : b.totp === "123456" ? [200, { token: "jeton", profile: account.profile }] : [401, { error: "invalid_totp", message: "Code incorrect." }]);
  const r = await V.login({ email: EMAIL, password: PASSWORD });
  assert.equal(r.needTotp, true);
  assert.deepEqual(r.pending.kdf, WEAK);
  const done = await V.finishLogin(r.pending, "123456");
  assert.equal(done.needTotp, false);
  assert.throws(() => P.checkKdf(EMAIL, { ...WEAK, m_kib: 1024 }), (e) => e.code === "kdf_downgrade");
  V.lock();
});

test("déverrouillage : wrong_password par code, sans comparer le texte", { skip }, async () => {
  await assert.rejects(V.unlock("mauvais mot de passe"), (e) => e.code === "wrong_password" && e.status === 0 && e.message === "Mot de passe maître incorrect.");
  assert.equal(V.isUnlocked(), false);
  await V.unlock(PASSWORD);
  assert.ok(V.isUnlocked());
  V.lock();
});

test("déverrouillage : clé publique substituée → key_mismatch", { skip }, async () => {
  const other = W.call("generate_keypair");
  routes["GET /me"] = () => [200, { ...account.profile, public_key: other.public_key }];
  await assert.rejects(V.unlock(PASSWORD), (e) => e.code === "key_mismatch");
  assert.equal(V.isUnlocked(), false);
});

test("déverrouillage : paramètres affaiblis par le serveur → kdf_downgrade", { skip }, async () => {
  P.pinKdf(EMAIL, STRONG);
  await assert.rejects(V.unlock(PASSWORD), (e) => e.code === "kdf_downgrade");
});

test("plan de rotation : états new/same/changed, épinglage après succès, 409 sans épinglage", { skip }, async () => {
  await V.unlock(PASSWORD);
  const cid = W.call("new_uuid");
  V.state.collections = new Map([[cid, { id: cid, name: "Équipe", key: W.call("generate_key"), role: "manager" }]]);
  V.state.items = new Map();
  const bob = { user_id: "bob", name: "Bob", email: "bob@exemple.fr", role: "editor", public_key: W.call("generate_keypair").public_key };
  const carol = { user_id: "carol", name: "Carol", email: "carol@exemple.fr", role: "reader", public_key: W.call("generate_keypair").public_key };
  const me = { user_id: account.profile.id, name: "Alice", email: EMAIL, role: "manager", public_key: account.profile.public_key };
  routes[`GET /collections/${cid}/members`] = () => [200, [me, bob, carol]];

  // Premier plan : tout est nouveau, Carol est retirée.
  const plan = await V.planRotation(cid, ["carol"]);
  assert.deepEqual(plan.members.map((m) => [m.user_id, m.pin]), [[me.user_id, "same"], ["bob", "new"]]);
  assert.equal(plan.members[1].fingerprint, V.fingerprint(bob.public_key));

  // Conflit : la liste a changé côté serveur, rien n'est épinglé.
  routes[`POST /collections/${cid}/rotate`] = () => [409, { error: "conflict", message: "La liste des membres a changé. Rechargez puis recommencez." }];
  await assert.rejects(V.rotateCollection(cid, ["carol"], plan), (e) => e.status === 409);
  assert.equal(P.keyPinStatus("bob", bob.public_key), "new");

  // Succès : la nouvelle clé est scellée pour les membres du plan, puis épinglée.
  let sent = null;
  routes[`POST /collections/${cid}/rotate`] = (b) => { sent = b; return [204]; };
  await V.rotateCollection(cid, ["carol"], plan);
  assert.deepEqual(sent.members.map((m) => m.user_id), [me.user_id, "bob"]);
  assert.deepEqual(sent.remove_user_ids, ["carol"]);
  assert.equal(P.keyPinStatus("bob", bob.public_key), "same");

  // Clé de Bob substituée : signalée.
  const bob2 = { ...bob, public_key: W.call("generate_keypair").public_key };
  routes[`GET /collections/${cid}/members`] = () => [200, [me, bob2]];
  const plan2 = await V.planRotation(cid, []);
  assert.equal(plan2.members.find((m) => m.user_id === "bob").pin, "changed");

  // Notre propre clé substituée, ou nous absents de la liste : key_mismatch.
  routes[`GET /collections/${cid}/members`] = () => [200, [{ ...me, public_key: bob.public_key }, bob]];
  await assert.rejects(V.planRotation(cid, []), (e) => e.code === "key_mismatch");
  routes[`GET /collections/${cid}/members`] = () => [200, [bob]];
  await assert.rejects(V.planRotation(cid, []), (e) => e.code === "key_mismatch");
  V.lock();
});

test("ajout de membre : clé épinglée après le succès", { skip }, async () => {
  await V.unlock(PASSWORD);
  const cid = W.call("new_uuid");
  V.state.collections = new Map([[cid, { id: cid, name: "Équipe", key: W.call("generate_key"), role: "manager" }]]);
  const dave = { id: "dave", name: "Dave", email: "dave@exemple.fr", public_key: W.call("generate_keypair").public_key };
  routes[`POST /collections/${cid}/members`] = () => [500, { error: "internal", message: "Erreur interne." }];
  await assert.rejects(V.addMember(cid, dave, "reader"));
  assert.equal(P.keyPinStatus("dave", dave.public_key), "new");
  routes[`POST /collections/${cid}/members`] = () => [204];
  await V.addMember(cid, dave, "reader");
  assert.equal(P.keyPinStatus("dave", dave.public_key), "same");
  V.lock();
});
