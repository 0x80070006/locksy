// Tests des ajouts de vault.js en vague 2 (contrat C4.4), avec le vrai module
// WebAssembly (dist/release/locksy.wasm) et un serveur simulé :
// préférences chiffrées liées au compte (AAD verrou:v1:prefs:<id>), preuve du
// mot de passe maître, synchronisation incrémentale, refus rekey_required,
// lien sécurisé avec preuve de possession, limites des pièces jointes lues
// dans la politique. Ignorés si le module n'a pas été compilé.
import { test, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const WASM = fileURLToPath(new URL("../../dist/release/locksy.wasm", import.meta.url));
const skip = existsSync(WASM) ? false : "dist/release/locksy.wasm absent (compiler locksy-wasm)";

let W, A, V, S;
let routes;
let calls;

/** Serveur simulé : routes « MÉTHODE /chemin?requête » → (corps) => [statut, réponse]. */
async function fakeFetch(url, opts = {}) {
  if (String(url).endsWith("/locksy.wasm")) {
    return new Response(readFileSync(WASM), { headers: { "content-type": "application/wasm" } });
  }
  const path = String(url).replace(/^.*\/api/, "");
  const key = `${opts.method || "GET"} ${path}`;
  const body = opts.body ? JSON.parse(opts.body) : undefined;
  calls.push({ key, body, headers: opts.headers || {} });
  const handler = routes[key];
  if (!handler) return new Response(JSON.stringify({ error: "not_found", message: key }), { status: 404 });
  const [status, res, headers = {}] = await handler(body);
  if (status === 204) return new Response(null, { status });
  return new Response(JSON.stringify(res), { status, headers: { "content-type": "application/json", ...headers } });
}

const salt = Buffer.alloc(16, 7).toString("base64url");
const KDF = { alg: "argon2id", m_kib: 19 * 1024, t: 2, p: 1, salt };
const PASSWORD = "cheval agrafe batterie correct";
let account;
let col;

before(async () => {
  if (skip) return;
  globalThis.fetch = fakeFetch;
  W = await import("../js/wasm.js");
  A = await import("../js/aad.js");
  V = await import("../js/vault.js");
  S = await import("../js/settings-client.js");
  (await import("../js/api.js")).setBase("https://locksy.exemple.fr");
  await W.loadCrypto("/locksy.wasm");
  const mk = W.call("derive_master", { password: PASSWORD, kdf: KDF });
  const id = W.call("new_uuid");
  const userKey = W.call("generate_key");
  const kp = W.call("generate_keypair");
  account = {
    profile: {
      id, email: "alice@exemple.fr", name: "Alice", role: "user", kdf: KDF, public_key: kp.public_key,
      wrapped_user_key: W.call("wrap", { wrapping: mk.enc_key, key: userKey, aad: A.userKey() }),
      wrapped_private_key: W.call("wrap", { wrapping: userKey, key: kp.private_key, aad: A.privateKey(id) }),
    },
    authKey: mk.auth_key,
    privKey: kp.private_key,
  };
  W.call("drop_key", { key: mk.enc_key });
});

/** Coffre chiffré pour le compte de test : { id, key, view(kv) }. */
function makeCollection(name = "Équipe") {
  const id = W.call("new_uuid");
  const key = W.call("generate_key");
  const pub = account.profile.public_key;
  const view = (keyVersion = 1, k = key) => ({
    id, personal: false, role: "manager", member_count: 2, updated_at: 1,
    enc_name: W.call("encrypt", { key: k, plaintext: name, aad: A.collectionName(id) }),
    sealed_key: W.call("seal", { public_key: pub, key: k, context: A.collectionKey(id, account.profile.id) }),
    key_version: keyVersion, rotation_suggested_at: null,
  });
  return { id, key, view };
}

function itemView(c, id, data, { revision = 1, key = c.key, deleted_at = null } = {}) {
  return {
    id, collection_id: c.id, revision, created_at: 1, updated_at: 1, deleted_at, deleted_by: null, purge_at: null,
    data: W.call("encrypt", { key, plaintext: JSON.stringify(data), aad: A.item(c.id, id) }),
  };
}

beforeEach(async () => {
  if (skip) return;
  calls = [];
  routes = { "GET /me": () => [200, account.profile] };
  S.reset();
  // Verrouillage d'abord : position de synchronisation et clés oubliées entre deux tests.
  if (V.isUnlocked()) V.lock();
  await V.unlock(PASSWORD);
  col = makeCollection();
});

// ------------------------------------------------------------ Préférences chiffrées

test("préférences : aller-retour chiffré, AAD liée au compte", { skip }, () => {
  const doc = { v: 1, favorites: ["i1", "i2"], links: { s1: { item_id: "i1", label: "Serveur NAS" } } };
  const cipher = V.encryptPrefs(doc);
  assert.match(cipher, /^v1\./);
  assert.ok(!cipher.includes("Serveur"), "le chiffré ne contient pas le nom en clair");
  assert.deepEqual(V.decryptPrefs(cipher), doc);
  // Même clé, autre compte annoncé : l'AAD diffère, le déchiffrement échoue.
  const real = V.state.profile;
  V.state.profile = { ...real, id: W.call("new_uuid") };
  try {
    assert.throws(() => V.decryptPrefs(cipher));
  } finally {
    V.state.profile = real;
  }
  // Un élément chiffré avec la même clé mais une autre AAD n'est pas accepté comme préférences.
  const other = W.call("encrypt", { key: V.state.userKey, plaintext: JSON.stringify(doc), aad: A.userKey() });
  assert.throws(() => V.decryptPrefs(other));
  V.lock();
  assert.throws(() => V.encryptPrefs(doc), (e) => e.code === "unauthorized");
  assert.throws(() => V.decryptPrefs(cipher), (e) => e.code === "unauthorized");
});

test("préférences : settings-client enregistre un chiffré que seul ce compte relit", { skip }, async () => {
  let stored = null;
  routes["GET /me/prefs"] = () => (stored ? [200, { revision: 3, cipher: stored, updated_at: 1 }] : [404, { error: "not_found", message: "Aucun document." }]);
  routes["PUT /me/prefs"] = (b) => { stored = b.cipher; return [200, { revision: 4 }]; };
  S.configure({ vault: V });
  await S.loadPrefs();
  await S.savePrefs({ favorites: ["x"] });
  assert.ok(stored && !stored.includes("favorites"));
  assert.deepEqual(V.decryptPrefs(stored).favorites, ["x"]);
  S.reset();
  const doc = await S.loadPrefs();
  assert.deepEqual(doc.favorites, ["x"]);
  S.configure({ vault: null });
});

test("authProof : preuve du mot de passe maître vérifiée localement", { skip }, async () => {
  assert.equal(await V.authProof(PASSWORD), account.authKey);
  await assert.rejects(V.authProof("pas le bon"), (e) => e.code === "wrong_password" && e.status === 0);
  assert.deepEqual(calls.filter((c) => c.key !== "GET /me"), [], "aucun envoi");
});

// ------------------------------------------------------------ Synchronisation

test("sync : complet puis incrémental (changés, retirés, coffre retiré)", { skip }, async () => {
  const other = makeCollection("Autre");
  const a = { ...V.emptyItem("login"), name: "Société A" };
  const b = { ...V.emptyItem("note"), name: "B" };
  const c = { ...V.emptyItem("note"), name: "C" };
  routes["GET /sync"] = () => [200, {
    profile: account.profile, server_time: 10, seq: 7, full: true, policy_revision: 2, prefs_revision: 5,
    removed: { items: [], collections: [] },
    collections: [col.view(), other.view()],
    items: [itemView(col, "a", a), itemView(col, "b", b), itemView(other, "c", c)],
  }];
  assert.deepEqual(await V.sync(), { full: true, seq: 7 });
  assert.equal(V.state.items.size, 3);
  assert.deepEqual(V.state.revisions, { policy: 2, prefs: 5 });
  assert.equal(V.state.collections.get(col.id).key_version, 1);

  const a2 = { ...a, username: "camille" };
  routes["GET /sync?since=7"] = () => [200, {
    profile: account.profile, server_time: 11, seq: 9, full: false, policy_revision: 2, prefs_revision: 6,
    removed: { items: ["b"], collections: [other.id] },
    collections: [], items: [itemView(col, "a", a2, { revision: 2 })],
  }];
  assert.deepEqual(await V.sync(), { full: false, seq: 9 });
  assert.deepEqual([...V.state.items.keys()], ["a"]);
  assert.equal(V.state.items.get("a").data.username, "camille");
  assert.equal(V.state.items.get("a").revision, 2);
  assert.ok(!V.state.collections.has(other.id));
  assert.equal(V.state.revisions.prefs, 6);

  // Position trop ancienne : le serveur répond complet, tout est remplacé.
  routes["GET /sync?since=9"] = () => [200, {
    profile: account.profile, server_time: 12, seq: 12, full: true, removed: { items: [], collections: [] },
    collections: [col.view()], items: [itemView(col, "d", c)],
  }];
  assert.deepEqual(await V.sync(), { full: true, seq: 12 });
  assert.deepEqual([...V.state.items.keys()], ["d"]);
  // Demande explicite d'une synchronisation complète : pas de since.
  routes["GET /sync"] = () => [200, { profile: account.profile, server_time: 13, seq: 13, full: true, collections: [col.view()], items: [] }];
  await V.sync({ incremental: false });
  assert.equal(calls.at(-1).key, "GET /sync");
  V.lock();
  // Après verrouillage, la position est oubliée.
  await V.unlock(PASSWORD);
  const fresh = makeCollection();
  routes["GET /sync"] = () => [200, { profile: account.profile, server_time: 14, seq: 14, full: true, collections: [fresh.view()], items: [] }];
  await V.sync();
  assert.equal(calls.at(-1).key, "GET /sync");
});

test("sync : serveur sans seq (1.0) → jamais de since", { skip }, async () => {
  routes["GET /sync"] = () => [200, { profile: account.profile, server_time: 1, collections: [col.view()], items: [itemView(col, "a", V.emptyItem())] }];
  await V.sync();
  await V.sync();
  assert.deepEqual(calls.filter((c) => c.key.startsWith("GET /sync")).map((c) => c.key), ["GET /sync", "GET /sync"]);
  assert.deepEqual(V.state.revisions, { policy: null, prefs: null });
});

test("sync : au-delà de 10 000 éléments, avancement par lots de 500", { skip }, async () => {
  const data = { ...V.emptyItem("note"), name: "x" };
  const one = itemView(col, "x", data);
  const items = Array.from({ length: 10_001 }, (_, i) => ({ ...one, id: `i${i}`, data: W.call("encrypt", { key: col.key, plaintext: JSON.stringify(data), aad: A.item(col.id, `i${i}`) }) }));
  routes["GET /sync"] = () => [200, { profile: account.profile, server_time: 1, collections: [col.view()], items }];
  const seen = [];
  await V.sync({ onProgress: (p) => seen.push(p.done) });
  assert.equal(V.state.items.size, 10_001);
  assert.equal(seen.length, 21);
  assert.equal(seen[0], 500);
  assert.equal(seen.at(-1), 10_001);
});

// ------------------------------------------------------------ Rotation pendant l'édition

test("rekey_required : resynchronisation puis nouvel envoi avec la nouvelle clé", { skip }, async () => {
  const data = { ...V.emptyItem("login"), name: "Serveur NAS", password: "a" };
  routes["GET /sync"] = () => [200, { profile: account.profile, server_time: 1, seq: 1, full: true, collections: [col.view(1)], items: [itemView(col, "n", data)] }];
  await V.sync();
  const item = V.state.items.get("n");
  // Rotation faite ailleurs : nouvelle clé, version 2, révision 2.
  const newKey = W.call("generate_key");
  routes["GET /sync?since=1"] = () => [200, { profile: account.profile, server_time: 2, seq: 2, full: false, removed: { items: [], collections: [] },
    collections: [col.view(2, newKey)], items: [itemView(col, "n", data, { revision: 2, key: newKey })] }];
  const puts = [];
  routes["PUT /items/n"] = (b) => {
    puts.push(b);
    return b.key_version === 2 ? [200, 3] : [409, { error: "rekey_required", message: "Clé renouvelée.", collection_id: col.id, key_version: 2 }];
  };
  const out = { ...data, password: "b" };
  assert.equal(await V.updateItem(item, out), 3);
  assert.deepEqual(puts.map((p) => [p.key_version, p.revision]), [[1, 1], [2, 2]]);
  const plain = JSON.parse(W.call("decrypt", { key: newKey, data: puts[1].data, aad: A.item(col.id, "n") }));
  assert.equal(plain.password, "b");

  // Création : même reprise.
  const posts = [];
  routes["POST /items"] = (b) => { posts.push(b.key_version); return b.key_version === 3 ? [200, null] : [409, { error: "rekey_required", message: "Clé renouvelée." }]; };
  routes["GET /sync?since=2"] = () => [200, { profile: account.profile, server_time: 3, seq: 3, full: false, removed: { items: [], collections: [] }, collections: [col.view(3, newKey)], items: [] }];
  await V.createItem(col.id, data);
  assert.deepEqual(posts, [2, 3]);
});

test("rekey_required : contenu modifié entre-temps → refus rendu, pas d'écrasement", { skip }, async () => {
  const data = { ...V.emptyItem("login"), name: "Wi-Fi", password: "a" };
  routes["GET /sync"] = () => [200, { profile: account.profile, server_time: 1, seq: 1, full: true, collections: [col.view(1)], items: [itemView(col, "w", data)] }];
  await V.sync();
  const item = V.state.items.get("w");
  routes["GET /sync?since=1"] = () => [200, { profile: account.profile, server_time: 2, seq: 2, full: false, removed: { items: [], collections: [] },
    collections: [col.view(2)], items: [itemView(col, "w", { ...data, password: "autre" }, { revision: 2 })] }];
  let n = 0;
  routes["PUT /items/w"] = () => { n++; return [409, { error: "rekey_required", message: "Clé renouvelée." }]; };
  await assert.rejects(V.updateItem(item, { ...data, password: "mien" }), (e) => e.code === "rekey_required");
  assert.equal(n, 1);
});

// ------------------------------------------------------------ Liens sécurisés

test("lien sécurisé : preuve de possession si le module la fournit, élément rattaché", { skip }, async () => {
  let sent = null;
  routes["POST /shares"] = (b) => { sent = b; return [200, { id: "s1", expires_at: 99 }]; };
  const res = await V.createShareLink({ password: "x" }, 60, 1, { itemId: "i1", collectionId: col.id });
  assert.equal(res.id, "s1");
  assert.equal(sent.item_id, "i1");
  assert.equal(sent.collection_id, col.id);
  assert.equal(sent.expires_in_minutes, 60);
  const fragment = res.url.split("#")[1];
  let hasOp = true;
  try { W.call("share_proof", { key: "abc" }); } catch { hasOp = false; }
  if (hasOp) {
    const proof = createHash("sha256").update(fragment, "utf8").digest();
    assert.equal(sent.verifier, createHash("sha256").update(proof).digest("hex"));
    assert.equal(res.verified, true);
  } else {
    assert.equal(sent.verifier, undefined);
    assert.equal(res.verified, false);
  }
  // La charge chiffrée ne contient que ce qui a été donné.
  const key = W.call("import_key", { key: fragment });
  assert.deepEqual(JSON.parse(W.call("decrypt", { key, data: sent.data, aad: A.share() })), { password: "x" });
});

// ------------------------------------------------------------ Pièces jointes

test("pièces jointes : limites lues dans la politique, refus avant chiffrement", { skip }, async () => {
  assert.deepEqual(V.attachmentLimits(), { enabled: true, maxFileMib: 10, maxFileBytes: 10 * 1024 * 1024, maxPerItem: 20 });
  routes["GET /settings/policy"] = () => [200, { revision: 1, policy: {
    "attachment.enabled": { value: true }, "attachment.max_file_mib": { value: 1 }, "attachment.max_per_item": { value: 1 },
  } }];
  await S.loadPolicy();
  assert.deepEqual(V.attachmentLimits(), { enabled: true, maxFileMib: 1, maxFileBytes: 1024 * 1024, maxPerItem: 1 });
  const item = { id: "i", collection_id: col.id, data: { ...V.emptyItem(), attachments: [] } };
  const big = { size: 2 * 1024 * 1024, name: "gros.bin", type: "", arrayBuffer: async () => new ArrayBuffer(0) };
  await assert.rejects(V.addAttachment(item, big), (e) => e.code === "attachment_too_large");
  const full = { ...item, data: { ...item.data, attachments: [{ id: "a" }] } };
  await assert.rejects(V.addAttachment(full, { ...big, size: 10 }), (e) => e.code === "attachment_limit");
  routes["GET /settings/policy"] = () => [200, { revision: 2, policy: { "attachment.enabled": { value: false } } }];
  await S.loadPolicy(2);
  await assert.rejects(V.addAttachment(item, { ...big, size: 10 }), (e) => e.code === "attachments_disabled");
  assert.ok(!calls.some((c) => c.key.startsWith("PUT /items/i/attachments")), "rien n'est envoyé");
});

test("modèle : plus de favori dans l'élément, SSH complet, remplissage du code", { skip }, () => {
  const d = V.emptyItem("ssh");
  assert.ok(!("favorite" in d));
  assert.deepEqual(Object.keys(d.ssh).sort(), ["host", "passphrase", "password", "port", "private_key", "public_key", "username"]);
  assert.equal(typeof d.ssh.port, "string");
  assert.equal(d.totp_fill, false);
});

// ------------------------------------------------------------ Intégration (fin de vague 2)

test("importItems : identifiants créés dans l'ordre de la liste, lots de 500", { skip }, async () => {
  routes["GET /sync"] = () => [200, { profile: account.profile, server_time: 1, seq: 1, full: true, collections: [col.view(1)], items: [] }];
  await V.sync();
  const lots = [];
  routes["POST /items/batch"] = (b) => { lots.push(b.items.map((i) => i.id)); return [200, null]; };
  const list = Array.from({ length: 502 }, (_, n) => ({ ...V.emptyItem("login"), name: `n${n}` }));
  const ids = await V.importItems(col.id, list);
  assert.equal(ids.length, 502);
  assert.deepEqual(lots.map((l) => l.length), [500, 2]);
  assert.deepEqual(ids, lots.flat());
  // Le favori ne voyage pas dans l'élément : l'appelant le range par identifiant.
  assert.ok(lots.flat().every((id) => typeof id === "string" && id.length === 36));
});

test("changePassword et rotateRecovery : code de vérification transmis si fourni", { skip }, async () => {
  const bodies = [];
  routes["POST /me/password"] = (b) => { bodies.push(b); return [200, {}]; };
  routes["POST /me/recovery"] = (b) => { bodies.push(b); return [204]; };
  await V.changePassword(PASSWORD, PASSWORD, { totp: "123456" });
  await V.rotateRecovery(PASSWORD, { totp: "ABCDE-FGHJK" });
  await V.rotateRecovery(PASSWORD);
  assert.deepEqual(bodies.map((b) => b.totp), ["123456", "ABCDE-FGHJK", undefined]);
});
