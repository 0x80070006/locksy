// Tests de web/js/settings-client.js (cahier §4.1 et §4.9, contrat C4.2) :
// valeur effective (libre, défaut borné, imposé, poste plus strict), options
// des menus, politique du mot de passe maître, préférences chiffrées et
// conflit 409, réglages « cet appareil seulement ».
//   node --test tools/test
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

import * as S from "../../web/js/settings-client.js";

/** Serveur simulé : « MÉTHODE /chemin » -> (requête) => [statut, corps, en-têtes]. */
let routes = {};
let calls = [];
globalThis.fetch = async (url, opts = {}) => {
  const path = String(url).replace(/^.*\/api/, "");
  const key = `${opts.method || "GET"} ${path}`;
  calls.push({ key, headers: opts.headers || {}, body: opts.body ? JSON.parse(opts.body) : undefined });
  const handler = routes[key];
  if (!handler) return new Response(JSON.stringify({ error: "not_found", message: key }), { status: 404 });
  const [status, body, headers = {}] = await handler(calls.at(-1));
  if (status === 204 || status === 304) return new Response(null, { status, headers });
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
};

/** « Chiffrement » de test : JSON préfixé, pour vérifier qu'il est bien appelé. */
const fakeVault = {
  encryptPrefs: (doc) => `v1.test.${JSON.stringify(doc)}`,
  decryptPrefs: (cipher) => JSON.parse(cipher.replace(/^v1\.test\./, "")),
};

function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), m };
}

async function withPolicy(policy, revision = 1) {
  routes["GET /settings/policy"] = () => [200, { revision, policy }, { etag: `"r${revision}"` }];
  await S.loadPolicy();
}

async function withPrefs(doc, revision = 1) {
  routes["GET /me/prefs"] = () => [200, { revision, cipher: fakeVault.encryptPrefs(doc), updated_at: 1 }];
  await S.loadPrefs();
}

beforeEach(() => {
  routes = {};
  calls = [];
  S.configure({ vault: fakeVault, machine: {}, estimator: null, storage: memoryStorage() });
  S.reset();
});

// ------------------------------------------------------------------ effective

test("libre : sans politique ni préférence, défaut du registre", () => {
  const e = S.effective("client.autolock_minutes");
  assert.equal(e.value, 10);
  assert.equal(e.source, "default");
  assert.equal(e.mode, "free");
  assert.equal(S.effective("ui.theme").value, "system");
});

test("libre : la préférence de la personne l'emporte dans les bornes", async () => {
  await withPolicy({ "client.autolock_minutes": { value: 10, mode: "free", min: 1, max: 1440 } });
  await withPrefs({ lock: { minutes: 45 } });
  const e = S.effective("client.autolock_minutes");
  assert.deepEqual([e.value, e.source, e.clamped], [45, "user", false]);
});

test("défaut borné : une préférence hors bornes est ramenée et signalée une fois", async () => {
  await withPolicy({ "client.autolock_minutes": { value: 10, mode: "default", min: 1, max: 30 } });
  await withPrefs({ lock: { minutes: 240 } });
  const e = S.effective("client.autolock_minutes");
  assert.deepEqual([e.value, e.source, e.clamped, e.max], [30, "user", true, 30]);
  assert.equal(S.consumeClampNotice("client.autolock_minutes"), true);
  assert.equal(S.consumeClampNotice("client.autolock_minutes"), false);
});

test("défaut borné : sans préférence, la valeur proposée par l'organisation", async () => {
  await withPolicy({ "client.clipboard_clear_seconds": { value: 20, mode: "default", min: 5, max: 60 } });
  const e = S.effective("client.clipboard_clear_seconds");
  assert.deepEqual([e.value, e.source], [20, "policy"]);
});

test("imposé : la valeur de l'organisation, quelle que soit la préférence", async () => {
  await withPolicy({ "client.autolock_minutes": { value: 5, mode: "enforced", min: 5, max: 5 } });
  await withPrefs({ lock: { minutes: 60 } });
  const e = S.effective("client.autolock_minutes");
  assert.deepEqual([e.value, e.source, e.mode], [5, "policy", "enforced"]);
});

test("clé sans mode (valeur de l'organisation) : jamais remplacée par une préférence", async () => {
  await withPolicy({ "client.autolock_allow_never": { value: false }, "share.enabled": { value: true } });
  assert.equal(S.effective("client.autolock_allow_never").value, false);
  assert.equal(S.effective("share.enabled").source, "policy");
});

test("poste plus strict : la règle du poste l'emporte et le dit", async () => {
  await withPolicy({ "client.autolock_minutes": { value: 10, mode: "default", min: 1, max: 30 } });
  await withPrefs({ lock: { minutes: 20 } });
  S.configure({ machine: { "client.autolock_minutes": 5 } });
  let e = S.effective("client.autolock_minutes");
  assert.deepEqual([e.value, e.source], [5, "machine"]);
  // Poste moins strict que la personne : la préférence reste.
  S.configure({ machine: { "client.autolock_minutes": 25 } });
  e = S.effective("client.autolock_minutes");
  assert.deepEqual([e.value, e.source], [20, "user"]);
  // Plus strict même qu'une valeur imposée.
  await withPolicy({ "client.autolock_minutes": { value: 15, mode: "enforced" } }, 2);
  S.configure({ machine: { "client.autolock_minutes": 5 } });
  e = S.effective("client.autolock_minutes");
  assert.deepEqual([e.value, e.source], [5, "machine"]);
});

test("« Jamais » : refusé si l'organisation l'interdit, permis sinon", async () => {
  await withPolicy({
    "client.autolock_minutes": { value: 10, mode: "default", min: 1, max: 1440 },
    "client.autolock_allow_never": { value: true },
  });
  await withPrefs({ lock: { minutes: 0 } });
  assert.equal(S.effective("client.autolock_minutes").value, 0);
  await withPolicy({
    "client.autolock_minutes": { value: 10, mode: "default", min: 1, max: 30 },
    "client.autolock_allow_never": { value: false },
  }, 2);
  const e = S.effective("client.autolock_minutes");
  assert.deepEqual([e.value, e.clamped], [30, true]);
  // Poste qui verrouille : « Jamais » est le moins strict.
  S.configure({ machine: { "client.autolock_minutes": 0 } });
  assert.equal(S.effective("client.autolock_minutes").value, 30);
});

test("optionsFor : options hors bornes désactivées avec la raison", async () => {
  await withPolicy({
    "client.autolock_minutes": { value: 10, mode: "default", min: 5, max: 30 },
    "client.autolock_allow_never": { value: false },
  });
  const opts = S.optionsFor("client.autolock_minutes", [1, 5, 30, 60, 0]);
  assert.deepEqual(opts.map((o) => [o.value, o.disabled, o.reason]), [
    [1, true, "below_min"], [5, false, null], [30, false, null], [60, true, "above_max"], [0, true, "never_forbidden"],
  ]);
  assert.deepEqual(opts[3].params, { max: 30 });
  await withPolicy({ "client.autolock_minutes": { value: 15, mode: "enforced" } }, 2);
  assert.deepEqual(S.optionsFor("client.autolock_minutes", [10, 15]).map((o) => o.reason), ["enforced", null]);
  await withPolicy({ "client.autolock_minutes": { value: 10, mode: "free", min: 1, max: 1440 } }, 3);
  S.configure({ machine: { "client.autolock_minutes": 10 } });
  assert.deepEqual(S.optionsFor("client.autolock_minutes", [5, 10, 15]).map((o) => o.reason), [null, null, "machine"]);
});

test("serveur sans /settings/policy (404) : politique vide, défauts du registre", async () => {
  await S.loadPolicy();
  assert.equal(S.effective("client.clipboard_clear_seconds").value, 30);
});

test("loadPolicy : même révision, pas de requête ; 304 garde le cache", async () => {
  await withPolicy({ "client.lock_on_hide": { value: true, mode: "enforced" } }, 7);
  calls = [];
  await S.loadPolicy(7);
  assert.equal(calls.length, 0);
  routes["GET /settings/policy"] = () => [304, null];
  await S.loadPolicy(8);
  assert.equal(calls[0].headers["if-none-match"], "\"r7\"");
  assert.equal(S.effective("client.lock_on_hide").value, true);
});

// ------------------------------------------------------------------ préférences

test("défaut borné : document chargé sans ce choix, la valeur proposée par l'organisation", async () => {
  await withPolicy({ "client.autolock_minutes": { value: 15, mode: "default", min: 1, max: 60 } });
  await withPrefs({ ui: { theme: "dark" } });
  const e = S.effective("client.autolock_minutes");
  assert.deepEqual([e.value, e.source], [15, "policy"], "le défaut du document (10) n'est pas un choix de la personne");
  assert.equal(S.prefs().lock.minutes, 10, "le document affiché garde ses défauts");
  // Un choix explicite, lui, l'emporte dans les bornes.
  routes["PUT /me/prefs"] = () => [200, { revision: 2 }];
  await S.savePrefs({ lock: { minutes: 5 } });
  assert.deepEqual([S.effective("client.autolock_minutes").value, S.effective("client.autolock_minutes").source], [5, "user"]);
});

test("savePrefs : seuls les choix explicites sont enregistrés", async () => {
  routes["GET /me/prefs"] = () => [404, { error: "not_found", message: "x" }];
  await S.loadPrefs();
  routes["PUT /me/prefs"] = () => [200, { revision: 1 }];
  await S.savePrefs({ lock: { minutes: 15 } });
  const envoye = fakeVault.decryptPrefs(calls.find((c) => c.key === "PUT /me/prefs").body.cipher);
  assert.deepEqual(envoye, { v: 1, lock: { minutes: 15 } });
});

test("savePrefs : chiffre, envoie If-Match et fusionne", async () => {
  routes["GET /me/prefs"] = () => [404, { error: "not_found", message: "x" }];
  await S.loadPrefs();
  routes["PUT /me/prefs"] = (req) => [200, { revision: 1 }];
  const doc = await S.savePrefs({ lock: { minutes: 15 } });
  assert.equal(doc.lock.minutes, 15);
  assert.equal(doc.lock.on_hide, false, "les autres valeurs du document restent");
  const put = calls.find((c) => c.key === "PUT /me/prefs");
  assert.equal(put.headers["if-match"], "\"0\"");
  assert.match(put.body.cipher, /^v1\.test\./);
  assert.equal(S.effective("client.autolock_minutes").value, 15);
});

test("savePrefs : 409 recharge le document du serveur, refusionne et réessaie une fois", async () => {
  await withPrefs({ lock: { minutes: 10 }, favorites: ["a"] }, 2);
  let puts = 0;
  routes["PUT /me/prefs"] = (req) => {
    puts += 1;
    if (req.headers["if-match"] === "\"2\"") return [409, { error: "prefs_conflict", message: "conflit" }];
    return [200, { revision: 4 }];
  };
  // Un autre appareil a ajouté un favori (révision 3).
  routes["GET /me/prefs"] = () => [200, { revision: 3, cipher: fakeVault.encryptPrefs({ lock: { minutes: 10 }, favorites: ["a", "b"] }), updated_at: 2 }];
  const doc = await S.savePrefs({ lock: { minutes: 5 } });
  assert.equal(puts, 2);
  assert.deepEqual(doc.favorites, ["a", "b"]);
  assert.equal(doc.lock.minutes, 5);
  assert.equal(calls.filter((c) => c.key === "PUT /me/prefs").at(-1).headers["if-match"], "\"3\"");
});

test("savePrefs : second conflit remonté, document local inchangé", async () => {
  await withPrefs({ lock: { minutes: 10 } }, 2);
  routes["PUT /me/prefs"] = () => [409, { error: "prefs_conflict", message: "conflit" }];
  await assert.rejects(S.savePrefs({ lock: { minutes: 5 } }), (e) => e.status === 409);
  assert.equal(S.prefs().lock.minutes, 10);
});

test("loadPrefs(révision) : 0 = aucun document, aucune requête ; même révision = cache", async () => {
  await S.loadPrefs(0);
  assert.equal(calls.length, 0, "révision 0 annoncée par /sync : pas de GET (ni 404 dans la console)");
  assert.equal(S.prefs().lock.minutes, 10);
  await withPrefs({ lock: { minutes: 7 } }, 3);
  calls = [];
  await S.loadPrefs(3);
  assert.equal(calls.length, 0, "révision déjà en mémoire");
  routes["GET /me/prefs"] = () => [200, { revision: 4, cipher: fakeVault.encryptPrefs({ lock: { minutes: 9 } }), updated_at: 2 }];
  await S.loadPrefs(4);
  assert.equal(calls.length, 1);
  assert.equal(S.effective("client.autolock_minutes").value, 9);
});

test("aucun document sur le serveur : l'affichage choisi sur cet appareil est gardé", async () => {
  const store = memoryStorage();
  S.configure({ storage: store });
  S.localOnly("ui.theme", "dark");
  routes["GET /me/prefs"] = () => [404, { error: "not_found", message: "x" }];
  await S.loadPrefs();
  assert.equal(S.effective("ui.theme").value, "dark");
  assert.equal(JSON.parse(store.getItem("locksy.local"))["ui.theme"], "dark");
  S.reset();
  await S.loadPrefs(0);
  assert.equal(S.prefs().ui.theme, "dark", "repris dans le document, synchronisé au premier enregistrement");
});

test("sans chiffrement disponible : préférences en mémoire seulement, aucune requête", async () => {
  S.configure({ vault: null });
  const doc = await S.savePrefs({ lock: { minutes: 15 } });
  assert.equal(doc.lock.minutes, 15);
  assert.equal(calls.length, 0);
});

test("préférences d'affichage recopiées sur l'appareil, jamais le reste", async () => {
  const store = memoryStorage();
  S.configure({ storage: store });
  await withPrefs({ ui: { theme: "dark" }, favorites: ["secret-id"], links: { s1: { item_id: "i", label: "NAS" } } });
  const local = JSON.parse(store.getItem("locksy.local"));
  assert.equal(local["ui.theme"], "dark");
  assert.doesNotMatch(store.getItem("locksy.local"), /secret-id|NAS/);
});

test("apparence propre à l'appareil (prefs.sync=false) : le document ne la remplace pas", async () => {
  const store = memoryStorage();
  S.configure({ storage: store });
  S.localOnly("prefs.sync", false);
  S.localOnly("ui.theme", "dark");
  await withPrefs({ ui: { theme: "light" } });
  // Lecture : la valeur de l'appareil l'emporte ; rien n'est recopié dessus.
  assert.equal(S.effective("ui.theme").value, "dark");
  assert.equal(JSON.parse(store.getItem("locksy.local"))["ui.theme"], "dark");
  // Un enregistrement du document ne touche pas non plus l'appareil.
  routes["PUT /me/prefs"] = () => [200, { revision: 2 }];
  await S.savePrefs({ lock: { minutes: 15 } });
  assert.equal(S.effective("ui.theme").value, "dark");
  assert.equal(S.prefs().ui.theme, "light", "document inchangé");
  // Synchronisation rétablie : le document reprend la main.
  S.localOnly("prefs.sync", null);
  assert.equal(S.effective("ui.theme").value, "light");
});

// ------------------------------------------------------------------ localOnly

test("localOnly : clés autorisées seulement, stockage en panne toléré", () => {
  assert.throws(() => S.localOnly("favorites", ["x"]), RangeError);
  S.localOnly("auth.last_email", "camille@acme.fr");
  assert.equal(S.localOnly("auth.last_email"), "camille@acme.fr");
  S.localOnly("auth.last_email", null);
  assert.equal(S.localOnly("auth.last_email"), undefined);
  S.configure({ storage: { getItem() { throw new Error("SecurityError"); }, setItem() { throw new Error("QuotaExceededError"); } } });
  assert.doesNotThrow(() => S.localOnly("ui.theme", "dark"));
  assert.equal(S.localOnly("ui.theme"), undefined);
});

test("subscribe : appelé à chaque changement de la valeur effective, puis désabonné", async () => {
  const seen = [];
  const off = S.subscribe("client.autolock_minutes", (e) => seen.push(e.value));
  await withPolicy({ "client.autolock_minutes": { value: 5, mode: "enforced" } });
  await withPolicy({ "client.autolock_minutes": { value: 5, mode: "enforced" } }, 2);
  off();
  await withPolicy({ "client.autolock_minutes": { value: 3, mode: "enforced" } }, 3);
  assert.deepEqual(seen, [5]);
});

// ------------------------------------------------------------------ mot de passe maître

test("checkMasterPolicy : longueur, score, identité, mots interdits", async () => {
  routes["GET /settings/public"] = () => [200, {
    master_password: { min_length: 14, min_score: 3, forbid_identity: true, banned_words: ["acme"] },
  }];
  await S.loadPublic({ force: true });
  S.configure({ estimator: (pw) => ({ score: pw.length >= 20 ? 4 : 1 }) });
  const codes = (pw, who = {}) => S.checkMasterPolicy(pw, who).problems.map((p) => p.code);
  assert.deepEqual(codes(""), ["empty"]);
  assert.deepEqual(codes("court"), ["too_short", "too_weak"]);
  assert.deepEqual(S.checkMasterPolicy("court").problems[0].params, { min: 14 });
  assert.deepEqual(codes("Camille-et-les-nuages-du-soir", { email: "camille.durand@acme.fr", name: "Camille Durand" }), ["contains_identity"]);
  assert.deepEqual(codes("Durand-et-les-nuages-du-soir", { email: "c.durand@acme.fr" }), ["contains_identity"]);
  assert.deepEqual(codes("Les-nuages-ACMÉ-du-soir-tombent"), ["banned_word"]);
  const ok = S.checkMasterPolicy("Les-nuages-du-soir-tombent-vite", { email: "camille@acme.fr", name: "Camille" });
  assert.deepEqual(ok, { ok: true, problems: [] });
});

test("checkMasterPolicy : serveur sans /settings/public, 12 caractères au moins", async () => {
  assert.equal(await S.loadPublic({ force: true }), null);
  assert.deepEqual(S.checkMasterPolicy("onze-caract").problems.map((p) => p.code), ["too_short"]);
  assert.equal(S.checkMasterPolicy("douze-caract").ok, true);
});
