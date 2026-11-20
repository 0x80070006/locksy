// Tests de l'épinglage local (web/js/pins.js) : node --test web/tests/
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { setPinStorage, checkKdf, pinKdf, keyPinStatus, pinKey, normEmail } from "../js/pins.js";

/** Stockage en mémoire, même interface que localStorage. */
function memoryStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
    dump: () => m,
  };
}

const KDF = { alg: "argon2id", m_kib: 65536, t: 3, p: 1, salt: "c2Vs" };
let store;

beforeEach(() => {
  store = memoryStorage();
  setPinStorage(store);
});

const downgrade = (fn) => assert.throws(fn, (e) => e.code === "kdf_downgrade" && e.status === 0 && /Connexion bloquée/.test(e.message));

test("sans épinglage, tout paramètre est accepté", () => {
  assert.doesNotThrow(() => checkKdf("a@b.fr", KDF));
  assert.doesNotThrow(() => checkKdf("a@b.fr", { ...KDF, m_kib: 19456, t: 2 }));
});

test("paramètres égaux à l'épinglage : accepté", () => {
  pinKdf("a@b.fr", KDF);
  assert.doesNotThrow(() => checkKdf("a@b.fr", KDF));
  assert.doesNotThrow(() => checkKdf("a@b.fr", { ...KDF, m_kib: 131072, t: 4 }));
});

test("mémoire ou passes plus faibles : kdf_downgrade", () => {
  pinKdf("a@b.fr", KDF);
  downgrade(() => checkKdf("a@b.fr", { ...KDF, m_kib: 32768 }));
  downgrade(() => checkKdf("a@b.fr", { ...KDF, t: 2 }));
  // Le message cite les deux jeux de paramètres, en Mio.
  try { checkKdf("a@b.fr", { ...KDF, m_kib: 19456, t: 2 }); } catch (e) {
    assert.match(e.message, /\(19 Mio, 2 passes\)/);
    assert.match(e.message, /\(64 Mio, 3 passes\)/);
  }
});

test("algorithme différent ou paramètres absents : refus", () => {
  pinKdf("a@b.fr", KDF);
  downgrade(() => checkKdf("a@b.fr", { ...KDF, alg: "pbkdf2" }));
  downgrade(() => checkKdf("a@b.fr", null));
  downgrade(() => checkKdf("a@b.fr", {}));
});

test("pinKdf garde le maximum vu", () => {
  pinKdf("a@b.fr", { ...KDF, m_kib: 131072, t: 2 });
  pinKdf("a@b.fr", { ...KDF, m_kib: 65536, t: 4 });
  const pins = JSON.parse(store.getItem("locksy.kdfpins"));
  assert.deepEqual(pins["a@b.fr"], { m_kib: 131072, t: 4, p: 1 });
  downgrade(() => checkKdf("a@b.fr", { ...KDF, m_kib: 131072, t: 3 }));
  downgrade(() => checkKdf("a@b.fr", { ...KDF, m_kib: 65536, t: 4 }));
});

test("pinKdf ignore un algorithme inconnu ; replace remplace l'épinglage", () => {
  pinKdf("a@b.fr", { ...KDF, alg: "scrypt", m_kib: 999999 });
  assert.equal(store.getItem("locksy.kdfpins"), null);
  pinKdf("a@b.fr", { ...KDF, m_kib: 131072 });
  pinKdf("a@b.fr", KDF, { replace: true });
  assert.doesNotThrow(() => checkKdf("a@b.fr", KDF));
});

test("adresse normalisée : casse et espaces ignorés", () => {
  assert.equal(normEmail("  Jean.Dupont@Exemple.FR "), "jean.dupont@exemple.fr");
  pinKdf(" Jean.Dupont@Exemple.FR", KDF);
  downgrade(() => checkKdf("jean.dupont@exemple.fr", { ...KDF, t: 1 }));
  assert.ok(JSON.parse(store.getItem("locksy.kdfpins"))["jean.dupont@exemple.fr"]);
});

test("keyPinStatus : new, same puis changed", () => {
  assert.equal(keyPinStatus("u1", "PK1"), "new");
  pinKey("u1", "PK1", "u1@b.fr");
  assert.equal(keyPinStatus("u1", "PK1"), "same");
  assert.equal(keyPinStatus("u1", "PK2"), "changed");
  assert.equal(keyPinStatus("u2", "PK1"), "new");
  const pin = JSON.parse(store.getItem("locksy.keypins")).u1;
  assert.equal(pin.public_key, "PK1");
  assert.equal(pin.email, "u1@b.fr");
  assert.ok(Number.isInteger(pin.pinned_at));
  // Après vérification, la nouvelle clé devient la référence.
  pinKey("u1", "PK2", "u1@b.fr");
  assert.equal(keyPinStatus("u1", "PK2"), "same");
});

test("stockage qui lève une exception : aucun plantage, épinglage inactif", () => {
  const broken = { getItem() { throw new Error("SecurityError"); }, setItem() { throw new Error("QuotaExceededError"); } };
  setPinStorage(broken);
  assert.doesNotThrow(() => pinKdf("a@b.fr", KDF));
  assert.doesNotThrow(() => checkKdf("a@b.fr", { ...KDF, m_kib: 1 }));
  assert.doesNotThrow(() => pinKey("u1", "PK1", "x"));
  assert.equal(keyPinStatus("u1", "PK1"), "new");
});

test("contenu de stockage corrompu : ignoré", () => {
  store.setItem("locksy.kdfpins", "{pas du json");
  store.setItem("locksy.keypins", "[1,2]");
  assert.doesNotThrow(() => checkKdf("a@b.fr", KDF));
  assert.equal(keyPinStatus("u1", "PK1"), "new");
  pinKdf("a@b.fr", KDF);
  downgrade(() => checkKdf("a@b.fr", { ...KDF, t: 1 }));
});
