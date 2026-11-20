// Tests du worker d'import (web/js/import-worker.js) : protocole de messages
// (contrat C1.7) avec un noyau simulé, puis bout en bout avec le vrai module
// WebAssembly (dist/release/locksy-import.wasm, ou locksy.wasm s'il contient
// l'import) sur un export JSON chiffré fabriqué ici avec le module crypto de
// Node : une implémentation indépendante de celle du noyau.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, createCipheriv, pbkdf2Sync } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { handleMessage, toBase64, ERROR_CODES, WORKER_FAILED } from "../js/import-worker.js";
import { CryptoError } from "../js/wasm.js";

/** Module neuf à chaque appel : l'état « instance hors d'usage » repart de zéro. */
let fresh = 0;
const freshWorker = () => import(`../js/import-worker.js?instance=${++fresh}`);

function harness(overrides = {}) {
  const posted = [];
  const loaded = [];
  const calls = [];
  const deps = {
    post: (m) => posted.push(structuredClone(m)),
    close: () => posted.push({ type: "closed" }),
    load: async (url) => {
      loaded.push(url);
    },
    call: (op, args) => {
      calls.push({ op, args: { ...args } });
      return { items: [{ data: { kind: "login", name: "Site" }, folder: "A/B", source_id: "s" }], folders: ["A", "A/B"], warnings: [{ code: "trash_skipped" }] };
    },
    ...overrides,
  };
  return { deps, posted, loaded, calls };
}

const PASSWORD = "a;b\nc « secret »";

test("dispose ferme le worker", async () => {
  const h = harness();
  await handleMessage({ type: "dispose" }, h.deps);
  assert.deepEqual(h.posted, [{ type: "closed" }]);
});

test("messages inconnus ignorés", async () => {
  const h = harness();
  await handleMessage(null, h.deps);
  await handleMessage({ type: "autre", id: 1 }, h.deps);
  assert.deepEqual(h.posted, []);
});

test("KDBX : progression, résultat, tampons effacés, mot de passe jamais renvoyé", async () => {
  const h = harness();
  const file = new Uint8Array([1, 2, 3, 250, 251]).buffer;
  const keyfile = new Uint8Array([9, 9]).buffer;
  await handleMessage({ type: "parse", id: 7, format: "kdbx", file, password: PASSWORD, keyfile }, h.deps);
  assert.deepEqual(h.calls, [{ op: "import_kdbx", args: { data_b64: "AQID+vs=", password: PASSWORD, keyfile_b64: "CQk=" } }]);
  assert.deepEqual(h.posted.map((m) => [m.type, m.phase]), [["progress", "kdf"], ["progress", "map"], ["result", undefined]]);
  assert.deepEqual(h.posted[2], {
    type: "result",
    id: 7,
    items: [{ data: { kind: "login", name: "Site" }, folder: "A/B", source_id: "s" }],
    folders: ["A", "A/B"],
    warnings: [{ code: "trash_skipped" }],
  });
  assert.ok(h.posted.every((m) => m.id === 7));
  assert.ok(!JSON.stringify(h.posted).includes("secret"));
  assert.deepEqual([...new Uint8Array(file)], [0, 0, 0, 0, 0]);
  assert.deepEqual([...new Uint8Array(keyfile)], [0, 0]);
  assert.deepEqual(h.loaded, ["/locksy-import.wasm"]);
});

test("export JSON : texte UTF-8 transmis, UTF-8 invalide refusé", async () => {
  const h = harness();
  const text = '{"encrypted":false,"items":[]} é';
  await handleMessage({ type: "parse", id: "a", format: "bitwarden_json", file: new TextEncoder().encode(text).buffer, password: "" }, h.deps);
  assert.deepEqual(h.calls, [{ op: "import_bitwarden_json", args: { text, password: "" } }]);
  await handleMessage({ type: "parse", id: "b", format: "bitwarden_json", file: new Uint8Array([0xff, 0xfe, 0x41]).buffer }, h.deps);
  assert.deepEqual(h.posted.at(-1), { type: "error", id: "b", code: "unsupported_format" });
});

test("format inconnu et message sans fichier", async () => {
  const h = harness();
  await handleMessage({ type: "parse", id: 1, format: "csv", file: new ArrayBuffer(1) }, h.deps);
  await handleMessage({ type: "parse", id: 2, format: "kdbx" }, h.deps);
  assert.deepEqual(h.posted, [
    { type: "error", id: 1, code: "unsupported_format" },
    { type: "error", id: 2, code: WORKER_FAILED },
  ]);
  assert.equal(h.calls.length, 0);
});

test("codes du noyau transmis tels quels, autres échecs en worker_failed", async () => {
  for (const code of ERROR_CODES) {
    const h = harness({ call: () => { throw new CryptoError(code); } });
    await handleMessage({ type: "parse", id: code, format: "kdbx", file: new ArrayBuffer(4), password: "x" }, h.deps);
    assert.deepEqual(h.posted.at(-1), { type: "error", id: code, code });
  }
  // Module sans les opérations d'import : erreur de requête du noyau.
  const h = harness({ call: () => { throw new CryptoError("requête invalide : unknown variant `import_kdbx`"); } });
  await handleMessage({ type: "parse", id: 3, format: "kdbx", file: new ArrayBuffer(4) }, h.deps);
  assert.deepEqual(h.posted.at(-1), { type: "error", id: 3, code: WORKER_FAILED });
});

test("module de repli quand locksy-import.wasm est absent, échec si aucun", async () => {
  const { handleMessage: handle } = await freshWorker();
  const h = harness({
    load: async (url) => {
      h.loaded.push(url);
      if (url === "/locksy-import.wasm") throw new Error("404");
    },
  });
  await handle({ type: "parse", id: 1, format: "kdbx", file: new ArrayBuffer(4) }, h.deps);
  assert.deepEqual(h.loaded, ["/locksy-import.wasm", "/locksy.wasm"]);
  assert.equal(h.posted.at(-1).type, "result");

  const { handleMessage: handle2 } = await freshWorker();
  const h2 = harness({ load: async () => { throw new Error("hors ligne"); } });
  await handle2({ type: "parse", id: 2, format: "kdbx", file: new ArrayBuffer(4) }, h2.deps);
  assert.deepEqual(h2.posted.at(-1), { type: "error", id: 2, code: WORKER_FAILED });
});

test("après un arrêt brutal du noyau, les demandes suivantes échouent d'emblée", async () => {
  const { handleMessage: handle } = await freshWorker();
  let calls = 0;
  const h = harness({ call: () => { calls++; throw new WebAssembly.RuntimeError("unreachable"); } });
  await handle({ type: "parse", id: 1, format: "kdbx", file: new ArrayBuffer(4) }, h.deps);
  await handle({ type: "parse", id: 2, format: "kdbx", file: new ArrayBuffer(4) }, h.deps);
  assert.equal(calls, 1);
  assert.deepEqual(h.posted.filter((m) => m.type === "error"), [
    { type: "error", id: 1, code: WORKER_FAILED },
    { type: "error", id: 2, code: WORKER_FAILED },
  ]);
});

test("base64 par tranches identique à Buffer", () => {
  const big = new Uint8Array(3 * 0x8000 * 2 + 5).map((_, i) => (i * 31) & 0xff);
  const viaChunks = toBase64({ length: big.length, subarray: (a, b) => big.subarray(a, b) });
  assert.equal(viaChunks, Buffer.from(big).toString("base64"));
  assert.equal(toBase64(new Uint8Array([])), "");
});

// ------------------------------------------------------------------ Vrai noyau

const candidates = ["locksy-import.wasm", "locksy.wasm"].map((n) => fileURLToPath(new URL(`../../dist/release/${n}`, import.meta.url)));
const WASM = candidates.find(existsSync);

/** Export JSON protégé par mot de passe (PBKDF2-SHA256, HKDF-Expand, AES-256-CBC, HMAC-SHA256). */
function encryptedExport(password, inner) {
  const salt = "c2VsLWRlLW5vZGU=";
  const master = pbkdf2Sync(password, salt, 5000, 32, "sha256");
  const expand = (info) => createHmac("sha256", master).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
  const [encKey, macKey] = [expand("enc"), expand("mac")];
  const enc = (plain, ivByte) => {
    const iv = Buffer.alloc(16, ivByte);
    const cipher = createCipheriv("aes-256-cbc", encKey, iv);
    const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
    const mac = createHmac("sha256", macKey).update(Buffer.concat([iv, ct])).digest();
    return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
  };
  return JSON.stringify({
    encrypted: true,
    passwordProtected: true,
    salt,
    kdfType: 0,
    kdfIterations: 5000,
    kdfMemory: null,
    kdfParallelism: null,
    encKeyValidation_DO_NOT_EDIT: enc("validation", 3),
    data: enc(inner, 4),
  });
}

let wasmReady = null;
const realFetch = globalThis.fetch;
after(() => {
  globalThis.fetch = realFetch;
});

/** Vrai noyau, ou raison de sauter les tests (module absent ou sans import). */
async function realDeps() {
  if (!WASM) return "dist/release/locksy-import.wasm absent (compiler locksy-wasm)";
  globalThis.fetch = async (url) => {
    const path = String(url);
    if (path === "/locksy-import.wasm" || path === "/locksy.wasm") {
      const file = fileURLToPath(new URL(`../../dist/release${path}`, import.meta.url));
      if (existsSync(file)) return new Response(readFileSync(file), { headers: { "content-type": "application/wasm" } });
    }
    return new Response("introuvable", { status: 404 });
  };
  const { handleMessage: handle } = await freshWorker();
  const posted = [];
  const deps = { post: (m) => posted.push(m), close() {} };
  await handle({ type: "parse", id: 0, format: "bitwarden_json", file: new TextEncoder().encode('{"encrypted":false,"items":[]}').buffer }, deps);
  if (posted.at(-1).type !== "result") return "le module compilé ne contient pas les opérations d'import";
  return { handle, posted, deps };
}

test("bout en bout : export chiffré par Node, lu par le noyau WebAssembly", async (t) => {
  wasmReady ??= realDeps();
  const real = await wasmReady;
  if (typeof real === "string") return t.skip(real);
  const inner = JSON.stringify({
    encrypted: false,
    folders: [{ id: "f", name: "Équipe/Réseau" }],
    items: [{ id: "i1", folderId: "f", type: 1, name: "Routeur", login: { username: "admin", password: PASSWORD, uris: [{ uri: "https://routeur.exemple.fr" }] } }],
  });
  const file = new TextEncoder().encode(encryptedExport("mot de passe d'export", inner)).buffer;
  await real.handle({ type: "parse", id: 10, format: "bitwarden_json", file, password: "mot de passe d'export" }, real.deps);
  const result = real.posted.at(-1);
  assert.equal(result.type, "result", JSON.stringify(result));
  assert.deepEqual(result.folders, ["Équipe/Réseau"]);
  assert.equal(result.items[0].folder, "Équipe/Réseau");
  assert.equal(result.items[0].data.password, PASSWORD);
  assert.deepEqual(result.items[0].data.urls, ["https://routeur.exemple.fr"]);

  const again = new TextEncoder().encode(encryptedExport("mot de passe d'export", inner)).buffer;
  await real.handle({ type: "parse", id: 11, format: "bitwarden_json", file: again, password: "faux" }, real.deps);
  assert.deepEqual(real.posted.at(-1), { type: "error", id: 11, code: "wrong_password" });

  await real.handle({ type: "parse", id: 12, format: "kdbx", file: new Uint8Array([1, 2, 3]).buffer, password: "x" }, real.deps);
  assert.deepEqual(real.posted.at(-1), { type: "error", id: 12, code: "unsupported_format" });
});
