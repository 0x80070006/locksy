// Tests du client HTTP (web/js/api.js, contrat C4.1) avec un serveur simulé :
// erreurs typées, nouvel essai poli (503 + Retry-After), session expirée,
// If-Match, jeton de réauthentification et withReauth().
//   node --test web/tests/
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import * as A from "../js/api.js";

let routes;
let calls;
let waits;

/** Serveur simulé : « MÉTHODE /chemin » -> (requête, n° d'appel) => [statut, corps, en-têtes]. */
globalThis.fetch = async (url, opts = {}) => {
  const path = String(url).replace(/^.*\/api/, "");
  const key = `${opts.method || "GET"} ${path}`;
  const req = { key, headers: opts.headers || {}, body: opts.body ? JSON.parse(opts.body) : undefined };
  calls.push(req);
  const handler = routes[key];
  if (!handler) return new Response(JSON.stringify({ error: "not_found", message: key }), { status: 404 });
  const n = calls.filter((c) => c.key === key).length;
  const out = await handler(req, n);
  if (out === "network") throw new TypeError("Failed to fetch");
  const [status, body, headers = {}] = out;
  if (status === 204 || status === 304) return new Response(null, { status, headers });
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
};

beforeEach(() => {
  routes = {};
  calls = [];
  waits = [];
  A.setRetrySleep(async (ms) => { waits.push(ms); });
  A.setToken("session-1");
  A.onSessionExpired(null);
  A.setReauthUi(null);
});

afterEach(() => A.setRetrySleep(null));

const busy = (retryAfter) => [503, { error: "server_busy", message: "occupé", retry_after: retryAfter }, retryAfter === undefined ? {} : { "retry-after": String(retryAfter) }];

// ------------------------------------------------------------------ réponses

test("api() renvoie le corps JSON, null pour 204 (forme historique)", async () => {
  routes["GET /me"] = () => [200, { id: "u1" }];
  routes["DELETE /x"] = () => [204];
  assert.deepEqual(await A.api("GET", "/me"), { id: "u1" });
  assert.equal(await A.api("DELETE", "/x"), null);
  assert.equal(calls[0].headers.authorization, "Bearer session-1");
});

test("apiFull() renvoie aussi l'ETag et le statut ; 304 sans corps", async () => {
  routes["GET /settings/policy"] = (req, n) => (n === 1 ? [200, { revision: 3 }, { etag: "\"r3\"" }] : [304, null, { etag: "\"r3\"" }]);
  const first = await A.apiFull("GET", "/settings/policy");
  assert.deepEqual([first.data, first.etag, first.status], [{ revision: 3 }, "\"r3\"", 200]);
  const second = await A.apiFull("GET", "/settings/policy", undefined, { ifNoneMatch: first.etag });
  assert.deepEqual([second.data, second.status], [null, 304]);
  assert.equal(calls[1].headers["if-none-match"], "\"r3\"");
});

test("If-Match et X-Locksy-Reauth posés par les options", async () => {
  routes["PUT /me/prefs"] = () => [200, { revision: 8 }];
  await A.api("PUT", "/me/prefs", { cipher: "v1.x" }, { ifMatch: 7, reauth: "rt1.abc" });
  assert.equal(calls[0].headers["if-match"], "\"7\"");
  assert.equal(calls[0].headers["x-locksy-reauth"], "rt1.abc");
  assert.equal(calls[0].headers["content-type"], "application/json");
});

test("erreur typée : code, message, champs, Retry-After et champs supplémentaires", async () => {
  routes["POST /shares"] = () => [422, { error: "share_limit", message: "trop long", max_minutes: 60, fields: [{ field: "x", code: "too_long" }] }];
  routes["POST /auth/login"] = () => [429, { error: "rate_limited", message: "trop", retry_after: 900 }, { "retry-after": "900" }];
  await assert.rejects(A.api("POST", "/shares", {}), (e) => {
    assert.ok(e instanceof A.ApiError);
    assert.deepEqual([e.status, e.code, e.message], [422, "share_limit", "trop long"]);
    assert.deepEqual(e.params, { max_minutes: 60 });
    assert.deepEqual(e.fields, [{ field: "x", code: "too_long" }]);
    return true;
  });
  await assert.rejects(A.api("POST", "/auth/login", {}), (e) => e.code === "rate_limited" && e.retryAfter === 900);
  assert.equal(calls.filter((c) => c.key === "POST /auth/login").length, 1, "un 429 n'est jamais réessayé");
});

test("panne réseau : ApiError « network » (status 0)", async () => {
  routes["POST /items"] = () => "network";
  await assert.rejects(A.api("POST", "/items", {}), (e) => e.status === 0 && e.code === "network");
  assert.equal(calls.length, 1, "une écriture n'est pas renvoyée après une panne réseau");
});

// ------------------------------------------------------------------ nouvel essai poli

test("503 server_busy + Retry-After : nouvel essai après le délai annoncé", async () => {
  routes["GET /sync"] = (req, n) => (n === 1 ? busy(2) : [200, { ok: true }]);
  assert.deepEqual(await A.api("GET", "/sync"), { ok: true });
  assert.deepEqual(waits, [2000]);
});

test("503 server_busy sur une écriture : réessayée aussi (rien n'a été traité)", async () => {
  routes["POST /items"] = (req, n) => (n === 1 ? busy(1) : [200, { id: "i1" }]);
  assert.deepEqual(await A.api("POST", "/items", { a: 1 }), { id: "i1" });
  assert.equal(calls.length, 2);
});

test("au plus 2 nouveaux essais ; délais 1 s puis 3 s sans Retry-After ; borne de 10 s", async () => {
  routes["GET /sync"] = () => busy();
  await assert.rejects(A.api("GET", "/sync"), (e) => e.code === "server_busy");
  assert.equal(calls.length, 3);
  assert.deepEqual(waits, [1000, 3000]);
  waits = [];
  calls = [];
  routes["GET /sync"] = (req, n) => (n === 1 ? busy(600) : [200, {}]);
  await A.api("GET", "/sync");
  assert.deepEqual(waits, [10_000]);
});

test("502 : réessayé pour une lecture, pas pour une écriture ; retry:false coupe tout", async () => {
  routes["GET /me"] = (req, n) => (n === 1 ? [502, {}] : [200, { id: "u" }]);
  routes["POST /me/kdf"] = () => [502, {}];
  assert.deepEqual(await A.api("GET", "/me"), { id: "u" });
  await assert.rejects(A.api("POST", "/me/kdf", {}), (e) => e.status === 502);
  assert.equal(calls.filter((c) => c.key === "POST /me/kdf").length, 1);
  calls = [];
  routes["GET /x"] = () => busy(0);
  await assert.rejects(A.api("GET", "/x", undefined, { retry: false }));
  assert.equal(calls.length, 1);
});

test("parseRetryAfter : secondes ou date HTTP", () => {
  assert.equal(A.parseRetryAfter("120"), 120);
  assert.equal(A.parseRetryAfter(new Date(Date.UTC(2026, 10, 18, 12, 0, 30)).toUTCString(), Date.UTC(2026, 10, 18, 12, 0, 0)), 30);
  assert.equal(A.parseRetryAfter(null), undefined);
  assert.equal(A.parseRetryAfter("bientôt"), undefined);
});

// ------------------------------------------------------------------ session

test("401 unauthorized : jeton vidé et onSessionExpired appelé", async () => {
  let expired = null;
  A.onSessionExpired((e) => { expired = e; });
  routes["GET /sync"] = () => [401, { error: "unauthorized", message: "session" }];
  await assert.rejects(A.api("GET", "/sync"));
  assert.equal(A.hasToken(), false);
  assert.equal(expired?.code, "unauthorized");
});

test("403 account_disabled ou account_expired pendant la session : jeton vidé, fin signalée", async () => {
  for (const code of ["account_disabled", "account_expired"]) {
    A.setToken("session-1");
    let expired = null;
    A.onSessionExpired((e) => { expired = e; });
    routes["GET /sync"] = () => [403, { error: code, message: "compte" }];
    await assert.rejects(A.api("GET", "/sync"), (e) => e.code === code);
    assert.equal(A.hasToken(), false, code);
    assert.equal(expired?.code, code);
  }
});

test("403 d'une autre nature (forbidden, owner_only) : la session reste intacte", async () => {
  let expired = false;
  A.onSessionExpired(() => { expired = true; });
  routes["GET /admin/stats"] = () => [403, { error: "forbidden", message: "non" }];
  await assert.rejects(A.api("GET", "/admin/stats"), (e) => e.code === "forbidden");
  assert.equal(A.hasToken(), true);
  assert.equal(expired, false);
});

test("401 totp_required ou invalid_totp : la session reste intacte", async () => {
  let expired = false;
  A.onSessionExpired(() => { expired = true; });
  routes["POST /auth/reauth"] = () => [401, { error: "totp_required", message: "code" }];
  await assert.rejects(A.api("POST", "/auth/reauth", {}), (e) => e.code === "totp_required");
  assert.equal(A.hasToken(), true);
  assert.equal(expired, false);
});

// ------------------------------------------------------------------ withReauth

/** Interface de test : enchaîne mot de passe puis code, comme la vraie fenêtre. */
function fakeUi({ password = "mdp", code = "123456", cancel = false } = {}) {
  const ui = {
    proofs: 0,
    asked: [],
    proof: async (pw) => { ui.proofs += 1; return `preuve(${pw})`; },
    ask: async ({ action, exchange, title }) => {
      ui.asked.push({ action, title });
      if (cancel) return null;
      try {
        return await exchange(password);
      } catch (e) {
        if (e.code !== "totp_required") throw e;
        return exchange(null, code);
      }
    },
  };
  return ui;
}

test("withReauth : jeton échangé puis passé à l'action", async () => {
  const ui = fakeUi();
  A.setReauthUi(ui);
  routes["POST /auth/reauth"] = (req) => [200, { token: `rt1.${req.body.action}`, expires_in: 120, action: req.body.action }];
  const got = await A.withReauth("vault.export", async ({ reauth }) => `fait avec ${reauth}`, { title: "Exporter" });
  assert.equal(got, "fait avec rt1.vault.export");
  assert.deepEqual(calls[0].body, { action: "vault.export", auth_key: "preuve(mdp)" });
  assert.deepEqual(ui.asked, [{ action: "vault.export", title: "Exporter" }]);
});

test("withReauth : totp_required, le code est demandé et la preuve n'est pas recalculée", async () => {
  const ui = fakeUi({ code: "654321" });
  A.setReauthUi(ui);
  routes["POST /auth/reauth"] = (req) => (req.body.totp
    ? [200, { token: "rt1.ok" }]
    : [401, { error: "totp_required", message: "code" }]);
  const got = await A.withReauth("totp.disable", async ({ reauth }) => reauth);
  assert.equal(got, "rt1.ok");
  assert.equal(ui.proofs, 1);
  assert.deepEqual(calls[1].body, { action: "totp.disable", auth_key: "preuve(mdp)", totp: "654321" });
});

test("withReauth : serveur sans /auth/reauth (404), repli sur la preuve historique", async () => {
  A.setReauthUi(fakeUi());
  const got = await A.withReauth("settings", async ({ reauth }) => reauth);
  assert.equal(got, "preuve(mdp)");
});

test("withReauth : annulation, l'action n'est pas appelée", async () => {
  A.setReauthUi(fakeUi({ cancel: true }));
  let called = false;
  const got = await A.withReauth("settings", async () => { called = true; });
  assert.equal(got, undefined);
  assert.equal(called, false);
});

test("withReauth sans interface branchée : erreur typée", async () => {
  await assert.rejects(A.withReauth("settings", async () => {}), (e) => e instanceof A.ApiError && e.code === "unknown");
});
