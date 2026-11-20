// 05 · Écritures, pendant DURATION (5 min) :
//   ecrivains : RATE écritures/s (20) : 60 % modifications (PUT avec la
//               révision courante), 30 % créations, 10 % mises à la corbeille,
//               chacune suivie d'un GET /sync (comme refresh() du client) ;
//   import    : un POST /items/batch de BATCH éléments (2 000) par minute ;
//   conflits  : toutes les 5 s, une modification valide puis la même avec
//               la révision périmée : 409 attendu dans 100 % des cas.
// Chaque écrivain travaille dans le coffre personnel de son compte ; l'import
// et les conflits ont chacun leur compte (les derniers du jeu), pour ne pas
// grossir les synchronisations mesurées.
import { check } from "k6";
import exec from "k6/execution";
import { api, login, sync, ROUTES, USERS, serverInfo, fakeCipher, uuid, envInt, envDuration } from "../lib/common.js";
import { conflict409 } from "../lib/metrics.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "05-ecritures";
const DURATION = envDuration("DURATION", "5m");
const BATCH = Math.min(envInt("BATCH", 2000), 2000);
const ITEM_BYTES = 400;
const IMPORT_USER = USERS[USERS.length - 1];
const CONFLICT_USER = USERS[USERS.length - 2];
const WRITERS = Math.max(1, USERS.length - 2);

export const options = {
  scenarios: {
    ecrivains: {
      executor: "constant-arrival-rate", rate: envInt("RATE", 20), timeUnit: "1s", duration: DURATION,
      preAllocatedVUs: 40, maxVUs: envInt("MAX_VUS", 150), exec: "ecrire",
    },
    import: { executor: "constant-arrival-rate", rate: 1, timeUnit: "1m", duration: DURATION, preAllocatedVUs: 2, maxVUs: 3, exec: "importer" },
    conflits: { executor: "constant-arrival-rate", rate: 12, timeUnit: "1m", duration: DURATION, preAllocatedVUs: 1, maxVUs: 2, exec: "conflit" },
  },
  thresholds: k6Thresholds(SCENARIO, __ENV, routeMetrics([
    ROUTES.itemUpdate, ROUTES.itemCreate, ROUTES.itemTrash, ROUTES.itemBatch, ROUTES.itemConflict, ROUTES.sync,
  ])),
  summaryTrendStats: [...TREND_STATS],
};

export function setup() {
  return { public: { serveur: serverInfo(), lot: BATCH } };
}

// État du VU : session et élément de travail.
const vu = { user: null, token: null, item: null };

function session(user) {
  if (vu.token) return true;
  vu.user = user;
  vu.token = login(user, { on429: true, tags: { groupe: "connexion_initiale" } });
  return !!vu.token;
}

function forget(res) {
  if (res.status === 401) vu.token = null;
}

function createItem() {
  const id = uuid();
  const res = api("POST", "/items", {
    token: vu.token, ip: vu.user.xff, name: ROUTES.itemCreate,
    body: { id, collection_id: vu.user.collections[0], data: fakeCipher(ITEM_BYTES) },
  });
  check(res, { "création acceptée (201)": (r) => r.status === 201 });
  forget(res);
  vu.item = res.status === 201 ? { id, revision: 1 } : null;
  return vu.item;
}

function updateItem(revision, name, expect) {
  return api("PUT", `/items/${vu.item.id}`, {
    token: vu.token, ip: vu.user.xff, name, expect,
    body: { collection_id: vu.user.collections[0], data: fakeCipher(ITEM_BYTES), revision },
  });
}

export function ecrire() {
  if (!session(USERS[(exec.vu.idInTest - 1) % WRITERS])) return;
  const r = Math.random() * 100;
  if (r < 60 && (vu.item || createItem())) {
    const res = updateItem(vu.item.revision, ROUTES.itemUpdate);
    check(res, { "modification acceptée (200)": (x) => x.status === 200 });
    forget(res);
    if (res.status === 200) vu.item.revision = Number(res.body);
    else vu.item = null;
  } else if (r < 90 || !vu.item) {
    createItem();
  } else {
    const res = api("DELETE", `/items/${vu.item.id}`, { token: vu.token, ip: vu.user.xff, name: ROUTES.itemTrash });
    check(res, { "mise à la corbeille acceptée (204)": (x) => x.status === 204 });
    forget(res);
    vu.item = null;
  }
  if (vu.token) sync(vu.token, vu.user.xff);
}

export function importer() {
  if (!session(IMPORT_USER)) return;
  const items = [];
  for (let i = 0; i < BATCH; i++) items.push({ id: uuid(), collection_id: IMPORT_USER.collections[0], data: fakeCipher(300) });
  const res = api("POST", "/items/batch", { token: vu.token, ip: vu.user.xff, name: ROUTES.itemBatch, body: { items }, timeout: "60s" });
  check(res, { "import accepté (201)": (x) => x.status === 201 });
  forget(res);
}

export function conflit() {
  if (!session(CONFLICT_USER)) return;
  if (!vu.item && !createItem()) return;
  const stale = vu.item.revision;
  const ok = updateItem(stale, ROUTES.itemUpdate);
  forget(ok);
  if (ok.status !== 200) {
    vu.item = null;
    return;
  }
  vu.item.revision = Number(ok.body);
  // Même modification, révision d'avant : un autre poste a écrit entre-temps.
  const res = updateItem(stale, ROUTES.itemConflict, [409]);
  check(res, { "révision périmée refusée (409)": (x) => x.status === 409 });
  conflict409.add(res.status === 409);
}

export const handleSummary = makeSummary(SCENARIO);
