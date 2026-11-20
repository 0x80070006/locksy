// 00 · Smoke : 1 VU pendant 30 s (DURATION). Santé, prelogin, connexion,
// synchronisation, création, modification, mise à la corbeille, déconnexion.
// Seuil : 100 % des contrôles réussis, prérequis de toute autre passe.
import { check, sleep } from "k6";
import { api, login, logout, sync, ROUTES, fakeCipher, uuid, myUser, serverInfo, envDuration } from "../lib/common.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "00-smoke";
const USED = [ROUTES.health, ROUTES.prelogin, ROUTES.login, ROUTES.sync, ROUTES.itemCreate, ROUTES.itemUpdate, ROUTES.itemTrash, ROUTES.logout];

export const options = {
  scenarios: { smoke: { executor: "constant-vus", vus: 1, duration: envDuration("DURATION", "30s") } },
  thresholds: k6Thresholds(SCENARIO, __ENV, routeMetrics(USED)),
  summaryTrendStats: [...TREND_STATS],
};

export function setup() {
  return { public: { serveur: serverInfo() } };
}

export default function () {
  const u = myUser();
  const h = api("GET", "/health", { ip: u.xff, name: ROUTES.health });
  check(h, { "santé 200": (r) => r.status === 200 });
  const token = login(u);
  if (!token) {
    sleep(1);
    return;
  }
  const s = sync(token, u.xff);
  check(s, { "synchronisation avec au moins un coffre": (r) => r.status === 200 && r.json("collections.#") > 0 });

  const id = uuid();
  const collection = u.collections[0];
  const created = api("POST", "/items", {
    token, ip: u.xff, name: ROUTES.itemCreate, body: { id, collection_id: collection, data: fakeCipher(400) },
  });
  check(created, { "élément créé (201)": (r) => r.status === 201 });
  const updated = api("PUT", `/items/${id}`, {
    token, ip: u.xff, name: ROUTES.itemUpdate, body: { collection_id: collection, data: fakeCipher(400), revision: 1 },
  });
  check(updated, { "élément modifié, révision 2": (r) => r.status === 200 && Number(r.body) === 2 });
  const trashed = api("DELETE", `/items/${id}`, { token, ip: u.xff, name: ROUTES.itemTrash });
  check(trashed, { "élément mis à la corbeille (204)": (r) => r.status === 204 });
  logout(token, u.xff);
  sleep(1);
}

export const handleSummary = makeSummary(SCENARIO);
