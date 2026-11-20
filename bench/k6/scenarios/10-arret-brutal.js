// 10 · Arrêt brutal sous écriture, piloté par bench/scripts/run.sh (le
// serveur est tué par « docker kill -s KILL » KILLS fois, toutes les
// INTERVAL secondes, puis redémarré).
//   PHASE vide          : VUS écrivains (10) créent des éléments en continu
//                         pendant DURATION ; chaque création acquittée (201)
//                         est journalisée sur la console (« ACQUITTE <e-mail>
//                         <id> », fichier --console-output de run.sh) ;
//   PHASE=verification : relit ce journal (ACKS_FILE), reconnecte chaque
//                         compte et vérifie que 100 % des éléments acquittés
//                         sont présents dans /sync.
import { check, sleep } from "k6";
import { SharedArray } from "k6/data";
import exec from "k6/execution";
import { api, login, sync, ROUTES, USERS, userFor, serverInfo, fakeCipher, uuid, envInt, envDuration } from "../lib/common.js";
import { acked, ackPresent } from "../lib/metrics.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "10-arret-brutal";
const VERIFY = __ENV.PHASE === "verification";
const ACK_RE = /ACQUITTE (\S+@\S+) ([0-9a-f-]{36})/g;

// Accusés de la phase d'écriture, regroupés par compte (phase de vérification seulement).
const ACKS = new SharedArray("acquittements", () => {
  if (!VERIFY) return [];
  const file = __ENV.ACKS_FILE || `/bench/results/${__ENV.RUN || "manuel"}/k6-console.log`;
  const byEmail = {};
  const text = open(file);
  let m;
  while ((m = ACK_RE.exec(text)) !== null) (byEmail[m[1]] = byEmail[m[1]] || []).push(m[2]);
  return Object.keys(byEmail).map((email) => ({ email, ids: byEmail[email] }));
});

export const options = {
  scenarios: VERIFY
    ? { verification: { executor: "per-vu-iterations", vus: 1, iterations: 1, maxDuration: "15m", exec: "verifier" } }
    : { ecrivains: { executor: "constant-vus", vus: envInt("VUS", 10), duration: envDuration("DURATION", "11m"), exec: "ecrire" } },
  thresholds: k6Thresholds(SCENARIO, __ENV, routeMetrics([ROUTES.itemCreate, ROUTES.sync, ROUTES.login])),
  summaryTrendStats: [...TREND_STATS],
};

export function setup() {
  return { public: { serveur: serverInfo(), phase: VERIFY ? "verification" : "ecriture" } };
}

const vu = { token: null };

export function ecrire() {
  const u = userFor(exec.vu.idInTest);
  if (!vu.token) {
    vu.token = login(u, { on429: true, max: 2 });
    if (!vu.token) {
      sleep(1);
      return;
    }
  }
  const id = uuid();
  const res = api("POST", "/items", {
    token: vu.token, ip: u.xff, name: ROUTES.itemCreate, timeout: "10s",
    body: { id, collection_id: u.collections[0], data: fakeCipher(300) },
  });
  if (res.status === 201) {
    // Accusé de réception : l'élément DOIT survivre à tout arrêt ultérieur.
    console.log(`ACQUITTE ${u.email} ${id}`);
    acked.add(1);
    sleep(0.1);
  } else {
    if (res.status === 401) vu.token = null;
    // Serveur arrêté ou en redémarrage : on patiente.
    sleep(0.5);
  }
}

export function verifier() {
  check(null, { "journal des accusés non vide": () => ACKS.length > 0 });
  for (let i = 0; i < ACKS.length; i++) {
    const entry = ACKS[i];
    let u = null;
    for (let k = 0; k < USERS.length && !u; k++) if (USERS[k].email === entry.email) u = USERS[k];
    if (!u) continue;
    const token = login(u, { on429: true });
    const res = token ? sync(token, u.xff, { timeout: "120s" }) : null;
    const present = {};
    if (res && res.status === 200) for (const id of res.json("items.#.id") || []) present[id] = true;
    let missing = 0;
    for (const id of entry.ids) {
      ackPresent.add(!!present[id]);
      if (!present[id]) missing += 1;
    }
    check(null, { "écritures acquittées présentes": () => missing === 0 });
  }
}

export const handleSummary = makeSummary(SCENARIO);
