// 06 · Pièces jointes.
//   simultanes : 5 envois de 10 Mo partis au même instant (mémoire : aucun
//                arrêt pour manque de mémoire, RSS < 450 Mio) ;
//   tailles    : envois puis téléchargements de 100 Ko (N_100K), 1 Mo (N_1M)
//                et 10 Mo (N_10M), étiquette « taille », chaque pièce
//                supprimée après lecture (quotas inchangés) ;
//   limites    : la (max_per_item + 1)e pièce d'un élément refusée ; un fichier
//                au-delà de attachment.max_file_mib (MAX_FILE_MIB, 10) refusé en
//                413 en moins de 200 ms ; un corps de plus de 16 Mo (limite de
//                l'hébergeur) refusé en moins de 200 ms : 413, ou connexion
//                fermée par le serveur avant la fin de l'envoi (il n'attend
//                pas le reste du corps).
// Les sessions et les éléments porteurs sont créés dans setup().
import { check, sleep } from "k6";
import exec from "k6/execution";
import { api, login, logout, ROUTES, userFor, serverInfo, fakeCipher, uuid, envInt } from "../lib/common.js";
import { attachmentRefused, bodyRefusal } from "../lib/metrics.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "06-pieces-jointes";
const KIB = 1024;
const MIB = 1024 * 1024;
const SIMULTANEOUS = 5;
const SIZES = [
  { tag: "100k", bytes: 100 * KIB, count: envInt("N_100K", 20) },
  { tag: "1m", bytes: MIB, count: envInt("N_1M", 20) },
  { tag: "10m", bytes: 10 * MIB, count: envInt("N_10M", 10) },
];
/** Nombre maximal de pièces par élément (attachment.max_per_item, défaut 20). */
const MAX_PER_ITEM = envInt("MAX_PER_ITEM", 20);
/** Taille maximale d'un fichier (attachment.max_file_mib, défaut 10 Mio). */
const MAX_FILE_MIB = envInt("MAX_FILE_MIB", 10);
/** Corps au-delà de la limite de l'hébergeur (LOCKSY_MAX_BODY_MIB, 16 Mo). */
const BODY_OVER_LIMIT = 17 * MIB;
const TIMEOUT = "120s";

const observe = [];
for (const s of SIZES) {
  observe.push(...routeMetrics([ROUTES.attachmentUpload, ROUTES.attachmentDownload], `taille:${s.tag}`));
}

export const options = {
  setupTimeout: "2m",
  scenarios: {
    simultanes: { executor: "per-vu-iterations", vus: SIMULTANEOUS, iterations: 1, maxDuration: "3m", exec: "simultanes" },
    tailles: { executor: "per-vu-iterations", vus: 1, iterations: 1, maxDuration: "20m", startTime: "40s", exec: "tailles" },
  },
  thresholds: k6Thresholds(SCENARIO, __ENV, observe.concat(routeMetrics([ROUTES.attachmentOverLimit, ROUTES.attachmentTooLarge, ROUTES.attachmentDelete]))),
  summaryTrendStats: [...TREND_STATS],
};

/** Session et élément porteur, pour SIMULTANEOUS + 1 comptes. */
export function setup() {
  const carriers = [];
  for (let i = 1; i <= SIMULTANEOUS + 1; i++) {
    const u = userFor(i);
    const token = login(u, { on429: true, tags: { groupe: "connexion_initiale" } });
    if (!token) continue;
    const item = newItem(token, u);
    if (item) carriers.push({ token, ip: u.xff, collection: u.collections[0], item });
  }
  if (carriers.length < 2) throw new Error("Sessions insuffisantes : vérifiez le jeu semé et preflight.sh.");
  return { public: { serveur: serverInfo() }, carriers };
}

function newItem(token, u) {
  const id = uuid();
  const res = api("POST", "/items", {
    token, ip: u.xff, name: ROUTES.itemCreate, tags: { groupe: "preparation" },
    body: { id, collection_id: u.collections[0], data: fakeCipher(300) },
  });
  return res.status === 201 ? id : null;
}

function upload(c, item, cipher, name, tags, expect) {
  const id = uuid();
  const res = api("PUT", `/items/${item}/attachments/${id}`, {
    token: c.token, ip: c.ip, name, tags, body: `{"data":"${cipher}"}`, timeout: TIMEOUT, expect,
  });
  return { id, res };
}

function remove(c, id) {
  api("DELETE", `/attachments/${id}`, { token: c.token, ip: c.ip, name: ROUTES.attachmentDelete });
}

export function simultanes(data) {
  const c = data.carriers[(exec.vu.idInTest - 1) % data.carriers.length];
  const cipher = fakeCipher(10 * MIB);
  // Départ commun : 5 s après le début du scénario, chiffré déjà préparé.
  const wait = exec.scenario.startTime + 5000 - Date.now();
  if (wait > 0) sleep(wait / 1000);
  const { id, res } = upload(c, c.item, cipher, ROUTES.attachmentUpload, { taille: "10m", groupe: "simultane" });
  check(res, { "envoi simultané de 10 Mo accepté (201)": (r) => r.status === 201 });
  if (res.status === 201) remove(c, id);
}

export function tailles(data) {
  const c = data.carriers[data.carriers.length - 1];
  for (const s of SIZES) {
    const cipher = fakeCipher(s.bytes);
    const tags = { taille: s.tag };
    for (let i = 0; i < s.count; i++) {
      const { id, res } = upload(c, c.item, cipher, ROUTES.attachmentUpload, tags);
      check(res, { [`envoi de ${s.tag} accepté (201)`]: (r) => r.status === 201 });
      if (res.status !== 201) continue;
      const get = api("GET", `/attachments/${id}`, { token: c.token, ip: c.ip, name: ROUTES.attachmentDownload, tags, timeout: TIMEOUT });
      check(get, { [`téléchargement de ${s.tag} (200)`]: (r) => r.status === 200 && r.body.length >= cipher.length });
      remove(c, id);
    }
  }
  limites(c);
}

/** Refus attendus : une pièce de trop sur un élément, un corps de plus de 16 Mo. */
function limites(c) {
  const item = newItem(c.token, { xff: c.ip, collections: [c.collection] });
  if (!item) return;
  const small = fakeCipher(KIB);
  const kept = [];
  for (let i = 0; i < MAX_PER_ITEM; i++) {
    const { id, res } = upload(c, item, small, ROUTES.attachmentUpload, { taille: "1k" });
    if (res.status === 201) kept.push(id);
  }
  const over = upload(c, item, small, ROUTES.attachmentOverLimit, {}, [400, 409, 413, 422]);
  const refusedCount = over.res.status === 400 || over.res.status === 422;
  check(over.res, { "pièce jointe en trop refusée (400 ou 422)": () => refusedCount });
  attachmentRefused.add(refusedCount, { motif: "nombre" });
  for (const id of kept) remove(c, id);
  if (over.res.status === 201) remove(c, over.id);

  // Fichier trop gros pour le réglage, corps encore sous la limite de
  // l'hébergeur : 413 attachment_too_large (400 sur un serveur antérieur à la
  // vague 2, refus tout de même).
  const big = upload(c, item, fakeCipher((MAX_FILE_MIB + 1) * MIB), ROUTES.attachmentTooLarge, {}, [400, 413]);
  const bigRefused = big.res.status === 413 || big.res.status === 400;
  check(big.res, {
    "fichier au-delà de la taille permise refusé": () => bigRefused,
    "fichier au-delà de la taille permise refusé en 413": (r) => r.status === 413,
  });
  attachmentRefused.add(bigRefused, { motif: "taille" });

  // Corps au-delà de la limite de l'hébergeur : 413, ou connexion fermée tôt.
  const body = fakeCipher(BODY_OVER_LIMIT);
  const started = Date.now();
  const huge = upload(c, item, body, ROUTES.attachmentBodyTooLarge, {}, [413]);
  const refused = huge.res.status === 413 || (huge.res.status === 0 && /broken pipe|connection reset|EOF/i.test(huge.res.error || ""));
  bodyRefusal.add(Date.now() - started);
  check(huge.res, { "corps de plus de 16 Mo refusé": () => refused });
  attachmentRefused.add(refused, { motif: "corps" });
}

export function teardown(data) {
  for (const c of data.carriers) logout(c.token, c.ip, { groupe: "fin" });
}

export const handleSummary = makeSummary(SCENARIO);
