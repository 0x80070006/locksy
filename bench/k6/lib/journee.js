// Journée type d'un utilisateur (audit 05 §10.1), partagée par les scénarios
// 07 (journée type), 08 (endurance), 09 (utilisateurs légitimes) et 11
// (réglages sous charge). Chaque utilisateur virtuel garde sa session, son
// élément de travail et sa pièce jointe (état propre au VU : chaque VU a son
// propre environnement JavaScript dans k6).
//
// | Action                    | Part | Requêtes                                         |
// | Consulter et rafraîchir   | 55 % | GET /sync                                        |
// | Modifier un élément       | 15 % | PUT /items/:id (révision courante), GET /sync    |
// | Créer un élément          | 10 % | POST /items, GET /sync                           |
// | Gérer un coffre partagé   |  5 % | GET /directory, GET /collections/:id/members     |
// | Partager par lien         |  5 % | POST /shares ; GET /public/shares/:id (anonyme)  |
// | Pièce jointe              |  3 % | GET /attachments/:id (50 Ko à 1 Mo)              |
// | Compte                    |  2 % | GET /me, GET /me/sessions                        |
// | Reconnexion               |  5 % | logout, prelogin, login, sync                    |
import { check, sleep } from "k6";
import { api, login, logout, sync, ROUTES, fakeCipher, uuid, think, myUser, ipFor, jsonField } from "./common.js";
import { policyFresh, policyNotInSync } from "./metrics.js";

/** Routes de la journée type (tableau par route du rapport). */
export const JOURNEE_ROUTES = [
  ROUTES.sync, ROUTES.itemUpdate, ROUTES.itemCreate, ROUTES.directory, ROUTES.members, ROUTES.shareCreate,
  ROUTES.shareOpen, ROUTES.attachmentUpload, ROUTES.attachmentDownload, ROUTES.me, ROUTES.sessions,
  ROUTES.logout, ROUTES.prelogin, ROUTES.login, ROUTES.policy,
];

/** Taille claire d'un élément chiffré typique (identifiant avec notes). */
const ITEM_BYTES = 400;

// État de l'utilisateur virtuel.
const vu = { user: null, token: null, item: null, attachment: null };

/** Étiquettes d'une requête de la journée (groupe « journee » + étiquettes du scénario). */
function tagsOf(o) {
  return Object.assign({ groupe: "journee" }, o.tags || {});
}

/** Ouvre la session du VU (hors mesure de la journée : groupe « connexion_initiale »). */
function ensureSession(o) {
  if (vu.token) return true;
  if (!vu.user) vu.user = myUser();
  vu.token = login(vu.user, { on429: true, tags: Object.assign({}, o.tags || {}, { groupe: "connexion_initiale" }) });
  return !!vu.token;
}

/** Session expirée ou révoquée : nouvelle connexion à l'itération suivante. */
function onAuthError(res) {
  if (res.status === 401) {
    vu.token = null;
    vu.item = null;
    vu.attachment = null;
  }
}

function personalCollection() {
  return vu.user.collections[0];
}

/** Élément de travail du VU, créé dans son coffre personnel au premier besoin. */
function ensureItem(o) {
  if (vu.item) return vu.item;
  const id = uuid();
  const res = api("POST", "/items", {
    token: vu.token, ip: vu.user.xff, name: ROUTES.itemCreate, tags: tagsOf(o),
    body: { id, collection_id: personalCollection(), data: fakeCipher(ITEM_BYTES) },
  });
  check(res, { "élément créé": (r) => r.status === 201 });
  onAuthError(res);
  if (res.status === 201) vu.item = { id, revision: 1 };
  return vu.item;
}

function actionSync(o) {
  const res = sync(vu.token, vu.user.xff, { tags: tagsOf(o) });
  onAuthError(res);
  if (o.politique && res.status === 200) checkPolicy(res, o);
}

/**
 * 11 : la révision de politique portée par /sync est-elle la révision
 * courante ? Contrôle par GET /settings/policy (If-None-Match) ; en cas
 * d'écart (écriture entre les deux requêtes), le /sync suivant doit l'avoir.
 */
function checkPolicy(res, o) {
  const rev = jsonField(res, "policy_revision");
  if (rev === undefined || rev === null) {
    policyNotInSync.add(1);
    return;
  }
  // Sondes hors groupe « journee » : elles ne faussent pas la comparaison avec 07.
  const probeTags = Object.assign({}, o.tags || {}, { groupe: "politique" });
  const probe = (r) => api("GET", "/settings/policy", {
    token: vu.token, ip: vu.user.xff, name: ROUTES.policy, tags: probeTags,
    headers: { "if-none-match": `"r${r}"` }, expect: [200, 304],
  });
  let p = probe(rev);
  if (p.status === 304) {
    policyFresh.add(true);
    return;
  }
  const again = sync(vu.token, vu.user.xff, { tags: probeTags });
  const rev2 = jsonField(again, "policy_revision");
  p = probe(rev2);
  policyFresh.add(p.status === 304);
}

function actionModify(o) {
  const item = ensureItem(o);
  if (!item) return;
  const res = api("PUT", `/items/${item.id}`, {
    token: vu.token, ip: vu.user.xff, name: ROUTES.itemUpdate, tags: tagsOf(o),
    body: { collection_id: personalCollection(), data: fakeCipher(ITEM_BYTES), revision: item.revision },
  });
  check(res, { "élément modifié": (r) => r.status === 200 });
  onAuthError(res);
  if (res.status === 200) item.revision = Number(res.body) || item.revision + 1;
  else vu.item = null;
  actionSync(o);
}

function actionCreate(o) {
  vu.item = null;
  ensureItem(o);
  actionSync(o);
}

function actionCollections(o) {
  const res = api("GET", "/directory", { token: vu.token, ip: vu.user.xff, name: ROUTES.directory, tags: tagsOf(o) });
  onAuthError(res);
  const cols = vu.user.collections;
  const cid = cols.length > 1 ? cols[1 + Math.floor(Math.random() * (cols.length - 1))] : cols[0];
  const m = api("GET", `/collections/${cid}/members`, { token: vu.token, ip: vu.user.xff, name: ROUTES.members, tags: tagsOf(o) });
  check(m, { "membres lus": (r) => r.status === 200 });
}

function actionShare(o) {
  const res = api("POST", "/shares", {
    token: vu.token, ip: vu.user.xff, name: ROUTES.shareCreate, tags: tagsOf(o),
    body: { data: fakeCipher(200), expires_in_minutes: 60, max_views: 3 },
  });
  check(res, { "lien créé": (r) => r.status === 200 || r.status === 201 });
  onAuthError(res);
  const id = jsonField(res, "id");
  if (!id) return;
  // Le destinataire ouvre le lien depuis une autre adresse, sans compte.
  const open = api("GET", `/public/shares/${id}`, {
    ip: ipFor(150, Math.floor(Math.random() * 65000) + 1), name: ROUTES.shareOpen, tags: tagsOf(o),
  });
  check(open, { "lien ouvert": (r) => r.status === 200 });
}

function actionAttachment(o) {
  if (!vu.attachment) {
    const item = ensureItem(o);
    if (!item) return;
    const id = uuid();
    const size = 50 * 1024 + Math.floor(Math.random() * (974 * 1024));
    const up = api("PUT", `/items/${item.id}/attachments/${id}`, {
      token: vu.token, ip: vu.user.xff, name: ROUTES.attachmentUpload, tags: tagsOf(o),
      body: { data: fakeCipher(size) }, timeout: "60s",
    });
    check(up, { "pièce jointe envoyée": (r) => r.status === 201 });
    onAuthError(up);
    if (up.status !== 201) return;
    vu.attachment = id;
  }
  const res = api("GET", `/attachments/${vu.attachment}`, {
    token: vu.token, ip: vu.user.xff, name: ROUTES.attachmentDownload, tags: tagsOf(o), timeout: "60s",
  });
  check(res, { "pièce jointe téléchargée": (r) => r.status === 200 });
  onAuthError(res);
}

function actionAccount(o) {
  const me = api("GET", "/me", { token: vu.token, ip: vu.user.xff, name: ROUTES.me, tags: tagsOf(o) });
  onAuthError(me);
  const s = api("GET", "/me/sessions", { token: vu.token, ip: vu.user.xff, name: ROUTES.sessions, tags: tagsOf(o) });
  check(s, { "sessions lues": (r) => r.status === 200 });
}

function actionRelogin(o) {
  logout(vu.token, vu.user.xff, tagsOf(o));
  vu.token = login(vu.user, { on429: true, tags: tagsOf(o) });
  if (vu.token) actionSync(o);
}

/**
 * Une action de la journée type, puis une pause de `pause` s ± 50 %
 * (10 s par défaut). Options : tags (étiquettes en plus), politique (11),
 * pause.
 */
export function journeeIteration(opts) {
  const o = opts || {};
  if (!ensureSession(o)) {
    sleep(2);
    return;
  }
  const r = Math.random() * 100;
  if (r < 55) actionSync(o);
  else if (r < 70) actionModify(o);
  else if (r < 80) actionCreate(o);
  else if (r < 85) actionCollections(o);
  else if (r < 90) actionShare(o);
  else if (r < 93) actionAttachment(o);
  else if (r < 95) actionAccount(o);
  else actionRelogin(o);
  think(o.pause === undefined ? 10 : o.pause);
}
