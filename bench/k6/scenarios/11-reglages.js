// 11 · Réglages et politique sous charge : VUS utilisateurs (200) font leur
// journée type (07) pendant que l'administrateur enregistre un réglage toutes
// les PERIODE (30 s), par PATCH /admin/settings avec If-Match.
// Mesures (serveur lancé avec LOCKSY_ENV=test, posé par run.sh) :
//   - compteurs GET /api/test/counters avant et après : aucun chargement SQL
//     des réglages au-delà des révisions écrites (+ 2), aucune lecture de
//     l'ancien stockage ;
//   - chaque /sync porte la révision de politique courante (vérifiée par
//     GET /settings/policy avec If-None-Match), sinon le /sync suivant ;
//   - p95 de la journée comparé à une passe 07-200 (run.sh --reference).
// Le réglage modifié (branding.support_contact) est sans effet de sécurité :
// il n'exige pas de réauthentification.
import { check } from "k6";
import { api, login, logout, ROUTES, adminUser, serverInfo, envInt, envDuration, seconds, jsonField } from "../lib/common.js";
import { settingsWrites, settingsExtraLoads, settingsLegacyReads } from "../lib/metrics.js";
import { journeeIteration, JOURNEE_ROUTES } from "../lib/journee.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "11-reglages";
const VUS = envInt("VUS", 200);
const RAMP = envDuration("RAMP", "3m");
const PLATEAU = envDuration("DURATION", "20m");
const PERIODE = envDuration("PERIODE", "30s");
const PAUSE = envInt("PAUSE", 10);
const SETTING = "branding.support_contact";
/** Chargements tolérés en plus des révisions écrites (démarrage du cache, génération concurrente). */
const LOAD_SLACK = 2;

export const options = {
  setupTimeout: "2m",
  scenarios: {
    utilisateurs: {
      executor: "ramping-vus", startVUs: 0,
      stages: [{ target: VUS, duration: RAMP }, { target: VUS, duration: PLATEAU }],
      gracefulRampDown: "30s", exec: "utilisateur",
    },
    administrateur: {
      executor: "constant-arrival-rate", rate: 1, timeUnit: PERIODE, duration: `${seconds(RAMP) + seconds(PLATEAU)}s`,
      preAllocatedVUs: 1, maxVUs: 2, exec: "administrateur",
    },
  },
  thresholds: k6Thresholds(SCENARIO, __ENV, routeMetrics(JOURNEE_ROUTES, "groupe:journee").concat(routeMetrics([ROUTES.settingsWrite, ROUTES.policy]))),
  summaryTrendStats: [...TREND_STATS],
};

/** Révision de la politique d'après l'ETag « "r42" ». */
function revisionOf(res) {
  const m = /r(\d+)/.exec((res.headers && (res.headers.Etag || res.headers.ETag || res.headers.etag)) || "");
  return m ? Number(m[1]) : null;
}

function readPolicyRevision(token, ip) {
  return revisionOf(api("GET", "/settings/policy", { token, ip, name: ROUTES.policy, tags: { groupe: "admin" } }));
}

function readCounters(token, ip) {
  const res = api("GET", "/test/counters", { token, ip, name: ROUTES.counters, tags: { groupe: "admin" }, expect: [200, 404] });
  if (res.status !== 200) return null;
  return {
    settings_loads: Number(jsonField(res, "settings_loads")),
    legacy_settings_reads: Number(jsonField(res, "legacy_settings_reads")),
  };
}

export function setup() {
  const a = adminUser();
  const token = login(a, { on429: true, tags: { groupe: "admin" } });
  if (!token) throw new Error("Connexion de l'administrateur impossible.");
  const counters = readCounters(token, a.xff);
  const revision = readPolicyRevision(token, a.xff);
  return {
    public: { serveur: serverInfo(), compteurs_avant: counters, revision_avant: revision, compteurs_disponibles: counters !== null },
    admin: { token, ip: a.xff, revision },
  };
}

export function utilisateur() {
  journeeIteration({ politique: true, pause: PAUSE });
}

// Révision connue de l'administrateur (VU administrateur).
const adm = { revision: null };

export function administrateur(data) {
  const a = data.admin;
  if (adm.revision === null) adm.revision = data.admin.revision;
  const patch = () => api("PATCH", "/admin/settings", {
    token: a.token, ip: a.ip, name: ROUTES.settingsWrite, tags: { groupe: "admin" }, expect: [200, 409],
    headers: { "if-match": `"r${adm.revision}"` },
    body: { changes: { [SETTING]: `Support banc k6 ${Date.now()}` } },
  });
  let res = patch();
  if (res.status === 409) {
    adm.revision = readPolicyRevision(a.token, a.ip);
    res = patch();
  }
  const ok = check(res, { "réglage enregistré (200)": (r) => r.status === 200 });
  if (ok) {
    settingsWrites.add(1);
    adm.revision = revisionOf(res) || adm.revision + 1;
  }
}

export function teardown(data) {
  const a = data.admin;
  const before = data.public.compteurs_avant;
  const after = readCounters(a.token, a.ip);
  const revision = readPolicyRevision(a.token, a.ip);
  if (before && after && revision !== null && data.admin.revision !== null) {
    const written = revision - data.admin.revision;
    settingsExtraLoads.add(after.settings_loads - before.settings_loads - written - LOAD_SLACK);
    settingsLegacyReads.add(after.legacy_settings_reads - before.legacy_settings_reads);
  }
  logout(a.token, a.ip, { groupe: "admin" });
}

export const handleSummary = makeSummary(SCENARIO, { vus: VUS, ramp_s: seconds(RAMP), plateau_s: seconds(PLATEAU), reglage: SETTING });
