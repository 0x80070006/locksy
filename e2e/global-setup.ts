// Préparation globale : attend que les deux serveurs Locksy répondent sur
// /api/health et prépare le dossier d'état de l'exécution (.state/<cle>/).
// Le démarrage et l'arrêt de l'environnement sont faits par tools/run.sh.

import { existsSync, rmSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { BASE_URL, FRESH_URL, KEY, stateDir, statePath } from "./fixtures/env.ts";
import { forgetStaleOrg, health } from "./fixtures/org.ts";
import { FRESH_FILE } from "./fixtures/fresh.ts";

async function waitHealthy(url: string, timeoutMs = 120_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await health(url)) return;
    await sleep(500);
  }
  throw new Error(`${url}/api/health ne répond pas après ${timeoutMs / 1000} s (environnement « ${KEY} » démarré ?).`);
}

export default async function globalSetup() {
  stateDir();
  // E2E_NO_SERVER=1 : galerie seule, hors de l'environnement compose.
  if (process.env.E2E_NO_SERVER === "1") return;
  await Promise.all([waitHealthy(BASE_URL), waitHealthy(FRESH_URL)]);
  // Un état laissé par une exécution précédente (--keep) n'est gardé que si le
  // serveur correspondant est toujours le même (déjà installé).
  await forgetStaleOrg();
  const fresh = statePath(FRESH_FILE);
  if (existsSync(fresh) && (await health(FRESH_URL))?.needs_setup) rmSync(fresh);
  for (const name of ["org.json.echec", `${FRESH_FILE}.echec`]) rmSync(statePath(name), { force: true });
}
