// Amorçage « une seule fois par exécution » partagé entre workers (processus
// distincts) : verrou par création atomique de dossier, résultat en JSON.

import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

export interface OnceResult<T> {
  value: T;
  /** Vrai si CE processus a exécuté `make` (et non relu le résultat d'un autre). */
  made: boolean;
}

/**
 * Renvoie le contenu de `file` ; s'il n'existe pas, un seul processus exécute
 * `make` (les autres attendent) puis l'écrit de façon atomique. Un verrou plus
 * vieux que `staleMs` est considéré comme abandonné (worker tué).
 */
export async function once<T>(file: string, make: () => Promise<T>, { timeoutMs = 300_000, staleMs = 300_000 } = {}): Promise<OnceResult<T>> {
  const lock = `${file}.lock`;
  const failed = `${file}.echec`;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (existsSync(failed)) throw new Error(`Amorçage échoué dans un autre worker : ${readFileSync(failed, "utf8")}`);
    if (existsSync(file)) return { value: JSON.parse(readFileSync(file, "utf8")) as T, made: false };
    try {
      mkdirSync(lock);
    } catch {
      let age = 0;
      try {
        age = Date.now() - statSync(lock).mtimeMs;
      } catch {
        continue; // libéré entre-temps
      }
      if (age > staleMs) rmSync(lock, { recursive: true, force: true });
      else if (Date.now() > deadline) throw new Error(`Attente trop longue de ${file} (verrou tenu par un autre worker).`);
      else await sleep(250);
      continue;
    }
    try {
      if (existsSync(file)) return { value: JSON.parse(readFileSync(file, "utf8")) as T, made: false };
      let value: T;
      try {
        value = await make();
      } catch (e) {
        writeFileSync(failed, String((e as Error)?.message || e));
        throw e;
      }
      const tmp = `${file}.${process.pid}.tmp`;
      writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
      renameSync(tmp, file);
      return { value, made: true };
    } finally {
      rmSync(lock, { recursive: true, force: true });
    }
  }
}
