// Fin d'exécution : rien de destructif ici. tools/run.sh arrête et supprime
// l'environnement (« down -v ») ; avec --keep, l'état de .state/<cle>/ reste
// cohérent avec les serveurs conservés et sera réutilisé. On retire seulement
// les verrous qu'un worker interrompu aurait laissés.

import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { stateDir } from "./fixtures/env.ts";

export default async function globalTeardown() {
  const dir = stateDir();
  for (const name of readdirSync(dir)) {
    if (name.endsWith(".lock") || name.endsWith(".tmp")) rmSync(join(dir, name), { recursive: true, force: true });
  }
}
