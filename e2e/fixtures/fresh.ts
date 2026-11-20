// Serveur neuf (FRESH_URL) : une seule installation possible par exécution.
// Le premier test qui en a besoin installe Locksy PAR L'INTERFACE, dans sa
// propre page (donc sous les gardes CSP, console et texte) ; les autres (autres
// projets, autres workers) réutilisent le compte propriétaire ainsi créé
// (.state/<cle>/fresh.json).

import { statePath } from "./env.ts";
import { once } from "./lock.ts";
import { testPassword, type Account } from "./ui.ts";

export const FRESH_FILE = "fresh.json";

export interface FreshOwner {
  account: Omit<Account, "id">;
  /** Projet Playwright qui a fait l'installation. */
  installedBy: string;
}

/**
 * Propriétaire du serveur neuf. Si personne n'a encore installé, `install`
 * est appelé avec le compte à créer et `made` vaut vrai.
 */
export async function freshOwner(
  project: string,
  install: (account: Omit<Account, "id">) => Promise<void>,
): Promise<{ owner: FreshOwner; made: boolean }> {
  const { value, made } = await once<FreshOwner>(statePath(FRESH_FILE), async () => {
    const account = { email: "installation@e2e.test", name: "Inès Installatrice", password: testPassword() };
    await install(account);
    return { account, installedBy: project };
  });
  return { owner: value, made };
}
