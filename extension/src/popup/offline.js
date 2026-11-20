// Serveur injoignable alors qu'une session est ouverte : le coffre reste
// déverrouillé jusqu'à son échéance ; « Réessayer » ou « Verrouiller ».

import { h, t } from "../lib/ui/index.js";
import { go, screen, showError, action } from "./context.js";
import { lock } from "./session.js";

export function renderOffline(error, retry) {
  screen({ session: true },
    h("p", { class: "u-muted" }, t("extension.offline.text")),
    action({ label: t("common.action.retry"), icon: "refresh", variant: "primary", onClick: retry }),
    action({
      label: t("common.action.lock"), icon: "lock", variant: "quiet",
      onClick: async () => { await lock({ revoke: true }); go("login", { info: t("extension.session.locked") }); },
    }));
  showError(error);
}
