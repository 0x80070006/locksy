// Aide au choix de la méthode de connexion (cahier §3.4.7) : une question,
// trois réponses, « Continuer » ouvre l'assistant adapté (ou les invitations).

import { alertCard, button, clear, h, radioCards, t } from "../../../ui/index.js";
import { goTo } from "./common.js";

/** Réponse -> destination. */
const TARGETS = Object.freeze({
  cloud: () => goTo("sso"),
  windows: () => goTo("ad"),
  none: () => { location.hash = "#/admin/personnes"; },
});

/** Bloc d'aide au choix (le choix n'est pas une saisie à protéger). */
export function chooser() {
  let choice = "";
  const message = h("div", {});
  const group = radioCards({
    legend: t("identity.choose.legend"),
    options: ["cloud", "windows", "none"].map((value) => ({
      value,
      label: t(`identity.choose.${value}.label`),
      description: t(`identity.choose.${value}.description`),
    })),
    value: "",
    onChange: (v) => {
      choice = v;
      clear(message);
    },
  });
  return h("section", { class: "c-card l-stack", "data-gap": "3", "aria-labelledby": "identite-choix" },
    h("h2", { id: "identite-choix" }, t("identity.choose.title")),
    group,
    message,
    h("div", { class: "l-cluster", "data-justify": "end" },
      button({
        label: t("common.action.continue"), variant: "primary",
        onClick: () => {
          if (!TARGETS[choice]) {
            clear(message, alertCard({ tone: "warn", text: t("identity.choose.required") }));
            group.querySelector("input")?.focus();
            return;
          }
          TARGETS[choice]();
        },
      })));
}
