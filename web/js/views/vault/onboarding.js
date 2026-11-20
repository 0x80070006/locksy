// Accueil d'un coffre vide (cahier §3.3.2) : trois cartes, chacune avec
// l'action qui remplit le coffre : importer depuis un autre outil, ajouter un
// premier mot de passe, installer l'extension.
//
// onboarding({ env }) -> HTMLElement

import { t, h, icon } from "../../ui/index.js";
import { writableCollections } from "./common.js";

function card(href, iconName, title, text) {
  return h("a", { class: "c-card l-stack", "data-gap": "2", href },
    icon(iconName), h("strong", {}, title), h("span", { class: "u-muted" }, text));
}

export function onboarding() {
  const canAdd = writableCollections().length > 0;
  return h("section", { class: "l-stack", "data-gap": "3", "aria-labelledby": "coffre-bienvenue" },
    h("h2", { id: "coffre-bienvenue" }, t("vault.onboarding.title")),
    h("p", { class: "u-muted" }, t("vault.onboarding.text")),
    h("div", { class: "l-grid" },
      card("#/parametres/donnees", "upload", t("vault.onboarding.import"), t("vault.onboarding.import_text")),
      canAdd ? card("#/nouveau/login", "plus", t("vault.onboarding.first"), t("vault.onboarding.first_text")) : null,
      card("#/aide", "download", t("vault.onboarding.extension"), t("vault.onboarding.extension_text"))));
}
