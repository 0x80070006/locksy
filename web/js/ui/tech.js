// Volet « Détails techniques » : seul endroit où les termes techniques (clé
// d'un réglage, identifiant, code d'erreur) sont affichés. Le contrôle des
// textes des tests l'exclut grâce à data-technical.

import { t } from "../i18n.js";
import { h } from "./core.js";

/** { body, summary } -> <details class="c-tech" data-technical>. */
export function technicalDetails({ body, summary = t("common.glossary.technical_details") }) {
  return h("details", { class: "c-tech", "data-technical": "" },
    h("summary", {}, summary),
    h("div", { translate: "no" }, body));
}
