// Analyse d'accessibilité avec axe-core, réglée pour les gardes du harnais.
//
// Le préchargement des feuilles de style d'axe (preload) résout les @import de
// web/css/app.css par rapport à la PAGE et non à la feuille : il demande alors
// des fichiers inexistants (« /gallery/base.css »), ce qui produit des 404 dans
// la console et ferait échouer consoleGuard. Il ne sert qu'à la règle
// css-orientation-lock ; on le coupe.

import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

/** Normes du cahier §6.4 : WCAG 2.0, 2.1 et 2.2, niveaux A et AA. */
export const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

export function axe(page: Page, tags: string[] = WCAG_TAGS): AxeBuilder {
  return new AxeBuilder({ page }).withTags(tags).options({ preload: false });
}

/** Violations « serious » et « critical », une ligne lisible par règle. */
export async function seriousViolations(page: Page, tags: string[] = WCAG_TAGS): Promise<string[]> {
  const { violations } = await axe(page, tags).analyze();
  return violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => `${v.id} (${v.impact}) : ${v.nodes.slice(0, 6).map((n) => n.target.join(" ")).join(" | ")}`);
}
