// Aides des tests de la galerie des composants (projet Playwright « ui-gallery »).

import { expect, type Page } from "@playwright/test";
import { fileURLToPath } from "node:url";

/** Racine du dépôt (le dépôt est monté en /work dans le lanceur). */
export const REPO = fileURLToPath(new URL("../../../", import.meta.url));

/** Ouvre la galerie (une section avec `only`) et attend la fin du montage. */
export async function openGallery(page: Page, only?: string, query = "") {
  const q = new URLSearchParams(query);
  if (only) q.set("only", only);
  const s = q.toString();
  await page.goto(`/gallery/${s ? `?${s}` : ""}`);
  await expect(page.locator("html")).toHaveAttribute("data-gallery-ready", "true");
}

/** Sortie de démonstration d'une section (texte écrit par la galerie). */
export const sortie = (page: Page, name: string) => page.locator(`[data-sortie="${name}"]`);

/** Élément actif : description courte (rôle et nom) pour les messages d'échec. */
export async function activeInfo(page: Page) {
  return page.evaluate(() => {
    const el = document.activeElement as HTMLElement | null;
    if (!el) return "aucun";
    return `${el.tagName.toLowerCase()}|${el.getAttribute("aria-label") || el.textContent?.trim().slice(0, 40) || ""}|dialog:${!!el.closest("dialog")}`;
  });
}
