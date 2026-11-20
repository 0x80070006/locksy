// axe-core tourne sous les gardes du harnais sans les déclencher (ni 404 de
// préchargement, ni violation CSP attribuée au produit). Le nombre de défauts
// de l'interface actuelle est joint au rapport ; le seuil « 0 serious » est
// vérifié écran par écran par la suite a11y (lot Q3b).

import { test, expect } from "../../fixtures/index.ts";
import { axe } from "../../fixtures/axe.ts";

test("axe s'exécute sous les gardes sur l'écran d'accueil", { tag: "@smoke" }, async ({ page }, testInfo) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  const { violations } = await axe(page).analyze();
  await testInfo.attach("axe.json", {
    body: JSON.stringify(violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length })), null, 2),
    contentType: "application/json",
  });
  expect(Array.isArray(violations)).toBe(true);
});
