// copySecret (effacement différé du presse-papiers, horloge simulée) et
// totpCode (aucune annonce aux lecteurs d'écran, règle A2).

import { test, expect } from "../../fixtures/index.ts";
import { openGallery } from "./galerie.ts";

const SECRET = "Tq7!vLp2#Rz9@Wm4";

test.describe("copySecret()", () => {
  test.beforeEach(async ({ context, page, baseURL, browserName }) => {
    // Firefox : presse-papiers ouvert par préférences (playwright.config.ts).
    if (browserName === "chromium") await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: new URL(baseURL!).origin });
    await page.clock.install();
    await openGallery(page, "secret");
  });

  const clipboard = (page: import("@playwright/test").Page) => page.evaluate(() => navigator.clipboard.readText());

  test("efface le presse-papiers après le délai, sans annoncer le secret", async ({ page }) => {
    await page.getByRole("button", { name: "Copier le mot de passe" }).click();
    await expect(page.locator("#status")).toHaveText("Mot de passe copié, effacé dans 30 s");
    expect(await clipboard(page)).toBe(SECRET);
    await page.clock.runFor(29_000);
    expect(await clipboard(page)).toBe(SECRET);
    await page.clock.runFor(2_000);
    await expect.poll(() => clipboard(page)).toBe("");
    expect(await page.locator("#status, #alert, .c-toasts").allTextContents()).not.toContain(SECRET);
  });

  test("n'efface pas si le presse-papiers a changé entre-temps", async ({ page }) => {
    await page.getByRole("button", { name: "Copier le mot de passe" }).click();
    await expect(page.locator("#status")).toHaveText("Mot de passe copié, effacé dans 30 s");
    await page.evaluate(() => navigator.clipboard.writeText("autre texte copié ailleurs"));
    await page.clock.runFor(31_000);
    expect(await clipboard(page)).toBe("autre texte copié ailleurs");
  });

  test("la valeur est masquée puis révélée par « Afficher le mot de passe »", async ({ page }) => {
    const reveal = page.getByRole("button", { name: "Afficher le mot de passe" });
    await expect(reveal).toHaveAttribute("aria-pressed", "false");
    await expect(page.getByText(SECRET)).toHaveCount(0);
    await reveal.click();
    await expect(reveal).toHaveAttribute("aria-pressed", "true");
    // Groupes de 4 sans espace réel : le texte reste exact.
    expect(await page.locator(".c-secret-row .c-secret").first().textContent()).toBe(SECRET);
  });
});

test.describe("totpCode()", () => {
  test("aucune annonce pendant 90 s, texte changé seulement au changement de code", async ({ page }) => {
    await page.clock.install();
    await openGallery(page, "code-site");
    const code = page.locator(".c-totp__code").first();
    await expect(code).toHaveAttribute("aria-live", "off");
    await expect(code).toHaveText(/^\d{3} \d{3}$/);
    await page.evaluate(() => {
      const w = window as any;
      w.annonces = [];
      w.changements = 0;
      const watch = new MutationObserver((records) => {
        for (const r of records) w.annonces.push((r.target as HTMLElement).textContent || (r.target.parentElement?.textContent ?? ""));
      });
      for (const id of ["status", "alert"]) watch.observe(document.getElementById(id)!, { childList: true, characterData: true, subtree: true });
      new MutationObserver((records) => { w.changements += records.length; })
        .observe(document.querySelector(".c-totp__code")!, { childList: true, characterData: true, subtree: true });
    });
    const first = await code.textContent();
    await page.clock.runFor(90_000);
    const result = await page.evaluate(() => ({ annonces: (window as any).annonces, changements: (window as any).changements }));
    expect(result.annonces).toEqual([]);
    await expect(page.locator("#status")).toHaveText("");
    expect(await code.textContent()).not.toBe(first);
    // 90 s = 3 périodes : au plus 4 changements de texte (pas un par seconde).
    expect(result.changements).toBeGreaterThan(0);
    expect(result.changements).toBeLessThanOrEqual(4);
    expect(await page.locator(".c-totp").first().evaluate((el) => el.style.getPropertyValue("--progress"))).toMatch(/^0(\.\d+)?$|^1$/);
  });
});
