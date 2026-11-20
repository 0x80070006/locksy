// Réglages › Système (cahier §3.4.6, contrats C1.5 et C1.6, fiche L12) :
// e-mail de test (réussite, échec expliqué par son code, route absente),
// envois en échec avec « Renvoyer », vérification du journal chaîné
// (intègre, altéré, route absente), configuration de l'hébergeur.

import { test, expect } from "../../fixtures/index.ts";
import { goHash, missing, now, simulate } from "./outils.ts";

test.use({ textGuardMode: "strict" });

test.describe("Système", () => {
  test("e-mail de test : réussite, puis échec expliqué en français", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/502|Failed to load resource/);
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await sim.on("POST", "/admin/mail/test", () => ({ sent: true }));
    await sim.on("GET", "/admin/mail/queue", () => [
      { id: "m1", kind: "invite", to_email: "l***@exemple.fr", subject: "", status: "failed", attempts: 5, last_error_code: "smtp_auth", created_at: now() - 7200, updated_at: now() - 600, sent_at: null },
    ]);
    await sim.on("POST", "/admin/mail/queue/m1/retry", () => ({ status: 202, json: {} }));
    await goHash(page, "#/admin/reglages/systeme");
    await expect(page.getByRole("heading", { level: 1, name: "Système" })).toBeVisible();

    await page.getByRole("button", { name: "Envoyer un e-mail de test" }).click();
    await expect(page.getByText(/E-mail de test envoyé à .* Vérifiez sa réception\./)).toBeVisible();

    sim.fail("POST", "/admin/mail/test", 502, { error: "email_not_sent", message: "Non envoyé.", error_code: "smtp_auth" });
    await page.getByRole("button", { name: "Envoyer un e-mail de test" }).click();
    // Même texte dans le résultat du test et dans la file des envois en échec.
    await expect(page.locator(".c-alert").filter({ hasText: "Le serveur d'envoi a refusé l'identifiant ou le mot de passe. Saisissez-les de nouveau." })).toBeVisible();

    const queue = page.getByRole("table", { name: "1 envoi en échec" });
    await expect(queue.getByText("Invitation")).toBeVisible();
    await queue.getByRole("button", { name: "Renvoyer l'e-mail à l***@exemple.fr" }).click();
    await expect(page.locator(".c-toast").filter({ hasText: "Nouvel envoi programmé." })).toBeVisible();
    expect(sim.called("POST", "/admin/mail/queue/m1/retry")).toHaveLength(1);
  });

  test("vérification du journal : intègre, puis altération détectée", async ({ loggedIn }) => {
    const page = await loggedIn("owner");
    const sim = await simulate(page);
    await sim.on("GET", "/admin/mail/queue", () => []);
    let ok = true;
    await page.route((url) => url.pathname === "/api/admin/audit/verify", (route) => route.fulfill({
      json: ok
        ? { ok: true, checked: 1204, first_id: 1, last_id: 1204, anchors: 3, unchained_before: null, breaks: [], verified_at: now() }
        : { ok: false, checked: 1204, first_id: 1, last_id: 1204, anchors: 3, unchained_before: null, breaks: [{ id: 57, kind: "altered" }], verified_at: now() },
    }));
    await goHash(page, "#/admin/reglages/systeme");
    await page.getByRole("button", { name: "Vérifier le journal" }).click();
    await expect(page.getByText("Journal intègre")).toBeVisible();
    await expect(page.getByText(/1 204 événements vérifiés|1 204 événements vérifiés/)).toBeVisible();
    ok = false;
    await page.getByRole("button", { name: "Vérifier le journal" }).click();
    await expect(page.getByText("Altération détectée")).toBeVisible();
  });

  test("replis : serveur sans e-mail de test ni vérification du journal", async ({ loggedIn, consoleGuard }) => {
    consoleGuard.allow(/404|405|Failed to load resource/);
    const page = await loggedIn("owner");
    await missing(page, "POST", "/admin/mail/test");
    await missing(page, "GET", "/admin/mail/queue");
    await missing(page, "GET", "/admin/audit/verify");
    await goHash(page, "#/admin/reglages/systeme");
    await expect(page.getByText("Le suivi des envois arrive avec une prochaine version du serveur.")).toBeVisible();
    await page.getByRole("button", { name: "Envoyer un e-mail de test" }).click();
    await expect(page.getByText("L'envoi d'un e-mail de test arrive avec une prochaine version du serveur.")).toBeVisible();
    await page.getByRole("button", { name: "Vérifier le journal" }).click();
    await expect(page.getByText("La vérification du journal arrive avec une prochaine version du serveur.")).toBeVisible();
    // Configuration de l'hébergeur : route réelle (propriétaire).
    await expect(page.getByRole("heading", { name: "Configuration de l'hébergeur" })).toBeVisible();
  });
});
