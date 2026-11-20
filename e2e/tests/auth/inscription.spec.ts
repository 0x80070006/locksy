// Inscription sur invitation, clé de récupération (copie, fichier .txt,
// confirmation obligatoire) et récupération du compte avec confirmation du
// nouveau mot de passe maître (cahier §3.3.1, écart #4).

import { readFile } from "node:fs/promises";
import { test, expect } from "../../fixtures/index.ts";
import { expectShell, KDF_TIMEOUT, loginUi, logoutUi, testPassword } from "../../fixtures/ui.ts";
import { preparer } from "../shell/outils.ts";

test.use({ textGuardMode: "strict" });
test.beforeEach(preparer);

const L = {
  name: "Votre nom",
  password: /^Mot de passe maître$/,
  confirm: "Confirmer le mot de passe maître",
  create: "Créer mon coffre",
  ack: "J'ai conservé ma clé de récupération",
  download: "Télécharger (.txt)",
  email: "Adresse e-mail",
  recoveryKey: "Clé de récupération",
  newPassword: "Nouveau mot de passe maître",
  newConfirm: "Confirmer le nouveau mot de passe maître",
};

test("inscription : contrôle du mot de passe, clé téléchargée en .txt, puis récupération confirmée", async ({ page, apiAs }) => {
  test.setTimeout(180_000);
  const email = `recup-${Date.now()}@e2e.test`;
  const res = await (await apiAs("owner")).post("/api/admin/invites", { data: { email, role: "user" } });
  expect(res.ok()).toBe(true);
  const { token } = await res.json();

  // Ancienne adresse d'invitation : redirigée vers #/inscription/<jeton>.
  await page.goto(`/#/register?token=${encodeURIComponent(token)}`);
  await expect(page).toHaveURL(/#\/inscription\//);
  await expect(page.getByLabel(L.email)).toHaveValue(email);
  await expect(page.getByLabel(L.email)).toHaveAttribute("readonly", "");
  await expect(page.getByLabel(L.name)).toBeFocused();

  await page.getByLabel(L.name).fill("Rémi Récupération");
  await page.getByLabel(L.password).fill("court");
  await page.getByLabel(L.confirm).fill("court");
  await page.getByRole("button", { name: L.create }).click();
  await expect(page.locator("#contenu").getByText("Au moins 12 caractères.")).toBeVisible();

  const password = testPassword();
  await page.getByLabel(L.password).fill(password);
  await page.getByLabel(L.confirm).fill(`${password}x`);
  await page.getByRole("button", { name: L.create }).click();
  await expect(page.locator("#contenu").getByText("Les deux saisies ne correspondent pas.")).toBeVisible();

  await page.getByLabel(L.confirm).fill(password);
  await page.getByRole("button", { name: L.create }).click();

  // Clé de récupération : « Continuer » impossible avant la case.
  await expect(page.getByRole("heading", { level: 1, name: "Votre clé de récupération" })).toBeVisible({ timeout: KDF_TIMEOUT });
  const key = (await page.locator("p.u-mono").innerText()).trim();
  expect(key.length).toBeGreaterThan(20);
  const next = page.getByRole("button", { name: "Continuer" });
  await expect(next).toBeDisabled();

  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: L.download }).click()]);
  expect(download.suggestedFilename()).toBe("locksy-cle-de-recuperation.txt");
  const text = await readFile(await download.path(), "utf8");
  expect(text).toContain(key);
  expect(text).toContain(email);
  // Rien n'est gardé dans le navigateur.
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
  expect(stored).not.toContain(key);

  await page.getByLabel(L.ack).check();
  await next.click();
  await expectShell(page);
  await logoutUi(page);

  // Récupération : la confirmation du nouveau mot de passe est exigée avant tout envoi.
  await page.goto("/#/recover");
  await expect(page).toHaveURL(/#\/recuperation$/);
  await expect(page.getByRole("heading", { level: 1, name: "Récupérer mon compte" })).toBeVisible();
  let sent = 0;
  page.on("request", (r) => { if (r.url().includes("/api/auth/recover/")) sent += 1; });
  const fresh = testPassword();
  await page.getByLabel(L.email).fill(email);
  await page.getByLabel(L.recoveryKey).fill(key);
  await page.getByLabel(L.newPassword, { exact: true }).fill(fresh);
  await page.getByLabel(L.newConfirm).fill(`${fresh}-autre`);
  await page.getByRole("button", { name: "Définir le nouveau mot de passe" }).click();
  await expect(page.locator("#contenu").getByText("Les deux saisies ne correspondent pas.")).toBeVisible();
  expect(sent).toBe(0);

  await page.getByLabel(L.newConfirm).fill(fresh);
  await page.getByRole("button", { name: "Définir le nouveau mot de passe" }).click();
  await expect(page.locator(".c-toasts").getByText("Mot de passe maître remplacé. Connectez-vous avec le nouveau.")).toBeVisible({ timeout: KDF_TIMEOUT });
  await expect(page).toHaveURL(/#\/connexion$/);
  await loginUi(page, { email, password: fresh });
});

test("invitation périmée : message clair et retour à la connexion", async ({ page, consoleGuard }) => {
  consoleGuard.allow(/status of 4\d\d/);
  await page.goto("/#/inscription/jeton-inconnu-0000");
  await expect(page.getByRole("heading", { level: 1, name: "Invitation invalide" })).toBeVisible();
  await page.getByRole("link", { name: "Retour à la connexion" }).click();
  await expect(page.getByRole("button", { name: /^Se connecter$/ })).toBeVisible();
});
