// Contrôle des fixtures sur le serveur amorcé (BASE_URL) : organisation créée
// par l'interface, connexion par rôle, requêtes API authentifiées.

import { test, expect } from "../../fixtures/index.ts";
import { sessionToken } from "../../fixtures/ui.ts";

test.describe("Fixtures de l'organisation de test", { tag: ["@smoke", "@mobile"] }, () => {
  test("loggedIn(\"user\") ouvre une session valide", async ({ loggedIn, org }) => {
    const page = await loggedIn("user");
    const token = await sessionToken(page);
    const res = await page.request.get("/api/me", { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status()).toBe(200);
    expect(await res.json()).toMatchObject({ id: org.accounts.user.id, email: org.accounts.user.email, role: "user" });
  });

  test("apiAs(\"admin\") interroge l'API avec le rôle administrateur", async ({ apiAs, org }) => {
    const api = await apiAs("admin");
    const me = await api.get("/api/me");
    expect(me.status()).toBe(200);
    expect(await me.json()).toMatchObject({ id: org.accounts.admin.id, email: org.accounts.admin.email, role: "admin" });
    // Le rôle est réel : la liste des comptes est réservée à l'administration.
    expect((await api.get("/api/admin/users")).status()).toBe(200);
  });

  test("les trois comptes ont le bon rôle", async ({ apiAs, org }) => {
    const users: { id: string; email: string; role: string }[] = await (await (await apiAs("owner")).get("/api/admin/users")).json();
    for (const role of ["owner", "admin", "user"] as const) {
      const a = org.accounts[role];
      expect(users.find((u) => u.id === a.id), a.email).toMatchObject({ email: a.email, role });
    }
  });
});
