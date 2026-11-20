// Autorisations en boîte noire (G9), échantillon de la matrice générée de
// crates/locksy-server/src/tests/authz_matrix.rs. Les objets sont créés par
// l'interface et le vrai client (élément, pièce jointe, lien). Un étranger et
// un administrateur NON membre reçoivent le 404 uniforme : même code et même
// message qu'un identifiant inexistant, sans rien modifier. Un compte
// « user » est refusé sur /api/admin/*, une session sur /scim/v2.

import { test, expect } from "../fixtures/index.ts";
import type { APIRequestContext, APIResponse, Page } from "@playwright/test";
import { randomBytes, randomUUID } from "node:crypto";
import { BASE_URL } from "../fixtures/env.ts";
import { addPasswordItem, sessionToken, testPassword } from "../fixtures/ui.ts";
import { adresse, avec, b64, chiffre, json, nouveauCompte, refus } from "./outils.ts";

interface Objets {
  element: string;
  coffre: string;
  piece: string;
  lien: string;
  revision: number;
}

/** Élément ajouté par l'éditeur, puis pièce jointe et lien par le vrai client de la page. */
async function creerObjets(page: Page, nom: string): Promise<Objets> {
  await addPasswordItem(page, { name: nom, username: "idor@exemple.fr", password: testPassword() });
  return page.evaluate(async (nom) => {
    const V = await import("/js/vault.js");
    await V.sync();
    const trouve = () => [...V.state.items.values()].find((i) => i.data?.name === nom);
    const item = trouve();
    if (!item) throw new Error(`élément ${nom} introuvable après synchronisation`);
    await V.addAttachment(item, new File(["contenu de la pièce jointe"], "piece.txt", { type: "text/plain" }));
    await V.sync();
    const apres = trouve();
    const lien = await V.createShareLink({ name: nom }, 60, 3, { itemId: item.id });
    return { element: item.id, coffre: item.collection_id, piece: apres.data.attachments[0].id, lien: lien.id, revision: apres.revision };
  }, nom);
}

/** Statut, code et message : ce qu'un étranger apprend d'une réponse. */
async function forme(res: APIResponse) {
  const corps = await json(res);
  return { statut: res.status(), code: corps?.error, message: corps?.message };
}

test.describe("Objets d'autrui : 404 uniforme", () => {
  test.describe.configure({ mode: "serial" });

  test("étranger et administrateur non membre ne voient ni ne modifient rien", async ({ loggedIn, apiAs, browser, playwright }) => {
    const proprietaire = await loggedIn("user");
    const o = await creerObjets(proprietaire, `IDOR-${randomBytes(4).toString("hex")}`);
    const jetonProprietaire = await sessionToken(proprietaire);
    const etranger = await nouveauCompte(browser, await apiAs("admin"), "etranger");
    const admin = await apiAs("admin");

    const fantome = randomUUID();
    const cas: { nom: string; methode: string; reel: string; faux: string; corps?: unknown }[] = [
      { nom: "lecture de pièce jointe", methode: "GET", reel: `/api/attachments/${o.piece}`, faux: `/api/attachments/${fantome}` },
      { nom: "suppression de pièce jointe", methode: "DELETE", reel: `/api/attachments/${o.piece}`, faux: `/api/attachments/${fantome}` },
      {
        nom: "modification d'élément",
        methode: "PUT",
        reel: `/api/items/${o.element}`,
        faux: `/api/items/${fantome}`,
        corps: { collection_id: o.coffre, data: chiffre(), revision: o.revision },
      },
      { nom: "mise à la corbeille", methode: "DELETE", reel: `/api/items/${o.element}`, faux: `/api/items/${fantome}` },
      {
        nom: "ajout de pièce jointe",
        methode: "PUT",
        reel: `/api/items/${o.element}/attachments/${randomUUID()}`,
        faux: `/api/items/${fantome}/attachments/${randomUUID()}`,
        corps: { data: chiffre() },
      },
      { nom: "membres du coffre", methode: "GET", reel: `/api/collections/${o.coffre}/members`, faux: `/api/collections/${fantome}/members` },
      { nom: "renommage du coffre", methode: "PUT", reel: `/api/collections/${o.coffre}`, faux: `/api/collections/${fantome}`, corps: { enc_name: chiffre() } },
      { nom: "révocation du lien", methode: "DELETE", reel: `/api/shares/${o.lien}`, faux: `/api/shares/${b64(32)}` },
    ];

    const acteurs: [string, (m: string, url: string, corps?: unknown) => Promise<APIResponse>][] = [
      ["étranger", (m, url, corps) => etranger.page.request.fetch(url, { method: m, data: corps, headers: avec(etranger.token) })],
      ["administrateur non membre", (m, url, corps) => admin.fetch(url, { method: m, data: corps })],
    ];
    for (const [qui, appel] of acteurs) {
      for (const c of cas) {
        const reel = await forme(await appel(c.methode, c.reel, c.corps));
        const faux = await forme(await appel(c.methode, c.faux, c.corps));
        expect(reel, `${qui} : ${c.nom}`).toEqual(faux);
        expect(reel.statut, `${qui} : ${c.nom}`).toBe(404);
        expect(reel.code).toBe("not_found");
      }
    }

    // Rien n'a bougé : l'élément garde sa révision, la pièce jointe et le lien existent.
    const api = await playwright.request.newContext({ baseURL: BASE_URL, extraHTTPHeaders: avec(jetonProprietaire) });
    try {
      const sync = (await (await api.get("/api/sync")).json()) as { items: { id: string; revision: number; deleted_at?: number | null }[] };
      expect(sync.items.find((i) => i.id === o.element)).toMatchObject({ revision: o.revision });
      expect((await api.get(`/api/attachments/${o.piece}`)).status()).toBe(200);
      const liens = (await (await api.get("/api/shares")).json()) as { id: string }[];
      expect(liens.map((l) => l.id)).toContain(o.lien);
    } finally {
      await api.dispose();
      await etranger.context.close();
    }
  });
});

test.describe("Rôles d'organisation", () => {
  test("un compte « user » est refusé sur /api/admin/*", async ({ apiAs }) => {
    const user = await apiAs("user");
    const lectures = ["/api/admin/users", "/api/admin/people", "/api/admin/stats", "/api/admin/settings", "/api/admin/audit", "/api/admin/scim", "/api/admin/config/effective"];
    for (const url of lectures) await refus(await user.get(url), 403, "forbidden");
    await refus(await user.post("/api/admin/invites", { data: { email: "intrus@e2e.test", role: "admin" } }), 403, "forbidden");
    await refus(await user.patch("/api/admin/settings", { data: { changes: {} } }), 403, "forbidden");
  });

  test("une session, même de propriétaire, est refusée sur /scim/v2", async ({ apiAs, playwright, baseURL }) => {
    const owner = await apiAs("owner");
    const me = (await (await owner.get("/api/me")).json()) as { role: string };
    expect(me.role).toBe("owner");
    // Le jeton de session de apiAs est relu dans ses en-têtes : on rejoue la même session sur SCIM.
    const scim = await owner.get("/scim/v2/Users");
    expect(scim.status()).toBe(401);
    expect(await json(scim)).toMatchObject({ status: "401" });
    // Sans aucun en-tête : même refus.
    const nu: APIRequestContext = await playwright.request.newContext({ baseURL, extraHTTPHeaders: { "X-Forwarded-For": adresse() } });
    try {
      expect((await nu.get("/scim/v2/ServiceProviderConfig")).status()).toBe(401);
    } finally {
      await nu.dispose();
    }
  });
});
