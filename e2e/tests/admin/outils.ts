// Outils des tests de l'administration (lot L12).
//
// L'image de test (locksy-e2e-server:fast) ne contient pas les routes de la
// vague 2 (/admin/people, /admin/users/bulk, /admin/invites/batch, départ,
// e-mails, vérification du journal…) : elles sont simulées par page.route()
// selon le contrat C1. Les routes des réglages (/admin/settings/*) existent
// dans l'image et sont utilisées réellement, sauf mention.
//
// `server` relève les requêtes reçues ; `server.fail(route, 500 | "reseau")`
// force un échec pour les tests « chaque écriture a son test d'échec ».

import type { Page, Route } from "@playwright/test";
import { expect } from "../../fixtures/index.ts";

export const now = () => Math.floor(Date.now() / 1000);
export const DAY = 86400;

/** Libellés contractuels (annexe C) et textes des écrans de l'administration. */
export const L = {
  adminNav: /^Administration$/,
  settingsSearch: "Chercher un réglage",
  saveSettings: /^Vérifier et enregistrer$/,
  resetAll: /^Tout annuler$/,
  save: /^Enregistrer$/,
  peopleSearch: "Rechercher un nom ou une adresse",
  invite: /^Inviter des personnes$/,
  changeRole: /^Changer le rôle/,
  masterPassword: /^Mot de passe maître$/,
};

/** Va à une route de l'application sans recharger la page (le coffre reste ouvert). */
export async function goHash(page: Page, hash: string) {
  await page.evaluate((h) => { location.hash = h; }, hash);
}

type Failure = number | "reseau";
type Handler = (route: Route, body: unknown, url: URL) => unknown | Promise<unknown>;

export interface SimServer {
  calls: { method: string; path: string; query: URLSearchParams; body: unknown; headers: Record<string, string> }[];
  on(method: string, path: string | RegExp, handler: Handler): Promise<void>;
  fail(method: string, path: string | RegExp, how: Failure, error?: { error: string; message?: string; [k: string]: unknown }): void;
  heal(method: string, path: string | RegExp): void;
  called(method: string, path: string | RegExp): SimServer["calls"];
}

const same = (a: string | RegExp, b: string) => (typeof a === "string" ? a === b : a.test(b));

/**
 * Serveur simulé : chaque route déclarée par on() répond avec le JSON renvoyé
 * par son gestionnaire (ou { status, json } pour un statut précis).
 */
export async function simulate(page: Page): Promise<SimServer> {
  const failures: { method: string; path: string | RegExp; how: Failure; error?: Record<string, unknown> }[] = [];
  const sim: SimServer = {
    calls: [],
    async on(method, path, handler) {
      await page.route((url) => url.pathname.startsWith("/api/") && same(path, url.pathname.slice(4)), async (route) => {
        const req = route.request();
        if (req.method() !== method) return route.fallback();
        const url = new URL(req.url());
        const p = url.pathname.slice(4);
        let body: unknown = null;
        try { body = req.postDataJSON(); } catch { body = req.postData(); }
        sim.calls.push({ method, path: p, query: url.searchParams, body, headers: req.headers() });
        const f = failures.find((x) => x.method === method && same(x.path, p));
        if (f?.how === "reseau") return route.abort("failed");
        if (typeof f?.how === "number") {
          return route.fulfill({ status: f.how, json: f.error || { error: "internal", message: "Erreur interne du serveur." } });
        }
        const out = await handler(route, body, url);
        if (out && typeof out === "object" && "status" in (out as object) && "json" in (out as object)) {
          const o = out as { status: number; json: unknown; headers?: Record<string, string> };
          return route.fulfill({ status: o.status, json: o.json, headers: o.headers });
        }
        if (out === undefined || out === null) return route.fulfill({ status: 204, body: "" });
        return route.fulfill({ json: out });
      });
    },
    fail(method, path, how, error) {
      failures.unshift({ method, path, how, error });
    },
    heal(method, path) {
      for (let i = failures.length - 1; i >= 0; i--) if (failures[i].method === method && String(failures[i].path) === String(path)) failures.splice(i, 1);
    },
    called(method, path) {
      return sim.calls.filter((c) => c.method === method && same(path, c.path));
    },
  };
  return sim;
}

/** Route absente du serveur (404 sans corps JSON, comme une route inconnue). */
export async function missing(page: Page, method: string, path: string | RegExp) {
  await page.route((url) => url.pathname.startsWith("/api/") && same(path, url.pathname.slice(4)), async (route) => {
    if (route.request().method() !== method) return route.fallback();
    return route.fulfill({ status: 404, body: "" });
  });
}

/** Attend un message dans la zone d'annonces ou un toast. */
export async function expectToast(page: Page, text: string | RegExp) {
  await expect(page.locator(".c-toast").filter({ hasText: text }).first()).toBeVisible();
}

// ------------------------------------------------------------------ Personnes simulées (A.6)

export const PEOPLE = {
  hugo: {
    kind: "user", id: "u-hugo", name: "Hugo Martin", email: "hugo.martin@exemple.fr", role: "user", status: "active",
    twofa: false, origin: "ldap", last_seen_at: now() - 3 * DAY, created_at: now() - 90 * DAY, access_until: null,
    deprovision_at: null, disabled_reason: null, is_self: false,
  },
  camille: {
    kind: "user", id: "u-camille", name: "Camille Durand", email: "camille.durand@exemple.fr", role: "admin", status: "active",
    twofa: true, origin: "local", last_seen_at: now() - 3600, created_at: now() - 200 * DAY, access_until: null,
    deprovision_at: null, disabled_reason: null, is_self: false,
  },
  lea: {
    kind: "invite", id: "i-lea", email: "lea.petit@exemple.fr", role: "user", status: "invited", expires_at: now() + 5 * DAY,
    created_at: now() - 2 * DAY, sent_count: 1, last_sent_at: null, access_until: null, origin: "invite",
  },
};

/** GET /admin/people : renvoie les lignes données (filtres relevés dans `calls`). */
export async function simulatePeople(sim: SimServer, rows: Record<string, unknown>[] = Object.values(PEOPLE)) {
  await sim.on("GET", "/admin/people", (_r, _b, url) => {
    const etat = url.searchParams.get("etat");
    const list = etat === "actif" ? rows.filter((r) => r.status === "active") : rows;
    return { total: list.length, page: Number(url.searchParams.get("page") || 1), per_page: 25, rows: list };
  });
}

/** Fiche détaillée (GET /admin/users/:id). */
export function personDetail(row: Record<string, unknown>) {
  return {
    ...row,
    sessions: [
      { id: "s1", device: "Chrome sur Windows", ip: "10.0.0.8", last_seen_at: now() - 3 * DAY, created_at: now() - 10 * DAY, current: false },
      { id: "s2", device: "Client Windows", ip: "10.0.0.9", last_seen_at: now() - 5 * DAY, created_at: now() - 20 * DAY, current: false },
    ],
    collections: [
      { id: "c1", role: "manager", personal: false, members_count: 12, managers_count: 1, items_count: 340, sole_manager: true, shared: true, rotation_suggested_at: null },
      { id: "c2", role: "manager", personal: true, members_count: 1, managers_count: 1, items_count: 20, sole_manager: true, shared: false, rotation_suggested_at: null },
    ],
    recent_events: [{ at: now() - 3 * DAY, action: "login.failed", severity: "warning", target: "" }],
  };
}
