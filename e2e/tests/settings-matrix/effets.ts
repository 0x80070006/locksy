// Preuves d'application « { e2e: "ici" } » de la matrice (matrice.ts) :
// une vérification par clé, exécutée par reglages.isole.ts juste après
// l'enregistrement de la section, avec la valeur cible.
//
// - Clés diffusées aux clients (`.clients()`) : GET /api/settings/policy, vu
//   par un UTILISATEUR, porte la nouvelle valeur ; dans sa page connectée
//   après l'enregistrement, settings-client.js (module de l'application)
//   donne cette valeur comme valeur effective.
// - Clés publiques : GET /api/settings/public, sans session, porte la
//   nouvelle valeur ; les textes de l'organisation s'affichent sur l'écran de
//   connexion.
// - invite.ttl_days : une invitation créée expire après la durée réglée.
//
// Le garde-fou vérifie que chaque preuve « ici » de la matrice a son entrée
// dans EFFETS.

import type { APIRequestContext, Page } from "@playwright/test";
import { expect } from "../../fixtures/index.ts";

export interface CtxEffet {
  cle: string;
  cible: unknown;
  /** API du propriétaire. */
  owner: APIRequestContext;
  /** API d'un utilisateur (rôle user). */
  user: APIRequestContext;
  /** Page de cet utilisateur, connectée APRÈS l'enregistrement. */
  page: Page;
  /** Requêtes sans session. */
  anonyme: APIRequestContext;
  /** Page sans session (écran de connexion). */
  accueil: Page;
}

export type Verif = (c: CtxEffet) => Promise<void>;

/** Valeur comparable : listes triées, nombres et textes tels quels. */
export function normale(v: unknown): unknown {
  if (Array.isArray(v)) return [...v].map(String).sort();
  return v;
}

/** Politique diffusée à l'utilisateur, puis valeur effective dans sa page. */
const politique: Verif = async ({ cle, cible, user, page }) => {
  const res = await user.get("/api/settings/policy");
  expect(res.ok(), `GET /api/settings/policy : ${res.status()}`).toBe(true);
  const body = await res.json();
  expect(normale(body.policy?.[cle]?.value), `Politique diffusée : ${cle}`).toEqual(normale(cible));
  const effective = await page.evaluate(async (k) => (await import("/js/settings-client.js")).effective(k).value, cle);
  expect(normale(effective), `Valeur effective dans la page de l'utilisateur : ${cle}`).toEqual(normale(cible));
};

/** Valeur d'une clé dans GET /api/settings/public (annexe A.5). */
export function valeurPublique(pub: Record<string, Record<string, unknown>>, cle: string): unknown {
  if (cle === "master_password.banned_words") return pub.master_password?.banned_words_count;
  if (cle === "branding.logo") return pub.branding?.logo_url;
  if (cle === "auth.primary_method") return pub.login?.primary_method;
  const [groupe, ...reste] = cle.split(".");
  return pub[groupe]?.[reste.join(".")];
}

const publique: Verif = async ({ cle, cible, anonyme }) => {
  const res = await anonyme.get("/api/settings/public");
  expect(res.ok(), `GET /api/settings/public : ${res.status()}`).toBe(true);
  const v = valeurPublique(await res.json(), cle);
  if (cle === "master_password.banned_words") expect(v, "Nombre de mots interdits publié").toBe((cible as unknown[]).length);
  else if (cle === "branding.logo") expect(String(v || ""), "Adresse du logo publiée").toMatch(/^\/api\/branding\/logo/);
  else expect(normale(v), `Réglage public : ${cle}`).toEqual(normale(cible));
};

/** Texte de l'organisation affiché sur l'écran de connexion. */
const surConnexion: Verif = async (c) => {
  await publique(c);
  await c.accueil.goto("/");
  await expect(c.accueil.getByText(String(c.cible), { exact: false }).first(), `Écran de connexion : ${c.cle}`).toBeVisible();
};

/** Lien légal affiché sur l'écran de connexion (pied de page). */
const lienConnexion: Verif = async (c) => {
  await publique(c);
  await c.accueil.goto("/");
  await expect(c.accueil.locator(`a[href="${String(c.cible)}"]`).first(), `Lien légal sur l'écran de connexion : ${c.cle}`).toBeVisible();
};

const invitation: Verif = async ({ cible, owner }) => {
  const avant = Math.floor(Date.now() / 1000);
  const res = await owner.post("/api/admin/invites", { data: { email: `duree-${Date.now()}@e2e.test`, role: "user" } });
  expect(res.ok(), await res.text()).toBe(true);
  const { id, expires_at } = await res.json();
  const jours = Number(cible);
  expect(expires_at, "Fin de validité de l'invitation").toBeGreaterThanOrEqual(avant + jours * 86_400 - 5);
  expect(expires_at, "Fin de validité de l'invitation").toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + jours * 86_400 + 5);
  await owner.delete(`/api/admin/invites/${id}`);
};

const ensemble = (...verifs: Verif[]): Verif => async (c) => {
  for (const v of verifs) await v(c);
};

/** Clés diffusées aux clients (registre `.clients()`), vérifiées par la politique. */
const CLIENTS = [
  "client.autolock_minutes", "client.autolock_allow_never", "client.lock_on_hide", "client.lock_on_os_lock",
  "client.clipboard_clear_seconds", "client.remember_email", "client.single_key_shortcuts",
  "generator.length", "generator.min_length", "generator.require_classes", "generator.avoid_ambiguous",
  "generator.symbols", "generator.words", "generator.min_words", "health.weak_below_score", "health.max_password_age_days",
  "share.enabled", "share.max_expiry_minutes", "share.default_expiry_minutes", "share.max_views", "share.default_views",
  "vault.users_can_create_shared", "vault.rotate_on_member_removal", "vault.personal_enabled",
  "attachment.enabled", "attachment.max_file_mib", "attachment.max_per_item", "export.enabled", "export.min_password_length",
  "import.max_file_mib", "extension.http_fill", "extension.allow_mismatch_fill", "extension.offer_save",
  "extension.copy_totp_after_fill", "extension.excluded_sites", "retention.trash_days", "legal.charter_text",
];

/** Clés publiques vérifiées par GET /api/settings/public seul. */
const PUBLIQUES = [
  "master_password.min_length", "master_password.min_score", "master_password.forbid_identity", "master_password.banned_words",
  "branding.logo", "branding.accent_color", "legal.charter_version", "legal.dpo_contact", "i18n.default_locale", "i18n.timezone",
  "kdf.memory_mib", "kdf.iterations", "kdf.parallelism", "kdf.upgrade_on_login",
];

export const EFFETS: Record<string, Verif> = {
  ...Object.fromEntries(CLIENTS.map((k) => [k, politique])),
  ...Object.fromEntries(PUBLIQUES.map((k) => [k, publique])),
  "branding.org_name": surConnexion,
  "branding.login_message": surConnexion,
  "branding.support_contact": surConnexion,
  "legal.login_banner": surConnexion,
  "legal.notice_url": publique,
  "legal.privacy_url": lienConnexion,
  "legal.accessibility_url": lienConnexion,
  "invite.ttl_days": ensemble(invitation),
};
