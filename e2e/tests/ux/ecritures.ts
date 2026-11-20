// Écritures du client web et leur test d'échec (critère G36 « zéro action
// muette », contrat V2.3). Clé : « MÉTHODE /chemin », paramètres remplacés
// par « :p », sans préfixe /api ni requête (V1.8). La liste de référence est
// GÉNÉRÉE par echecs.spec.ts depuis web/js : une écriture sans entrée, ou une
// entrée qui ne correspond plus à aucun appel, fait échouer la suite.
//
//   { ici: true }                      testée par echecs.spec.ts (500, puis réseau coupé) ;
//   { spec: "tests/…", titre }         test existant qui simule déjà la panne
//                                      (le fichier contient le titre exact et
//                                      route.abort(, status: 500 ou .fail() ;
//   { exempte: "<raison>" }            appel qui n'est pas une action de la personne.

export type Ecriture = { ici: true } | { spec: string; titre: string } | { exempte: string };

const ICI = { ici: true } as const;
const ref = (spec: string, titre: string): Ecriture => ({ spec, titre });

const LISTE_VAULT = "tests/vault/liste.spec.ts";
const PANNE_LISTE = "panne réseau sur chaque action : message français, état inchangé";
const PERSONNES = "tests/admin/personnes.spec.ts";
const SSO = "tests/identity/sso.spec.ts";

export const ECRITURES: Record<string, Ecriture> = {
  // ---------------------------------------------------------------- Accès
  "POST /auth/prelogin": { exempte: "Étape interne de la connexion : son échec arrête POST /auth/login, dont le message d'échec est testé ici." },
  "POST /auth/login": ICI,
  "POST /auth/logout": { exempte: "Déconnexion locale garantie : le navigateur efface la session même si le serveur ne répond pas." },
  "POST /auth/register": ICI,
  "POST /auth/recover/start": ICI,
  "POST /auth/recover/finish": ICI,
  "POST /auth/reauth": ICI,
  "POST /ldap/login": ICI,
  "POST /sso/redeem": ICI,
  "POST /me/kdf": { exempte: "Mise à niveau silencieuse des paramètres de dérivation après la connexion ; un échec est rejoué à la connexion suivante." },
  "POST /me/charter": ref("tests/auth/charte.spec.ts", "nouvelle version de la charte : lecture, échec d'enregistrement, puis acceptation"),

  // ---------------------------------------------------------------- Coffre
  "POST /items": ref("tests/vault/editeur.spec.ts", "panne réseau à l'enregistrement : message français, saisie intacte"),
  "PUT /items/:p": ICI,
  "DELETE /items/:p": ref(LISTE_VAULT, PANNE_LISTE),
  "POST /items/:p/restore": ref(LISTE_VAULT, PANNE_LISTE),
  "DELETE /items/:p/purge": ref(LISTE_VAULT, PANNE_LISTE),
  "POST /items/batch": ref("tests/tools/donnees.spec.ts", "import CSV : « a;b » intact, rapport ligne par ligne, envoi interrompu puis repris"),
  "PUT /items/:p/attachments/:p": ICI,
  "DELETE /attachments/:p": ICI,
  "POST /collections": ICI,
  "PUT /collections/:p": ICI,
  "DELETE /collections/:p": ICI,
  "POST /collections/:p/members": ref("tests/vault/partage.spec.ts", "échec au 2e appel : retour arrière complet, rien n'est modifié"),
  "PUT /collections/:p/members/:p": ICI,
  "DELETE /collections/:p/members/:p": ICI,
  "POST /collections/:p/rotate": ICI,
  "POST /shares": ref("tests/vault/partage.spec.ts", "panne à la création du lien : message français, aucun lien affiché"),
  "DELETE /shares/:p": ref("tests/tools/liens.spec.ts", "noms locaux, états terminaux lisibles, révocation (échec puis réussite)"),
  "POST /public/shares/:p/peek": ICI,
  "POST /public/shares/:p/open": ICI,

  // ---------------------------------------------------------------- Compte et préférences
  "PUT /me": ICI,
  "PUT /me/prefs": ref("tests/tools/preferences.spec.ts", "échec d'enregistrement : message en français, valeur réelle rétablie"),
  "POST /me/password": ICI,
  "POST /me/recovery": ref("tests/tools/compte.spec.ts", "clé de récupération : échec signalé, puis nouvelle clé téléchargée en .txt"),
  "POST /me/2fa/setup": ICI,
  "POST /me/2fa/enable": ICI,
  "POST /me/2fa/disable": ICI,
  "POST /me/2fa/recovery-codes": ref("tests/tools/compte.spec.ts", "double authentification : codes de secours montrés une fois, compteur, régénération confirmée"),
  "DELETE /me/sessions/:p": ICI,
  "POST /me/export": ref("tests/tools/donnees.spec.ts", "export chiffré : trace serveur avant le fichier ; refus du serveur ; panne"),

  // ---------------------------------------------------------------- Administration : personnes
  "POST /admin/invites": ICI,
  "POST /admin/invites/batch": ref(PERSONNES, "invitations en échec : saisie conservée, message français"),
  "POST /admin/invites/:p/resend": ICI,
  "DELETE /admin/invites/:p": ICI,
  "PUT /admin/users/:p": ref(PERSONNES, "rétrogradation : confirmation simple, sans mot de passe ; échec affiché dans la fenêtre"),
  "PATCH /admin/users/:p": ICI,
  "DELETE /admin/users/:p": ICI,
  "DELETE /admin/users/:p/sessions/:p": ICI,
  "POST /admin/users/:p/revoke-sessions": ICI,
  "POST /admin/users/:p/reset-2fa": ICI,
  "POST /admin/users/:p/offboard": ref("tests/admin/depart.spec.ts", "échec du départ : message français, rien n'est annoncé comme fait"),
  "POST /admin/users/bulk": ref(PERSONNES, "action de masse en échec : message français, sélection gardée"),
  "POST /admin/shares/revoke": ref(PERSONNES, "fiche : révoquer les liens sécurisés d'une personne, puis échec affiché en français"),

  // ---------------------------------------------------------------- Administration : réglages et système
  "POST /admin/settings/validate": ICI,
  "PATCH /admin/settings": ref("tests/admin/reglages.spec.ts", "échec d'enregistrement (500 puis réseau coupé) : message français, saisie intacte"),
  "PUT /admin/settings": ICI,
  "POST /admin/settings/profile": ICI,
  "POST /admin/settings/revert/:p": ref("tests/admin/reglages-ecritures.spec.ts", "historique : retour en échec (500 puis réseau coupé), message français et réglages intacts"),
  "POST /admin/settings/import": ref("tests/admin/annexes.spec.ts", "import : fichier illisible puis essai à blanc en échec, messages français"),
  "POST /admin/mail/test": ref("tests/admin/systeme.spec.ts", "e-mail de test : réussite, puis échec expliqué en français"),
  "POST /admin/mail/queue/:p/retry": ICI,

  // ---------------------------------------------------------------- Connexion d'entreprise
  "PUT /admin/sso": ref(SSO, "enregistrement des identifiants en échec (500 puis réseau coupé) : message, saisie intacte"),
  "POST /admin/sso/test": ref(SSO, "enregistrement des identifiants en échec (500 puis réseau coupé) : message, saisie intacte"),
  "POST /admin/sso/test-start": ref(SSO, "lancement du test en échec (500 puis réseau coupé) : message en français"),
  "PUT /admin/ldap": ICI,
  "POST /admin/ldap/test": ICI,
  "POST /admin/ldap/test-login": ICI,
  "POST /admin/ldap/sync": ref("tests/identity/annuaire.spec.ts", "synchronisation à blanc refusée ou en échec (409, réseau coupé) : message, saisie intacte"),
  "POST /admin/scim/token": ref("tests/identity/scim.spec.ts", "création du jeton en échec (500) : message, aucun jeton affiché"),
  "DELETE /admin/scim/token": ref("tests/identity/scim.spec.ts", "révocation en échec (500 puis réseau coupé) : message, jeton toujours actif ; puis réussite"),
};
