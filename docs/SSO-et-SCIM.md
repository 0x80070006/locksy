# SSO OpenID Connect et provisionnement SCIM

> Pour un Active Directory sur site sans fournisseur d'identité, préférez le
> [connecteur Active Directory](Deploiement-Active-Directory.md). Les deux peuvent coexister.

## Connexion unique (OpenID Connect)

Compatible ADFS 2016+, Microsoft Entra ID, Okta, Google Workspace, Keycloak, Auth0…

Le SSO **prouve l'identité** et ouvre une session. Le **mot de passe maître reste demandé** :
lui seul déchiffre le coffre, et ni l'entreprise ni le fournisseur ne le connaissent.

La **double authentification Locksy reste exigée après le SSO** pour les comptes qui l'ont
activée (ou si la règle « 2FA obligatoire » est posée) : le fournisseur prouve l'identité
d'entreprise, pas la possession du second facteur Locksy. Le ticket SSO (5 minutes, usage
unique) n'est consommé qu'à l'ouverture de la session ; il reste donc valable le temps de
saisir le code. Web, extension et client Windows demandent le code après le retour du
fournisseur (`totp_required`).

### Réglage

1. Chez le fournisseur : application « Web », URI de redirection
   `https://locksy.corp.local/api/sso/callback`, étendues `openid email profile`.
2. Dans Locksy (Administration > Connexion d'entreprise > SSO, `#/admin/connexion/sso`) :
   l'assistant demande le fournisseur et son émetteur, puis l'identifiant et le secret de
   l'application. « Tester avec mon compte » vérifie la connexion avec votre propre compte :
   facultatif pour proposer la connexion d'entreprise, obligatoire pour l'imposer.

| Fournisseur | Émetteur |
|---|---|
| ADFS | `https://adfs.corp.local/adfs` |
| Entra ID | `https://login.microsoftonline.com/<ID de l'annuaire>/v2.0` |
| Okta | `https://<organisation>.okta.com` |
| Keycloak | `https://sso.corp.local/realms/<royaume>` |

### Options

- **Imposer le SSO** : mot de passe seul refusé, sauf propriétaires (accès de secours).
- **Création de compte à la première connexion** ; sinon seules les personnes poussées par
  l'annuaire ou invitées peuvent créer leur coffre.
- **Domaines autorisés** : par exemple `corp.local`. Nécessaires au rattachement automatique
  d'un compte Locksy existant (voir ci-dessous).
- **Accepter les adresses e-mail non vérifiées par le fournisseur** (`trust_unverified_email`) : à cocher
  seulement pour un fournisseur qui n'envoie jamais `email_verified`, comme Entra ID.
- **Extensions de navigateur autorisées** (`allowed_extension_ids`) : identifiants des
  extensions qui peuvent recevoir le retour SSO (`https://<id>.chromiumapp.org`). Liste vide :
  SSO refusé depuis l'extension (400 `extension_not_allowed`) ; l'extension affiche son
  identifiant pour que l'utilisateur le transmette.

### Adresse e-mail et rattachement des comptes

- Seule une revendication `email_verified` vraie prouve l'adresse. Absente ou fausse, l'adresse
  est considérée comme non vérifiée, sauf option `trust_unverified_email`.
- Une identité déjà liée (sujet `sub` signé par le fournisseur) est toujours reconnue, même si
  l'adresse change.
- Un compte Locksy existant n'est rattaché automatiquement par son adresse que si elle est
  vérifiée **et** qu'une liste de domaines autorisés est définie ; sinon 403
  `sso_link_refused`.
- Une adresse inconnue et non vérifiée ne reçoit pas de ticket d'inscription : 403
  `email_unverified`.

### Client Windows

Le client ouvre le navigateur du système vers
`/api/sso/start?target=desktop&port=<p>&client_state=<cs>` et attend le retour sur
`http://127.0.0.1:<p>/sso` (RFC 8252). `client_state` est une valeur aléatoire de **16 à 128
caractères `[A-Za-z0-9_-]`** (sinon 400 « Paramètre client_state invalide. », avant tout appel
au fournisseur), renvoyée avec le ticket ou l'erreur ; le client ignore tout retour qui ne la
porte pas. Un ancien client sans `client_state` fonctionne toujours.

### Sécurité

PKCE (S256), `state` et `nonce` à usage unique, signature du jeton vérifiée avec les clés
publiées (RSA, RSA-PSS, ECDSA ; HMAC refusé), émetteur, audience et expiration contrôlés. Ticket
de 5 minutes à usage unique, transmis après le `#` (absent des journaux). Retours limités à
l'adresse publique de Locksy, à `127.0.0.1` (client Windows) et aux extensions déclarées.
Demandes en cours limitées (503 `sso_busy` si la table est pleine) et purgées après 10
minutes ; 30 démarrages par minute et par adresse. Secret client chiffré au repos par la clé
serveur.

Filtre anti-SSRF : la découverte OpenID, les clés publiées et l'échange du jeton refusent les
adresses de boucle locale, privées, de lien local, non spécifiées et de multidiffusion, après
résolution DNS et à chaque redirection (422 `ssrf_blocked`, événement
`sso.discovery_blocked`). Un fournisseur hébergé sur le réseau interne demande
`LOCKSY_SSO_ALLOW_PRIVATE=true` (voir [Exploitation](Exploitation.md)).

### Tester avant d'imposer

L'assistant (Administration > Connexion d'entreprise > SSO) propose **Tester avec mon
compte** : un vrai parcours de connexion, dans une autre fenêtre, réussi seulement si
l'adresse rendue par le fournisseur est celle de l'administrateur. « Imposé » reste
indisponible tant qu'aucun test réussi de moins de 24 heures n'existe pour cet
administrateur (409 `test_required` sinon). Même règle pour l'annuaire Active Directory
(test avec son compte Windows).

## Provisionnement SCIM 2.0

Pour un annuaire qui **pousse** les comptes (Entra ID, Okta, OneLogin).

1. Administration > Connexion d'entreprise > SCIM (`#/admin/connexion/scim`) > **Créer un
   jeton**. Copiez-le aussitôt : il ne sera plus affiché.
2. Dans l'annuaire : URL du locataire `https://locksy.corp.local/scim/v2` et le jeton secret.

| Opération de l'annuaire | Effet dans Locksy |
|---|---|
| Création | compte en attente ; la personne crée son coffre à sa première connexion SSO |
| Renommage, changement d'adresse | repris |
| Désactivation (`active = false`) | **toutes ses sessions coupées**, SSO refusé |
| Suppression | selon le réglage `directory.deprovision` : désactivation seule, ou désactivation puis suppression après `directory.delete_after_days` jours (0 = immédiate) ; jamais le dernier propriétaire |
| Groupes | non pris en charge (les accès aux coffres se donnent dans Locksy) |

Points d'accès : `/Users` (GET avec filtre `userName eq`, `externalId eq`, POST, PUT, PATCH,
DELETE), `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`. Le format d'Entra ID
(`"active": "False"` en texte, opérations `Replace`) est accepté.

Jeton porteur de 256 bits, stocké haché, comparé en temps constant ; blocage après 10 échecs.
Il est affiché une seule fois et expire après `scim.token_ttl_days` jours (0 = jamais).
Régénérez-le (Administration > Connexion d'entreprise > SCIM, avec confirmation du mot de
passe maître) en cas de doute : l'ancien cesse aussitôt de fonctionner. Les domaines
d'adresse autorisés (`access.allowed_email_domains`) s'appliquent aux comptes poussés.

Le SCIM exige que l'annuaire **joigne** Locksy : pour un service cloud, Locksy doit être
accessible depuis Internet ou via l'agent de provisionnement de l'éditeur.
