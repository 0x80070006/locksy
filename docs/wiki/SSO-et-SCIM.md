# SSO OpenID Connect et provisionnement SCIM

> Pour un Active Directory sur site sans fournisseur d'identité, préférez le
> [connecteur Active Directory](Deploiement-Active-Directory). Les deux peuvent coexister.

## Connexion unique (OpenID Connect)

Compatible ADFS 2016+, Microsoft Entra ID, Okta, Google Workspace, Keycloak, Auth0…

Le SSO **prouve l'identité** et ouvre une session ; il remplace la double authentification de
Locksy (le fournisseur s'en charge). Le **mot de passe maître reste demandé** : lui seul
déchiffre le coffre, et ni l'entreprise ni le fournisseur ne le connaissent.

### Réglage

1. Chez le fournisseur : application « Web », URI de redirection
   `https://locksy.corp.local/api/sso/callback`, étendues `openid email profile`.
2. Dans Locksy (Administration > Authentification unique) : émetteur, identifiant et secret
   client, adresse publique ; **Tester le fournisseur**, puis **Enregistrer**.

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
- **Domaines autorisés** : par exemple `corp.local`.

### Sécurité

PKCE (S256), `state` et `nonce` à usage unique, signature du jeton vérifiée avec les clés
publiées (RSA, RSA-PSS, ECDSA ; HMAC refusé), émetteur, audience et expiration contrôlés. Ticket
de 5 minutes à usage unique, transmis après le `#` (absent des journaux). Retours limités à
l'adresse publique de Locksy, à `127.0.0.1` (client Windows) et aux adresses réservées aux
extensions. Secret client chiffré au repos.

## Provisionnement SCIM 2.0

Pour un annuaire qui **pousse** les comptes (Entra ID, Okta, OneLogin).

1. Administration > Annuaire (SCIM) > **Générer un jeton**.
2. Dans l'annuaire : URL du locataire `https://locksy.corp.local/scim/v2` et le jeton secret.

| Opération de l'annuaire | Effet dans Locksy |
|---|---|
| Création | compte en attente ; la personne crée son coffre à sa première connexion SSO |
| Renommage, changement d'adresse | repris |
| Désactivation (`active = false`) | **toutes ses sessions coupées**, SSO refusé |
| Suppression | compte supprimé (mêmes règles que l'administration) |
| Groupes | non pris en charge (les accès aux coffres se donnent dans Locksy) |

Points d'accès : `/Users` (GET avec filtre `userName eq`, `externalId eq`, POST, PUT, PATCH,
DELETE), `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`. Le format d'Entra ID
(`"active": "False"` en texte, opérations `Replace`) est accepté.

Le SCIM exige que l'annuaire **joigne** Locksy : pour un service cloud, Locksy doit être
accessible depuis Internet ou via l'agent de provisionnement de l'éditeur.
