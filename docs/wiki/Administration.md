# Administration

Les administrateurs **gèrent les accès sans pouvoir lire un seul secret** : ils n'ont ni les
mots de passe maîtres, ni les clés des coffres.

## Rôles d'organisation

| Rôle | Droits |
|---|---|
| Propriétaire | tout ; seul à gérer les administrateurs ; accès de secours quand le SSO est imposé |
| Administrateur | comptes utilisateurs, invitations, journal, règles, annuaire |
| Utilisateur | son coffre et les coffres partagés avec lui |

L'organisation garde toujours au moins un propriétaire actif.

## Onglets

| Onglet | Contenu |
|---|---|
| Vue d'ensemble | comptes actifs, taux de 2FA, éléments, coffres partagés, liens actifs, échecs de connexion sur 24 h, derniers événements |
| Utilisateurs | rôle, désactivation (**coupure immédiate**), déconnexion de tous les appareils, réinitialisation de la 2FA, suppression |
| Invitations | lien à usage unique, lié à une adresse, valable 7 jours |
| Journal d'audit | recherche, filtres par type et par date, pagination, **export CSV** |
| Règles de sécurité | 2FA obligatoire, inactivité, durée de session, conservation du journal et de la corbeille |
| Active Directory | connecteur LDAPS : voir [Déploiement avec Active Directory](Deploiement-Active-Directory) |
| Authentification unique | OpenID Connect : voir [SSO et SCIM](SSO-et-SCIM) |
| Annuaire (SCIM) | jeton, URL du locataire, comptes poussés par l'annuaire |

## Supprimer un compte

- Son coffre personnel est détruit (personne ne peut le déchiffrer).
- Les coffres partagés restent à leurs autres membres ; s'il en était le seul gestionnaire, le
  membre le plus ancien le devient.
- Les coffres qui n'ont plus aucun membre sont supprimés.

## Journal d'audit

Chaque action est tracée avec la date, l'utilisateur, l'adresse IP et le navigateur :
connexions (réussies, échouées, SSO, Windows), éléments, coffres, membres, partages, pièces
jointes, administration, synchronisations d'annuaire. L'export CSV neutralise les formules
(ouverture sûre dans un tableur). Envoi continu vers un SIEM avec `LOCKSY_SYSLOG` (format RFC
5424, facilité authpriv, gravité « warning » pour les échecs, détail en JSON).

Ces traces servent de preuves pour vos audits **NIS2**, **ISO 27001** ou **DORA**.
