# RGPD : registre de traitement et conservation

Ce document aide le responsable de traitement (l'organisation qui héberge Locksy) à remplir
sa fiche de registre (article 30 du RGPD) et son analyse d'impact. Il décrit ce que le code
enregistre réellement. Les choix juridiques (base légale, durées, information des personnes)
sont **à valider par votre DPO**.

## Fiche de registre

| Rubrique | Contenu |
|---|---|
| Traitement | Gestion des mots de passe et secrets professionnels des collaborateurs |
| Responsable de traitement | l'organisation qui exploite Locksy (à compléter) |
| DPO | à compléter |
| Finalités | stocker et partager de façon sécurisée les secrets nécessaires au travail ; contrôler les accès ; tracer les actions pour la sécurité et l'audit (NIS2, ISO 27001, DORA) |
| Base légale | intérêt légitime de l'employeur à sécuriser son système d'information, ou exécution du contrat de travail : **à valider par le DPO** |
| Personnes concernées | collaborateurs et prestataires disposant d'un compte ; personnes invitées ; personnes poussées par l'annuaire (AD, SCIM) avant la création de leur compte |
| Destinataires | administrateurs et propriétaires Locksy (comptes, journal d'audit, aucun secret) ; exploitant du serveur ; SIEM et fournisseur d'identité de l'organisation s'ils sont configurés |
| Sous-traitants | aucun par défaut (logiciel auto-hébergé, aucun appel à un service de l'éditeur) ; le cas échéant, l'hébergeur de la VM, l'éditeur du SIEM ou du fournisseur d'identité |
| Transferts hors UE | aucun par défaut (hébergement sur site) ; à examiner si le fournisseur d'identité ou le SIEM est un service en nuage |
| Durées | voir ci-dessous |
| Sécurité | voir « Mesures de sécurité » |

## Données traitées

Source : schéma de la base (`crates/locksy-server/src/db.rs`).

| Table | Données personnelles | Remarque |
|---|---|---|
| `users` | adresse e-mail, nom, rôle, état (actif ou désactivé), dates de création, de modification et de dernière connexion, identifiant SSO (`sso_subject`) | plus des éléments cryptographiques : paramètres de dérivation, empreinte Argon2id de la preuve, clés chiffrées, clé publique, secret TOTP chiffré par la clé serveur |
| `sessions` | adresse IP, nom de l'appareil (fourni par le client, sinon user-agent), dates | une ligne par appareil connecté |
| `audit` | adresse e-mail, identifiant de compte, action, cible, adresse IP, user-agent, détail, date | journal de sécurité |
| `directory_users` | adresse e-mail, nom affiché, identifiant externe, état, source (`ldap` ou `scim`) | comptes poussés par l'annuaire |
| `invites` | adresse e-mail invitée, rôle, auteur, dates | |
| `shares` | auteur du lien, dates, nombre de consultations | contenu chiffré, clé hors serveur |
| `sso_tickets` | adresse e-mail, nom, identifiant SSO | ticket de 5 minutes |
| `memberships`, `items`, `attachments`, `collections` | appartenance aux coffres, auteur de la dernière modification | **contenu chiffré de bout en bout** |
| `recovery_tokens` | identifiant de compte | jeton de 10 minutes |

**Contenu des coffres** (mots de passe, notes, cartes, identités, pièces jointes, noms des
coffres) : chiffré sur le poste de l'utilisateur, **illisible par l'hébergeur et par les
administrateurs**. Si des collaborateurs y rangent des données personnelles de tiers, ces
données sont protégées par le chiffrement mais restent sous la responsabilité de
l'organisation.

**Hors base.**
- Mémoire du serveur : le limiteur de débit garde temporairement adresses IP et adresses
  e-mail des tentatives de connexion (purge toutes les 10 minutes des entrées échues).
- Journal technique (`journalctl` ou `docker logs`) : route générique, statut, latence,
  `X-Request-Id`, sans adresse IP ni URL réelle ; certains messages d'erreur d'annuaire ou de
  fournisseur d'identité peuvent citer un identifiant. Durée : celle de votre journal système.
- SIEM (`LOCKSY_SYSLOG`) : copie du journal d'audit. Durée : celle du SIEM.
- Postes : `bureau.json` (adresse du serveur, dernière adresse e-mail, préférences,
  paramètres de dérivation épinglés) ; navigateur : `localStorage` (préférences, épinglages
  `locksy.kdfpins` et `locksy.keypins`), `storage.session` de l'extension (effacé au
  verrouillage).

## Durées de conservation

| Donnée | Durée | Réglage |
|---|---|---|
| Journal d'audit | **365 jours** par défaut, puis purge automatique | Administration > Réglages, de 30 à 3650 jours |
| Corbeille | **30 jours** par défaut, puis suppression définitive | Administration > Réglages, de 1 à 365 jours |
| Sessions | supprimées après **60 min** d'inactivité ou **12 h** au plus (défauts) | Administration > Réglages (5 à 1440 min, 1 à 720 h) |
| Invitations non utilisées | expirent après 7 jours, supprimées **30 jours** après expiration | — |
| Liens de partage | supprimés à expiration (5 min à 30 jours) ou au nombre de consultations atteint | choisi à la création |
| Jetons de récupération | supprimés à expiration (10 min) | — |
| Tickets SSO | 5 minutes ; purgés à l'émission d'un ticket suivant | — |
| Compte utilisateur | jusqu'à sa suppression par un administrateur (ou par l'annuaire, sauf administrateurs) | — |
| Sauvegardes | les `LOCKSY_BACKUP_KEEP` plus récentes (14 par défaut, soit 14 jours au rythme quotidien) | `/etc/locksy/backup.env` |

La purge automatique (sessions, jetons, liens, invitations, corbeille, journal) s'exécute
toutes les 10 minutes. Une donnée purgée de la base reste dans les sauvegardes jusqu'à leur
rotation, et dans le SIEM selon sa propre politique.

## Droits des personnes

| Droit | Mise en œuvre |
|---|---|
| Information | à faire par l'organisation (charte informatique, note d'information) |
| Accès | la personne voit son profil, ses appareils (Paramètres > Appareils) et son historique (Paramètres > Mon activité, `GET /api/me/audit`) ; elle exporte ses éléments (Paramètres > Import et export). Un extrait complet du journal la concernant est produit par un administrateur (filtre par adresse, export CSV). |
| Rectification | nom modifiable par la personne (Paramètres > Compte) ; adresse modifiée par l'annuaire (SCIM) ou par recréation du compte |
| Effacement | suppression du compte par un administrateur : profil, sessions, appartenances et coffre personnel supprimés ; les coffres partagés restent à leurs autres membres |
| Limitation | désactivation du compte (coupure immédiate des sessions, données conservées) |
| Opposition | à examiner au cas par cas : l'usage de l'outil peut être une obligation professionnelle |
| Portabilité | export des éléments lisibles par la personne : sauvegarde JSON chiffrée par un mot de passe, ou CSV en clair (`name`, `url`, `username`, `password`, `totp`, `notes`, `folder`) réimportable dans la plupart des gestionnaires |

**Limite assumée** : à la suppression d'un compte, les lignes du **journal d'audit** qui le
concernent sont **conservées** (adresse e-mail comprise) jusqu'à la fin de la durée de
conservation du journal, pour la sécurité et la preuve. Les sauvegardes et le SIEM en gardent
aussi une copie jusqu'à leur propre échéance. Mentionnez-le dans l'information des personnes.

## Mesures de sécurité (article 32)

- Chiffrement de bout en bout des coffres (Argon2id, XChaCha20-Poly1305, X25519) : une fuite
  de la base ne révèle aucun secret sans les mots de passe maîtres
  ([Chiffrement et sécurité](Chiffrement-et-securite.md)).
- Authentification : mot de passe maître, double authentification TOTP (imposable), SSO et AD
  en option ; limitation des tentatives ; sessions bornées.
- Administration sans accès aux secrets ; journal d'audit horodaté, exportable, envoyé au SIEM.
- Transport HTTPS (HSTS) ; serveur durci (systemd ou conteneur en lecture seule) ; secrets
  du serveur chiffrés par une clé dédiée.
- Sauvegardes chiffrées et testées ; plan de reprise ([PRA/PCA](PRA-PCA.md)).
- Chaîne d'approvisionnement : versions signées, SBOM, analyses de dépendances
  ([SECURITE.md](../SECURITE.md)).
- Limites connues documentées : [SECURITE.md](../SECURITE.md#limites-connues).

## Analyse d'impact (AIPD) : trame

Une AIPD est recommandée : le traitement porte sur des moyens d'accès à l'ensemble du système
d'information et inclut une surveillance des actions (journal d'audit). Trame :

1. **Description** : la fiche de registre ci-dessus, l'architecture
   ([Documentation](README.md#architecture)), les flux (postes vers serveur en HTTPS, serveur
   vers AD en LDAPS, serveur vers fournisseur d'identité, serveur vers SIEM).
2. **Nécessité et proportionnalité** : finalités, base légale, minimisation (le contenu des
   coffres est illisible par l'hébergeur), durées ci-dessus, information et droits.
3. **Risques** pour les personnes, par événement redouté :
   - accès illégitime aux secrets (compromission du serveur, d'un poste, d'un compte) ;
   - modification ou destruction des secrets (indisponibilité, rançongiciel) ;
   - surveillance excessive des collaborateurs par le journal d'audit.
   Pour chacun : sources de risque, gravité, vraisemblance, mesures existantes
   ([SECURITE.md](../SECURITE.md), [PRA/PCA](PRA-PCA.md)).
4. **Plan d'action** : mesures complémentaires (2FA obligatoire, durée du journal réduite au
   besoin, accès au journal limité aux administrateurs désignés, audit externe), validation
   par le DPO et le RSSI, date de révision.
