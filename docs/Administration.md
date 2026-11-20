# Guide administrateur

Les administrateurs **gèrent les accès sans pouvoir lire un seul secret** : ils n'ont ni les
mots de passe maîtres, ni les clés des coffres. Ce guide suit l'écran d'administration, ouvert
par le commutateur « Mon coffre » / « Administration » ou par le menu du compte
(`#/admin`). Il a cinq entrées : Accueil, Personnes, Réglages, Connexion d'entreprise et
Journal.

Pour l'installation du serveur, voir [Installation du serveur](Installation-du-serveur.md) ;
pour l'exploitation (variables, sauvegardes, supervision), voir [Exploitation](Exploitation.md).

## Rôles

| Rôle | Droits |
|---|---|
| Propriétaire | tout, y compris nommer les autres administrateurs et propriétaires ; seul à modifier les réglages « Réservé aux propriétaires » ; accès de secours quand la connexion d'entreprise est imposée |
| Administrateur | personnes, invitations, réglages, connexion d'entreprise, journal |
| Utilisateur | son coffre et les coffres partagés avec lui |

L'organisation garde toujours au moins un propriétaire actif. Nommez-en un deuxième : l'Accueil
le rappelle tant qu'il n'y en a qu'un.

**Confirmation d'identité.** Les actions sensibles demandent votre mot de passe maître (puis
votre code de vérification si la double authentification est active) : changer un rôle,
supprimer un compte, réinitialiser une double authentification, agir sur plusieurs personnes à
la fois, faire partir quelqu'un, créer un jeton de l'annuaire, abaisser un réglage de sécurité.
La confirmation vaut deux minutes, pour cette seule action.

## Accueil

`#/admin` réunit ce qui demande votre attention.

- **Mise en service** : sept étapes (sécuriser votre compte, choisir un profil de sécurité,
  choisir le mode de connexion, inviter vos collègues, déployer l'extension, nommer un deuxième
  propriétaire, et, en option, envoyer le journal à votre outil de supervision). Chaque étape
  a son bouton ; « Masquer » range le bloc.
- **À traiter** : personnes sans double authentification (avec « Imposer la double
  authentification… »), administrateurs sans double authentification, comptes inactifs,
  invitations expirées, comptes en attente de suppression, réglages abaissés récemment, seul
  propriétaire. Chaque ligne mène à l'écran qui règle le point. « Rien à traiter pour le
  moment. » quand tout est en ordre.
- **Service** : version du serveur et lien vers Réglages > Système.

## Personnes

`#/admin/personnes` liste les comptes et les invitations en cours.

- **Chercher et filtrer** : « Rechercher un nom ou une adresse », filtres État, Rôle, Double
  authentification et Origine (Compte Locksy, Invitation, Active Directory, Annuaire de
  l'entreprise, Connexion d'entreprise). Les filtres
  restent dans l'adresse : un lien vers une liste filtrée se partage.
- **Inviter** : « Inviter des personnes », collez une ou plusieurs « Adresses e-mail »
  (séparées par une virgule, un point-virgule ou un retour à la ligne), choisissez le rôle,
  puis « Inviter ». Si l'envoi des e-mails est activé, chacun reçoit son lien ; sinon, copiez
  les liens affichés et transmettez-les vous-même. Un lien ne vaut que pour son adresse ; sa
  durée de validité est un réglage (7 jours par défaut).
- **Agir sur plusieurs personnes** : cochez-les, puis « Changer le rôle… », « Déconnecter
  partout », « Désactiver » ou « Réactiver ». Le compte rendu indique ce qui a été fait et ce
  qui a été ignoré, avec le motif.
- **Exporter (CSV)** : la liste filtrée, pour un audit des accès.

**Fiche d'une personne** (`#/admin/personnes/<id>`) : rôle, état, double authentification,
sessions, coffres partagés avec ses droits (leur nom est chiffré : seuls leurs membres le
lisent). Actions : « Changer le rôle… »,
« Réinitialiser la double authentification » (téléphone perdu : ses codes de secours sont aussi
supprimés), « Désactiver » (accès coupé tout de suite sur tous ses appareils, liens sécurisés
révoqués, réactivable), « Supprimer » (son coffre personnel est détruit, définitivement) et
« Départ de l'entreprise… ».

### Départ de l'entreprise

L'assistant (`#/admin/personnes/<id>/depart`) prépare le départ en quatre étapes, **sans rien
modifier avant la confirmation finale** :

1. **Accès** : désactiver le compte et fermer toutes ses sessions.
2. **Coffres** : pour chaque coffre partagé dont la personne est seule gestionnaire, choisir un
   repreneur parmi ses membres actuels. Aucune clé n'est transmise : le repreneur avait déjà
   accès. Un coffre sans autre membre est signalé : il sera supprimé avec le compte.
3. **Mots de passe connus** : conseiller aux gestionnaires de changer les mots de passe des
   coffres partagés que la personne connaissait.
4. **Rapport** : la simulation montre tout ce qui sera fait ; « Télécharger le rapport (CSV) »
   en garde la trace (identifiants des coffres, jamais leur nom). Choisissez la suppression
   (« Supprimer dans … jours », délai de conservation de l'organisation, ou « Supprimer
   maintenant »), puis « Confirmer le départ ».

Avec un annuaire (Active Directory ou SCIM), un compte retiré de l'annuaire suit le réglage
« départ » de la section Conservation des données : désactivation, ou désactivation puis
suppression différée.

## Réglages

`#/admin/reglages/<section>` présente les réglages de l'organisation, générés depuis un
registre unique : chaque réglage a son libellé, son aide, ses bornes et sa valeur par défaut.
La liste complète, avec les bornes, est dans **[Réglages de l'organisation](Reglages.md)**.

- **Sections** : Sécurité de connexion, Sessions et verrouillage, Mots de passe, Partage et
  coffres, Applications et extension, Conservation des données, Apparence et textes, E-mails,
  Avancé, Connexion d'entreprise. Les réglages rarement utiles sont repliés sous « Réglages
  avancés ».
- **Chercher** : « Chercher un réglage » trouve un réglage par son nom ou un synonyme
  (« verrouillage », « 2fa », « presse-papiers »…) dans toutes les sections ; « Modifiés
  seulement » ne montre que ce qui s'écarte des valeurs par défaut.
- **Profil de sécurité** : Standard (la plupart des organisations), Renforcé (exigences de type
  NIS2 ou ISO 27001) ou Strict (secteur public, données sensibles). « Appliquer le profil … »
  montre d'abord les réglages qui vont changer. L'écran indique ensuite les écarts avec le
  profil choisi.
- **Liberté des utilisateurs** : pour un réglage diffusé aux postes, « Pour les utilisateurs »
  propose Libres, Par défaut (« Ils peuvent choisir au plus … ») ou Imposé.
- **Mentions** : « Modifié », « Avancé », « Imposé », « Réservé aux propriétaires » et « Fixé
  par l'hébergeur » (valeur verrouillée par le fichier `LOCKSY_SETTINGS_FILE` du serveur, non
  modifiable ici).
- **Enregistrer** : les modifications s'accumulent dans une barre en bas de l'écran.
  « Vérifier et enregistrer » affiche le récapitulatif (avec le nombre de personnes concernées,
  par exemple pour la double authentification obligatoire) et un « Motif » facultatif, visible
  dans l'historique. Un réglage abaissé demande votre mot de passe maître et est signalé aux
  autres propriétaires. « Tout annuler » abandonne la saisie. Si quelqu'un a enregistré
  entre-temps, l'écran le dit : « Voir ses changements », puis « Recharger en gardant les
  miens ».

Pages complémentaires, dans le menu des sections :

| Page | Adresse | Contenu |
|---|---|---|
| Historique | `#/admin/reglages/historique` | une révision par enregistrement, avec l'auteur, le motif et le détail ; « Revenir à cette version » (propriétaires ; les mots de passe de service sont à ressaisir) |
| Importer / exporter | `#/admin/reglages/transfert` | « Exporter les réglages » (ceux qui diffèrent des valeurs par défaut, sans secret) ; « Importer » un fichier : un essai à blanc montre les différences, vous choisissez ce qui s'applique, en une révision |
| Système | `#/admin/reglages/systeme` | état du service, envoi des e-mails, intégrité du journal, quotas des pièces jointes, configuration de l'hébergeur (variables `LOCKSY_*`, secrets masqués) |

La section **Applications et extension** génère aussi les extraits de **déploiement sur les
postes** (registre Windows, modèle d'administration, Intune, Chrome et Edge) : voir
[Extension navigateur](Extension-navigateur.md#déploiement-par-intune).

## Connexion d'entreprise

`#/admin/connexion` aide à choisir la méthode par une question : « Comment vos collègues se
connectent-ils aujourd'hui à leur poste ? ».

| Réponse | Méthode | Guide |
|---|---|---|
| Microsoft 365 / Entra ID, Google Workspace ou Okta | connexion d'entreprise (SSO, `#/admin/connexion/sso`) et création automatique des comptes (SCIM, `#/admin/connexion/scim`) | [SSO et SCIM](SSO-et-SCIM.md) |
| Compte Windows de domaine | compte Windows et synchronisation de l'annuaire (`#/admin/connexion/ad`) | [Déploiement avec Active Directory](Deploiement-Active-Directory.md) |
| Ni l'un ni l'autre | invitations par e-mail | ci-dessus |

Chaque méthode est « Désactivé », « Proposé » ou « Imposé ». « Imposé » n'est disponible
qu'après un test réussi avec votre propre compte (« Tester avec mon compte », moins de
24 heures). Les propriétaires gardent un accès de secours. Pour l'annuaire Windows, « Lancer
une synchronisation à blanc » montre l'effet d'une synchronisation sans rien écrire ; une
synchronisation qui désactiverait trop de comptes à la fois est refusée (garde-fou réglable).

## Journal

`#/admin/journal` répond à « qui a fait quoi, et quand ». Il ne contient jamais de secret ni le
nom d'un élément.

- **Chercher et filtrer** : « Rechercher dans le journal » (adresse, cible, adresse IP),
  Période, Type, Gravité (Information, Attention, Critique) et Personne. Une ligne s'ouvre pour
  le détail : appareil, adresse IP, navigateur.
- **Exporter (CSV)** : les événements filtrés. Les formules sont neutralisées pour une ouverture
  sûre dans un tableur ; le séparateur est un réglage (point-virgule par défaut).
- **Transfert vers votre outil de supervision** : envoi de chaque événement en syslog (adresse
  et format dans Réglages > Avancé, ou fixés par l'hébergeur avec `LOCKSY_SYSLOG`).

### Journal chaîné

Chaque événement est lié au précédent par une empreinte calculée avec la clé du serveur
(`server.key`). Une ligne modifiée, supprimée ou ajoutée après coup casse la chaîne. Pour
vérifier :

- dans l'interface : Réglages > Système > Intégrité du journal > « Vérifier le journal ». Le
  résultat donne le nombre d'événements vérifiés, ou chaque anomalie (événement modifié,
  supprimé, ajouté après coup) ;
- sur le serveur : `locksy-server verify-audit` (lecture seule ; code 0 si le journal est
  intègre, 1 en cas d'altération, 2 si la clé ou la base sont illisibles). Détails :
  [Exploitation](Exploitation.md#journal-daudit-chaîné).

La vérification exige la `server.key` d'origine : **sauvegardez-la avec la base**, et rangez-la
à part ([Sauvegarde et mises à jour](Sauvegarde-et-mises-a-jour.md)). Une altération détectée
est un incident de sécurité : prévenez votre responsable de la sécurité.

Ces traces servent de preuves pour vos audits **NIS2**, **ISO 27001** ou **DORA**. Alertes à
poser, réponse à une compromission : [Exploitation](Exploitation.md) ; conservation et droits
des personnes : [RGPD](RGPD.md).

## E-mails

Sans e-mail, Locksy fonctionne : les invitations sont à transmettre vous-même. Pour l'activer :

1. Réglages > E-mails (`#/admin/reglages/mail`) : activez l'envoi, puis renseignez le serveur
   d'envoi (adresse, port, chiffrement STARTTLS ou TLS, identifiant, mot de passe),
   l'« Adresse d'expédition » et, si besoin, l'« Adresse de réponse ». Le mot de passe est
   chiffré par la clé du serveur et ne s'affiche plus. Un envoi sans chiffrement n'est permis que
   vers un serveur du réseau interne.
2. Réglages > Système > E-mails : « Envoyer un e-mail de test ». En cas d'échec, la cause est
   affichée en clair (serveur injoignable, chiffrement, identifiant refusé…).
3. Choisissez les notifications, dans la même section :

| Notification | Destinataire |
|---|---|
| E-mail d'invitation | la personne invitée |
| Alerte de connexion depuis un nouvel appareil | la personne concernée |
| Alerte de changement de sécurité (mot de passe maître, double authentification) | la personne concernée |
| Alerte de sécurité abaissée | les autres propriétaires |
| Résumé pour les administrateurs (quotidien ou hebdomadaire) | les administrateurs |

Les e-mails partent par une file : un envoi en échec est réessayé plusieurs fois, puis apparaît
dans Réglages > Système > « Envois en échec », avec sa cause et un bouton « Renvoyer ». Pour un
serveur d'envoi signé par une autorité interne, l'hébergeur renseigne `LOCKSY_SMTP_CA_FILE`
([Exploitation](Exploitation.md#e-mails)).

## Supprimer un compte

- Son coffre personnel est détruit (personne ne peut le déchiffrer).
- Les coffres partagés restent à leurs autres membres ; s'il en était le seul gestionnaire, le
  membre le plus ancien le devient (l'assistant Départ permet de choisir le repreneur).
- Les coffres qui n'ont plus aucun membre sont supprimés.
