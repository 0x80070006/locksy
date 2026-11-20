# Fonctionnalités

Vue d'ensemble de Locksy 1.1. Le mode d'emploi est dans le [guide utilisateur](Guide-utilisateur.md)
et le [guide administrateur](Administration.md) ; toutes les valeurs réglables sont dans
[Réglages](Reglages.md).

## Coffre

| Fonction | Détail |
|---|---|
| Types d'éléments | mot de passe d'un site, note secrète, carte bancaire, identité, clé SSH |
| Mots de passe | plusieurs sites, champs personnalisés (masqués ou non), étiquettes, favoris personnels |
| Codes de vérification | « Scanner le QR code » ou « Coller la clé » ; code affiché avec compte à rebours, copié ou rempli par l'extension |
| Historique | 20 derniers mots de passe de chaque élément |
| Renouvellement | date « à renouveler avant », signalée dans la fiche et le Bilan de sécurité |
| Pièces jointes | chiffrées avec une clé propre ; taille par fichier, nombre par élément et quotas réglables (10 Mio et 20 par élément par défaut) |
| Corbeille | « Annuler » juste après, « Restaurer » ensuite, purge automatique (30 jours par défaut) |
| Recherche | sur tout le coffre, sans accents ni majuscules : nom, identifiant, sites, étiquettes, début des notes |
| Édition | dans le panneau de la fiche, mot de passe solide proposé d'office, garde avant de quitter sans enregistrer |

## Générateur

Mots de passe jusqu'à 128 caractères (minuscules, majuscules, chiffres, symboles, sans
caractères ambigus) ou **phrases de passe** (« Facile à taper (mots) »). Tirage uniforme sans
biais sur l'aléa du système. L'organisation peut imposer une longueur et des types de
caractères minimaux.

## Bilan de sécurité

Calculé **sur le poste** (le serveur n'en sait rien) : mots de passe faibles, réutilisés,
inchangés depuis longtemps, date de renouvellement dépassée, comptes sans code de
vérification, liens sécurisés encore actifs. Score sur 100 et bouton « Corriger » par élément.

## Partage

- **Avec des collègues**, en une fenêtre : l'élément rejoint un coffre partagé existant qui
  réunit les mêmes personnes, ou un nouveau coffre.
- **Coffres partagés** : droits « Gère le coffre », « Peut modifier », « Peut voir ».
- **Empreinte de clé** affichée pour vérifier un destinataire ; une clé changée est signalée
  avant tout partage.
- **Renouvellement de la clé** au retrait d'un membre : tout le coffre est rechiffré. Selon
  l'organisation, le renouvellement est exigé, proposé (par défaut) ou laissé au gestionnaire.
- **Liens sécurisés** pour une personne sans Locksy : durée et nombre d'ouvertures limités,
  nom de l'élément facultatif, clé dans le `#` du lien ; aucune lecture sans la clé du lien.
  Liste des « Liens envoyés » et révocation.

## Compte

- Double authentification par code de vérification (QR code), imposable par l'organisation,
  avec **codes de secours** à usage unique.
- Clé de récupération, régénérable.
- Changement de mot de passe maître instantané (déconnecte les autres appareils).
- Appareils et sessions, fermeture à distance ; « Mon activité » en langage clair.
- **Préférences chiffrées** et synchronisées entre les appareils (ou propres à un appareil).
- Import CSV (séparateur détecté), KeePass (KDBX 3.1 et 4) et export Bitwarden (JSON), lus
  dans le navigateur ; sauvegarde chiffrée par mot de passe ; export CSV en clair sur
  confirmation.

## Confort et accessibilité

- **Copie en un clic** depuis la liste et la fiche.
- **Raccourcis clavier** : Ctrl+K ou / rechercher, Ctrl+Alt+L verrouiller, N nouvel élément,
  Ctrl+Maj+C copier le mot de passe, ? aide (liste complète dans « Aide et raccourcis »).
- Verrouillage automatique (délai réglable, au masquage de l'onglet, avec la session Windows),
  effacement du presse-papiers.
- Thème clair, sombre ou comme le système, taille du texte ; interface adaptée aux téléphones,
  **installable comme une application**.
- Conçue pour le RGAA 4.1 (WCAG 2.2 AA) : navigation au clavier, lecteurs d'écran, contrastes
  vérifiés ; déclaration d'accessibilité à l'adresse `#/accessibilite`.

## Administration

Accueil avec mise en service et « À traiter », Personnes (invitations par lot, actions
groupées, Départ de l'entreprise), Réglages générés depuis un registre unique (profils de
sécurité, historique, import et export), Connexion d'entreprise testée avant d'être imposée,
Journal chaîné et vérifiable, e-mails et notifications. Détail : [guide administrateur](Administration.md).

## Connexion

| Mode | Remarques |
|---|---|
| Adresse + mot de passe maître (+ code) | toujours disponible pour les propriétaires |
| Compte Windows (Active Directory) | identifiant et mot de passe Windows, puis mot de passe maître (+ code) |
| Connexion d'entreprise (OpenID Connect) | Microsoft Entra, Google, Okta, ADFS, Keycloak…, puis mot de passe maître (+ code) |

Le code de vérification est demandé, quel que soit le mode, aux comptes qui ont activé la
double authentification ; l'organisation peut en imposer l'activation (Réglages > Sécurité de
connexion).

Voir aussi : [Client Windows](Client-Windows.md), [Extension navigateur](Extension-navigateur.md).
