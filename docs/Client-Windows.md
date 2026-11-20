# Client Windows

> **La refonte du client Windows arrive en version 1.2.** Le client livré avec Locksy 1.1
> garde son interface actuelle. Il ne lit pas encore les réglages de l'organisation
> (Administration > Réglages) ni les préférences synchronisées de l'interface web : il applique
> seulement la **politique locale du poste** (`ServerUrl`, `MaxAutoLockMinutes`,
> `ClipboardSeconds`, `LockOnFocusLossMinutes` : voir [Politique d'entreprise](#politique-dentreprise)).
> Le serveur, lui, applique les règles de l'organisation à toutes les applications (double
> authentification, durée des sessions, réseaux autorisés…).

Application native (`locksy.exe`, environ 6 Mo, sans installation de prérequis), avec le même
noyau cryptographique que le serveur. Rien de secret n'est écrit sur le disque : seules
l'adresse du serveur, la dernière adresse e-mail, les préférences et les paramètres de
dérivation déjà vus (anti-rétrogradation) sont mémorisés.

## Fonctions

- Connexion par mot de passe maître, **compte Windows** (identifiant de la session pré-rempli)
  ou **SSO** (via le navigateur du système, retour sur `127.0.0.1` selon la RFC 8252).
  - Le client tire une valeur aléatoire (`client_state`) et n'accepte que le retour qui la
    porte : un autre programme du poste ne peut ni injecter un ticket ni faire échouer la
    connexion. Bouton **Annuler la connexion SSO**.
  - Si la double authentification Locksy est active, le code est demandé après le SSO ou le
    compte Windows. Le champ accepte aussi un **code de secours**.
  - Le motif d'un refus renvoyé par le fournisseur n'est jamais affiché : message générique.
- Coffres, recherche, favoris, corbeille ; fiche avec copie, affichage des secrets, code 2FA,
  ouverture des sites, historique des mots de passe.
- Création et modification des éléments, générateur.
- **Pièces jointes** : « Enregistrer sous… » ouvre le dialogue Windows (dossier Documents par
  défaut). Un avertissement s'affiche si l'emplacement est synchronisé avec OneDrive.
- **Presse-papiers** : un secret copié est exclu de l'historique Win+V et de la
  synchronisation cloud. Il est effacé au délai choisi, au verrouillage et à la fermeture
  (seulement s'il est encore présent).
- **Verrouillage** (**Ctrl+L** à tout moment) :
  - après inactivité (délai réglable) ;
  - après une mise en veille ou une hibernation ;
  - quand Locksy reste en arrière-plan (5 min par défaut ; couvre aussi le verrouillage de
    session Win+L).
  Le verrouillage efface aussi l'état de l'interface (champs saisis, fiche affichée).
- **Réglages** (bouton ⚙) : verrouillage, presse-papiers, arrière-plan. Une valeur imposée
  par la politique s'affiche avec la mention « imposé par votre organisation ».
- Refuse le HTTP en clair vers un autre poste que lui-même.

La création de compte, la récupération, l'administration, les imports, le partage par lien
sécurisé et le Bilan de sécurité se font dans l'interface web.

## Limites de la version 1.1

- Les réglages de l'organisation diffusés aux postes (verrouillage, presse-papiers,
  générateur, liens sécurisés…) ne s'appliquent pas encore au client Windows : réglez le poste
  par sa politique locale.
- Les favoris du client Windows sont encore enregistrés dans l'élément : dans un coffre partagé,
  ils sont donc communs à ses membres, et ils ne suivent pas les favoris personnels de
  l'interface web.
- Les extraits « Registre Windows (stratégie de groupe) », « Modèle d'administration » et
  « Microsoft Intune » de la section Réglages > Applications et extension utilisent les noms
  du serveur (`client.autolock_minutes`…) : ils préparent la version 1.2 et ne sont pas lus
  par le client 1.1.

## Installation sur un poste

Dans les fichiers de la version : `locksy-windows-x64.exe`, `install-client.ps1` et
`SHA256SUMS`, à poser dans le même dossier.

```powershell
powershell -NoProfile -File .\install-client.ps1 [-Server https://locksy.corp.local] [-CurrentUser] [-Sha256 <hex>] [-NoDesktopShortcut]
```

- **En administrateur** (sans `-CurrentUser`) : installation pour tout le poste dans
  `Program Files\Locksy`, avec des raccourcis communs. Avec `-Server`, le fichier
  `C:\ProgramData\Locksy\bureau.json` est créé (lecture seule pour les utilisateurs) et
  l'adresse est imposée.
- **Utilisateur standard** (ou `-CurrentUser`) : `%LOCALAPPDATA%\Programs\Locksy` ;
  `-Server` pré-remplit seulement l'adresse.
- L'empreinte SHA-256 de l'exécutable est vérifiée avant et après la copie. Elle est lue dans
  `-Sha256`, sinon dans `SHA256SUMS` à côté du script. Sans empreinte, l'installation est
  refusée (sauf `-SkipHashCheck`, déconseillé).
- Plus de `-ExecutionPolicy Bypass` : si la stratégie d'exécution bloque le script, signez-le
  avec le certificat de code de l'entreprise, ou déployez-le par GPO ou Intune.

## Vérifier l'exécutable

`install-client.ps1` vérifie l'empreinte, mais `SHA256SUMS` lui-même doit d'abord être
authentifié, une fois, sur le poste qui télécharge la version (signature cosign ou minisign,
voir [SECURITY.md](../SECURITY.md#vérifier-une-version)) :

```bash
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/0x80070006/locksy/\.github/workflows/release\.yml@refs/tags/v' \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

Sous Windows, sans ces outils : `Get-FileHash .\locksy-windows-x64.exe -Algorithm SHA256`,
à comparer à la ligne `locksy-windows-x64.exe` de `SHA256SUMS` (vérifié par ailleurs).
`gh attestation verify locksy-windows-x64.exe --repo 0x80070006/locksy` prouve en plus que
l'exécutable a été construit par le workflow du dépôt.

**Signature Authenticode** : elle n'est apposée que si l'éditeur a fourni un certificat de
signature de code à la CI (secrets `WINDOWS_CERT_PFX` et `WINDOWS_CERT_PASSWORD`). Sans elle,
SmartScreen peut avertir au premier lancement et AppLocker ou WDAC ne peuvent pas autoriser
l'exécutable par éditeur : autorisez-le par empreinte, ou signez-le avec le certificat de code
de l'entreprise avant le déploiement. Vérification :
`Get-AuthenticodeSignature .\locksy-windows-x64.exe`. `install-client.ps1` n'a pas changé avec
la publication signée.

## Politique d'entreprise

Le client 1.1 lit uniquement les valeurs ci-dessous. Registre
`HKLM\SOFTWARE\Policies\Locksy` (prioritaire), sinon fichier machine
`C:\ProgramData\Locksy\bureau.json`. Priorité : registre > fichier machine > préférences de
l'utilisateur.

| Registre | Clé du fichier machine | Effet |
|---|---|---|
| `ServerUrl` (REG_SZ) | `server_url` | adresse imposée, champ serveur non modifiable |
| `MaxAutoLockMinutes` (REG_DWORD, 1-1440) | `max_auto_lock_minutes` | délai maximal de verrouillage ; « Jamais » interdit |
| `ClipboardSeconds` (REG_DWORD, 5-600) | `clipboard_seconds` | délai maximal d'effacement ; ni désactivable ni allongeable |
| `LockOnFocusLossMinutes` (REG_DWORD, 0-1440) | `lock_on_focus_loss_minutes` | délai maximal en arrière-plan ; 0 = désactivé |

Les valeurs invalides ou hors bornes sont ignorées. Une valeur imposée n'est jamais recopiée
dans le fichier de l'utilisateur.

> Changement de comportement : un ancien `C:\ProgramData\Locksy\bureau.json` complet qui
> contient `clipboard_seconds` impose désormais ce délai comme maximum ; ses autres clés de
> préférences sont ignorées et n'initialisent plus les préférences de l'utilisateur.

## Déploiement par GPO

1. Copiez `locksy-windows-x64.exe` dans un partage en lecture, par exemple
   `\\corp.local\NETLOGON\Locksy\locksy.exe`, après avoir vérifié son empreinte
   (`SHA256SUMS`).
2. GPO ordinateur > Préférences > Fichiers : copie vers `%ProgramFiles%\Locksy\locksy.exe`.
3. GPO ordinateur > Préférences > Registre : valeurs de `HKLM\SOFTWARE\Policies\Locksy`
   (tableau ci-dessus), par exemple `ServerUrl` = `https://locksy.corp.local`.
4. GPO utilisateur > Préférences > Raccourcis : menu Démarrer et Bureau.

## Fichiers

| Fichier | Contenu |
|---|---|
| `%APPDATA%\Locksy\bureau.json` | adresse du serveur, dernière adresse, verrouillage auto, presse-papiers, `lock_on_focus_loss_minutes`, `kdf_pins` (paramètres de dérivation déjà vus) ; jamais une valeur imposée |
| `C:\ProgramData\Locksy\bureau.json` | politique de l'entreprise (si le registre ne la fournit pas) |
| `HKLM\SOFTWARE\Policies\Locksy` | politique de l'entreprise (prioritaire) |
