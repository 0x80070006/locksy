# Client Windows

Application native (`locksy.exe`, environ 6 Mo, sans installation de prérequis), avec le même
noyau cryptographique que le serveur. Rien de secret n'est écrit sur le disque : seules
l'adresse du serveur, la dernière adresse e-mail et les préférences sont mémorisées.

## Fonctions

- Connexion par mot de passe maître, **compte Windows** (identifiant de la session pré-rempli)
  ou **SSO** (via le navigateur du système, retour sur `127.0.0.1` selon la RFC 8252).
- Coffres, recherche, favoris, corbeille ; fiche avec copie, affichage des secrets, code 2FA,
  ouverture des sites, historique des mots de passe.
- Création et modification des éléments, générateur.
- **Pièces jointes** : déchiffrées et enregistrées dans le dossier Téléchargements.
- Verrouillage automatique (réglable), **Ctrl+L** pour verrouiller, presse-papiers effacé.
- Refuse le HTTP en clair vers un autre poste que lui-même.

La création de compte, la récupération et l'administration se font dans l'interface web.

## Installation sur un poste

Dans les fichiers de la version : `locksy-windows-x64.exe` et `install-client.ps1`.

```powershell
powershell -ExecutionPolicy Bypass -File install-client.ps1 -Server https://locksy.corp.local
```

Installation pour l'utilisateur courant (sans droits administrateur) dans
`%LOCALAPPDATA%\Programs\Locksy`, avec raccourcis menu Démarrer et Bureau.

## Déploiement par GPO

1. Copiez `locksy-windows-x64.exe` dans un partage en lecture, par exemple
   `\\corp.local\NETLOGON\Locksy\locksy.exe`.
2. GPO ordinateur > Préférences > Fichiers : copie vers `%ProgramFiles%\Locksy\locksy.exe`.
3. GPO > Préférences > Fichiers : `C:\ProgramData\Locksy\bureau.json` contenant
   ```json
   { "server_url": "https://locksy.corp.local" }
   ```
   L'adresse est alors imposée sur le poste.
4. GPO utilisateur > Préférences > Raccourcis : menu Démarrer et Bureau.

## Fichiers

| Fichier | Contenu |
|---|---|
| `%APPDATA%\Locksy\bureau.json` | adresse du serveur, dernière adresse, verrouillage auto, presse-papiers |
| `C:\ProgramData\Locksy\bureau.json` | adresse imposée par l'entreprise (prioritaire) |
