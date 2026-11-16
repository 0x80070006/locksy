# Extension navigateur (Edge, Chrome, Brave)

Raccourci : **Ctrl+Maj+L**.

## Fonctions

- Identifiants du site ouvert en tête de liste ; recherche dans tout le coffre.
- **Remplir** : saisit identifiant et mot de passe dans la page (compatible avec les sites
  React, Vue, Angular). Si le site ne correspond pas à l'adresse enregistrée, un **second clic**
  est exigé (protection contre l'hameçonnage) ; avertissement sur les pages non chiffrées.
- Copie de l'identifiant, du mot de passe, du **code 2FA**.
- **Enregistrer ce site** avec un mot de passe généré.
- Connexion par mot de passe maître, **compte Windows** ou **SSO**.

## Permissions

| Permission | Pourquoi |
|---|---|
| `activeTab`, `scripting` | lire l'adresse et remplir la page **active, au moment du clic** seulement |
| `storage` | adresse du serveur ; clés déverrouillées en mémoire (`storage.session`, jamais sur disque) |
| `clipboardWrite` | copier |
| `identity` | connexion SSO |
| accès au serveur | demandé une fois, uniquement pour l'adresse de votre serveur Locksy |

L'extension ne lit pas vos pages en arrière-plan. Les clés sont effacées après 15 minutes
d'inactivité ou à la fermeture du navigateur.

## Installation manuelle

1. Décompressez `locksy-extension.zip`.
2. `edge://extensions` (ou `chrome://extensions`) > **Mode développeur**.
3. **Charger l'extension non empaquetée** > dossier `locksy-extension`.
4. Ouvrez l'extension et indiquez l'adresse du serveur.

## Installation forcée par GPO

L'installation hors boutique est autorisée sur les postes membres du domaine.

1. Empaquetez une fois : `edge://extensions` > **Empaqueter l'extension** > dossier
   `locksy-extension`. Conservez le fichier `.pem` (il signe les mises à jour) et notez
   l'identifiant de l'extension.
2. Publiez le `.crx` et un manifeste `update.xml` sur un serveur web interne :
   ```xml
   <?xml version='1.0' encoding='UTF-8'?>
   <gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
     <app appid='IDENTIFIANT'>
       <updatecheck codebase='https://intranet.corp.local/locksy/locksy.crx' version='1.0.0' />
     </app>
   </gupdate>
   ```
3. Modèles d'administration Edge (ou Chrome) > Extensions > **Contrôler les extensions
   installées sans intervention de l'utilisateur** (`ExtensionInstallForcelist`) :
   `IDENTIFIANT;https://intranet.corp.local/locksy/update.xml`.
