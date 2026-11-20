# Extension navigateur (Edge, Chrome, Brave)

Raccourci : **Ctrl+Maj+L**. Version minimale : Chrome ou Edge 120.

## Fonctions

- Les comptes du site ouvert en tête (« Pour ce site »), les favoris, et la recherche dans tout
  le coffre (« Rechercher dans le coffre »).
- **Remplir** : « Remplir » saisit l'identifiant et le mot de passe dans la page (compatible avec
  les sites React, Vue, Angular) ; « Remplir et copier le code » copie en plus le code de
  vérification, à coller à l'étape suivante. Le remplissage n'a lieu **que sur le site de
  l'élément** :
  - même domaine enregistrable (`login.example.com` = `www.example.com`, mais
    `alice.github.io` ≠ `bob.github.io` et `a.co.uk` ≠ `b.co.uk`) ;
  - même port ;
  - jamais en HTTP pour un élément enregistré en HTTPS ;
  - sur une page HTTP, remplissage bloqué, ou permis avec avertissement si l'organisation
    l'autorise ;
  - jamais sur un site exclu par l'organisation.

  Un compte d'un autre site garde ses boutons de copie, sans remplissage, sauf si
  l'organisation autorise le remplissage hors du site : l'extension demande alors une
  confirmation (« Remplir un compte d'un autre site ? »). Juste avant de remplir, l'adresse de
  l'onglet est relue et l'origine revérifiée dans la page ; seul le cadre principal est rempli.
- Copie de l'identifiant, du mot de passe, du code de vérification.
- **Enregistrer le compte saisi sur ce site**, ou « Créer un mot de passe pour ce site » avec le
  générateur.
- Connexion par mot de passe maître, **compte Windows** ou **connexion d'entreprise** (code de
  vérification demandé ensuite si la double authentification est active ; le ticket de
  connexion d'entreprise reste valable 5 minutes).
- **Préférences** : « Verrouiller Locksy après », « Effacer le presse-papiers après », « Copier
  le code de vérification après le remplissage », « Proposer d'enregistrer le compte saisi ».
  Ce sont les préférences du compte : elles s'appliquent aussi à l'interface web. La page
  affiche aussi l'identifiant de l'extension, à transmettre à l'administrateur pour la
  connexion d'entreprise.

## Verrouillage et presse-papiers

- Le coffre déverrouillé (jeton et clés, en mémoire seulement : `storage.session`) est effacé
  par le service worker :
  - quand le délai expire (choix entre 1 min et 4 h, dans la limite fixée par l'organisation) :
    ouvrir la fenêtre, chercher ou synchroniser ne compte pas comme une utilisation ; seuls le
    déverrouillage, le remplissage, une copie ou un enregistrement prolongent la session ;
  - quand la session Windows est verrouillée (actif par défaut) ;
  - au démarrage du navigateur ;
  - au verrouillage manuel (immédiat).
  La session est aussi fermée côté serveur (au mieux).
- Pendant la session, la clé utilisateur et la clé privée sont gardées **exportées** (base64)
  dans `storage.session`, pour que la fenêtre, détruite à chaque fermeture, n'ait pas à
  redemander le mot de passe maître. C'est une limite assumée (voir
  [SECURITE.md](../SECURITE.md#limites-connues)) : dans l'interface web, les clés ne quittent
  jamais la mémoire WebAssembly.
- Un mot de passe ou un code copié est effacé après le délai choisi, et au verrouillage. Sans la
  permission `clipboardRead`, l'effacement est inconditionnel mais ne concerne que la dernière
  copie faite par Locksy. Il remplace le contenu par une chaîne vide, ou par une espace si le
  navigateur refuse la chaîne vide.

## Permissions

| Permission | Pourquoi |
|---|---|
| `activeTab`, `scripting` | lire l'adresse et remplir la page **active, au moment du clic** seulement |
| `storage` | adresse du serveur et réglages ; clés déverrouillées en mémoire (`storage.session`, jamais sur disque) ; politique d'entreprise (`storage.managed`) |
| `alarms` | verrouiller et effacer le presse-papiers même fenêtre fermée |
| `offscreen`, `clipboardWrite` | copier ; le service worker n'a pas de presse-papiers : un document invisible l'efface |
| `idle` | verrouiller avec la session Windows |
| `identity` | connexion d'entreprise |
| accès au serveur | demandé une fois, uniquement pour l'adresse de votre serveur Locksy |

L'extension ne lit pas vos pages en arrière-plan.

## Politique d'entreprise

L'extension applique d'abord les réglages de l'organisation (Administration > Réglages,
section Applications et extension : voir [Réglages](Reglages.md#applications-et-extension)).
Le service informatique peut en plus imposer des valeurs sur le poste, dans
`chrome.storage.managed` (schéma `managed-schema.json`). Les noms sont **ceux du serveur** :

| Clé | Type | Effet |
|---|---|---|
| `server_url` | texte | adresse imposée ; le champ serveur est masqué |
| `client.autolock_minutes` | entier, 1-1440 | délai maximal de verrouillage ; « Jamais » n'est plus proposé |
| `client.clipboard_clear_seconds` | entier, 5-600 | délai maximal d'effacement du presse-papiers |
| `client.lock_on_os_lock` | booléen | vrai : verrouillage avec la session Windows, quel que soit le choix de l'organisation |
| `extension.http_fill` | `warn` ou `block` | `block` : jamais de remplissage sur une page HTTP |
| `extension.allow_mismatch_fill` | booléen | faux : jamais de remplissage hors du site de l'élément |
| `extension.offer_save` | booléen | proposer d'enregistrer le compte saisi |
| `extension.copy_totp_after_fill` | booléen | copier le code de vérification après le remplissage |
| `extension.excluded_sites` | liste de domaines | sites (et sous-domaines) où l'extension ne remplit ni n'enregistre rien |

Sur un poste, **la valeur la plus stricte l'emporte** entre celle du poste et celle de
l'organisation. Une valeur imposée s'affiche avec sa limite. Une baisse de la politique
raccourcit immédiatement la session en cours. Les noms de la version 1.0
(`max_auto_lock_minutes`, `clipboard_seconds`) restent lus ; préférez les nouveaux.

## Installation manuelle

1. Vérifiez l'empreinte de `locksy-extension.zip` (`SHA256SUMS`), puis décompressez-le.
2. `edge://extensions` (ou `chrome://extensions`) > **Mode développeur**.
3. **Charger l'extension non empaquetée** > dossier `locksy-extension`.
4. Ouvrez l'extension et indiquez l'adresse du serveur (sauf si la politique l'impose).

L'archive est construite par `node extension/build.mjs --wasm <locksy.wasm>` : elle est
déterministe (même contenu, même empreinte) et ne contient ni le mode de démonstration ni
les tests. Le build écrit aussi `locksy-extension.zip.sha256`.

**Vérification.** `locksy-extension.zip` figure dans `SHA256SUMS`, signé par cosign (et en
option minisign) : vérifiez d'abord la signature de `SHA256SUMS`
([SECURITY.md](../SECURITY.md#vérifier-une-version)), puis l'empreinte du zip
(`sha256sum --ignore-missing -c SHA256SUMS`). L'empreinte du zip **change d'une version à
l'autre dès que `web/js` ou `web/css` change** (modules partagés embarqués dans `lib/`), même
si le code propre à l'extension est identique : comparez toujours à la `SHA256SUMS` de la même
version.

## Déploiement sur les postes

L'extension n'est pas encore publiée dans les boutiques de Chrome et d'Edge : vous l'hébergez
sur un serveur web interne, et son identifiant dépend de votre clé d'empaquetage. Un navigateur
n'accepte l'installation imposée d'une extension hors boutique que sur un poste **joint au
domaine** ou **inscrit dans Intune**.

### Préparer l'extension

1. Empaquetez une fois : `edge://extensions` > **Empaqueter l'extension** > dossier
   `locksy-extension`. Conservez le fichier `.pem` (il signe les mises à jour) et notez
   l'identifiant de l'extension (32 lettres de a à p).
2. Publiez le `.crx` et un manifeste `update.xml` sur un serveur web interne en HTTPS :
   ```xml
   <?xml version='1.0' encoding='UTF-8'?>
   <gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
     <app appid='IDENTIFIANT'>
       <updatecheck codebase='https://intranet.corp.local/locksy/locksy.crx' version='1.1.0' />
     </app>
   </gupdate>
   ```
3. Déclarez l'identifiant pour la connexion d'entreprise : Administration > Connexion
   d'entreprise > SSO, champ « Extensions de navigateur autorisées » (c'est aussi le réglage
   « Extensions autorisées » de la section Applications et extension). Tant qu'il n'y figure
   pas, l'extension refuse d'ouvrir la connexion d'entreprise (`extension_not_allowed`) et
   affiche son identifiant. Cette vérification préalable passe par `/api/sso/start` : elle crée
   un état de connexion inutile, purgé après 10 minutes.

### Extraits générés par Locksy

Administration > Réglages > **Applications et extension** (`#/admin/reglages/clients`) affiche,
sous « Déploiement sur les postes », des extraits **générés depuis vos réglages actuels**, avec
« Copier » et « Télécharger » : saisissez d'abord l'« Identifiant de l'extension ».

| Extrait | Usage |
|---|---|
| Google Chrome, Microsoft Edge | JSON des stratégies du navigateur : `ExtensionInstallForcelist`, `ExtensionSettings` (installation imposée) et `3rdparty.extensions.<id>` (réglages imposés à l'extension) |
| Registre Windows (stratégie de groupe), Modèle d'administration (ADMX et ADML), Microsoft Intune | réglages des applications Locksy du poste sous `HKLM\SOFTWARE\Policies\Locksy` ; ils préparent le client Windows 1.2 (voir la remarque ci-dessous) |

Dans les extraits de navigateur, l'adresse de mise à jour est celle de la boutique : si vous
hébergez l'extension, remplacez-la par l'adresse de votre `update.xml`.

> Le client Windows 1.1 lit sa politique sous `HKLM\SOFTWARE\Policies\Locksy` avec ses propres
> noms (`ServerUrl`, `MaxAutoLockMinutes`, `ClipboardSeconds`, `LockOnFocusLossMinutes`), pas
> encore ceux des extraits : voir [Client Windows](Client-Windows.md#politique-dentreprise).

### Déploiement par GPO

Avec les modèles d'administration d'Edge (ou de Chrome), dans une GPO ordinateur :

1. Extensions > **Contrôler les extensions installées sans intervention de l'utilisateur**
   (`ExtensionInstallForcelist`) : `IDENTIFIANT;https://intranet.corp.local/locksy/update.xml`.
   Vous pouvez aussi utiliser **Configurer les paramètres de gestion des extensions**
   (`ExtensionSettings`) avec `installation_mode` = `force_installed` et la même `update_url`.
2. Réglages imposés à l'extension, par GPO ordinateur > Préférences > Registre, sous :
   - Edge : `HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<id>\policy` ;
   - Chrome : `HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<id>\policy`.

   Une valeur par clé du tableau [Politique d'entreprise](#politique-dentreprise) : texte en
   `REG_SZ` (`server_url` = `https://locksy.corp.local`), entier ou booléen en `REG_DWORD`
   (`client.autolock_minutes` = 15, `client.lock_on_os_lock` = 1). Pour une liste
   (`extension.excluded_sites`), créez une sous-clé du même nom avec des valeurs `1`, `2`, `3`…

Vérification sur un poste : `edge://policy` (ou `chrome://policy`), puis « Recharger les
stratégies ». La politique de l'extension s'affiche sous son identifiant.

### Déploiement par Intune

Pour des postes inscrits dans Intune (Configuration des appareils, profil Windows) :

1. **Installation imposée** : profil de type **Catalogue des paramètres**, catégorie Microsoft
   Edge (ou Google Chrome) > Extensions. Activez `ExtensionInstallForcelist` avec la valeur
   `IDENTIFIANT;https://intranet.corp.local/locksy/update.xml`, ou `ExtensionSettings` avec le
   JSON de l'extrait généré (adresse de mise à jour remplacée si besoin). Affectez le profil
   à un groupe d'appareils.

   Variante : un **profil personnalisé** (OMA-URI), après ingestion du modèle
   d'administration du navigateur ; les noms des stratégies restent les mêmes. Le catalogue
   des paramètres est plus simple à maintenir.
2. **Réglages imposés à l'extension** : ils vivent dans le registre, sous les mêmes clés
   `3rdparty` que pour la GPO. Le plus simple est un script PowerShell exécuté en contexte
   système (Appareils > Scripts et corrections, ou Scripts de plateforme) :

   ```powershell
   $id = "identifiant-de-l-extension"
   $valeurs = [ordered]@{
     "server_url"                     = "https://locksy.corp.local"
     "client.autolock_minutes"        = 15
     "client.clipboard_clear_seconds" = 60
     "client.lock_on_os_lock"         = 1
   }
   foreach ($nav in "Microsoft\Edge", "Google\Chrome") {
     $cle = "HKLM:\SOFTWARE\Policies\$nav\3rdparty\extensions\$id\policy"
     New-Item -Path $cle -Force | Out-Null
     foreach ($nom in $valeurs.Keys) {
       $v = $valeurs[$nom]
       $type = if ($v -is [int]) { "DWord" } else { "String" }
       New-ItemProperty -Path $cle -Name $nom -Value $v -PropertyType $type -Force | Out-Null
     }
   }
   ```

3. Vérifiez sur un poste avec `edge://policy`, puis dans Intune l'état du profil et du script.

L'extrait « Microsoft Intune » de Locksy (lignes OMA-URI d'un profil personnalisé, après
ingestion du modèle d'administration) concerne les réglages des applications Locksy du poste,
et non l'installation de l'extension.
