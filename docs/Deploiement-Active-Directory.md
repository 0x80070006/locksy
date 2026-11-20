# Déploiement sur site avec Active Directory

Tout reste dans votre réseau, sans aucun service cloud. Exemple : domaine `corp.local`
(NetBIOS `CORP`), Locksy publié sous `https://locksy.corp.local`.

## 1. Certificat HTTPS émis par AD CS

Les postes du domaine font déjà confiance à votre autorité : un certificat qu'elle émet est
reconnu sans alerte par les navigateurs et le client Windows.

```bash
openssl req -new -newkey rsa:3072 -nodes -keyout locksy.key -out locksy.csr \
  -subj "/CN=locksy.corp.local" -addext "subjectAltName=DNS:locksy.corp.local"
```

Soumettez `locksy.csr` avec le modèle **Serveur Web** :

```powershell
certreq -submit -attrib "CertificateTemplate:WebServer" locksy.csr locksy.cer
```

Convertissez en Base 64 si besoin (`certutil -encode locksy.cer locksy.crt`) et ajoutez à la
suite le certificat de l'autorité intermédiaire éventuelle. Installez ensuite :

```bash
sudo bash install.sh --domain locksy.corp.local --cert locksy.crt --key locksy.key
```

## 2. Préparer l'annuaire

1. **Compte de service** en lecture seule : un simple utilisateur du domaine, mot de passe long
   et sans expiration, par exemple `svc_locksy`.
2. **Groupe de sécurité**, par exemple `GG_Locksy_Utilisateurs`. Les groupes imbriqués sont
   pris en compte.
3. **LDAPS sur les contrôleurs** : chaque contrôleur doit avoir un certificat contenant son nom
   DNS (modèle « Authentification Kerberos » ou « Contrôleur de domaine »). Test : `ldp.exe` >
   connexion à `dc1.corp.local`, port 636, SSL coché.
4. Exportez le certificat de l'**autorité racine** en Base 64 (`.cer`).
5. Pare-feu : le serveur Locksy doit joindre les contrôleurs en **TCP 636**.

## 3. Configurer Locksy

**Administration > Connexion d'entreprise > Compte Windows (Active Directory)**
(`#/admin/connexion/ad`). L'assistant suit quatre étapes : « Serveur et compte de service »,
« Qui peut se connecter », « Test avec votre compte » et « Activation ». Champs :

| Champ | Exemple |
|---|---|
| Contrôleur de domaine | `ldaps://dc1.corp.local:636` |
| Compte de service | `svc_locksy@corp.local` |
| Racine de recherche | `DC=corp,DC=local` |
| Groupe d'accès | `CN=GG_Locksy_Utilisateurs,OU=Groupes,DC=corp,DC=local` |
| Attributs | `sAMAccountName`, `mail` (repli : `userPrincipalName`) |
| Certificat de l'autorité | contenu du `.cer` |

L'étape « Test avec votre compte » vérifie la connexion avec votre propre compte Windows
(« Identifiant Windows », « Mot de passe Windows »). Réglez ensuite :

- **Synchroniser les comptes depuis l'annuaire** (« Synchroniser toutes les » 15 minutes par
  défaut, bouton « Synchroniser maintenant ») :
  - ajouté au groupe : compte ouvert, en attente de première connexion ;
  - désactivé dans l'AD ou retiré du groupe : **accès coupé immédiatement**, toutes sessions ;
  - renommé : nom et adresse mis à jour ;
  - garde-fou : si l'annuaire ne renvoie **aucun** compte (panne, mauvaise racine), rien
    n'est désactivé.
- **Connexion avec le compte Windows** : `CORP\jdupont` ou `jdupont@corp.local`, mot de passe
  Windows vérifié par le contrôleur, puis mot de passe maître.
- **Mode « Imposé »** une fois tout vérifié, disponible après un test réussi de moins de
  24 heures (les propriétaires gardent l'accès de secours par mot de passe maître).

### Synchronisation à blanc et garde-fou

**Lancer une synchronisation à blanc** (`POST /api/admin/ldap/sync?dry_run=true`) montre ce que ferait la
synchronisation sans rien écrire : comptes trouvés, créés, mis à jour, désactivés, et la
liste des comptes ignorés avec leur raison (adresse absente ou invalide, domaine non
autorisé, compte désactivé dans l'annuaire, adresse en double, dernier propriétaire).
L'historique des synchronisations est affiché sur la page d'état.

Une synchronisation qui désactiverait plus de `directory.max_deprovision_percent` % des
comptes issus de l'annuaire est refusée (409 `too_many_deprovisions`, événement critique
`ldap.sync_refused`) : vérifiez le filtre et le groupe, ou relevez le seuil. Un compte
disparu de l'annuaire suit `directory.deprovision` (désactivation, ou désactivation puis
suppression après `directory.delete_after_days` jours).

## 4. Première connexion d'un collaborateur

1. Il ouvre `https://locksy.corp.local` (ou le client Windows, ou l'extension).
2. Il s'identifie avec son **compte Windows**.
3. Il choisit son **mot de passe maître** (distinct du mot de passe Windows, inconnu de
   l'entreprise) et reçoit sa **clé de récupération**.

## 5. Sécurité de la connexion Windows

- LDAPS ou STARTTLS obligatoire, certificat du contrôleur vérifié avec votre autorité.
- Mot de passe vide refusé (une liaison LDAP sans mot de passe « réussirait » de façon anonyme).
- Valeurs échappées dans les filtres LDAP (RFC 4515) ; un seul compte actif du groupe accepté.
- Le mot de passe Windows transite en HTTPS jusqu'au serveur, qui le présente au contrôleur ;
  il n'est **jamais enregistré** et est effacé de la mémoire.
- Tentatives comptées avant toute liaison : blocage après 5 échecs par couple (identifiant,
  adresse IP) et 50 par identifiant, avant le verrouillage de l'AD ; 100 tentatives par
  adresse IP en 10 minutes au plus.
- Réponses génériques : `invalid_credentials` (401) pour tout échec d'identifiants,
  `ldap_unavailable` (503) pour toute panne d'annuaire (le détail ne va qu'au journal du
  serveur) ; un échec dure au moins 1,5 s. Chaque opération sur l'annuaire est limitée à
  10 s, une synchronisation à 5 min.
- Le code de **double authentification** Locksy est demandé ensuite si le compte l'a activée.

## 6. ADFS (facultatif)

Avec ADFS 2016 ou plus récent, vous pouvez aussi utiliser la connexion **OpenID Connect**, qui
profite de l'authentification Windows intégrée : voir [SSO et SCIM](SSO-et-SCIM.md).

## 7. Postes de travail par GPO

Voir [Client Windows](Client-Windows.md) et [Extension navigateur](Extension-navigateur.md).
