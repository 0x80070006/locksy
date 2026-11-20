//! Contrat de l'API HTTP, partagé par le serveur et le client de bureau.
//! Tous les champs `*_key`, `data`, `enc_name` sont des chiffrés opaques.

use crate::crypto::KdfParams;
use serde::{Deserialize, Serialize};

pub mod roles {
    pub const OWNER: &str = "owner";
    pub const ADMIN: &str = "admin";
    pub const USER: &str = "user";
    pub const ORG_ROLES: [&str; 3] = [OWNER, ADMIN, USER];

    pub const MANAGER: &str = "manager";
    pub const EDITOR: &str = "editor";
    pub const READER: &str = "reader";
    pub const COLLECTION_ROLES: [&str; 3] = [MANAGER, EDITOR, READER];
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
}

// ---------------------------------------------------------------- Auth

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreloginRequest {
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreloginResponse {
    pub kdf: KdfParams,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewCollection {
    pub id: String,
    pub enc_name: String,
    pub sealed_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterRequest {
    pub user_id: String,
    pub email: String,
    pub name: String,
    #[serde(default)]
    pub invite_token: Option<String>,
    /// Ticket remis après une authentification SSO réussie.
    #[serde(default)]
    pub sso_ticket: Option<String>,
    pub auth_key: String,
    pub kdf: KdfParams,
    pub wrapped_user_key: String,
    pub recovery_wrapped_user_key: String,
    pub recovery_auth: String,
    pub public_key: String,
    pub wrapped_private_key: String,
    pub personal_collection: NewCollection,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginRequest {
    pub email: String,
    pub auth_key: String,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub device: Option<String>,
    #[serde(default)]
    pub sso_ticket: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Profile {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub totp_enabled: bool,
    pub must_setup_2fa: bool,
    pub kdf: KdfParams,
    pub wrapped_user_key: String,
    pub public_key: String,
    pub wrapped_private_key: String,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginResponse {
    pub token: String,
    pub profile: Profile,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteInfo {
    pub email: String,
    pub role: String,
    /// Nom saisi par l'administrateur (« Prénom Nom »), vide si non renseigné.
    #[serde(default)]
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecoverStartRequest {
    pub email: String,
    pub recovery_auth: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecoverStartResponse {
    pub recovery_token: String,
    pub user_id: String,
    pub recovery_wrapped_user_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecoverFinishRequest {
    pub recovery_token: String,
    pub auth_key: String,
    pub kdf: KdfParams,
    pub wrapped_user_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChangePasswordRequest {
    pub current_auth_key: String,
    pub auth_key: String,
    pub kdf: KdfParams,
    pub wrapped_user_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotateRecoveryRequest {
    pub current_auth_key: String,
    pub recovery_wrapped_user_key: String,
    pub recovery_auth: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateProfileRequest {
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub uri: String,
    pub qr_svg: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TotpCodeRequest {
    pub code: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionView {
    pub id: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
    pub ip: String,
    pub device: String,
    pub current: bool,
}

// ---------------------------------------------------------------- Coffres

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CollectionView {
    pub id: String,
    pub enc_name: String,
    pub personal: bool,
    pub role: String,
    pub sealed_key: String,
    pub member_count: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ItemView {
    pub id: String,
    pub collection_id: String,
    pub data: String,
    pub revision: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SyncResponse {
    pub profile: Profile,
    pub collections: Vec<CollectionView>,
    pub items: Vec<ItemView>,
    pub server_time: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateItemRequest {
    pub id: String,
    pub collection_id: String,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchCreateItemsRequest {
    pub items: Vec<CreateItemRequest>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateItemRequest {
    pub collection_id: String,
    pub data: String,
    pub revision: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateCollectionRequest {
    pub enc_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberView {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddMemberRequest {
    pub user_id: String,
    pub role: String,
    pub sealed_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateMemberRequest {
    pub role: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotatedMember {
    pub user_id: String,
    pub sealed_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotatedItem {
    pub id: String,
    pub data: String,
}

/// Renouvelle la clé d'un coffre : retire éventuellement des membres et
/// rechiffre tout le contenu, en une seule transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotateCollectionRequest {
    #[serde(default)]
    pub remove_user_ids: Vec<String>,
    pub enc_name: String,
    pub members: Vec<RotatedMember>,
    pub items: Vec<RotatedItem>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirectoryUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub public_key: String,
}

// ---------------------------------------------------------------- Partages

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateShareRequest {
    pub data: String,
    pub expires_in_minutes: i64,
    pub max_views: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateShareResponse {
    pub id: String,
    pub expires_at: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShareView {
    pub data: String,
    pub expires_at: i64,
    pub views_left: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShareSummary {
    pub id: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub max_views: i64,
    pub views: i64,
}

// ---------------------------------------------------------------- Admin

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AdminUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub disabled: bool,
    pub totp_enabled: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
    pub collections: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub disabled: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateInviteRequest {
    pub email: String,
    pub role: String,
    /// Nom de la personne invitée (« Prénom Nom »), facultatif.
    #[serde(default)]
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteCreated {
    pub id: String,
    pub token: String,
    pub expires_at: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteView {
    pub id: String,
    pub email: String,
    pub role: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub at: i64,
    pub user_id: Option<String>,
    pub email: String,
    pub action: String,
    pub target: String,
    pub ip: String,
    pub user_agent: String,
    pub details: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditPage {
    pub entries: Vec<AuditEntry>,
    pub total: i64,
}

/// Réglages de l'organisation. `serde(default)` : un champ absent du JSON
/// enregistré (base d'une version antérieure) prend sa valeur par défaut au
/// lieu de faire échouer la lecture, ce qui remettrait tous les réglages à zéro.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct OrgSettings {
    pub require_2fa: bool,
    pub session_idle_minutes: i64,
    pub session_max_hours: i64,
    pub audit_retention_days: i64,
    pub trash_retention_days: i64,
}

impl Default for OrgSettings {
    fn default() -> Self {
        Self {
            require_2fa: false,
            session_idle_minutes: 60,
            session_max_hours: 12,
            audit_retention_days: 365,
            trash_retention_days: 30,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AdminStats {
    pub users: i64,
    pub active_users: i64,
    pub users_with_2fa: i64,
    pub collections: i64,
    pub shared_collections: i64,
    pub items: i64,
    pub active_shares: i64,
    pub failed_logins_24h: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub needs_setup: bool,
    #[serde(default)]
    pub sso: Option<SsoPublic>,
    /// Connexion avec le compte Windows (Active Directory), si activée.
    #[serde(default)]
    pub ldap: Option<SsoPublic>,
}

// ---------------------------------------------------------------- SSO et SCIM

/// Ce que les clients doivent savoir pour proposer la connexion SSO.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SsoPublic {
    pub label: String,
    pub enforced: bool,
}

/// Configuration OpenID Connect (le secret n'est jamais renvoyé).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct SsoConfig {
    pub enabled: bool,
    pub label: String,
    pub issuer: String,
    pub client_id: String,
    /// En écriture seulement ; vide = conserver le secret actuel.
    pub client_secret: String,
    pub has_secret: bool,
    /// Adresse publique de Locksy, pour l'URI de redirection.
    pub public_url: String,
    /// Connexion par mot de passe seul refusée (sauf propriétaires, accès de secours).
    pub enforce: bool,
    /// Création de compte sans invitation pour toute identité SSO autorisée.
    pub auto_provision: bool,
    /// Domaines e-mail acceptés (vide = tous).
    pub allowed_domains: Vec<String>,
    /// Lecture seule : URI à déclarer chez le fournisseur d'identité.
    pub redirect_uri: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SsoRedeemRequest {
    pub ticket: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SsoRedeemResponse {
    pub email: String,
    pub name: String,
    pub registered: bool,
    pub can_register: bool,
    pub kdf: Option<KdfParams>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScimStatus {
    pub enabled: bool,
    pub created_at: Option<i64>,
    pub base_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScimTokenCreated {
    pub token: String,
    pub base_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirectoryEntry {
    pub id: String,
    pub external_id: Option<String>,
    pub email: String,
    pub display_name: String,
    pub active: bool,
    pub registered: bool,
    pub updated_at: i64,
}

// ---------------------------------------------------------------- Active Directory (LDAP)

/// Connecteur Active Directory / LDAP sur site.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct LdapConfig {
    /// Synchronisation des comptes depuis l'annuaire.
    pub enabled: bool,
    /// `ldaps://dc1.entreprise.local:636` (ou `ldap://…:389` avec STARTTLS).
    pub url: String,
    pub starttls: bool,
    /// Compte de service en lecture seule (DN ou `svc@domaine.local`).
    pub bind_dn: String,
    /// En écriture seulement ; vide = conserver le mot de passe actuel.
    pub bind_password: String,
    pub has_password: bool,
    /// Racine de recherche, par exemple `DC=entreprise,DC=local`.
    pub base_dn: String,
    /// Groupe donnant accès à Locksy (groupes imbriqués pris en compte).
    pub group_dn: String,
    pub login_attribute: String,
    pub email_attribute: String,
    /// Certificat de l'autorité qui a signé le certificat LDAPS des contrôleurs (PEM).
    pub ca_pem: String,
    pub sync_minutes: i64,
    /// Connexion avec l'identifiant et le mot de passe Windows.
    pub allow_login: bool,
    /// Connexion par mot de passe maître seul refusée (sauf propriétaires).
    pub enforce: bool,
    pub label: String,
    /// Lecture seule.
    pub last_sync: i64,
    pub last_result: String,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            starttls: false,
            bind_dn: String::new(),
            bind_password: String::new(),
            has_password: false,
            base_dn: String::new(),
            group_dn: String::new(),
            login_attribute: "sAMAccountName".into(),
            email_attribute: "mail".into(),
            ca_pem: String::new(),
            sync_minutes: 15,
            allow_login: false,
            enforce: false,
            label: "Compte Windows".into(),
            last_sync: 0,
            last_result: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LdapLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LdapLoginResponse {
    pub ticket: String,
    pub info: SsoRedeemResponse,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LdapTestResult {
    pub users: usize,
    pub sample: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LdapSyncReport {
    pub found: usize,
    pub created: usize,
    pub updated: usize,
    pub disabled: usize,
    pub enabled: usize,
    pub skipped: Vec<String>,
}

// ---------------------------------------------------------------- Réglages et préférences

/// Une clé de la politique diffusée aux clients (`/settings/policy`).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PolicyEntry {
    pub value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<serde_json::Value>,
}

/// `GET /settings/policy` (annexe A.4).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PolicyResponse {
    pub revision: i64,
    pub policy: std::collections::BTreeMap<String, PolicyEntry>,
}

/// Apparence de l'organisation, avant connexion.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PublicBranding {
    pub org_name: String,
    pub accent_color: String,
    /// `/api/branding/logo?v=<révision>`, ou absent : logo de Locksy.
    pub logo_url: Option<String>,
    pub login_message: String,
    pub support_contact: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PublicLegal {
    pub notice_url: String,
    pub privacy_url: String,
    pub accessibility_url: String,
    pub login_banner: String,
    pub charter_version: i64,
    pub dpo_contact: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PublicI18n {
    pub default_locale: String,
    pub timezone: String,
}

/// Méthodes de connexion proposées, la principale d'abord.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PublicLogin {
    pub primary_method: String,
    pub methods: Vec<String>,
    pub sso_label: Option<String>,
    pub ldap_label: Option<String>,
    /// Connexion par mot de passe seul refusée (sauf propriétaires).
    pub enforced: bool,
}

/// Politique du mot de passe maître, vérifiée par le client avant l'envoi.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PublicMasterPassword {
    pub min_length: i64,
    pub min_score: i64,
    pub forbid_identity: bool,
    pub banned_words_count: i64,
    pub banned_words: Vec<String>,
}

/// Paramètres de dérivation proposés à la création et au changement du mot
/// de passe maître.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PublicKdf {
    pub memory_mib: i64,
    pub iterations: i64,
    pub parallelism: i64,
    pub upgrade_on_login: bool,
}

/// `GET /settings/public` (annexe A.5), sans authentification.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PublicSettings {
    pub revision: i64,
    pub branding: PublicBranding,
    pub legal: PublicLegal,
    pub i18n: PublicI18n,
    pub login: PublicLogin,
    pub master_password: PublicMasterPassword,
    pub kdf: PublicKdf,
}

/// `GET /me/prefs` : document de préférences chiffré par le client (opaque).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PrefsDocument {
    pub revision: i64,
    pub cipher: String,
    pub updated_at: i64,
}

/// `PUT /me/prefs` (en-tête `If-Match` : révision connue, « 0 » à la création).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PutPrefsRequest {
    pub cipher: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct PutPrefsResponse {
    pub revision: i64,
}

/// Révisions de la politique et des préférences : le client ne recharge que
/// ce qui a changé.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct SyncRevisions {
    pub policy_revision: i64,
    pub prefs_revision: i64,
}

/// `GET /me/charter` : version de la charte exigée et version acceptée
/// (0 : aucune charte, ou jamais acceptée).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct CharterStatus {
    pub required_version: i64,
    pub accepted_version: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct AcceptCharterRequest {
    pub version: i64,
}
