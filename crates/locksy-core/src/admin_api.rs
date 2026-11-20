//! Contrat de l'API d'administration des personnes (annexes A.6 à A.9) :
//! liste unifiée des comptes et invitations, fiche, actions de masse,
//! invitations par lot, départ de l'entreprise, statistiques, journal.
//!
//! Le noyau ne fait aucune entrée-sortie : DTO, gravité des événements du
//! journal et fuseaux horaires des exports (calcul pur, testé en natif).
//!
//! Règle : aucune réponse ne porte de nom de coffre ni d'élément (ils sont
//! chiffrés et illisibles pour l'administration).

use crate::api::AuditEntry;
use serde::{Deserialize, Deserializer, Serialize};

// ------------------------------------------------------------ Personnes (A.6)

/// Paramètres de `GET /admin/people`, lus en texte puis validés par le
/// serveur (une valeur invalide donne 400 `bad_request`, pas un rejet brut).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct PeopleQuery {
    pub q: Option<String>,
    pub etat: Option<String>,
    pub role: Option<String>,
    #[serde(rename = "2fa")]
    pub twofa: Option<String>,
    pub origine: Option<String>,
    pub tri: Option<String>,
    pub page: Option<String>,
    pub par_page: Option<String>,
}

/// Valeurs acceptées par `GET /admin/people`.
pub mod people {
    pub const ETATS: [&str; 8] =
        ["tous", "actif", "desactive", "invite", "invitation_expiree", "expire", "inactif", "suppression_programmee"];
    pub const ROLES: [&str; 3] = ["owner", "admin", "user"];
    pub const TWOFA: [&str; 2] = ["oui", "non"];
    pub const ORIGINES: [&str; 5] = ["local", "sso", "ldap", "scim", "invite"];
    pub const TRIS: [&str; 10] = [
        "nom",
        "-nom",
        "email",
        "-email",
        "role",
        "-role",
        "derniere_connexion",
        "-derniere_connexion",
        "creation",
        "-creation",
    ];
    pub const PER_PAGE_DEFAULT: i64 = 25;
    pub const PER_PAGE_MAX: i64 = 100;

    /// Statut calculé correspondant à un filtre d'état (`None` : tous).
    pub fn status_for_etat(etat: &str) -> Option<&'static str> {
        Some(match etat {
            "actif" => "active",
            "desactive" => "disabled",
            "invite" => "invited",
            "invitation_expiree" => "invite_expired",
            "expire" => "expired",
            "inactif" => "inactive",
            "suppression_programmee" => "pending_deprovision",
            _ => return None,
        })
    }

    /// Ordre de tri : colonne (`nom`, `email`, `role`, `derniere_connexion`,
    /// `creation`) et sens. Le serveur le complète toujours par l'identifiant.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Sort {
        pub column: &'static str,
        pub desc: bool,
    }

    /// Paramètres validés de `GET /admin/people`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PeopleFilter {
        /// Texte cherché dans le nom et l'adresse (vide : aucun filtre).
        pub q: String,
        /// Statut calculé exigé (`None` : tous).
        pub status: Option<&'static str>,
        pub role: Option<&'static str>,
        /// Double authentification activée (comptes seulement).
        pub twofa: Option<bool>,
        pub origin: Option<&'static str>,
        pub sort: Sort,
        pub page: i64,
        pub per_page: i64,
    }

    fn pick(list: &[&'static str], v: &str, what: &str) -> Result<&'static str, String> {
        list.iter().copied().find(|x| *x == v).ok_or_else(|| format!("Valeur de « {what} » inconnue : {v}."))
    }

    fn number(v: Option<&str>, default: i64, range: std::ops::RangeInclusive<i64>, what: &str) -> Result<i64, String> {
        match v.map(str::trim).filter(|s| !s.is_empty()) {
            None => Ok(default),
            Some(s) => s
                .parse::<i64>()
                .ok()
                .filter(|n| range.contains(n))
                .ok_or_else(|| format!("« {what} » doit être un nombre entre {} et {}.", range.start(), range.end())),
        }
    }

    impl super::PeopleQuery {
        /// Valide les paramètres (message français en cas de refus : 400).
        /// Un paramètre vide vaut absent.
        pub fn parse(&self) -> Result<PeopleFilter, String> {
            let opt = |v: &Option<String>| v.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
            let status = match opt(&self.etat) {
                None => None,
                Some(e) => {
                    pick(&ETATS, &e, "état")?;
                    status_for_etat(&e)
                }
            };
            let role = opt(&self.role).map(|r| pick(&ROLES, &r, "rôle")).transpose()?;
            let twofa = opt(&self.twofa).map(|v| pick(&TWOFA, &v, "double authentification").map(|v| v == "oui")).transpose()?;
            let origin = opt(&self.origine).map(|o| pick(&ORIGINES, &o, "origine")).transpose()?;
            let tri = opt(&self.tri).map(|t| pick(&TRIS, &t, "tri")).transpose()?.unwrap_or("nom");
            let sort = match tri.strip_prefix('-') {
                Some(c) => Sort { column: pick(&TRIS, c, "tri")?, desc: true },
                None => Sort { column: tri, desc: false },
            };
            let q = opt(&self.q).unwrap_or_default();
            if q.chars().count() > 200 {
                return Err("Recherche trop longue : 200 caractères au plus.".into());
            }
            Ok(PeopleFilter {
                q,
                status,
                role,
                twofa,
                origin,
                sort,
                page: number(self.page.as_deref(), 1, 1..=1_000_000, "page")?,
                per_page: number(self.par_page.as_deref(), PER_PAGE_DEFAULT, 1..=PER_PAGE_MAX, "par_page")?,
            })
        }
    }
}

/// Compte dans la liste des personnes. `status` (calculé) ∈ active |
/// disabled | expired (fin d'accès passée) | inactive (aucune connexion
/// depuis `users.inactive_alert_days`) | pending_deprovision.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PersonUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub twofa: bool,
    /// local | sso | ldap | scim | invite
    pub origin: String,
    #[serde(default)]
    pub last_seen_at: Option<i64>,
    pub created_at: i64,
    #[serde(default)]
    pub access_until: Option<i64>,
    #[serde(default)]
    pub deprovision_at: Option<i64>,
    #[serde(default)]
    pub disabled_reason: Option<String>,
    pub is_self: bool,
}

/// Invitation en attente dans la liste des personnes (status ∈ invited |
/// invite_expired ; origin = "invite").
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PersonInvite {
    pub id: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub sent_count: i64,
    #[serde(default)]
    pub last_sent_at: Option<i64>,
    #[serde(default)]
    pub access_until: Option<i64>,
    pub origin: String,
}

/// Ligne de la liste : compte ou invitation (`kind`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum PeopleRow {
    User(PersonUser),
    Invite(PersonInvite),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeoplePage {
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub rows: Vec<PeopleRow>,
}

// ------------------------------------------------------------ Fiche personne

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersonSession {
    pub id: String,
    pub device: String,
    pub ip: String,
    pub last_seen_at: i64,
    pub created_at: i64,
    /// Session de l'administrateur qui consulte (sa propre fiche).
    pub current: bool,
}

/// Coffre d'une personne : métadonnées seulement, jamais le nom (chiffré).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersonCollection {
    pub id: String,
    /// Rôle de la personne dans le coffre : manager | editor | reader.
    pub role: String,
    pub personal: bool,
    pub members_count: i64,
    pub managers_count: i64,
    pub items_count: i64,
    pub sole_manager: bool,
    pub shared: bool,
    #[serde(default)]
    pub rotation_suggested_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersonEvent {
    pub at: i64,
    pub action: String,
    pub severity: String,
    pub target: String,
}

/// `GET /admin/users/:id` : ligne A.6 et détails.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersonDetail {
    #[serde(flatten)]
    pub person: PersonUser,
    pub sessions: Vec<PersonSession>,
    pub collections: Vec<PersonCollection>,
    pub recent_events: Vec<PersonEvent>,
    /// Codes de secours restants (comptes avec double authentification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_codes_remaining: Option<i64>,
}

/// Distingue un champ absent (`None`) d'un champ `null` (`Some(None)`).
fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// `PATCH /admin/users/:id` : champs absents inchangés ; `access_until`
/// à `null` retire la date de fin d'accès.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PersonPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub access_until: Option<Option<i64>>,
}

// ------------------------------------------------------------ Actions de masse (A.7)

pub mod bulk {
    pub const MAX_IDS: usize = 500;
    pub const ACTIONS: [&str; 5] = ["disable", "enable", "revoke_sessions", "reset_2fa", "set_role"];
    /// Raisons d'un compte ignoré.
    pub const SKIP_SELF: &str = "self";
    pub const SKIP_LAST_OWNER: &str = "last_owner";
    pub const SKIP_OWNER_ONLY: &str = "owner_only";
    pub const SKIP_NOT_FOUND: &str = "not_found";
    pub const SKIP_UNCHANGED: &str = "unchanged";
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BulkRequest {
    pub ids: Vec<String>,
    pub action: String,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub id: String,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BulkResponse {
    pub done: Vec<String>,
    pub skipped: Vec<Skipped>,
}

// ------------------------------------------------------------ Invitations (A.9)

pub mod invites {
    pub const MAX_BATCH: usize = 200;
    pub const SKIP_EXISTS: &str = "exists";
    pub const SKIP_INVITED: &str = "invited";
    pub const SKIP_DOMAIN: &str = "domain_not_allowed";
    pub const SKIP_INVALID: &str = "invalid";
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteBatchRequest {
    pub emails: Vec<String>,
    /// Noms (« Prénom Nom ») dans l'ordre des adresses ; facultatif, peut être plus court.
    #[serde(default)]
    pub names: Vec<String>,
    pub role: String,
    #[serde(default)]
    pub access_until: Option<i64>,
}

/// Invitation créée ou renvoyée : lien à transmettre, et `mailed` si
/// l'e-mail est parti en file d'envoi.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteLink {
    pub id: String,
    pub email: String,
    pub link: String,
    pub mailed: bool,
    pub expires_at: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct InviteSkipped {
    pub email: String,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct InviteBatchResponse {
    pub created: Vec<InviteLink>,
    pub skipped: Vec<InviteSkipped>,
}

/// `POST /admin/invites/:id/resend`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteResent {
    pub id: String,
    pub link: String,
    pub mailed: bool,
    pub expires_at: i64,
}

// ------------------------------------------------------------ Départ (A.8)

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OffboardUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OffboardMember {
    pub user_id: String,
    pub name: String,
    pub email: String,
    /// Rôle dans le coffre.
    pub role: String,
}

/// Coffre de la personne qui part, avec les AUTRES membres (repreneurs
/// possibles : seul un membre existant peut devenir gestionnaire).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OffboardCollection {
    pub id: String,
    pub personal: bool,
    pub items_count: i64,
    pub members: Vec<OffboardMember>,
    pub sole_manager: bool,
    pub shared: bool,
}

/// `GET /admin/users/:id/offboard-plan` (métadonnées seulement).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OffboardPlan {
    pub user: OffboardUser,
    pub sessions: i64,
    pub collections: Vec<OffboardCollection>,
    pub delete_after_days: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub collection_id: String,
    pub new_manager_id: String,
}

const fn yes() -> bool {
    true
}

/// `POST /admin/users/:id/offboard`. Désactivation, fermeture des sessions
/// et rotation conseillée sont demandées par défaut (cases cochées de
/// l'assistant) ; `delete_after_days` absent : `directory.delete_after_days`
/// (0 explicite : suppression immédiate).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OffboardRequest {
    #[serde(default = "yes")]
    pub disable: bool,
    #[serde(default = "yes")]
    pub revoke_sessions: bool,
    #[serde(default)]
    pub transfers: Vec<Transfer>,
    #[serde(default = "yes")]
    pub suggest_rotation: bool,
    #[serde(default)]
    pub delete_after_days: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Orphaned {
    pub collection_id: String,
    pub items_count: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct OffboardReport {
    pub disabled: bool,
    pub sessions_closed: i64,
    pub transferred: i64,
    /// Coffres dont la personne est le seul membre : illisibles après son
    /// départ, supprimés avec le compte.
    pub orphaned: Vec<Orphaned>,
    pub rotation_suggested: i64,
    pub shares_revoked: i64,
    #[serde(default)]
    pub deprovision_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OffboardResponse {
    pub report: OffboardReport,
    pub report_csv: String,
}

// ------------------------------------------------------------ Statistiques (A.9)

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LdapSyncSummary {
    pub at: i64,
    pub ok: bool,
    pub found: i64,
}

/// Mise en service, déduite de l'état réel.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct SetupProgress {
    pub second_owner: bool,
    pub twofa_self: bool,
    pub login_method_chosen: bool,
    pub profile_chosen: bool,
    pub invites_sent: bool,
    pub extension_seen: bool,
    pub siem_configured: bool,
}

/// Champs ajoutés à `AdminStats` (aplati) par `GET /admin/stats`. Les
/// comptes « actifs » ne sont ni désactivés ni arrivés en fin d'accès ;
/// `active_with_2fa` ≤ `active_users`.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct StatsExtra {
    pub active_with_2fa: i64,
    pub admins_without_2fa: i64,
    pub owners: i64,
    pub inactive_users: i64,
    pub pending_invites: i64,
    pub expired_invites: i64,
    pub active_share_links: i64,
    #[serde(default)]
    pub last_ldap_sync: Option<LdapSyncSummary>,
    #[serde(default)]
    pub scim_last_used_at: Option<i64>,
    #[serde(default)]
    pub last_backup_at: Option<i64>,
    pub pending_deprovision: i64,
    pub setup: SetupProgress,
}

// ------------------------------------------------------------ Journal

/// Ligne du journal avec sa gravité.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditRow {
    #[serde(flatten)]
    pub entry: AuditEntry,
    pub severity: String,
}

/// `GET /admin/audit` : `next_cursor` = `before_id` de la page suivante.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditRows {
    pub entries: Vec<AuditRow>,
    pub total: i64,
    #[serde(default)]
    pub next_cursor: Option<i64>,
}

pub const SEVERITY_INFO: &str = "info";
pub const SEVERITY_WARNING: &str = "warning";
pub const SEVERITY_CRITICAL: &str = "critical";
pub const SEVERITIES: [&str; 3] = [SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL];

/// Règle de gravité : action exacte, ou préfixe si `action` finit par un
/// point ; `details` restreint la règle à un motif exact.
#[derive(Debug, Clone, Copy)]
pub struct SeverityRule {
    pub action: &'static str,
    pub details: Option<&'static str>,
    pub severity: &'static str,
}

const fn rule(action: &'static str, severity: &'static str) -> SeverityRule {
    SeverityRule { action, details: None, severity }
}

/// Table unique des gravités (la première règle applicable l'emporte ;
/// sinon « info »). Le serveur en dérive aussi le filtre SQL du journal.
pub const SEVERITY_RULES: &[SeverityRule] = &[
    rule("settings.lowered", SEVERITY_CRITICAL),
    rule("admin.user_role", SEVERITY_CRITICAL),
    rule("audit.verify_failed", SEVERITY_CRITICAL),
    rule("ldap.sync_refused", SEVERITY_CRITICAL),
    rule("sso.discovery_blocked", SEVERITY_CRITICAL),
    // Double authentification retirée alors que l'organisation l'impose
    // (motif écrit par l'auteur de l'événement).
    SeverityRule { action: "2fa.disabled", details: Some("imposée"), severity: SEVERITY_CRITICAL },
    rule("login.failed", SEVERITY_WARNING),
    rule("login.locked", SEVERITY_WARNING),
    rule("login.refused", SEVERITY_WARNING),
    rule("ldap.login_failed", SEVERITY_WARNING),
    rule("recovery.", SEVERITY_WARNING),
    rule("2fa.recovery_code_used", SEVERITY_WARNING),
    rule("admin.user_disabled", SEVERITY_WARNING),
    rule("admin.user_deleted", SEVERITY_WARNING),
    rule("admin.2fa_reset", SEVERITY_WARNING),
    rule("admin.user_offboarded", SEVERITY_WARNING),
    rule("admin.sessions_revoked", SEVERITY_WARNING),
    rule("admin.shares_revoked", SEVERITY_WARNING),
    SeverityRule { action: "share.ended", details: Some("revoked_admin"), severity: SEVERITY_WARNING },
    rule("mail.failed", SEVERITY_WARNING),
    rule("sso.denied", SEVERITY_WARNING),
];

impl SeverityRule {
    pub fn is_prefix(&self) -> bool {
        self.action.ends_with('.')
    }

    pub fn matches(&self, action: &str, details: &str) -> bool {
        let action_ok = if self.is_prefix() { action.starts_with(self.action) } else { action == self.action };
        action_ok && self.details.is_none_or(|d| d == details)
    }
}

/// Gravité d'une action du journal, sans tenir compte du motif.
pub fn audit_severity(action: &str) -> &'static str {
    SEVERITY_RULES
        .iter()
        .find(|r| r.details.is_none() && r.matches(action, ""))
        .map(|r| r.severity)
        .unwrap_or(SEVERITY_INFO)
}

/// Gravité d'une ligne du journal (action et motif).
pub fn entry_severity(action: &str, details: &str) -> &'static str {
    SEVERITY_RULES.iter().find(|r| r.matches(action, details)).map(|r| r.severity).unwrap_or(SEVERITY_INFO)
}

/// Séparateur des exports CSV selon `audit.csv_separator`.
pub fn csv_separator(setting: &str) -> &'static str {
    match setting {
        "comma" => ",",
        "tab" => "\t",
        _ => ";",
    }
}

/// Colonnes de l'export du journal (`GET /admin/audit.csv`). Si le fuseau
/// `i18n.timezone` est inconnu de la table, la première colonne s'appelle
/// `date_locale_utc` (date en UTC).
pub const AUDIT_CSV_COLUMNS: [&str; 10] =
    ["date_locale", "date_utc", "horodatage", "utilisateur", "action", "gravite", "cible", "adresse_ip", "navigateur", "details"];

/// Colonnes du rapport d'accès d'une personne (identifiants de coffre,
/// jamais de nom).
pub const ACCESS_REPORT_COLUMNS: [&str; 7] =
    ["coffre", "role", "membres", "elements", "seul_gestionnaire", "derniere_connexion", "actions"];

// ------------------------------------------------------------ Fuseaux horaires

/// Jours depuis le 1970-01-01 d'une date civile (algorithme des jours civils).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Année civile (UTC) d'un horodatage.
fn year_of(ts: i64) -> i64 {
    let z = ts.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    yoe + era * 400 + i64::from(mp >= 10)
}

/// Dernier dimanche d'un mois, à 01:00 UTC (règle de l'Union européenne).
fn last_sunday_0100_utc(y: i64, m: i64) -> i64 {
    let first_next = if m == 12 { days_from_civil(y + 1, 1, 1) } else { days_from_civil(y, m + 1, 1) };
    let last = first_next - 1;
    // 1970-01-01 était un jeudi : (jours + 4) mod 7 = 0 le dimanche.
    let sunday = last - (last + 4).rem_euclid(7);
    sunday * 86_400 + 3600
}

/// Heure d'été de l'Union européenne en vigueur à cet instant.
pub fn eu_summer_time(ts: i64) -> bool {
    let y = year_of(ts);
    (last_sunday_0100_utc(y, 3)..last_sunday_0100_utc(y, 10)).contains(&ts)
}

/// Zones européennes à heure d'été (règles UE) : décalage d'hiver en heures.
const EU_ZONES: &[(i64, &[&str])] = &[
    (
        0,
        &[
            "Europe/London",
            "Europe/Dublin",
            "Europe/Lisbon",
            "Europe/Guernsey",
            "Europe/Isle_of_Man",
            "Europe/Jersey",
            "Atlantic/Canary",
            "Atlantic/Madeira",
            "Atlantic/Faroe",
        ],
    ),
    (
        1,
        &[
            "Europe/Paris",
            "Europe/Berlin",
            "Europe/Brussels",
            "Europe/Amsterdam",
            "Europe/Luxembourg",
            "Europe/Monaco",
            "Europe/Andorra",
            "Europe/Madrid",
            "Europe/Rome",
            "Europe/Vatican",
            "Europe/San_Marino",
            "Europe/Malta",
            "Europe/Vienna",
            "Europe/Zurich",
            "Europe/Vaduz",
            "Europe/Busingen",
            "Europe/Prague",
            "Europe/Bratislava",
            "Europe/Warsaw",
            "Europe/Budapest",
            "Europe/Ljubljana",
            "Europe/Zagreb",
            "Europe/Sarajevo",
            "Europe/Belgrade",
            "Europe/Podgorica",
            "Europe/Skopje",
            "Europe/Tirane",
            "Europe/Copenhagen",
            "Europe/Stockholm",
            "Europe/Oslo",
            "Europe/Gibraltar",
            "Africa/Ceuta",
            "Arctic/Longyearbyen",
        ],
    ),
    (
        2,
        &[
            "Europe/Athens",
            "Europe/Helsinki",
            "Europe/Mariehamn",
            "Europe/Tallinn",
            "Europe/Riga",
            "Europe/Vilnius",
            "Europe/Sofia",
            "Europe/Bucharest",
            "Europe/Kiev",
            "Europe/Kyiv",
            "Europe/Uzhgorod",
            "Europe/Zaporozhye",
            "Europe/Nicosia",
            "Asia/Nicosia",
            "Asia/Famagusta",
        ],
    ),
];

/// Zones sans heure d'été : décalage fixe en minutes (outre-mer français et
/// zones courantes).
const FIXED_ZONES: &[(i64, &[&str])] = &[
    (-600, &["Pacific/Tahiti"]),
    (-570, &["Pacific/Marquesas"]),
    (-540, &["Pacific/Gambier"]),
    (-300, &["America/Bogota", "America/Lima", "America/Panama", "America/Cancun"]),
    (
        -240,
        &[
            "America/Guadeloupe",
            "America/Martinique",
            "America/St_Barthelemy",
            "America/Marigot",
            "America/Puerto_Rico",
            "America/Caracas",
        ],
    ),
    (-180, &["America/Cayenne", "America/Sao_Paulo", "America/Argentina/Buenos_Aires", "America/Montevideo"]),
    (0, &["Africa/Abidjan", "Africa/Dakar", "Africa/Bamako", "Africa/Conakry", "Atlantic/Reykjavik"]),
    (60, &["Africa/Algiers", "Africa/Tunis", "Africa/Lagos", "Africa/Douala", "Africa/Kinshasa"]),
    (120, &["Africa/Johannesburg", "Africa/Kigali", "Africa/Lubumbashi", "Europe/Kaliningrad"]),
    (
        180,
        &[
            "Indian/Mayotte",
            "Indian/Comoro",
            "Africa/Nairobi",
            "Africa/Djibouti",
            "Asia/Riyadh",
            "Asia/Qatar",
            "Europe/Moscow",
            "Europe/Minsk",
            "Europe/Istanbul",
            "Europe/Simferopol",
            "Europe/Volgograd",
            "Europe/Kirov",
        ],
    ),
    (240, &["Indian/Reunion", "Indian/Mauritius", "Asia/Dubai", "Europe/Samara"]),
    (300, &["Indian/Kerguelen", "Asia/Karachi", "Asia/Tashkent"]),
    (330, &["Asia/Kolkata", "Asia/Calcutta"]),
    (420, &["Asia/Bangkok", "Asia/Ho_Chi_Minh", "Asia/Jakarta"]),
    (480, &["Asia/Shanghai", "Asia/Hong_Kong", "Asia/Singapore", "Asia/Taipei", "Australia/Perth"]),
    (540, &["Asia/Tokyo", "Asia/Seoul"]),
    (660, &["Pacific/Noumea"]),
    (720, &["Pacific/Wallis"]),
];

/// Décalage (secondes, à ajouter à l'heure UTC) du fuseau `tz` à l'instant
/// `ts`. `None` : fuseau inconnu de la table (l'appelant date en UTC).
///
/// Sans base de fuseaux (aucune dépendance) : UTC, `Etc/GMT±N` (signe
/// POSIX inversé : `Etc/GMT-1` = UTC+1), Europe avec les règles UE (dernier
/// dimanche de mars et d'octobre à 01:00 UTC), zones sans heure d'été.
pub fn tz_offset(tz: &str, ts: i64) -> Option<i64> {
    let tz = tz.trim();
    if matches!(tz, "UTC" | "Etc/UTC" | "GMT" | "Etc/GMT" | "Etc/UCT" | "UCT" | "Etc/Zulu" | "Zulu" | "Etc/Universal") {
        return Some(0);
    }
    if let Some(n) = tz.strip_prefix("Etc/GMT") {
        let (sign, digits) = match n.as_bytes().first() {
            Some(b'+') => (-1, &n[1..]),
            Some(b'-') => (1, &n[1..]),
            _ => return None,
        };
        if digits.is_empty() || digits.len() > 2 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let h: i64 = digits.parse().ok()?;
        let ok = if sign < 0 { h <= 12 } else { h <= 14 };
        return ok.then_some(sign * h * 3600);
    }
    if let Some((base, _)) = EU_ZONES.iter().find(|(_, zones)| zones.contains(&tz)) {
        let summer = i64::from(eu_summer_time(ts));
        return Some((base + summer) * 3600);
    }
    FIXED_ZONES.iter().find(|(_, zones)| zones.contains(&tz)).map(|(m, _)| m * 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gravite_critique() {
        for a in ["settings.lowered", "admin.user_role", "audit.verify_failed", "ldap.sync_refused", "sso.discovery_blocked"] {
            assert_eq!(audit_severity(a), "critical", "{a}");
            assert_eq!(entry_severity(a, "peu importe"), "critical", "{a}");
        }
        // Retrait imposé de la 2FA : motif « imposée » seulement.
        assert_eq!(entry_severity("2fa.disabled", "imposée"), "critical");
        assert_eq!(entry_severity("2fa.disabled", ""), "info");
        assert_eq!(audit_severity("2fa.disabled"), "info");
    }

    #[test]
    fn gravite_attention() {
        for a in [
            "login.failed",
            "login.locked",
            "login.refused",
            "ldap.login_failed",
            "recovery.started",
            "recovery.completed",
            "2fa.recovery_code_used",
            "admin.user_disabled",
            "admin.user_deleted",
            "admin.2fa_reset",
            "admin.user_offboarded",
            "admin.sessions_revoked",
            "admin.shares_revoked",
            "mail.failed",
            "sso.denied",
        ] {
            assert_eq!(audit_severity(a), "warning", "{a}");
        }
        assert_eq!(entry_severity("share.ended", "revoked_admin"), "warning");
        assert_eq!(entry_severity("share.ended", "expired"), "info");
    }

    #[test]
    fn gravite_information_par_defaut() {
        for a in ["login.success", "item.created", "admin.user_updated", "recovery", "settingsXlowered", "", "admin.user_roles"] {
            assert_eq!(audit_severity(a), "info", "{a}");
        }
        assert!(SEVERITY_RULES.iter().all(|r| SEVERITIES.contains(&r.severity)));
    }

    #[test]
    fn separateurs_csv() {
        assert_eq!(csv_separator("semicolon"), ";");
        assert_eq!(csv_separator("comma"), ",");
        assert_eq!(csv_separator("tab"), "\t");
        assert_eq!(csv_separator("inconnu"), ";");
    }

    #[test]
    fn jours_civils() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 11, 18), 20_775);
        for ts in [0_i64, 951_782_400, 1_700_000_000, 1_798_761_599, 1_798_761_600] {
            let d = ts.div_euclid(86_400);
            assert_eq!(year_of(ts), year_of(d * 86_400), "{ts}");
        }
        assert_eq!(year_of(1_798_761_599), 2026);
        assert_eq!(year_of(1_798_761_600), 2027);
    }

    #[test]
    fn heure_d_ete_europeenne() {
        // 2026 : du 29 mars 01:00 UTC au 25 octobre 01:00 UTC.
        let debut = days_from_civil(2026, 3, 29) * 86_400 + 3600;
        let fin = days_from_civil(2026, 10, 25) * 86_400 + 3600;
        assert!(!eu_summer_time(debut - 1));
        assert!(eu_summer_time(debut));
        assert!(eu_summer_time(fin - 1));
        assert!(!eu_summer_time(fin));
        assert_eq!(tz_offset("Europe/Paris", debut - 1), Some(3600));
        assert_eq!(tz_offset("Europe/Paris", debut), Some(7200));
        assert_eq!(tz_offset("Europe/Paris", fin), Some(3600));
        assert_eq!(tz_offset("Europe/London", debut), Some(3600));
        assert_eq!(tz_offset("Europe/Athens", debut), Some(3 * 3600));
        // 2024 : 31 mars et 27 octobre.
        assert!(eu_summer_time(days_from_civil(2024, 3, 31) * 86_400 + 3600));
        assert!(!eu_summer_time(days_from_civil(2024, 10, 27) * 86_400 + 3600));
    }

    #[test]
    fn fuseaux_fixes_et_etc() {
        assert_eq!(tz_offset("UTC", 0), Some(0));
        assert_eq!(tz_offset("Etc/GMT-1", 0), Some(3600));
        assert_eq!(tz_offset("Etc/GMT+5", 0), Some(-5 * 3600));
        assert_eq!(tz_offset("Etc/GMT-14", 0), Some(14 * 3600));
        assert_eq!(tz_offset("Etc/GMT+13", 0), None);
        assert_eq!(tz_offset("Etc/GMT+", 0), None);
        assert_eq!(tz_offset("Etc/GMTx", 0), None);
        assert_eq!(tz_offset("Etc/GMT+-5", 0), None);
        assert_eq!(tz_offset("Indian/Reunion", 0), Some(4 * 3600));
        assert_eq!(tz_offset("America/Martinique", 0), Some(-4 * 3600));
        assert_eq!(tz_offset("Pacific/Marquesas", 0), Some(-(9 * 3600 + 1800)));
        assert_eq!(tz_offset("Pacific/Noumea", 1_700_000_000), Some(11 * 3600));
        assert_eq!(tz_offset("America/New_York", 0), None);
        assert_eq!(tz_offset("", 0), None);
    }

    #[test]
    fn lignes_de_personnes_taguees() {
        let row = PeopleRow::Invite(PersonInvite {
            id: "i".into(),
            email: "a@exemple.fr".into(),
            role: "user".into(),
            status: "invited".into(),
            expires_at: 10,
            created_at: 1,
            sent_count: 1,
            last_sent_at: None,
            access_until: None,
            origin: "invite".into(),
        });
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["kind"], "invite");
        assert_eq!(v["origin"], "invite");
        assert_eq!(serde_json::from_value::<PeopleRow>(v).unwrap(), row);
    }

    #[test]
    fn correctif_distingue_absent_et_null() {
        let p: PersonPatch = serde_json::from_value(json!({ "name": "Léa" })).unwrap();
        assert_eq!(p.access_until, None);
        let p: PersonPatch = serde_json::from_value(json!({ "access_until": null })).unwrap();
        assert_eq!(p.access_until, Some(None));
        let p: PersonPatch = serde_json::from_value(json!({ "access_until": 42 })).unwrap();
        assert_eq!(p.access_until, Some(Some(42)));
    }

    fn query(v: serde_json::Value) -> PeopleQuery {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn parametres_des_personnes() {
        // Valeurs par défaut.
        let f = query(json!({})).parse().unwrap();
        assert_eq!(f.sort, people::Sort { column: "nom", desc: false });
        assert_eq!((f.page, f.per_page), (1, 25));
        assert_eq!((f.status, f.role, f.twofa, f.origin), (None, None, None, None));
        assert!(f.q.is_empty());
        // Paramètres vides : absents.
        let f = query(json!({ "etat": "", "tri": " ", "page": "" })).parse().unwrap();
        assert_eq!((f.status, f.sort.column, f.page), (None, "nom", 1));
        // Valeurs reconnues.
        let f = query(json!({
            "q": " Léa ", "etat": "invitation_expiree", "role": "admin", "2fa": "non",
            "origine": "ldap", "tri": "-derniere_connexion", "page": "3", "par_page": "100"
        }))
        .parse()
        .unwrap();
        assert_eq!(f.q, "Léa");
        assert_eq!(f.status, Some("invite_expired"));
        assert_eq!((f.role, f.twofa, f.origin), (Some("admin"), Some(false), Some("ldap")));
        assert_eq!(f.sort, people::Sort { column: "derniere_connexion", desc: true });
        assert_eq!((f.page, f.per_page), (3, 100));
        assert_eq!(query(json!({ "etat": "tous" })).parse().unwrap().status, None);
        assert_eq!(query(json!({ "2fa": "oui" })).parse().unwrap().twofa, Some(true));
        // Refus (message français).
        for bad in [
            json!({ "etat": "perdu" }),
            json!({ "role": "Owner" }),
            json!({ "2fa": "1" }),
            json!({ "origine": "ad" }),
            json!({ "tri": "--nom" }),
            json!({ "tri": "taille" }),
            json!({ "page": "0" }),
            json!({ "page": "x" }),
            json!({ "par_page": "101" }),
            json!({ "par_page": "0" }),
            json!({ "q": "x".repeat(201) }),
        ] {
            let e = query(bad.clone()).parse().unwrap_err();
            assert!(!e.is_empty(), "{bad}");
        }
    }

    #[test]
    fn colonnes_des_exports() {
        assert_eq!(AUDIT_CSV_COLUMNS.join(";"), "date_locale;date_utc;horodatage;utilisateur;action;gravite;cible;adresse_ip;navigateur;details");
        assert_eq!(ACCESS_REPORT_COLUMNS.join(";"), "coffre;role;membres;elements;seul_gestionnaire;derniere_connexion;actions");
    }

    #[test]
    fn depart_coche_par_defaut() {
        let r: OffboardRequest = serde_json::from_value(json!({})).unwrap();
        assert!(r.disable && r.revoke_sessions && r.suggest_rotation);
        assert!(r.transfers.is_empty() && r.delete_after_days.is_none());
        let q: PeopleQuery = serde_json::from_value(json!({ "2fa": "oui" })).unwrap();
        assert_eq!(q.twofa.as_deref(), Some("oui"));
        assert_eq!(people::status_for_etat("inactif"), Some("inactive"));
        assert_eq!(people::status_for_etat("tous"), None);
    }
}
