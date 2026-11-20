//! Registre unique des réglages de l'organisation.
//!
//! Chaque réglage modifiable par un propriétaire ou un administrateur est
//! décrit ici une seule fois : type, bornes, valeur par défaut, portée
//! (serveur, politique diffusée aux clients, page publique), sens de
//! sécurité, section d'affichage. Le serveur valide, stocke, journalise et
//! diffuse les réglages à partir de ce registre ; aucune borne n'existe
//! ailleurs.
//!
//! Précédence côté serveur : valeur verrouillée par l'hébergeur
//! (`LOCKSY_SETTINGS_FILE`, `LOCKSY_SYSLOG`) > valeur de l'organisation >
//! défaut du registre, le tout borné par les plafonds de l'hébergeur.
//!
//! Ce module compile aussi pour wasm32 : ni horloge, ni aléa, ni E/S.
//! L'heure courante est toujours fournie par l'appelant (`Ctx::now`).
//!
//! Libellés : `design/i18n/fr/settings.json` (`settings.<clé>.label`,
//! `.help`, `.unit`, `.synonyms`, `.value.<valeur en minuscules>`).

use crate::api::roles;
use base64::Engine as _;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Version du schéma du registre (1 = les 5 champs historiques d'`OrgSettings`).
pub const SCHEMA_VERSION: u32 = 2;

/// Couleur d'accent de Locksy : avec elle, les clients gardent leurs propres
/// teintes claire et sombre (jetons de design). Une couleur d'organisation,
/// elle, remplace l'accent dans les deux thèmes et doit donc y être lisible.
pub const DEFAULT_ACCENT: &str = "#0d6b64";
/// Surfaces des thèmes clair et sombre (`design/tokens.json`).
pub const SURFACE_LIGHT: &str = "#ffffff";
pub const SURFACE_DARK: &str = "#121922";
/// Textes possibles sur l'accent : blanc ou presque noir, le plus lisible.
const ON_ACCENT_LIGHT: &str = "#ffffff";
const ON_ACCENT_DARK: &str = "#0b1a17";

/// Durée de validité d'un test de connexion d'entreprise pour imposer la méthode.
pub const TEST_VALIDITY_SECS: i64 = 86_400;

// ------------------------------------------------------------ Types du registre

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unit {
    Seconds,
    Minutes,
    Hours,
    Days,
    Mib,
    Count,
    Percent,
}

/// Nature d'un réglage, qui décide du contrôle de saisie et de la validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bool,
    Int { min: i64, max: i64, unit: Unit },
    /// Valeurs permises ; pour un réglage à sens de sécurité, de la moins
    /// sûre à la plus sûre.
    Enum(&'static [&'static str]),
    Text { max_len: usize, multiline: bool },
    Url { https_only: bool },
    Email,
    /// `#rrggbb`.
    Color,
    Cidrs,
    Domains,
    Emails,
    Roles,
    Words { max: usize },
    /// Chiffré par le serveur, jamais renvoyé.
    Secret,
    /// PNG ou WebP en URL `data:` encodée en base64.
    Image { max_bytes: usize },
}

impl Kind {
    pub fn type_name(&self) -> &'static str {
        match self {
            Kind::Bool => "bool",
            Kind::Int { .. } => "int",
            Kind::Enum(_) => "enum",
            Kind::Text { .. } => "text",
            Kind::Url { .. } => "url",
            Kind::Email => "email",
            Kind::Color => "color",
            Kind::Cidrs => "cidrs",
            Kind::Domains => "domains",
            Kind::Emails => "emails",
            Kind::Roles => "roles",
            Kind::Words { .. } => "words",
            Kind::Secret => "secret",
            Kind::Image { .. } => "image",
        }
    }

    fn is_list(&self) -> bool {
        matches!(self, Kind::Cidrs | Kind::Domains | Kind::Emails | Kind::Roles | Kind::Words { .. })
    }
}

/// Où la valeur est diffusée.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Serveur seulement.
    Org,
    /// Politique des clients (`/settings/policy`, utilisateur connecté).
    Policy,
    /// Page publique (`/settings/public`, avant connexion).
    Public,
}

/// Sens de sécurité, pour détecter un abaissement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Safer {
    /// Plus haut (ou vrai, ou plus d'éléments) = plus sûr.
    #[serde(rename = "higher")]
    Higher,
    /// Plus bas (ou faux, ou moins d'éléments) = plus sûr.
    #[serde(rename = "lower")]
    Lower,
    #[serde(rename = "na")]
    NotApplicable,
}

/// Sections de l'écran Réglages, dans l'ordre d'affichage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Section {
    Login,
    Sessions,
    Passwords,
    Sharing,
    Clients,
    Retention,
    Branding,
    Mail,
    Advanced,
    Identity,
}

impl Section {
    pub const ALL: [Section; 10] = [
        Section::Login,
        Section::Sessions,
        Section::Passwords,
        Section::Sharing,
        Section::Clients,
        Section::Retention,
        Section::Branding,
        Section::Mail,
        Section::Advanced,
        Section::Identity,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Section::Login => "login",
            Section::Sessions => "sessions",
            Section::Passwords => "passwords",
            Section::Sharing => "sharing",
            Section::Clients => "clients",
            Section::Retention => "retention",
            Section::Branding => "branding",
            Section::Mail => "mail",
            Section::Advanced => "advanced",
            Section::Identity => "identity",
        }
    }
}

/// Liberté laissée aux utilisateurs pour un réglage diffusé aux clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// L'utilisateur choisit dans les bornes du registre.
    Free,
    /// Valeur proposée ; l'utilisateur choisit entre `min` et `max`.
    Default,
    /// Valeur imposée.
    Enforced,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Free => "free",
            Mode::Default => "default",
            Mode::Enforced => "enforced",
        }
    }

    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "free" => Some(Mode::Free),
            "default" => Some(Mode::Default),
            "enforced" => Some(Mode::Enforced),
            _ => None,
        }
    }
}

/// Origine de la valeur effective.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Default,
    Org,
    HostLocked,
}

/// Valeur par défaut, constante (le registre est une table statique).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Def {
    Bool(bool),
    Int(i64),
    Str(&'static str),
    List(&'static [&'static str]),
}

impl Def {
    pub fn to_value(&self) -> Value {
        match self {
            Def::Bool(b) => Value::Bool(*b),
            Def::Int(i) => json!(i),
            Def::Str(s) => Value::String((*s).to_string()),
            Def::List(l) => Value::Array(l.iter().map(|s| Value::String((*s).to_string())).collect()),
        }
    }
}

/// Contrôle propre à une clé, appliqué après celui de son type.
pub type Check = fn(&Value) -> Result<(), FieldError>;

/// Description d'un réglage.
#[derive(Clone, Copy, Debug)]
pub struct SettingDef {
    pub key: &'static str,
    pub kind: Kind,
    pub default: Def,
    pub default_mode: Option<Mode>,
    /// Bornes proposées par défaut aux utilisateurs (mode `default`).
    pub default_min: Option<i64>,
    pub default_max: Option<i64>,
    pub scope: Scope,
    pub owner_only: bool,
    /// Diffusé dans `/settings/policy`.
    pub client: bool,
    /// Accepte les modes free / default / enforced.
    pub modes: bool,
    pub safer: Safer,
    /// Variable de l'hébergeur qui plafonne la valeur.
    pub host_cap: Option<&'static str>,
    pub section: Section,
    /// Ordre d'affichage dans la section (les plus utiles d'abord).
    pub order: u16,
    /// Replié sous « Réglages avancés ».
    pub advanced: bool,
    /// Synonymes de repli pour la recherche (ceux affichés viennent d'i18n).
    pub synonyms: &'static [&'static str],
    /// Version du registre qui a introduit la clé.
    pub since: u32,
    /// Valeurs proposées par le sélecteur de durée.
    pub presets: &'static [i64],
    pub check: Option<Check>,
}

const fn s(key: &'static str, section: Section, order: u16, kind: Kind, default: Def) -> SettingDef {
    SettingDef {
        key,
        kind,
        default,
        default_mode: None,
        default_min: None,
        default_max: None,
        scope: Scope::Org,
        owner_only: false,
        client: false,
        modes: false,
        safer: Safer::NotApplicable,
        host_cap: None,
        section,
        order,
        advanced: false,
        synonyms: &[],
        since: SCHEMA_VERSION,
        presets: &[],
        check: None,
    }
}

const fn int(min: i64, max: i64, unit: Unit) -> Kind {
    Kind::Int { min, max, unit }
}

const fn text(max_len: usize) -> Kind {
    Kind::Text { max_len, multiline: false }
}

const fn multiline(max_len: usize) -> Kind {
    Kind::Text { max_len, multiline: true }
}

impl SettingDef {
    const fn owner(mut self) -> Self {
        self.owner_only = true;
        self
    }
    const fn clients(mut self) -> Self {
        self.client = true;
        self.scope = Scope::Policy;
        self
    }
    const fn public(mut self) -> Self {
        self.scope = Scope::Public;
        self
    }
    const fn modal(mut self, mode: Mode) -> Self {
        self.modes = true;
        self.default_mode = Some(mode);
        self
    }
    const fn admin_max(mut self, max: i64) -> Self {
        self.default_max = Some(max);
        self
    }
    const fn up(mut self) -> Self {
        self.safer = Safer::Higher;
        self
    }
    const fn down(mut self) -> Self {
        self.safer = Safer::Lower;
        self
    }
    const fn adv(mut self) -> Self {
        self.advanced = true;
        self
    }
    const fn pre(mut self, presets: &'static [i64]) -> Self {
        self.presets = presets;
        self
    }
    const fn syn(mut self, synonyms: &'static [&'static str]) -> Self {
        self.synonyms = synonyms;
        self
    }
    const fn capped(mut self, var: &'static str) -> Self {
        self.host_cap = Some(var);
        self
    }
    const fn checked(mut self, f: Check) -> Self {
        self.check = Some(f);
        self
    }
    const fn v1(mut self) -> Self {
        self.since = 1;
        self
    }

    pub fn default_value(&self) -> Value {
        self.default.to_value()
    }

    /// Valeur par défaut complète (mode et bornes compris).
    pub fn default_stored(&self) -> StoredValue {
        StoredValue {
            value: self.default_value(),
            mode: if self.modes { self.default_mode } else { None },
            min: self.default_min.map(|v| json!(v)),
            max: self.default_max.map(|v| json!(v)),
        }
    }

    /// Bornes du type, plafond de l'hébergeur compris.
    pub fn int_bounds(&self, host: &HostCaps) -> Option<(i64, i64)> {
        match self.kind {
            Kind::Int { min, max, .. } => {
                let cap = host.caps.get(self.key).map(|(c, _)| *c).unwrap_or(max);
                Some((min, max.min(cap).max(min)))
            }
            _ => None,
        }
    }

    pub fn is_secret(&self) -> bool {
        matches!(self.kind, Kind::Secret)
    }
}

// ------------------------------------------------------------ Le registre

const DURATIONS_MIN: &[i64] = &[5, 10, 15, 30, 60, 120, 240, 480, 1440];
const AUTOLOCK_MIN: &[i64] = &[1, 5, 10, 15, 30, 60, 240];
const SHARE_MIN: &[i64] = &[5, 15, 60, 240, 1440, 4320, 10_080, 43_200];
const HOURS: &[i64] = &[1, 4, 8, 12, 24, 72, 168, 720];
const CLIPBOARD_S: &[i64] = &[10, 20, 30, 60, 120, 300];
const DAYS_SHORT: &[i64] = &[1, 3, 7, 14, 30];
const DAYS_MEDIUM: &[i64] = &[7, 14, 30, 60, 90, 180, 365];
const DAYS_LONG: &[i64] = &[30, 90, 180, 365, 730, 1095, 1825, 3650];
const AGE_DAYS: &[i64] = &[30, 90, 180, 365, 730, 1825];
const ALERT_DAYS: &[i64] = &[30, 60, 90, 180, 365, 730];
const INACTIVE_DAYS: &[i64] = &[0, 30, 60, 90, 180, 365, 730];
const GRACE_DAYS: &[i64] = &[0, 1, 3, 7, 14, 30];
const BASE_DELAY_S: &[i64] = &[5, 15, 30, 60, 120, 300, 600];
const MAX_DELAY_S: &[i64] = &[60, 300, 900, 3600, 21_600, 86_400];

use Def::{Bool as B, Int as I, List as L, Str as S};
use Section as Sec;

/// Tous les réglages de la version 2 du registre.
pub static REGISTRY: &[SettingDef] = &[
    // ---------------------------------------------------- Sécurité de connexion
    s("twofa.required", Sec::Login, 10, Kind::Bool, B(false))
        .owner()
        .up()
        .syn(&["2fa", "double authentification", "mfa", "totp"]),
    s("twofa.required_roles", Sec::Login, 20, Kind::Roles, L(&[]))
        .owner()
        .up()
        .syn(&["2fa", "double authentification", "rôles"]),
    s("twofa.grace_days", Sec::Login, 30, int(0, 30, Unit::Days), I(7)).down().pre(GRACE_DAYS).syn(&["délai", "grâce"]),
    s("auth.primary_method", Sec::Login, 40, Kind::Enum(&["password", "ldap", "sso"]), S("password"))
        .public()
        .syn(&["connexion", "méthode"]),
    s("access.allowed_email_domains", Sec::Login, 50, Kind::Domains, L(&[])).up().syn(&["domaine", "e-mail", "invitation"]),
    s("access.ip_allowlist", Sec::Login, 60, Kind::Cidrs, L(&[]))
        .owner()
        .up()
        .adv()
        .syn(&["adresse ip", "réseau", "liste blanche", "filtrage"]),
    s("access.ip_rescue", Sec::Login, 70, Kind::Cidrs, L(&[])).owner().down().adv().syn(&["secours", "adresse ip"]),
    s("session.max_per_user", Sec::Login, 80, int(0, 100, Unit::Count), I(0)).down().adv().syn(&["appareils", "sessions"]),
    s("lockout.pair_threshold", Sec::Login, 90, int(3, 20, Unit::Count), I(5))
        .owner()
        .down()
        .adv()
        .syn(&["blocage", "tentatives", "force brute"]),
    s("lockout.account_threshold", Sec::Login, 100, int(10, 1000, Unit::Count), I(50))
        .owner()
        .down()
        .adv()
        .syn(&["blocage", "tentatives"]),
    s("lockout.base_delay_seconds", Sec::Login, 110, int(5, 600, Unit::Seconds), I(30)).up().adv().pre(BASE_DELAY_S),
    s("lockout.max_delay_seconds", Sec::Login, 120, int(60, 86_400, Unit::Seconds), I(3600)).up().adv().pre(MAX_DELAY_S),
    // ---------------------------------------------------- Sessions et verrouillage
    s("session.idle_minutes", Sec::Sessions, 10, int(5, 1440, Unit::Minutes), I(60))
        .down()
        .v1()
        .pre(DURATIONS_MIN)
        .syn(&["inactivité", "déconnexion"]),
    s("session.max_hours", Sec::Sessions, 20, int(1, 720, Unit::Hours), I(12)).down().v1().pre(HOURS).syn(&["durée", "session"]),
    s("client.autolock_minutes", Sec::Sessions, 30, int(1, 1440, Unit::Minutes), I(10))
        .clients()
        .modal(Mode::Default)
        .down()
        .pre(AUTOLOCK_MIN)
        .syn(&["verrou", "inactivité", "veille"]),
    s("client.autolock_allow_never", Sec::Sessions, 40, Kind::Bool, B(true)).clients().down().syn(&["jamais", "verrou"]),
    s("client.lock_on_hide", Sec::Sessions, 50, Kind::Bool, B(false)).clients().modal(Mode::Default).up().syn(&["onglet", "verrou"]),
    s("client.lock_on_os_lock", Sec::Sessions, 60, Kind::Bool, B(true))
        .clients()
        .modal(Mode::Default)
        .up()
        .syn(&["windows", "verrou", "session"]),
    s("client.clipboard_clear_seconds", Sec::Sessions, 70, int(5, 600, Unit::Seconds), I(30))
        .clients()
        .modal(Mode::Default)
        .admin_max(120)
        .down()
        .pre(CLIPBOARD_S)
        .syn(&["presse-papiers", "copie"]),
    s("client.remember_email", Sec::Sessions, 80, Kind::Bool, B(true)).clients().down().syn(&["e-mail", "mémoriser"]),
    s("client.single_key_shortcuts", Sec::Sessions, 90, Kind::Bool, B(true))
        .clients()
        .modal(Mode::Default)
        .syn(&["raccourcis", "clavier"]),
    // ---------------------------------------------------- Mots de passe
    s("master_password.min_length", Sec::Passwords, 10, int(10, 64, Unit::Count), I(12))
        .public()
        .up()
        .syn(&["mot de passe maître", "longueur"]),
    s("master_password.min_score", Sec::Passwords, 20, int(2, 4, Unit::Count), I(3))
        .public()
        .up()
        .syn(&["robustesse", "mot de passe maître"]),
    s("master_password.forbid_identity", Sec::Passwords, 30, Kind::Bool, B(true)).public().up().syn(&["nom", "e-mail"]),
    s("master_password.banned_words", Sec::Passwords, 40, Kind::Words { max: 500 }, L(&[]))
        .public()
        .up()
        .adv()
        .syn(&["mots interdits", "liste noire"]),
    s("generator.length", Sec::Passwords, 50, int(8, 128, Unit::Count), I(20))
        .clients()
        .modal(Mode::Default)
        .up()
        .syn(&["générateur", "longueur"]),
    s("generator.min_length", Sec::Passwords, 60, int(8, 64, Unit::Count), I(12)).clients().up().syn(&["générateur"]),
    s("generator.require_classes", Sec::Passwords, 70, int(1, 4, Unit::Count), I(3))
        .clients()
        .up()
        .syn(&["chiffres", "symboles", "majuscules"]),
    s("generator.avoid_ambiguous", Sec::Passwords, 80, Kind::Bool, B(true)).clients().modal(Mode::Default).syn(&["ambigus"]),
    s("generator.symbols", Sec::Passwords, 90, text(40), S("!@#$%^&*()-_=+[]{};:,.?/~"))
        .clients()
        .adv()
        .checked(check_symbols),
    s("generator.words", Sec::Passwords, 100, int(3, 12, Unit::Count), I(5)).clients().up().syn(&["phrase de passe", "mots"]),
    s("generator.min_words", Sec::Passwords, 110, int(3, 12, Unit::Count), I(4)).clients().up().syn(&["phrase de passe"]),
    s("passwords.unique_across_users", Sec::Passwords, 115, Kind::Bool, B(false))
        .clients()
        .up()
        .syn(&["unique", "réutilisation", "collègues", "doublon"]),
    s("health.weak_below_score", Sec::Passwords, 120, int(1, 4, Unit::Count), I(3)).clients().up().syn(&["bilan", "faible"]),
    s("health.max_password_age_days", Sec::Passwords, 130, int(30, 1825, Unit::Days), I(365))
        .clients()
        .down()
        .pre(AGE_DAYS)
        .syn(&["bilan", "ancien"]),
    // ---------------------------------------------------- Partage et coffres
    s("share.enabled", Sec::Sharing, 10, Kind::Bool, B(true)).clients().syn(&["lien", "partage"]),
    s("share.max_expiry_minutes", Sec::Sharing, 20, int(5, 43_200, Unit::Minutes), I(43_200))
        .clients()
        .down()
        .pre(SHARE_MIN)
        .syn(&["lien", "expiration"]),
    s("share.default_expiry_minutes", Sec::Sharing, 30, int(5, 43_200, Unit::Minutes), I(1440))
        .clients()
        .modal(Mode::Default)
        .down()
        .pre(SHARE_MIN)
        .syn(&["lien", "expiration"]),
    s("share.max_views", Sec::Sharing, 40, int(1, 100, Unit::Count), I(100)).clients().down().syn(&["lien", "consultations"]),
    s("share.default_views", Sec::Sharing, 50, int(1, 100, Unit::Count), I(1))
        .clients()
        .modal(Mode::Default)
        .down()
        .syn(&["lien", "consultations"]),
    s("share.max_per_hour", Sec::Sharing, 60, int(1, 1000, Unit::Count), I(60)).down().adv().syn(&["lien", "limite"]),
    s("vault.users_can_create_shared", Sec::Sharing, 70, Kind::Bool, B(true)).clients().syn(&["coffre partagé", "création"]),
    s("vault.rotate_on_member_removal", Sec::Sharing, 80, Kind::Enum(&["off", "suggest", "force"]), S("suggest"))
        .clients()
        .up()
        .syn(&["rotation", "clé", "départ"]),
    s("vault.personal_enabled", Sec::Sharing, 90, Kind::Bool, B(true)).owner().clients().syn(&["coffre personnel"]),
    s("attachment.enabled", Sec::Sharing, 100, Kind::Bool, B(true)).clients().syn(&["pièce jointe", "fichier"]),
    s("attachment.max_file_mib", Sec::Sharing, 110, int(1, 15, Unit::Mib), I(10))
        .clients()
        .capped("LOCKSY_MAX_ATTACHMENT_MIB")
        .syn(&["pièce jointe", "taille"]),
    s("attachment.max_per_item", Sec::Sharing, 120, int(1, 100, Unit::Count), I(20)).clients().syn(&["pièce jointe"]),
    s("attachment.quota_user_mib", Sec::Sharing, 130, int(1, 102_400, Unit::Mib), I(1024)).syn(&["quota", "espace"]),
    s("attachment.quota_total_mib", Sec::Sharing, 140, int(1, 1_048_576, Unit::Mib), I(20_480)).syn(&["quota", "espace"]),
    s("export.enabled", Sec::Sharing, 150, Kind::Bool, B(true)).clients().syn(&["export", "sauvegarde"]),
    s("export.min_password_length", Sec::Sharing, 160, int(12, 64, Unit::Count), I(12)).clients().up().syn(&["export"]),
    s("import.max_file_mib", Sec::Sharing, 170, int(1, 200, Unit::Mib), I(20)).clients().syn(&["import"]),
    // ---------------------------------------------------- Applications et extension
    s("extension.http_fill", Sec::Clients, 10, Kind::Enum(&["warn", "block"]), S("block"))
        .clients()
        .up()
        .syn(&["http", "remplissage", "non sécurisé"]),
    s("extension.allow_mismatch_fill", Sec::Clients, 20, Kind::Bool, B(false)).clients().down().syn(&["remplissage", "site"]),
    s("extension.offer_save", Sec::Clients, 30, Kind::Bool, B(true)).clients().modal(Mode::Default).syn(&["enregistrer"]),
    s("extension.autofill", Sec::Clients, 35, Kind::Bool, B(false)).clients().modal(Mode::Default).syn(&["remplissage", "automatique"]),
    s("extension.copy_totp_after_fill", Sec::Clients, 40, Kind::Bool, B(true))
        .clients()
        .modal(Mode::Default)
        .syn(&["code", "totp"]),
    s("extension.excluded_sites", Sec::Clients, 50, Kind::Domains, L(&[])).clients().syn(&["sites", "exclus"]),
    s("extension.allowed_ids", Sec::Clients, 60, Kind::Words { max: 50 }, L(&[]))
        .down()
        .checked(check_extension_ids)
        .syn(&["extension", "identifiant"]),
    // ---------------------------------------------------- Conservation des données
    s("retention.trash_days", Sec::Retention, 10, int(1, 365, Unit::Days), I(30))
        .clients()
        .v1()
        .pre(DAYS_MEDIUM)
        .syn(&["corbeille", "suppression"]),
    s("retention.audit_days", Sec::Retention, 20, int(30, 3650, Unit::Days), I(365))
        .owner()
        .up()
        .v1()
        .pre(DAYS_LONG)
        .syn(&["journal", "audit", "conservation"]),
    s("retention.expired_invites_days", Sec::Retention, 30, int(1, 365, Unit::Days), I(30)).pre(DAYS_MEDIUM).syn(&["invitation"]),
    s("invite.ttl_days", Sec::Retention, 40, int(1, 30, Unit::Days), I(7)).down().pre(DAYS_SHORT).syn(&["invitation", "validité"]),
    s("users.inactive_alert_days", Sec::Retention, 50, int(30, 730, Unit::Days), I(90)).pre(ALERT_DAYS).syn(&["inactif", "alerte"]),
    s("users.disable_after_inactive_days", Sec::Retention, 60, int(0, 730, Unit::Days), I(0))
        .down()
        .pre(INACTIVE_DAYS)
        .checked(check_disable_after)
        .syn(&["inactif", "désactivation"]),
    s(
        "directory.deprovision",
        Sec::Retention,
        70,
        Kind::Enum(&["disable", "disable_then_delete"]),
        S("disable_then_delete"),
    )
    .syn(&["annuaire", "départ"]),
    s("directory.delete_after_days", Sec::Retention, 80, int(0, 365, Unit::Days), I(30)).pre(DAYS_MEDIUM).syn(&["annuaire"]),
    s("directory.max_deprovision_percent", Sec::Retention, 90, int(1, 100, Unit::Percent), I(20))
        .down()
        .adv()
        .syn(&["annuaire", "garde-fou"]),
    // ---------------------------------------------------- Apparence et textes
    s("branding.org_name", Sec::Branding, 10, text(60), S("")).public().syn(&["nom", "entreprise"]),
    s("branding.logo", Sec::Branding, 20, Kind::Image { max_bytes: 262_144 }, S("")).public().syn(&["logo", "image"]),
    s("branding.accent_color", Sec::Branding, 30, Kind::Color, S(DEFAULT_ACCENT))
        .public()
        .checked(check_accent)
        .syn(&["couleur", "thème"]),
    s("branding.login_message", Sec::Branding, 40, multiline(500), S("")).public().syn(&["message", "accueil"]),
    s("branding.support_contact", Sec::Branding, 50, text(120), S("")).public().syn(&["support", "aide"]),
    s("branding.totp_issuer", Sec::Branding, 60, text(40), S("Locksy")).checked(check_totp_issuer).syn(&["application", "2fa"]),
    s("legal.notice_url", Sec::Branding, 70, Kind::Url { https_only: true }, S("")).public().syn(&["mentions légales"]),
    s("legal.privacy_url", Sec::Branding, 80, Kind::Url { https_only: true }, S("")).public().syn(&["confidentialité", "rgpd"]),
    s("legal.accessibility_url", Sec::Branding, 90, Kind::Url { https_only: true }, S("")).public().syn(&["accessibilité"]),
    s("legal.login_banner", Sec::Branding, 100, multiline(1000), S("")).public().syn(&["bannière", "avertissement"]),
    s("legal.charter_text", Sec::Branding, 110, multiline(20_000), S("")).clients().syn(&["charte", "règlement"]),
    s("legal.charter_version", Sec::Branding, 120, int(0, 1_000_000, Unit::Count), I(0)).public().syn(&["charte"]),
    s("legal.dpo_contact", Sec::Branding, 130, text(120), S("")).public().syn(&["dpo", "rgpd"]),
    s("i18n.default_locale", Sec::Branding, 140, Kind::Enum(&["fr-FR", "en-GB"]), S("fr-FR")).public().syn(&["langue"]),
    s("i18n.timezone", Sec::Branding, 150, text(64), S("Europe/Paris"))
        .public()
        .checked(check_timezone)
        .syn(&["fuseau", "heure"]),
    // ---------------------------------------------------- E-mails
    s("mail.enabled", Sec::Mail, 10, Kind::Bool, B(false)).syn(&["e-mail", "smtp", "notifications"]),
    s("mail.smtp.host", Sec::Mail, 20, text(253), S("")).checked(check_host).syn(&["smtp", "serveur"]),
    s("mail.smtp.port", Sec::Mail, 30, int(1, 65_535, Unit::Count), I(587)).syn(&["smtp", "port"]),
    s("mail.smtp.security", Sec::Mail, 40, Kind::Enum(&["none", "starttls", "tls"]), S("starttls")).up().syn(&["smtp", "tls"]),
    s("mail.smtp.username", Sec::Mail, 50, text(254), S("")).syn(&["smtp", "identifiant"]),
    s("mail.smtp.password", Sec::Mail, 60, Kind::Secret, S("")).syn(&["smtp", "mot de passe"]),
    s("mail.from", Sec::Mail, 70, Kind::Email, S("")).syn(&["expéditeur"]),
    s("mail.reply_to", Sec::Mail, 80, Kind::Email, S("")).syn(&["réponse"]),
    s("mail.notify.invite", Sec::Mail, 90, Kind::Bool, B(true)).syn(&["invitation"]),
    s("mail.notify.new_device", Sec::Mail, 100, Kind::Bool, B(true)).up().syn(&["appareil", "connexion"]),
    s("mail.notify.security_change", Sec::Mail, 110, Kind::Bool, B(true)).up().syn(&["sécurité", "alerte"]),
    s("mail.notify.settings_lowered", Sec::Mail, 120, Kind::Bool, B(true)).up().syn(&["sécurité", "alerte"]),
    s("mail.notify.admin_digest", Sec::Mail, 130, Kind::Enum(&["off", "daily", "weekly"]), S("daily")).syn(&["résumé"]),
    // ---------------------------------------------------- Avancé
    s("instance.public_url", Sec::Advanced, 10, Kind::Url { https_only: false }, S(""))
        .owner()
        .checked(check_public_url)
        .syn(&["adresse", "url", "domaine"]),
    s("kdf.memory_mib", Sec::Advanced, 20, int(19, 1024, Unit::Mib), I(64)).owner().public().up().syn(&["argon2", "dérivation"]),
    s("kdf.iterations", Sec::Advanced, 30, int(2, 10, Unit::Count), I(3)).owner().public().up().syn(&["argon2", "dérivation"]),
    s("kdf.parallelism", Sec::Advanced, 40, int(1, 8, Unit::Count), I(1)).owner().public().up().syn(&["argon2"]),
    s("kdf.min_memory_mib", Sec::Advanced, 50, int(19, 1024, Unit::Mib), I(19)).owner().up().syn(&["argon2", "plancher"]),
    s("kdf.min_iterations", Sec::Advanced, 60, int(2, 10, Unit::Count), I(2)).owner().up().syn(&["argon2", "plancher"]),
    s("kdf.upgrade_on_login", Sec::Advanced, 70, Kind::Bool, B(true)).public().up().syn(&["argon2", "mise à niveau"]),
    s("audit.syslog.url", Sec::Advanced, 80, Kind::Url { https_only: false }, S(""))
        .owner()
        .checked(check_syslog_url)
        .syn(&["siem", "syslog"]),
    s("audit.syslog.format", Sec::Advanced, 90, Kind::Enum(&["rfc5424", "json"]), S("rfc5424")).syn(&["siem", "syslog"]),
    s("audit.csv_separator", Sec::Advanced, 100, Kind::Enum(&["semicolon", "comma", "tab"]), S("semicolon")).syn(&["csv", "excel"]),
    s("scim.token_ttl_days", Sec::Advanced, 110, int(0, 730, Unit::Days), I(0)).down().pre(&[0, 30, 90, 180, 365, 730]).syn(&["scim", "jeton"]),
    // ---------------------------------------------------- Connexion d'entreprise
    s("sso.enforce", Sec::Identity, 10, Kind::Bool, B(false)).up().syn(&["sso", "imposer"]),
    s("ldap.enforce", Sec::Identity, 20, Kind::Bool, B(false)).up().syn(&["active directory", "ldap", "imposer"]),
];

/// Réglages où 0 signifie « sans limite » (le moins sûr) pour le calcul des
/// abaissements.
const ZERO_IS_UNLIMITED: &[&str] = &["session.max_per_user", "users.disable_after_inactive_days", "scim.token_ttl_days"];

/// Définition d'une clé.
pub fn def(key: &str) -> Option<&'static SettingDef> {
    REGISTRY.iter().find(|d| d.key == key)
}

// ------------------------------------------------------------ Valeurs stockées et erreurs

/// Valeur enregistrée : la valeur, et pour un réglage à modes, le mode et les
/// bornes laissées aux utilisateurs (`None` = pas de borne).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredValue {
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<Value>,
}

impl StoredValue {
    pub fn plain(value: Value) -> Self {
        Self { value, mode: None, min: None, max: None }
    }

    pub fn min_i64(&self) -> Option<i64> {
        self.min.as_ref().and_then(Value::as_i64)
    }

    pub fn max_i64(&self) -> Option<i64> {
        self.max.as_ref().and_then(Value::as_i64)
    }
}

/// Forme JSON d'une valeur (historique, export, diff) : objet complet
/// `{value, mode, min, max}` pour un réglage à modes (borne absente = null),
/// valeur seule sinon.
pub fn stored_to_json(def: &SettingDef, sv: &StoredValue) -> Value {
    if def.modes {
        json!({
            "value": sv.value,
            "mode": sv.mode.map(|m| m.as_str()),
            "min": sv.min.clone().unwrap_or(Value::Null),
            "max": sv.max.clone().unwrap_or(Value::Null),
        })
    } else {
        sv.value.clone()
    }
}

/// Relit la forme produite par [`stored_to_json`].
pub fn stored_from_json(def: &SettingDef, v: &Value) -> Result<StoredValue, FieldError> {
    match v {
        Value::Object(o) if def.modes && o.contains_key("value") => parse_object(o),
        _ => Ok(StoredValue::plain(v.clone())),
    }
}

fn parse_object(o: &Map<String, Value>) -> Result<StoredValue, FieldError> {
    let mode = match o.get("mode") {
        None | Some(Value::Null) => None,
        Some(Value::String(m)) => Some(Mode::parse(m).ok_or_else(|| FieldError::new("invalid_mode"))?),
        Some(_) => return Err(FieldError::new("invalid_mode")),
    };
    let bound = |k: &str| o.get(k).filter(|v| !v.is_null()).cloned();
    Ok(StoredValue { value: o.get("value").cloned().unwrap_or(Value::Null), mode, min: bound("min"), max: bound("max") })
}

/// Erreur sur un champ : code stable (`errors.field.<code>`) et paramètres.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FieldError {
    pub code: &'static str,
    #[serde(flatten)]
    pub params: Map<String, Value>,
}

impl FieldError {
    pub fn new(code: &'static str) -> Self {
        Self { code, params: Map::new() }
    }

    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.params.insert(key.to_string(), value.into());
        self
    }

    fn range(min: i64, max: i64) -> Self {
        Self::new("out_of_range").with("min", min).with("max", max)
    }

    fn cross(rule: &str, other: &str) -> Self {
        Self::new("cross_rule").with("rule", rule).with("other", other)
    }
}

/// Avertissement non bloquant.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Warning {
    pub key: String,
    pub code: &'static str,
    pub params: Map<String, Value>,
}

impl Warning {
    fn new(key: &str, code: &'static str) -> Self {
        Self { key: key.to_string(), code, params: Map::new() }
    }

    fn with(mut self, k: &str, v: impl Into<Value>) -> Self {
        self.params.insert(k.to_string(), v.into());
        self
    }
}

/// Valeur enregistrée illisible ou inconnue (elle retombe sur son défaut).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadError {
    pub key: String,
    pub code: &'static str,
}

// ------------------------------------------------------------ Contraintes de l'hébergeur

/// Ce que l'hébergeur impose : valeurs verrouillées (avec la variable qui
/// les fixe), plafonds, taille maximale d'une requête, environnement de test.
#[derive(Clone, Debug)]
pub struct HostCaps {
    pub locked: BTreeMap<String, (StoredValue, String)>,
    pub caps: BTreeMap<String, (i64, String)>,
    pub max_body_mib: i64,
    pub env_test: bool,
}

impl Default for HostCaps {
    fn default() -> Self {
        Self { locked: BTreeMap::new(), caps: BTreeMap::new(), max_body_mib: 16, env_test: false }
    }
}

// ------------------------------------------------------------ Contrôle d'une valeur

fn string_of(v: &Value) -> Result<&str, FieldError> {
    v.as_str().ok_or_else(|| FieldError::new("invalid_type"))
}

fn has_control(s: &str, multiline: bool) -> bool {
    s.chars().any(|c| c.is_control() && !(multiline && (c == '\n' || c == '\t')))
}

fn list_of(v: &Value) -> Result<Vec<String>, FieldError> {
    let arr = v.as_array().ok_or_else(|| FieldError::new("invalid_type"))?;
    arr.iter().map(|x| string_of(x).map(|s| s.trim().to_string())).collect()
}

/// Liste sans doublon, dans l'ordre d'arrivée, entrées vides retirées.
fn dedupe(items: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    items.into_iter().filter(|s| !s.is_empty() && seen.insert(s.clone())).collect()
}

fn too_many(n: usize, max: usize) -> Result<(), FieldError> {
    if n > max {
        return Err(FieldError::new("too_many").with("max", max as i64));
    }
    Ok(())
}

/// Nom d'hôte DNS (étiquettes de 1 à 63 caractères a-z, 0-9, tiret).
pub fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Adresse e-mail plausible (forme seulement).
pub fn is_email(s: &str) -> bool {
    match s.rsplit_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && local.len() <= 64
                && !local.chars().any(|c| c.is_whitespace() || c.is_control() || c == '@')
                && domain.contains('.')
                && is_hostname(&domain.to_ascii_lowercase())
        }
        None => false,
    }
}

/// Découpe `schéma://hôte[:port][/chemin]` ; renvoie (schéma, hôte, port).
fn split_url(s: &str) -> Option<(String, String, Option<u16>)> {
    let (scheme, rest) = s.split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.') {
        return None;
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return None; // identifiants dans l'URL : refusés
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (h, after) = inner.split_once(']')?;
        h.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().ok()?),
            None if after.is_empty() => None,
            None => return None,
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.parse::<u16>().ok()?)),
            None => (authority.to_string(), None),
        }
    };
    let lower = host.to_ascii_lowercase();
    let valid_host = lower.parse::<IpAddr>().is_ok() || is_hostname(&lower);
    valid_host.then(|| (scheme.to_ascii_lowercase(), lower, port))
}

fn url_host_is_local(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// Contrôle et normalise une valeur selon son type (bornes, plafonds).
fn check_value(def: &SettingDef, v: &Value, host: &HostCaps) -> Result<Value, FieldError> {
    let normalized = match def.kind {
        Kind::Bool => Value::Bool(v.as_bool().ok_or_else(|| FieldError::new("invalid_type"))?),
        Kind::Int { .. } => {
            let n = v.as_i64().ok_or_else(|| FieldError::new("invalid_type"))?;
            let (min, max) = def.int_bounds(host).unwrap_or((i64::MIN, i64::MAX));
            if n < min || n > max {
                return Err(FieldError::range(min, max));
            }
            json!(n)
        }
        Kind::Enum(values) => {
            let s = string_of(v)?;
            if !values.contains(&s) {
                return Err(FieldError::new("invalid_value"));
            }
            Value::String(s.to_string())
        }
        Kind::Text { max_len, multiline } => {
            let raw = string_of(v)?.replace("\r\n", "\n");
            let s = raw.trim();
            if has_control(s, multiline) {
                return Err(FieldError::new("invalid_value"));
            }
            if s.chars().count() > max_len {
                return Err(FieldError::new("too_long").with("max", max_len as i64));
            }
            Value::String(s.to_string())
        }
        Kind::Url { https_only } => {
            let s = string_of(v)?.trim();
            if !s.is_empty() {
                if s.len() > 2048 {
                    return Err(FieldError::new("too_long").with("max", 2048));
                }
                let (scheme, _, _) = split_url(s).ok_or_else(|| FieldError::new("invalid_url"))?;
                if https_only && scheme != "https" {
                    return Err(FieldError::new("https_required"));
                }
            }
            Value::String(s.to_string())
        }
        Kind::Email => {
            let s = string_of(v)?.trim();
            if !s.is_empty() && (s.len() > 254 || !is_email(s)) {
                return Err(FieldError::new("invalid_email"));
            }
            Value::String(s.to_string())
        }
        Kind::Color => {
            let s = string_of(v)?.trim().to_ascii_lowercase();
            if parse_hex(&s).is_none() {
                return Err(FieldError::new("invalid_color"));
            }
            Value::String(s)
        }
        Kind::Cidrs => {
            let items = dedupe(list_of(v)?);
            too_many(items.len(), 200)?;
            if let Some(bad) = items.iter().find(|c| Cidr::parse(c).is_none()) {
                return Err(FieldError::new("invalid_cidr").with("value", bad.as_str()));
            }
            json!(items)
        }
        Kind::Domains => {
            let items = dedupe(list_of(v)?.into_iter().map(|d| d.to_ascii_lowercase()).collect());
            too_many(items.len(), 200)?;
            if let Some(bad) = items.iter().find(|d| !is_hostname(d)) {
                return Err(FieldError::new("invalid_domain").with("value", bad.as_str()));
            }
            json!(items)
        }
        Kind::Emails => {
            let items = dedupe(list_of(v)?);
            too_many(items.len(), 100)?;
            if let Some(bad) = items.iter().find(|e| !is_email(e)) {
                return Err(FieldError::new("invalid_email").with("value", bad.as_str()));
            }
            json!(items)
        }
        Kind::Roles => {
            let items = dedupe(list_of(v)?);
            if let Some(bad) = items.iter().find(|r| !roles::ORG_ROLES.contains(&r.as_str())) {
                return Err(FieldError::new("invalid_role").with("value", bad.as_str()));
            }
            // Ordre stable : propriétaire, administrateur, utilisateur.
            let ordered: Vec<&str> = roles::ORG_ROLES.iter().copied().filter(|r| items.iter().any(|i| i == r)).collect();
            json!(ordered)
        }
        Kind::Words { max } => {
            let items = dedupe(list_of(v)?.into_iter().map(|w| w.to_lowercase()).collect());
            too_many(items.len(), max)?;
            if let Some(bad) = items.iter().find(|w| w.chars().count() > 64 || has_control(w, false)) {
                return Err(FieldError::new("invalid_word").with("value", bad.as_str()));
            }
            json!(items)
        }
        Kind::Secret => {
            let s = string_of(v)?;
            if has_control(s, false) {
                return Err(FieldError::new("invalid_value"));
            }
            if s.chars().count() > 1024 {
                return Err(FieldError::new("too_long").with("max", 1024));
            }
            Value::String(s.to_string())
        }
        Kind::Image { max_bytes } => {
            let s = string_of(v)?.trim();
            if !s.is_empty() {
                decode_image(s, max_bytes)?;
            }
            Value::String(s.to_string())
        }
    };
    if let Some(check) = def.check {
        check(&normalized)?;
    }
    Ok(normalized)
}

/// Contrôle complet d'une valeur enregistrée : type, bornes, mode et bornes
/// d'administration. Renvoie la valeur normalisée.
pub fn check_stored(def: &SettingDef, sv: &StoredValue, host: &HostCaps) -> Result<StoredValue, FieldError> {
    let value = check_value(def, &sv.value, host)?;
    if !def.modes {
        if sv.mode.is_some() || sv.min.is_some() || sv.max.is_some() {
            return Err(FieldError::new("not_modes"));
        }
        return Ok(StoredValue::plain(value));
    }
    let mode = sv.mode.or(def.default_mode).unwrap_or(Mode::Free);
    let (min, max) = (sv.min.clone(), sv.max.clone());
    if min.is_some() || max.is_some() {
        let Some((lo, hi)) = def.int_bounds(host) else { return Err(FieldError::new("invalid_mode")) };
        if mode != Mode::Default {
            return Err(FieldError::new("invalid_mode"));
        }
        let parse = |b: &Option<Value>| -> Result<Option<i64>, FieldError> {
            match b {
                None => Ok(None),
                Some(v) => match v.as_i64() {
                    Some(n) if (lo..=hi).contains(&n) => Ok(Some(n)),
                    Some(_) => Err(FieldError::range(lo, hi)),
                    None => Err(FieldError::new("invalid_type")),
                },
            }
        };
        let (a, b) = (parse(&min)?, parse(&max)?);
        if let (Some(a), Some(b)) = (a, b) {
            if a > b {
                return Err(FieldError::range(lo, hi));
            }
        }
        return Ok(StoredValue { value, mode: Some(mode), min: a.map(|n| json!(n)), max: b.map(|n| json!(n)) });
    }
    Ok(StoredValue { value, mode: Some(mode), min: None, max: None })
}

/// Décode une image `data:image/(png|webp);base64,…` ; renvoie les octets
/// et le type MIME, vérifié sur les octets magiques.
pub fn decode_image(data_url: &str, max_bytes: usize) -> Result<(Vec<u8>, &'static str), FieldError> {
    let (declared, b64) = if let Some(rest) = data_url.strip_prefix("data:image/png;base64,") {
        ("image/png", rest)
    } else if let Some(rest) = data_url.strip_prefix("data:image/webp;base64,") {
        ("image/webp", rest)
    } else {
        return Err(FieldError::new("invalid_image"));
    };
    // Borne avant décodage : 4 caractères base64 pour 3 octets.
    if b64.len() > max_bytes.div_ceil(3).saturating_mul(4).saturating_add(4) {
        return Err(FieldError::new("image_too_large").with("max", max_bytes as i64));
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|_| FieldError::new("invalid_image"))?;
    if bytes.len() > max_bytes {
        return Err(FieldError::new("image_too_large").with("max", max_bytes as i64));
    }
    let detected = image_type(&bytes).ok_or_else(|| FieldError::new("invalid_image"))?;
    if detected != declared {
        return Err(FieldError::new("invalid_image"));
    }
    Ok((bytes, detected))
}

/// Type d'image d'après ses octets magiques (PNG ou WebP seulement).
pub fn image_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

// ------------------------------------------------------------ Contrôles propres à une clé

fn check_symbols(v: &Value) -> Result<(), FieldError> {
    let s = v.as_str().unwrap_or("");
    let ok = !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() && !b.is_ascii_alphanumeric());
    ok.then_some(()).ok_or_else(|| FieldError::new("invalid_value"))
}

fn check_totp_issuer(v: &Value) -> Result<(), FieldError> {
    let s = v.as_str().unwrap_or("");
    (!s.is_empty() && !s.contains(':')).then_some(()).ok_or_else(|| FieldError::new("invalid_value"))
}

/// Fuseau IANA plausible (« UTC » ou « Zone/Lieu »), sans base de fuseaux
/// (le noyau ne fait aucune E/S).
fn check_timezone(v: &Value) -> Result<(), FieldError> {
    const AREAS: &[&str] =
        &["Africa", "America", "Antarctica", "Arctic", "Asia", "Atlantic", "Australia", "Europe", "Indian", "Pacific", "Etc"];
    let s = v.as_str().unwrap_or("");
    let parts: Vec<&str> = s.split('/').collect();
    let ok = s == "UTC"
        || (parts.len() >= 2
            && parts.len() <= 3
            && AREAS.contains(&parts[0])
            && parts[1..].iter().all(|p| {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'+')
            }));
    ok.then_some(()).ok_or_else(|| FieldError::new("invalid_timezone"))
}

fn check_extension_ids(v: &Value) -> Result<(), FieldError> {
    for id in v.as_array().into_iter().flatten().filter_map(Value::as_str) {
        if id.len() != 32 || !id.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
            return Err(FieldError::new("invalid_extension_id").with("value", id));
        }
    }
    Ok(())
}

fn check_disable_after(v: &Value) -> Result<(), FieldError> {
    match v.as_i64() {
        Some(0) | Some(30..=730) => Ok(()),
        _ => Err(FieldError::range(30, 730)),
    }
}

fn check_accent(v: &Value) -> Result<(), FieldError> {
    match v.as_str() {
        Some(DEFAULT_ACCENT) => Ok(()),
        Some(c) => accent_ok(c),
        None => Err(FieldError::new("invalid_color")),
    }
}

fn check_public_url(v: &Value) -> Result<(), FieldError> {
    let s = v.as_str().unwrap_or("");
    if s.is_empty() {
        return Ok(());
    }
    match split_url(s) {
        Some((scheme, _, _)) if scheme == "https" || scheme == "http" => Ok(()),
        _ => Err(FieldError::new("invalid_url")),
    }
}

fn check_syslog_url(v: &Value) -> Result<(), FieldError> {
    let s = v.as_str().unwrap_or("");
    if s.is_empty() {
        return Ok(());
    }
    match split_url(s) {
        Some((scheme, _, Some(_))) if ["udp", "tcp", "tcp+tls"].contains(&scheme.as_str()) => Ok(()),
        _ => Err(FieldError::new("invalid_url")),
    }
}

fn check_host(v: &Value) -> Result<(), FieldError> {
    let s = v.as_str().unwrap_or("").to_ascii_lowercase();
    if s.is_empty() || s.parse::<IpAddr>().is_ok() || is_hostname(&s) {
        Ok(())
    } else {
        Err(FieldError::new("invalid_value"))
    }
}

/// Serveur SMTP joignable sans chiffrement acceptable : boucle locale,
/// adresse privée ou de lien local (crochets IPv6 tolérés), nom court ou
/// domaine interne. Même règle pour la validation du registre et l'envoi
/// (mail.rs).
pub fn is_private_host(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if let Ok(ip) = h.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
    }
    h == "localhost"
        || !h.contains('.')
        || [".local", ".lan", ".internal", ".intranet", ".corp", ".home.arpa", ".localhost"].iter().any(|s| h.ends_with(s))
}

// ------------------------------------------------------------ Contraste

fn parse_hex(s: &str) -> Option<[u8; 3]> {
    let h = s.strip_prefix('#')?;
    if h.len() != 6 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).ok();
    Some([byte(0)?, byte(2)?, byte(4)?])
}

fn linear(c: u8) -> f64 {
    let c = f64::from(c) / 255.0;
    if c <= 0.04045 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn luminance(rgb: [u8; 3]) -> f64 {
    0.2126 * linear(rgb[0]) + 0.7152 * linear(rgb[1]) + 0.0722 * linear(rgb[2])
}

fn ratio_rgb(a: [u8; 3], b: [u8; 3]) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// Rapport de contraste WCAG entre deux couleurs `#rrggbb`.
pub fn contrast_ratio(a: &str, b: &str) -> Option<f64> {
    Some(ratio_rgb(parse_hex(a)?, parse_hex(b)?))
}

/// Pires rapports (texte sur l'accent, accent sur la surface) d'un thème.
fn accent_ratios(rgb: [u8; 3], surface: [u8; 3]) -> (f64, f64) {
    let on = [ON_ACCENT_LIGHT, ON_ACCENT_DARK]
        .iter()
        .filter_map(|c| parse_hex(c))
        .map(|t| ratio_rgb(t, rgb))
        .fold(0.0_f64, f64::max);
    (on, ratio_rgb(rgb, surface))
}

fn accent_passes(rgb: [u8; 3]) -> (bool, f64, f64) {
    let light = parse_hex(SURFACE_LIGHT).unwrap_or([255; 3]);
    let dark = parse_hex(SURFACE_DARK).unwrap_or([0; 3]);
    let (text_l, surf_l) = accent_ratios(rgb, light);
    let (text_d, surf_d) = accent_ratios(rgb, dark);
    let ok = text_l >= 4.5 && surf_l >= 3.0 && text_d >= 4.5 && surf_d >= 3.0;
    (ok, surf_l.min(text_l), surf_d.min(text_d))
}

fn hex_of(rgb: [u8; 3]) -> String {
    format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2])
}

/// Mélange vers le blanc (`t` > 0) ou vers le noir (`t` < 0), par pas de 2 %.
fn shade(rgb: [u8; 3], t: f64) -> [u8; 3] {
    let target = if t > 0.0 { 255.0 } else { 0.0 };
    let t = t.abs();
    rgb.map(|c| (f64::from(c) + (target - f64::from(c)) * t).round().clamp(0.0, 255.0) as u8)
}

/// Couleur d'organisation lisible dans les deux thèmes : texte (blanc ou
/// presque noir) à 4,5:1 sur l'accent, accent à 3:1 sur la surface claire
/// ET sur la surface sombre. Refus : `low_contrast` avec les rapports et la
/// nuance conforme la plus proche (null si aucune).
pub fn accent_ok(hex: &str) -> Result<(), FieldError> {
    let rgb = parse_hex(&hex.to_ascii_lowercase()).ok_or_else(|| FieldError::new("invalid_color"))?;
    let (ok, light, dark) = accent_passes(rgb);
    if ok {
        return Ok(());
    }
    let suggestion = (1..=50)
        .flat_map(|i| {
            let t = f64::from(i) * 0.02;
            [shade(rgb, t), shade(rgb, -t)]
        })
        .find(|c| accent_passes(*c).0)
        .map(hex_of);
    let round = |r: f64| (r * 100.0).round() / 100.0;
    Err(FieldError::new("low_contrast")
        .with("ratio_light", round(light))
        .with("ratio_dark", round(dark))
        .with("suggestion", suggestion.map(Value::String).unwrap_or(Value::Null)))
}

// ------------------------------------------------------------ Réseau IP

/// Réseau IP (adresse et longueur de préfixe) : proxys de confiance, liste
/// blanche et adresses de secours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Lit `10.0.0.0/8`, `2001:db8::/32` ou une adresse seule (préfixe
    /// implicite 32 ou 128). Les IPv4 mappées en IPv6 sont ramenées en IPv4.
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim().parse::<u8>().ok()?)),
            None => (s, None),
        };
        let ip: IpAddr = addr.parse().ok()?;
        let (net, prefix) = match (ip, prefix) {
            (IpAddr::V6(v6), p) if v6.to_ipv4_mapped().is_some() => {
                let p = p.unwrap_or(128);
                if !(96..=128).contains(&p) {
                    return None;
                }
                (IpAddr::V4(v6.to_ipv4_mapped()?), p - 96)
            }
            (IpAddr::V4(_), p) => (ip, p.unwrap_or(32)),
            (IpAddr::V6(_), p) => (ip, p.unwrap_or(128)),
        };
        let max = if net.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Cidr { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

// ------------------------------------------------------------ Valeurs effectives

/// État effectif d'une clé.
#[derive(Clone, Debug, PartialEq)]
pub struct EntryState {
    pub stored: StoredValue,
    pub source: Source,
    pub updated_at: i64,
    /// Variable de l'hébergeur qui fixe la valeur.
    pub locked_by: Option<String>,
}

/// Réglages effectifs d'une révision : toutes les clés du registre.
#[derive(Clone, Debug)]
pub struct Effective {
    pub revision: i64,
    pub schema_version: u32,
    entries: BTreeMap<&'static str, EntryState>,
    warnings: Vec<Warning>,
    host: HostCaps,
}

static NULL: Value = Value::Null;

impl Effective {
    pub fn entry(&self, key: &str) -> Option<&EntryState> {
        self.entries.get(key)
    }

    /// Valeur enregistrée complète (défaut compris).
    pub fn stored(&self, key: &str) -> Option<&StoredValue> {
        self.entries.get(key).map(|e| &e.stored)
    }

    pub fn get(&self, key: &str) -> &Value {
        self.entries.get(key).map(|e| &e.stored.value).unwrap_or(&NULL)
    }

    pub fn bool(&self, key: &str) -> bool {
        self.get(key).as_bool().unwrap_or(false)
    }

    pub fn int(&self, key: &str) -> i64 {
        self.get(key).as_i64().unwrap_or(0)
    }

    pub fn str(&self, key: &str) -> &str {
        self.get(key).as_str().unwrap_or("")
    }

    pub fn list(&self, key: &str) -> Vec<String> {
        self.get(key).as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default()
    }

    pub fn mode(&self, key: &str) -> Option<Mode> {
        self.entries.get(key).and_then(|e| e.stored.mode)
    }

    /// Bornes effectives d'un entier : type et plafonds de l'hébergeur, puis
    /// selon le mode (imposé : la valeur seule ; par défaut : bornes de l'admin).
    pub fn bounds(&self, key: &str) -> (Option<i64>, Option<i64>) {
        let Some(d) = def(key) else { return (None, None) };
        let Some((lo, hi)) = d.int_bounds(&self.host) else { return (None, None) };
        let Some(e) = self.entries.get(key) else { return (Some(lo), Some(hi)) };
        match e.stored.mode {
            Some(Mode::Enforced) => {
                let v = self.int(key);
                (Some(v), Some(v))
            }
            Some(Mode::Default) => (
                Some(e.stored.min_i64().unwrap_or(lo).max(lo)),
                Some(e.stored.max_i64().unwrap_or(hi).min(hi)),
            ),
            _ => (Some(lo), Some(hi)),
        }
    }

    pub fn source(&self, key: &str) -> Source {
        self.entries.get(key).map(|e| e.source).unwrap_or(Source::Default)
    }

    pub fn updated_at(&self, key: &str) -> i64 {
        self.entries.get(key).map(|e| e.updated_at).unwrap_or(0)
    }

    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    pub fn host(&self) -> &HostCaps {
        &self.host
    }

    /// Politique diffusée aux clients (annexe A.4, sans la révision) : toutes
    /// les clés `client`, avec mode et bornes effectives pour un entier à modes.
    pub fn policy_json(&self) -> Value {
        let mut out = Map::new();
        for d in REGISTRY.iter().filter(|d| d.client) {
            let mut entry = Map::new();
            entry.insert("value".into(), self.get(d.key).clone());
            if d.modes {
                if let Some(m) = self.mode(d.key) {
                    entry.insert("mode".into(), Value::String(m.as_str().into()));
                }
                if matches!(d.kind, Kind::Int { .. }) {
                    let (min, max) = self.bounds(d.key);
                    entry.insert("min".into(), json!(min));
                    entry.insert("max".into(), json!(max));
                }
            }
            out.insert(d.key.into(), Value::Object(entry));
        }
        Value::Object(out)
    }

    /// Copie avec des valeurs remplacées (état « après » une modification).
    fn with_changes(&self, changes: &[(&'static SettingDef, StoredValue)]) -> Effective {
        let mut after = self.clone();
        for (d, sv) in changes {
            if let Some(e) = after.entries.get_mut(d.key) {
                e.stored = sv.clone();
                e.source = if *sv == d.default_stored() { Source::Default } else { Source::Org };
            }
        }
        after.warnings = compute_warnings(&after);
        after
    }
}

/// Avertissements non bloquants d'un état (§4.6, point 6).
fn compute_warnings(e: &Effective) -> Vec<Warning> {
    let mut w = Vec::new();
    if e.int("retention.audit_days") < 180 {
        w.push(Warning::new("retention.audit_days", "below_recommended").with("min", 180));
    }
    if e.int("kdf.memory_mib") > 256 {
        w.push(Warning::new("kdf.memory_mib", "above_recommended").with("max", 256));
    }
    if e.int("scim.token_ttl_days") == 0 {
        w.push(Warning::new("scim.token_ttl_days", "no_expiry"));
    }
    if !e.bool("vault.personal_enabled") {
        w.push(Warning::new("vault.personal_enabled", "hides_personal_vaults"));
    }
    if e.str("instance.public_url").is_empty() {
        w.push(Warning::new("instance.public_url", "public_url_missing"));
    }
    w
}

/// Réglages effectifs à partir des valeurs enregistrées (clé -> valeur et
/// date de modification). Une valeur illisible retombe sur SON défaut et
/// produit une `ReadError` ; les autres clés ne sont pas touchées.
pub fn build_effective(
    stored: &BTreeMap<String, (StoredValue, i64)>,
    host: &HostCaps,
    revision: i64,
) -> (Effective, Vec<ReadError>) {
    let uncapped = HostCaps { caps: BTreeMap::new(), ..HostCaps::default() };
    let mut errors = Vec::new();
    let mut entries = BTreeMap::new();
    let mut extra = Vec::new();
    for d in REGISTRY {
        let mut entry = if let Some((sv, var)) = host.locked.get(d.key) {
            EntryState { stored: sv.clone(), source: Source::HostLocked, updated_at: 0, locked_by: Some(var.clone()) }
        } else if let Some((sv, at)) = stored.get(d.key) {
            // Un secret est enregistré chiffré par le serveur : seule sa forme
            // de chaîne est contrôlée ici.
            let checked = match (d.is_secret(), &sv.value) {
                (true, Value::String(_)) => Ok(StoredValue::plain(sv.value.clone())),
                _ => check_stored(d, sv, &uncapped),
            };
            match checked {
                Ok(sv) => EntryState { stored: sv, source: Source::Org, updated_at: *at, locked_by: None },
                Err(e) => {
                    errors.push(ReadError { key: d.key.to_string(), code: e.code });
                    extra.push(Warning::new(d.key, "read_error").with("reason", e.code));
                    EntryState { stored: d.default_stored(), source: Source::Default, updated_at: 0, locked_by: None }
                }
            }
        } else {
            EntryState { stored: d.default_stored(), source: Source::Default, updated_at: 0, locked_by: None }
        };
        // Plafond de l'hébergeur : la valeur est ramenée sous le plafond.
        if let (Some((cap, var)), Some(v)) = (host.caps.get(d.key), entry.stored.value.as_i64()) {
            if v > *cap {
                entry.stored.value = json!(cap);
                extra.push(Warning::new(d.key, "capped_by_host").with("cap", *cap).with("variable", var.as_str()));
            }
        }
        entries.insert(d.key, entry);
    }
    for key in stored.keys().filter(|k| def(k).is_none()) {
        errors.push(ReadError { key: key.clone(), code: "unknown_key" });
    }
    let mut eff = Effective { revision, schema_version: SCHEMA_VERSION, entries, warnings: Vec::new(), host: host.clone() };
    let mut warnings = compute_warnings(&eff);
    warnings.extend(extra);
    eff.warnings = warnings;
    (eff, errors)
}

/// Réglages par défaut (aucune valeur enregistrée).
pub fn defaults(host: &HostCaps) -> Effective {
    build_effective(&BTreeMap::new(), host, 0).0
}

// ------------------------------------------------------------ Modifications

/// Modification demandée pour une clé.
#[derive(Clone, Debug, PartialEq)]
pub enum Change {
    /// Nouvelle valeur. Mode absent : mode actuel conservé ; mode, `min` et
    /// `max` tous absents : bornes actuelles conservées.
    Set(StoredValue),
    /// Retour au défaut du registre.
    Reset,
}

impl Change {
    /// JSON de PATCH : valeur nue, objet `{value, mode?, min?, max?}` ou null.
    pub fn from_json(v: Value) -> Result<Change, String> {
        match v {
            Value::Null => Ok(Change::Reset),
            Value::Object(o) if o.contains_key("value") => {
                parse_object(&o).map(Change::Set).map_err(|e| format!("mode illisible ({})", e.code))
            }
            Value::Object(_) => Err("objet sans « value »".into()),
            other => Ok(Change::Set(StoredValue::plain(other))),
        }
    }
}

impl<'de> Deserialize<'de> for Change {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Change::from_json(Value::deserialize(d)?).map_err(D::Error::custom)
    }
}

impl Serialize for Change {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Change::Reset => s.serialize_none(),
            Change::Set(sv) => sv.serialize(s),
        }
    }
}

/// Ensemble de modifications, par clé.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Changes(pub BTreeMap<String, Change>);

impl Changes {
    pub fn set(mut self, key: &str, value: Value) -> Self {
        self.0.insert(key.to_string(), Change::Set(StoredValue::plain(value)));
        self
    }

    pub fn set_full(mut self, key: &str, value: Value, mode: Mode, min: Option<i64>, max: Option<i64>) -> Self {
        let sv = StoredValue { value, mode: Some(mode), min: min.map(|v| json!(v)), max: max.map(|v| json!(v)) };
        self.0.insert(key.to_string(), Change::Set(sv));
        self
    }

    pub fn reset(mut self, key: &str) -> Self {
        self.0.insert(key.to_string(), Change::Reset);
        self
    }
}

/// Contexte de la demande : qui modifie, d'où, et état des connexions
/// d'entreprise (pour les garde-fous).
#[derive(Clone, Debug)]
pub struct Ctx {
    pub actor_role: String,
    pub actor_id: String,
    pub actor_ip: Option<IpAddr>,
    pub actor_has_2fa: bool,
    pub now: i64,
    pub sso_enabled: bool,
    pub ldap_login_enabled: bool,
    /// Dernier test RÉUSSI de l'acteur, par méthode ("sso" | "ldap").
    pub last_test_ok_at: BTreeMap<&'static str, i64>,
    pub host: HostCaps,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DiffEntry {
    pub key: String,
    pub old: StoredValue,
    pub new: StoredValue,
    pub lowered: bool,
}

/// Résultat d'une validation réussie : seules les clés réellement modifiées.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Diff {
    pub entries: Vec<DiffEntry>,
    /// Au moins un abaissement de sécurité.
    pub requires_reauth: bool,
    /// Au moins une clé réservée aux propriétaires.
    pub requires_owner: bool,
    pub warnings: Vec<Warning>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Rejection {
    Invalid(BTreeMap<String, FieldError>),
    OwnerOnly(Vec<String>),
    HostLocked(Vec<String>),
    TestRequired(String),
}

/// Nouvelle valeur complète à partir de la valeur actuelle et d'un `Set`.
fn merge_set(d: &SettingDef, old: &StoredValue, new: &StoredValue) -> StoredValue {
    if !d.modes {
        return new.clone();
    }
    let mode = new.mode.or(old.mode).or(d.default_mode);
    let (min, max) = if new.mode.is_none() && new.min.is_none() && new.max.is_none() {
        (old.min.clone(), old.max.clone())
    } else {
        (new.min.clone(), new.max.clone())
    };
    // Bornes seulement en mode « par défaut » : un passage à « libres » ou
    // « imposé » les retire.
    let (min, max) = if mode == Some(Mode::Default) { (min, max) } else { (None, None) };
    StoredValue { value: new.value.clone(), mode, min, max }
}

/// Valide un ensemble de modifications sur l'état actuel. Ordre des
/// contrôles : types et bornes, verrous de l'hébergeur, droits du
/// propriétaire, règles croisées, garde-fous, puis calcul des abaissements.
pub fn validate(current: &Effective, changes: &Changes, ctx: &Ctx) -> Result<Diff, Rejection> {
    // 1. Clés, types, bornes et plafonds.
    let mut errors = BTreeMap::new();
    let mut proposed: Vec<(&'static SettingDef, StoredValue, StoredValue)> = Vec::new();
    for (key, change) in &changes.0 {
        let Some(d) = def(key) else {
            errors.insert(key.clone(), FieldError::new("unknown_key"));
            continue;
        };
        let old = current.stored(d.key).cloned().unwrap_or_else(|| d.default_stored());
        let candidate = match change {
            Change::Reset => d.default_stored(),
            Change::Set(sv) => merge_set(d, &old, sv),
        };
        match check_stored(d, &candidate, &ctx.host) {
            Ok(new) => proposed.push((d, old, new)),
            Err(e) => {
                errors.insert(key.clone(), e);
            }
        }
    }
    if !errors.is_empty() {
        return Err(Rejection::Invalid(errors));
    }
    // Seules les vraies modifications comptent. Un secret enregistré est
    // chiffré : toute nouvelle valeur non vide le remplace.
    let changed: Vec<_> = proposed
        .into_iter()
        .filter(|(d, old, new)| {
            if d.is_secret() {
                !(old.value.as_str().unwrap_or("").is_empty() && new.value.as_str().unwrap_or("").is_empty())
            } else {
                old != new
            }
        })
        .collect();

    // 2. Clés fixées par l'hébergeur.
    let locked: Vec<String> =
        changed.iter().filter(|(d, _, _)| current.source(d.key) == Source::HostLocked).map(|(d, _, _)| d.key.into()).collect();
    if !locked.is_empty() {
        return Err(Rejection::HostLocked(locked));
    }
    // 3. Clés réservées aux propriétaires.
    let owner_keys: Vec<String> = changed.iter().filter(|(d, _, _)| d.owner_only).map(|(d, _, _)| d.key.into()).collect();
    if !owner_keys.is_empty() && ctx.actor_role != roles::OWNER {
        return Err(Rejection::OwnerOnly(owner_keys));
    }

    let pairs: Vec<(&'static SettingDef, StoredValue)> = changed.iter().map(|(d, _, new)| (*d, new.clone())).collect();
    let after = current.with_changes(&pairs);
    let keys: BTreeSet<&str> = changed.iter().map(|(d, _, _)| d.key).collect();

    // 4. Règles croisées, puis 5. garde-fous contre l'auto-blocage.
    let mut errors = cross_rules(&after, &keys, changes, ctx);
    guards(&after, &keys, ctx, &mut errors);
    if !errors.is_empty() {
        return Err(Rejection::Invalid(errors));
    }
    for (key, method) in [("sso.enforce", "sso"), ("ldap.enforce", "ldap")] {
        if keys.contains(key) && after.bool(key) {
            let recent = ctx.last_test_ok_at.get(method).is_some_and(|at| ctx.now - at < TEST_VALIDITY_SECS);
            if !recent {
                return Err(Rejection::TestRequired(key.into()));
            }
        }
    }

    // 6. Abaissements.
    let entries: Vec<DiffEntry> = changed
        .into_iter()
        .map(|(d, old, new)| DiffEntry { key: d.key.into(), lowered: is_lowered(d, &old, &new), old, new })
        .collect();
    Ok(Diff {
        requires_reauth: entries.iter().any(|e| e.lowered),
        requires_owner: entries.iter().any(|e| def(&e.key).is_some_and(|d| d.owner_only)),
        warnings: after.warnings().iter().filter(|w| keys.contains(w.key.as_str())).cloned().collect(),
        entries,
    })
}

/// Règles entre clés (§4.6.3). Une règle n'est vérifiée que si l'une de ses
/// clés change : un état antérieur incohérent ne bloque pas une modification
/// sans rapport.
fn cross_rules(
    after: &Effective,
    keys: &BTreeSet<&str>,
    changes: &Changes,
    ctx: &Ctx,
) -> BTreeMap<String, FieldError> {
    let mut errors = BTreeMap::new();
    let mut le = |rule: &str, small: &str, big: &str, ok: bool| {
        if !ok && (keys.contains(small) || keys.contains(big)) {
            let (at, other) = if keys.contains(small) { (small, big) } else { (big, small) };
            errors.insert(at.to_string(), FieldError::cross(rule, other));
        }
    };
    le("idle_within_max", "session.idle_minutes", "session.max_hours", after.int("session.idle_minutes") <= after.int("session.max_hours") * 60);
    le(
        "lockout_thresholds",
        "lockout.pair_threshold",
        "lockout.account_threshold",
        after.int("lockout.pair_threshold") < after.int("lockout.account_threshold"),
    );
    le(
        "lockout_delays",
        "lockout.base_delay_seconds",
        "lockout.max_delay_seconds",
        after.int("lockout.base_delay_seconds") <= after.int("lockout.max_delay_seconds"),
    );
    le("kdf_memory_floor", "kdf.min_memory_mib", "kdf.memory_mib", after.int("kdf.min_memory_mib") <= after.int("kdf.memory_mib"));
    le(
        "kdf_iterations_floor",
        "kdf.min_iterations",
        "kdf.iterations",
        after.int("kdf.min_iterations") <= after.int("kdf.iterations"),
    );
    le("generator_length", "generator.min_length", "generator.length", after.int("generator.min_length") <= after.int("generator.length"));
    le("generator_words", "generator.min_words", "generator.words", after.int("generator.min_words") <= after.int("generator.words"));
    le(
        "share_expiry",
        "share.default_expiry_minutes",
        "share.max_expiry_minutes",
        after.int("share.default_expiry_minutes") <= after.int("share.max_expiry_minutes"),
    );
    le("share_views", "share.default_views", "share.max_views", after.int("share.default_views") <= after.int("share.max_views"));

    // Une pièce jointe chiffrée et encodée (× 4/3, + 1 Mio d'enveloppe) doit
    // tenir dans la taille maximale d'une requête : 4m/3 + 1 ≤ B ⇔ 4m + 3 ≤ 3B.
    let file = "attachment.max_file_mib";
    if keys.contains(file) && 4 * after.int(file) + 3 > 3 * ctx.host.max_body_mib {
        errors.insert(file.into(), FieldError::cross("attachment_body", "LOCKSY_MAX_BODY_MIB").with("max_body_mib", ctx.host.max_body_mib));
    }

    // Mode « par défaut » : la valeur proposée est dans les bornes laissées
    // aux utilisateurs.
    for key in keys.iter().copied() {
        let Some(d) = def(key) else { continue };
        if !d.modes || after.mode(key) != Some(Mode::Default) {
            continue;
        }
        if let (Some(v), (Some(lo), Some(hi))) = (after.get(key).as_i64(), after.bounds(key)) {
            if v < lo || v > hi {
                errors.insert(key.into(), FieldError::cross("mode_bounds", key).with("min", lo).with("max", hi));
            }
        }
    }

    // Adresse publique en HTTPS, sauf boucle locale ou environnement de test.
    let url_key = "instance.public_url";
    if keys.contains(url_key) && !ctx.host.env_test {
        if let Some((scheme, host, _)) = split_url(after.str(url_key)) {
            if scheme != "https" && !url_host_is_local(&host) {
                errors.insert(url_key.into(), FieldError::new("https_required"));
            }
        }
    }

    // Une notification activée suppose l'envoi d'e-mails activé.
    for key in keys.iter().copied().filter(|k| k.starts_with("mail.notify.")) {
        let active = match after.get(key) {
            Value::Bool(b) => *b,
            Value::String(s) => s != "off",
            _ => false,
        };
        if active && !after.bool("mail.enabled") && matches!(changes.0.get(key), Some(Change::Set(_))) {
            errors.insert(key.into(), FieldError::cross("notify_requires_mail", "mail.enabled"));
        }
    }

    // Envoi SMTP sans chiffrement : réseau privé seulement.
    if (keys.contains("mail.smtp.security") || keys.contains("mail.smtp.host"))
        && after.str("mail.smtp.security") == "none"
        && !after.str("mail.smtp.host").is_empty()
        && !is_private_host(after.str("mail.smtp.host"))
    {
        let at = if keys.contains("mail.smtp.security") { "mail.smtp.security" } else { "mail.smtp.host" };
        errors.insert(at.into(), FieldError::cross("smtp_plain_private_only", "mail.smtp.host"));
    }

    // Méthode de connexion proposée ou imposée : elle doit être activée.
    let enabled = |m: &str| match m {
        "sso" => ctx.sso_enabled,
        "ldap" => ctx.ldap_login_enabled,
        _ => true,
    };
    if keys.contains("auth.primary_method") && !enabled(after.str("auth.primary_method")) {
        errors.insert("auth.primary_method".into(), FieldError::new("method_not_enabled"));
    }
    for (key, method) in [("sso.enforce", "sso"), ("ldap.enforce", "ldap")] {
        if keys.contains(key) && after.bool(key) && !enabled(method) {
            errors.insert(key.into(), FieldError::new("method_not_enabled"));
        }
    }
    errors
}

/// Garde-fous contre l'auto-blocage (§4.6.4).
fn guards(after: &Effective, keys: &BTreeSet<&str>, ctx: &Ctx, errors: &mut BTreeMap<String, FieldError>) {
    if keys.contains("access.ip_allowlist") || keys.contains("access.ip_rescue") {
        let allowed = ctx.actor_ip.is_some_and(|ip| ip_allowed(after, ip, &ctx.actor_role));
        if !allowed {
            let at = if keys.contains("access.ip_allowlist") { "access.ip_allowlist" } else { "access.ip_rescue" };
            let ip = ctx.actor_ip.map(|i| i.to_string()).unwrap_or_default();
            errors.insert(at.into(), FieldError::new("missing_own_ip").with("ip", ip));
        }
    }
    if (keys.contains("twofa.required") || keys.contains("twofa.required_roles"))
        && twofa_applies(after, &ctx.actor_role)
        && !ctx.actor_has_2fa
    {
        let at = if keys.contains("twofa.required") { "twofa.required" } else { "twofa.required_roles" };
        errors.insert(at.into(), FieldError::new("actor_without_2fa"));
    }
}

/// Une modification abaisse-t-elle la sécurité ?
fn is_lowered(d: &SettingDef, old: &StoredValue, new: &StoredValue) -> bool {
    if d.safer == Safer::NotApplicable {
        return false;
    }
    let higher = d.safer == Safer::Higher;
    let value_lowered = match d.kind {
        Kind::Bool => {
            let (o, n) = (old.value.as_bool().unwrap_or(false), new.value.as_bool().unwrap_or(false));
            if higher {
                o && !n
            } else {
                !o && n
            }
        }
        Kind::Int { .. } => {
            let norm = |v: &Value| {
                let n = v.as_i64().unwrap_or(0);
                if n == 0 && ZERO_IS_UNLIMITED.contains(&d.key) {
                    i64::MAX
                } else {
                    n
                }
            };
            let (o, n) = (norm(&old.value), norm(&new.value));
            if higher {
                n < o
            } else {
                n > o
            }
        }
        Kind::Enum(values) => {
            let pos = |v: &Value| v.as_str().and_then(|s| values.iter().position(|x| *x == s)).unwrap_or(0);
            let (o, n) = (pos(&old.value), pos(&new.value));
            if higher {
                n < o
            } else {
                n > o
            }
        }
        _ if d.kind.is_list() => {
            let set = |v: &Value| -> BTreeSet<String> {
                v.as_array().into_iter().flatten().filter_map(|x| x.as_str().map(str::to_string)).collect()
            };
            let (o, n) = (set(&old.value), set(&new.value));
            let added = n.difference(&o).next().is_some();
            let removed = o.difference(&n).next().is_some();
            match (d.kind, higher) {
                // Liste blanche : vide = tout est permis.
                (Kind::Cidrs | Kind::Domains, true) => (!o.is_empty() && n.is_empty()) || (added && !o.is_empty()),
                (_, true) => removed,
                (_, false) => added,
            }
        }
        _ => false,
    };
    // Mode imposé relâché, ou borne laissée aux utilisateurs élargie.
    let mode_lowered = old.mode == Some(Mode::Enforced) && new.mode != Some(Mode::Enforced);
    let bound_widened = if higher {
        let lo = |s: &StoredValue| s.min_i64().unwrap_or(i64::MIN);
        new.mode == Some(Mode::Default) && old.mode == Some(Mode::Default) && lo(new) < lo(old)
    } else {
        let hi = |s: &StoredValue| s.max_i64().unwrap_or(i64::MAX);
        new.mode == Some(Mode::Default) && old.mode == Some(Mode::Default) && hi(new) > hi(old)
    };
    value_lowered || mode_lowered || bound_widened
}

// ------------------------------------------------------------ Profils

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Standard,
    Reinforced,
    Strict,
}

impl Profile {
    pub const ALL: [Profile; 3] = [Profile::Standard, Profile::Reinforced, Profile::Strict];

    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::Standard => "standard",
            Profile::Reinforced => "reinforced",
            Profile::Strict => "strict",
        }
    }

    pub fn parse(s: &str) -> Option<Profile> {
        Profile::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

/// Valeurs d'un profil de sécurité (§4.7). Standard = défauts du registre.
pub fn profile(p: Profile) -> Changes {
    use Mode::{Default as D, Enforced as E};
    let (required, roles, grace) = match p {
        Profile::Standard => (false, json!([]), 7),
        Profile::Reinforced => (false, json!(["owner", "admin"]), 7),
        Profile::Strict => (true, json!(["owner", "admin", "user"]), 3),
    };
    let (idle, max_hours) = match p {
        Profile::Standard => (60, 12),
        Profile::Reinforced => (30, 8),
        Profile::Strict => (15, 8),
    };
    let c = Changes::default()
        .set("twofa.required", json!(required))
        .set("twofa.required_roles", roles)
        .set("twofa.grace_days", json!(grace))
        .set("session.idle_minutes", json!(idle))
        .set("session.max_hours", json!(max_hours));
    let c = match p {
        Profile::Standard => c
            .set_full("client.autolock_minutes", json!(10), D, None, None)
            .set("client.autolock_allow_never", json!(true))
            .set_full("client.clipboard_clear_seconds", json!(30), D, None, Some(120))
            .set_full("client.lock_on_os_lock", json!(true), D, None, None)
            .set_full("client.single_key_shortcuts", json!(true), D, None, None),
        Profile::Reinforced => c
            .set_full("client.autolock_minutes", json!(10), D, None, Some(30))
            .set("client.autolock_allow_never", json!(false))
            .set_full("client.clipboard_clear_seconds", json!(30), D, None, Some(60))
            .set_full("client.lock_on_os_lock", json!(true), E, None, None)
            .set_full("client.single_key_shortcuts", json!(true), D, None, None),
        Profile::Strict => c
            .set_full("client.autolock_minutes", json!(5), E, None, None)
            .set("client.autolock_allow_never", json!(false))
            .set_full("client.clipboard_clear_seconds", json!(20), E, None, None)
            .set_full("client.lock_on_os_lock", json!(true), E, None, None)
            .set_full("client.single_key_shortcuts", json!(false), D, None, None),
    };
    let (min_length, min_score, kdf_memory) = match p {
        Profile::Standard => (12, 3, 64),
        Profile::Reinforced => (14, 3, 64),
        Profile::Strict => (16, 4, 128),
    };
    let (share_expiry, share_views, rotate, audit_days, pair, max_delay, disable) = match p {
        Profile::Standard => (43_200, 100, "suggest", 365, 5, 3600, 0),
        Profile::Reinforced => (10_080, 10, "force", 730, 5, 3600, 180),
        Profile::Strict => (1440, 1, "force", 1825, 3, 86_400, 90),
    };
    c.set("master_password.min_length", json!(min_length))
        .set("master_password.min_score", json!(min_score))
        .set("kdf.memory_mib", json!(kdf_memory))
        .set("kdf.iterations", json!(3))
        .set("share.max_expiry_minutes", json!(share_expiry))
        .set("share.max_views", json!(share_views))
        .set("vault.rotate_on_member_removal", json!(rotate))
        .set("extension.http_fill", json!("block"))
        .set("retention.audit_days", json!(audit_days))
        .set("lockout.pair_threshold", json!(pair))
        .set("lockout.max_delay_seconds", json!(max_delay))
        .set("users.disable_after_inactive_days", json!(disable))
}

/// Écarts d'un état à un profil (clés du profil dont la valeur diffère).
fn deviations(e: &Effective, p: Profile) -> Vec<&'static str> {
    profile(p)
        .0
        .iter()
        .filter_map(|(key, change)| {
            let d = def(key)?;
            let current = e.stored(key)?;
            let target = match change {
                Change::Set(sv) => merge_set(d, current, sv),
                Change::Reset => d.default_stored(),
            };
            (current != &target).then_some(d.key)
        })
        .collect()
}

/// Profil le plus proche de l'état actuel et clés qui s'en écartent.
pub fn closest_profile(e: &Effective) -> (Profile, Vec<&'static str>) {
    Profile::ALL
        .into_iter()
        .map(|p| (p, deviations(e, p)))
        .min_by_key(|(_, d)| d.len())
        .unwrap_or((Profile::Standard, Vec::new()))
}

// ------------------------------------------------------------ Règles appliquées par le serveur

/// Exigence de double authentification pour un compte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwofaGate {
    NotRequired,
    /// Exigée, mais le délai de grâce court jusqu'à `deadline`.
    Grace { deadline: i64 },
    Required,
}

/// La double authentification est-elle exigée pour ce rôle (organisation
/// entière ou rôle listé), indépendamment du délai de grâce ?
pub fn twofa_applies(e: &Effective, role: &str) -> bool {
    e.bool("twofa.required") || e.list("twofa.required_roles").iter().any(|r| r == role)
}

/// La règle s'applique si `twofa.required` est vrai ou si le rôle est dans
/// `twofa.required_roles`. Échéance : max(création du compte, mise en place
/// de la règle) + délai de grâce.
///
/// Mise en place : la plus ANCIENNE des règles qui visent ce compte. Modifier
/// l'autre règle (ou en ajouter une seconde) ne rouvre donc pas de délai de
/// grâce à un compte déjà bloqué (écart assumé au « max » du contrat C2).
pub fn twofa_gate(e: &Effective, role: &str, has_totp: bool, user_created_at: i64, now: i64) -> TwofaGate {
    if has_totp || !twofa_applies(e, role) {
        return TwofaGate::NotRequired;
    }
    let by_org = e.bool("twofa.required").then(|| e.updated_at("twofa.required"));
    let by_role = e
        .list("twofa.required_roles")
        .iter()
        .any(|r| r == role)
        .then(|| e.updated_at("twofa.required_roles"));
    let since = by_org.into_iter().chain(by_role).min().unwrap_or(0);
    let deadline = user_created_at.max(since).saturating_add(e.int("twofa.grace_days").saturating_mul(86_400));
    if now < deadline {
        TwofaGate::Grace { deadline }
    } else {
        TwofaGate::Required
    }
}

/// Liste blanche d'adresses : vide, tout passe ; sinon l'adresse doit en
/// faire partie, ou, pour un propriétaire, faire partie des adresses de secours.
pub fn ip_allowed(e: &Effective, ip: IpAddr, role: &str) -> bool {
    let list = e.list("access.ip_allowlist");
    if list.is_empty() {
        return true;
    }
    let within = |key: &str| e.list(key).iter().filter_map(|c| Cidr::parse(c)).any(|c| c.contains(ip));
    within("access.ip_allowlist") || (role == roles::OWNER && within("access.ip_rescue"))
}

// ------------------------------------------------------------ Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ctx(role: &str) -> Ctx {
        Ctx {
            actor_role: role.into(),
            actor_id: "u1".into(),
            actor_ip: Some(ip("192.0.2.10")),
            actor_has_2fa: true,
            now: 1_800_000_000,
            sso_enabled: true,
            ldap_login_enabled: true,
            last_test_ok_at: BTreeMap::new(),
            host: HostCaps::default(),
        }
    }

    fn base() -> Effective {
        defaults(&HostCaps::default())
    }

    fn one(key: &str, v: Value) -> Changes {
        Changes::default().set(key, v)
    }

    #[track_caller]
    fn invalid(r: Result<Diff, Rejection>, key: &str) -> FieldError {
        match r {
            Err(Rejection::Invalid(m)) => m.get(key).cloned().unwrap_or_else(|| panic!("{key} absent de {m:?}")),
            other => panic!("refus attendu sur {key} : {other:?}"),
        }
    }

    #[track_caller]
    fn cross(r: Result<Diff, Rejection>, key: &str, rule: &str) {
        let e = invalid(r, key);
        assert_eq!(e.code, "cross_rule", "{e:?}");
        assert_eq!(e.params["rule"], json!(rule));
    }

    fn state_with(changes: Changes) -> Effective {
        let mut stored = BTreeMap::new();
        for (k, c) in changes.0 {
            let Change::Set(sv) = c else { continue };
            let d = def(&k).unwrap();
            let full = merge_set(d, &d.default_stored(), &sv);
            stored.insert(k, (full, 100));
        }
        let (e, errors) = build_effective(&stored, &HostCaps::default(), 5);
        assert!(errors.is_empty(), "{errors:?}");
        e
    }

    fn lowered(key: &str, from: Changes, to: Changes) -> bool {
        let cur = state_with(from);
        let diff = validate(&cur, &to, &ctx("owner")).unwrap_or_else(|e| panic!("{key} : {e:?}"));
        diff.entries.iter().find(|e| e.key == key).unwrap_or_else(|| panic!("{key} inchangé")).lowered
    }

    #[test]
    fn registre_coherent() {
        let mut keys = BTreeSet::new();
        assert!(REGISTRY.len() >= 90, "{} clés", REGISTRY.len());
        for d in REGISTRY {
            assert!(keys.insert(d.key), "clé en double : {}", d.key);
            assert!(d.key.split('.').count() >= 2, "{}", d.key);
            assert!(
                d.key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.'),
                "{}",
                d.key
            );
            // Un réglage à modes est diffusé aux clients et a un mode par défaut.
            if d.modes {
                assert!(d.client && d.default_mode.is_some(), "{}", d.key);
            }
            assert_eq!(d.client, d.scope == Scope::Policy, "{}", d.key);
            if d.default_min.is_some() || d.default_max.is_some() {
                assert!(d.modes && matches!(d.kind, Kind::Int { .. }), "{}", d.key);
            }
            if let Kind::Enum(values) = d.kind {
                for v in values {
                    let k = format!("settings.{}.value.{}", d.key, v.to_lowercase());
                    assert!(k.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b)), "{k}");
                }
            }
            if !d.presets.is_empty() {
                let (lo, hi) = d.int_bounds(&HostCaps::default()).expect("préréglages d'un entier");
                assert!(d.presets.iter().all(|p| (lo..=hi).contains(p)), "{}", d.key);
            }
        }
        assert!(def("session.idle_minutes").is_some() && def("inexistant").is_none());
    }

    #[test]
    fn chaque_defaut_dans_ses_bornes() {
        let host = HostCaps::default();
        for d in REGISTRY {
            let sv = d.default_stored();
            let checked = check_stored(d, &sv, &host).unwrap_or_else(|e| panic!("{} : {e:?}", d.key));
            assert_eq!(checked, sv, "défaut non normalisé : {}", d.key);
        }
        let e = base();
        assert!(e.warnings().iter().all(|w| w.code != "read_error"));
    }

    #[test]
    fn sections_dans_l_ordre_et_toutes_utilisees() {
        assert_eq!(Section::ALL.last(), Some(&Section::Identity));
        for s in Section::ALL {
            assert!(REGISTRY.iter().any(|d| d.section == s), "{s:?} vide");
        }
        assert_eq!(serde_json::to_value(Section::Login).unwrap(), json!("login"));
        assert_eq!(serde_json::to_value(Safer::NotApplicable).unwrap(), json!("na"));
        assert_eq!(serde_json::to_value(Source::HostLocked).unwrap(), json!("host_locked"));
        assert_eq!(serde_json::to_value(Unit::Mib).unwrap(), json!("mib"));
    }

    #[test]
    fn chaque_profil_est_valide() {
        let cur = base();
        for p in Profile::ALL {
            let diff = validate(&cur, &profile(p), &ctx("owner")).unwrap_or_else(|e| panic!("{p:?} : {e:?}"));
            let applied = cur.with_changes(
                &diff.entries.iter().map(|e| (def(&e.key).unwrap(), e.new.clone())).collect::<Vec<_>>(),
            );
            assert_eq!(closest_profile(&applied), (p, Vec::new()), "{p:?}");
        }
        // Les défauts sont exactement le profil Standard.
        assert!(validate(&cur, &profile(Profile::Standard), &ctx("owner")).unwrap().entries.is_empty());
        assert_eq!(Profile::parse("strict"), Some(Profile::Strict));
    }

    #[test]
    fn profil_le_plus_proche_et_ecarts() {
        let e = state_with(Changes::default().set("session.idle_minutes", json!(30)));
        let (p, d) = closest_profile(&e);
        assert_eq!(p, Profile::Standard);
        assert_eq!(d, vec!["session.idle_minutes"]);
    }

    #[test]
    fn valeur_illisible_retombe_sur_son_defaut() {
        let mut stored = BTreeMap::new();
        stored.insert("session.idle_minutes".to_string(), (StoredValue::plain(json!("abc")), 10));
        stored.insert("session.max_hours".to_string(), (StoredValue::plain(json!(8)), 11));
        stored.insert("cle.future".to_string(), (StoredValue::plain(json!(1)), 12));
        let (e, errors) = build_effective(&stored, &HostCaps::default(), 3);
        assert_eq!(e.int("session.idle_minutes"), 60);
        assert_eq!(e.source("session.idle_minutes"), Source::Default);
        assert_eq!(e.int("session.max_hours"), 8);
        assert_eq!(e.updated_at("session.max_hours"), 11);
        assert_eq!(errors.len(), 2);
        assert!(errors.iter().any(|r| r.key == "session.idle_minutes" && r.code == "invalid_type"));
        assert!(errors.iter().any(|r| r.key == "cle.future" && r.code == "unknown_key"));
        assert!(e.warnings().iter().any(|w| w.key == "session.idle_minutes" && w.code == "read_error"));
    }

    #[test]
    fn verrous_et_plafonds_de_l_hebergeur() {
        let mut host = HostCaps::default();
        host.locked.insert(
            "audit.syslog.url".into(),
            (StoredValue::plain(json!("tcp://siem:514")), "LOCKSY_SYSLOG".into()),
        );
        host.caps.insert("attachment.max_file_mib".into(), (5, "LOCKSY_MAX_ATTACHMENT_MIB".into()));
        let mut stored = BTreeMap::new();
        stored.insert("attachment.max_file_mib".to_string(), (StoredValue::plain(json!(12)), 1));
        let (e, _) = build_effective(&stored, &host, 1);
        assert_eq!(e.str("audit.syslog.url"), "tcp://siem:514");
        assert_eq!(e.source("audit.syslog.url"), Source::HostLocked);
        assert_eq!(e.entry("audit.syslog.url").unwrap().locked_by.as_deref(), Some("LOCKSY_SYSLOG"));
        assert_eq!(e.int("attachment.max_file_mib"), 5);
        assert!(e.warnings().iter().any(|w| w.code == "capped_by_host"));

        let mut c = ctx("owner");
        c.host = host;
        let r = validate(&e, &one("audit.syslog.url", json!("tcp://autre:514")), &c);
        assert_eq!(r, Err(Rejection::HostLocked(vec!["audit.syslog.url".into()])));
        let err = invalid(validate(&e, &one("attachment.max_file_mib", json!(6)), &c), "attachment.max_file_mib");
        assert_eq!((err.code, err.params["max"].clone()), ("out_of_range", json!(5)));
    }

    #[test]
    fn types_et_bornes() {
        let cur = base();
        let c = ctx("owner");
        let e = invalid(validate(&cur, &one("session.idle_minutes", json!(2)), &c), "session.idle_minutes");
        assert_eq!((e.code, e.params["min"].clone(), e.params["max"].clone()), ("out_of_range", json!(5), json!(1440)));
        assert_eq!(invalid(validate(&cur, &one("session.idle_minutes", json!("30")), &c), "session.idle_minutes").code, "invalid_type");
        assert_eq!(invalid(validate(&cur, &one("inconnue.cle", json!(1)), &c), "inconnue.cle").code, "unknown_key");
        assert_eq!(invalid(validate(&cur, &one("extension.http_fill", json!("x")), &c), "extension.http_fill").code, "invalid_value");
        assert_eq!(
            invalid(validate(&cur, &one("branding.org_name", json!("x".repeat(61))), &c), "branding.org_name").code,
            "too_long"
        );
        assert_eq!(invalid(validate(&cur, &one("legal.notice_url", json!("http://a.fr")), &c), "legal.notice_url").code, "https_required");
        assert_eq!(invalid(validate(&cur, &one("legal.notice_url", json!("pas une url")), &c), "legal.notice_url").code, "invalid_url");
        assert_eq!(invalid(validate(&cur, &one("mail.from", json!("pas@")), &c), "mail.from").code, "invalid_email");
        assert_eq!(invalid(validate(&cur, &one("branding.accent_color", json!("vert")), &c), "branding.accent_color").code, "invalid_color");
        let e = invalid(validate(&cur, &one("access.ip_allowlist", json!(["10.0.0.0/33"])), &c), "access.ip_allowlist");
        assert_eq!((e.code, e.params["value"].clone()), ("invalid_cidr", json!("10.0.0.0/33")));
        assert_eq!(
            invalid(validate(&cur, &one("access.allowed_email_domains", json!(["a b.fr"])), &c), "access.allowed_email_domains").code,
            "invalid_domain"
        );
        assert_eq!(invalid(validate(&cur, &one("twofa.required_roles", json!(["chef"])), &c), "twofa.required_roles").code, "invalid_role");
        let trop: Vec<String> = (0..501).map(|i| format!("mot{i}")).collect();
        assert_eq!(invalid(validate(&cur, &one("master_password.banned_words", json!(trop)), &c), "master_password.banned_words").code, "too_many");
        assert_eq!(
            invalid(validate(&cur, &one("master_password.banned_words", json!(["a\u{7}b"])), &c), "master_password.banned_words").code,
            "invalid_word"
        );
        assert_eq!(invalid(validate(&cur, &one("branding.logo", json!("data:image/gif;base64,AAAA")), &c), "branding.logo").code, "invalid_image");
        assert_eq!(invalid(validate(&cur, &one("i18n.timezone", json!("Mars/Olympus")), &c), "i18n.timezone").code, "invalid_timezone");
        assert_eq!(
            invalid(validate(&cur, &one("extension.allowed_ids", json!(["zzz"])), &c), "extension.allowed_ids").code,
            "invalid_extension_id"
        );
        assert_eq!(
            invalid(validate(&cur, &one("users.disable_after_inactive_days", json!(10)), &c), "users.disable_after_inactive_days").code,
            "out_of_range"
        );
        assert_eq!(invalid(validate(&cur, &one("generator.symbols", json!("abc")), &c), "generator.symbols").code, "invalid_value");
        assert_eq!(invalid(validate(&cur, &one("branding.totp_issuer", json!("A:B")), &c), "branding.totp_issuer").code, "invalid_value");
        // Mode sur une clé qui n'en a pas ; bornes hors du mode « par défaut ».
        let sans_mode = Changes(BTreeMap::from([(
            "session.max_hours".to_string(),
            Change::Set(StoredValue { value: json!(8), mode: Some(Mode::Enforced), min: None, max: None }),
        )]));
        assert_eq!(invalid(validate(&cur, &sans_mode, &c), "session.max_hours").code, "not_modes");
        let impose_borne = Changes(BTreeMap::from([(
            "client.autolock_minutes".to_string(),
            Change::Set(StoredValue { value: json!(5), mode: None, min: None, max: Some(json!(30)) }),
        )]));
        assert!(validate(&cur, &impose_borne, &c).is_ok());
        // Normalisation : domaines en minuscules, doublons retirés, rôles ordonnés.
        let d = validate(&cur, &one("access.allowed_email_domains", json!(["Exemple.FR", "exemple.fr"])), &c).unwrap();
        assert_eq!(d.entries[0].new.value, json!(["exemple.fr"]));
        let d = validate(&cur, &one("twofa.required_roles", json!(["user", "owner"])), &c).unwrap();
        assert_eq!(d.entries[0].new.value, json!(["owner", "user"]));
    }

    #[test]
    fn valeur_identique_ignoree_et_retour_au_defaut() {
        let cur = state_with(one("session.idle_minutes", json!(30)));
        let c = ctx("owner");
        assert!(validate(&cur, &one("session.idle_minutes", json!(30)), &c).unwrap().entries.is_empty());
        let d = validate(&cur, &Changes::default().reset("session.idle_minutes"), &c).unwrap();
        assert_eq!(d.entries[0].new.value, json!(60));
        assert!(d.entries[0].lowered, "60 min d'inactivité au lieu de 30 : abaissement");
    }

    #[test]
    fn json_de_patch() {
        let c: Changes = serde_json::from_value(json!({
            "session.max_hours": 8,
            "client.autolock_minutes": { "value": 10, "mode": "default", "max": 30 },
            "branding.logo": null
        }))
        .unwrap();
        assert_eq!(c.0["session.max_hours"], Change::Set(StoredValue::plain(json!(8))));
        assert_eq!(c.0["branding.logo"], Change::Reset);
        let Change::Set(sv) = &c.0["client.autolock_minutes"] else { panic!() };
        assert_eq!((sv.mode, sv.max_i64()), (Some(Mode::Default), Some(30)));
        assert!(serde_json::from_value::<Changes>(json!({ "x": { "value": 1, "mode": "toujours" } })).is_err());
        // Valeur nue : mode et bornes conservés.
        let cur = state_with(Changes::default().set_full("client.autolock_minutes", json!(10), Mode::Default, None, Some(30)));
        let d = validate(&cur, &one("client.autolock_minutes", json!(15)), &ctx("owner")).unwrap();
        assert_eq!(d.entries[0].new, StoredValue { value: json!(15), mode: Some(Mode::Default), min: None, max: Some(json!(30)) });
        // Forme JSON stable d'un réglage à modes (borne absente = null).
        let d = def("client.autolock_minutes").unwrap();
        let j = stored_to_json(d, &d.default_stored());
        assert_eq!(j, json!({ "value": 10, "mode": "default", "min": null, "max": null }));
        assert_eq!(stored_from_json(d, &j).unwrap(), d.default_stored());
    }

    // --- Règles croisées : une par test.

    #[test]
    fn regle_inactivite_et_duree_de_session() {
        let c = ctx("owner");
        cross(validate(&base(), &one("session.idle_minutes", json!(1000)).set("session.max_hours", json!(12)), &c), "session.idle_minutes", "idle_within_max");
        let longue = state_with(one("session.idle_minutes", json!(120)));
        cross(validate(&longue, &one("session.max_hours", json!(1)), &c), "session.max_hours", "idle_within_max");
    }

    #[test]
    fn regle_seuils_de_blocage() {
        cross(validate(&base(), &one("lockout.pair_threshold", json!(20)).set("lockout.account_threshold", json!(20)), &ctx("owner")), "lockout.pair_threshold", "lockout_thresholds");
    }

    #[test]
    fn regle_delais_de_blocage() {
        cross(validate(&base(), &one("lockout.base_delay_seconds", json!(600)).set("lockout.max_delay_seconds", json!(60)), &ctx("owner")), "lockout.base_delay_seconds", "lockout_delays");
    }

    #[test]
    fn regle_plancher_memoire_kdf() {
        cross(validate(&base(), &one("kdf.min_memory_mib", json!(128)), &ctx("owner")), "kdf.min_memory_mib", "kdf_memory_floor");
    }

    #[test]
    fn regle_plancher_iterations_kdf() {
        cross(validate(&base(), &one("kdf.min_iterations", json!(5)), &ctx("owner")), "kdf.min_iterations", "kdf_iterations_floor");
    }

    #[test]
    fn regle_longueur_du_generateur() {
        cross(validate(&base(), &one("generator.min_length", json!(30)), &ctx("owner")), "generator.min_length", "generator_length");
    }

    #[test]
    fn regle_mots_du_generateur() {
        cross(validate(&base(), &one("generator.min_words", json!(8)), &ctx("owner")), "generator.min_words", "generator_words");
    }

    #[test]
    fn regle_expiration_des_liens() {
        cross(validate(&base(), &one("share.max_expiry_minutes", json!(60)), &ctx("owner")), "share.max_expiry_minutes", "share_expiry");
    }

    #[test]
    fn regle_consultations_des_liens() {
        cross(validate(&base(), &one("share.default_views", json!(5)).set("share.max_views", json!(3)), &ctx("owner")), "share.default_views", "share_views");
    }

    #[test]
    fn regle_piece_jointe_et_taille_de_requete() {
        let mut c = ctx("owner");
        c.host.max_body_mib = 16;
        assert!(validate(&base(), &one("attachment.max_file_mib", json!(11)), &c).is_ok());
        cross(validate(&base(), &one("attachment.max_file_mib", json!(12)), &c), "attachment.max_file_mib", "attachment_body");
    }

    #[test]
    fn regle_valeur_dans_les_bornes_du_mode() {
        let ch = Changes::default().set_full("client.autolock_minutes", json!(45), Mode::Default, None, Some(30));
        cross(validate(&base(), &ch, &ctx("owner")), "client.autolock_minutes", "mode_bounds");
    }

    #[test]
    fn regle_adresse_publique_en_https() {
        let c = ctx("owner");
        let e = invalid(validate(&base(), &one("instance.public_url", json!("http://locksy.exemple.fr")), &c), "instance.public_url");
        assert_eq!(e.code, "https_required");
        assert!(validate(&base(), &one("instance.public_url", json!("http://localhost:8743")), &c).is_ok());
        assert!(validate(&base(), &one("instance.public_url", json!("https://locksy.exemple.fr")), &c).is_ok());
        let mut test = c.clone();
        test.host.env_test = true;
        assert!(validate(&base(), &one("instance.public_url", json!("http://locksy:8743")), &test).is_ok());
    }

    #[test]
    fn regle_notification_suppose_les_e_mails() {
        let c = ctx("owner");
        let cur = state_with(one("mail.notify.invite", json!(false)));
        cross(validate(&cur, &one("mail.notify.invite", json!(true)), &c), "mail.notify.invite", "notify_requires_mail");
        assert!(validate(&cur, &one("mail.notify.invite", json!(true)).set("mail.enabled", json!(true)), &c).is_ok());
        // Désactiver l'envoi ne bloque pas.
        assert!(validate(&base(), &one("mail.enabled", json!(false)), &c).is_ok());
    }

    #[test]
    fn regle_smtp_sans_chiffrement_en_reseau_prive() {
        let c = ctx("owner");
        let ch = one("mail.smtp.host", json!("smtp.exemple.fr")).set("mail.smtp.security", json!("none"));
        cross(validate(&base(), &ch, &c), "mail.smtp.security", "smtp_plain_private_only");
        assert!(validate(&base(), &one("mail.smtp.host", json!("10.0.0.5")).set("mail.smtp.security", json!("none")), &c).is_ok());
        assert!(validate(&base(), &one("mail.smtp.host", json!("relais")).set("mail.smtp.security", json!("none")), &c).is_ok());
    }

    #[test]
    fn regle_couleur_lisible_dans_les_deux_themes() {
        let c = ctx("owner");
        let e = invalid(validate(&base(), &one("branding.accent_color", json!("#ffff00")), &c), "branding.accent_color");
        assert_eq!(e.code, "low_contrast");
        assert!(e.params.contains_key("ratio_light") && e.params.contains_key("ratio_dark"));
        let suggestion = e.params["suggestion"].as_str().expect("nuance proposée").to_string();
        assert!(accent_ok(&suggestion).is_ok(), "{suggestion}");
        assert!(validate(&base(), &one("branding.accent_color", json!(suggestion)), &c).is_ok());
        // La couleur de Locksy reste permise : ses teintes viennent des jetons.
        assert!(check_accent(&json!(DEFAULT_ACCENT)).is_ok());
    }

    #[test]
    fn regle_methode_de_connexion_activee() {
        let mut c = ctx("owner");
        c.ldap_login_enabled = false;
        c.sso_enabled = false;
        assert_eq!(invalid(validate(&base(), &one("auth.primary_method", json!("ldap")), &c), "auth.primary_method").code, "method_not_enabled");
        assert_eq!(invalid(validate(&base(), &one("sso.enforce", json!(true)), &c), "sso.enforce").code, "method_not_enabled");
        assert!(validate(&base(), &one("auth.primary_method", json!("password")), &c).is_ok());
    }

    // --- Droits et garde-fous.

    #[test]
    fn reserve_aux_proprietaires() {
        let r = validate(&base(), &one("twofa.required", json!(true)).set("session.idle_minutes", json!(30)), &ctx("admin"));
        assert_eq!(r, Err(Rejection::OwnerOnly(vec!["twofa.required".into()])));
        let d = validate(&base(), &one("twofa.required", json!(true)), &ctx("owner")).unwrap();
        assert!(d.requires_owner);
        // Un admin peut modifier une clé ordinaire.
        assert!(!validate(&base(), &one("session.idle_minutes", json!(30)), &ctx("admin")).unwrap().requires_owner);
    }

    #[test]
    fn liste_blanche_sans_l_adresse_de_l_auteur() {
        let c = ctx("owner");
        let e = invalid(validate(&base(), &one("access.ip_allowlist", json!(["10.0.0.0/8"])), &c), "access.ip_allowlist");
        assert_eq!((e.code, e.params["ip"].clone()), ("missing_own_ip", json!("192.0.2.10")));
        assert!(validate(&base(), &one("access.ip_allowlist", json!(["192.0.2.0/24"])), &c).is_ok());
        // Un propriétaire peut passer par une adresse de secours.
        let ch = one("access.ip_allowlist", json!(["10.0.0.0/8"])).set("access.ip_rescue", json!(["192.0.2.10"]));
        assert!(validate(&base(), &ch, &c).is_ok());
        let mut sans_ip = c.clone();
        sans_ip.actor_ip = None;
        assert_eq!(invalid(validate(&base(), &one("access.ip_allowlist", json!(["10.0.0.0/8"])), &sans_ip), "access.ip_allowlist").code, "missing_own_ip");
    }

    #[test]
    fn deux_fa_exigee_sans_la_deux_fa_de_l_auteur() {
        let mut c = ctx("owner");
        c.actor_has_2fa = false;
        assert_eq!(invalid(validate(&base(), &one("twofa.required", json!(true)), &c), "twofa.required").code, "actor_without_2fa");
        assert_eq!(
            invalid(validate(&base(), &one("twofa.required_roles", json!(["owner"])), &c), "twofa.required_roles").code,
            "actor_without_2fa"
        );
        // Une règle qui ne concerne pas son rôle passe.
        assert!(validate(&base(), &one("twofa.required_roles", json!(["user"])), &c).is_ok());
    }

    #[test]
    fn imposer_une_methode_exige_un_test_recent() {
        let mut c = ctx("owner");
        let ch = one("sso.enforce", json!(true));
        assert_eq!(validate(&base(), &ch, &c), Err(Rejection::TestRequired("sso.enforce".into())));
        c.last_test_ok_at.insert("sso", c.now - TEST_VALIDITY_SECS - 1);
        assert_eq!(validate(&base(), &ch, &c), Err(Rejection::TestRequired("sso.enforce".into())));
        c.last_test_ok_at.insert("sso", c.now - 3600);
        assert!(validate(&base(), &ch, &c).is_ok());
        assert_eq!(validate(&base(), &one("ldap.enforce", json!(true)), &c), Err(Rejection::TestRequired("ldap.enforce".into())));
        // Désactiver ne demande aucun test.
        let cur = state_with(one("sso.enforce", json!(true)));
        assert!(validate(&cur, &one("sso.enforce", json!(false)), &ctx("owner")).is_ok());
    }

    // --- Abaissements, par type.

    #[test]
    fn abaissement_booleen() {
        assert!(lowered("twofa.required", one("twofa.required", json!(true)), one("twofa.required", json!(false))));
        assert!(!lowered("twofa.required", Changes::default(), one("twofa.required", json!(true))));
        assert!(lowered("client.autolock_allow_never", one("client.autolock_allow_never", json!(false)), one("client.autolock_allow_never", json!(true))));
        assert!(!lowered("share.enabled", Changes::default(), one("share.enabled", json!(false))));
    }

    #[test]
    fn abaissement_entier() {
        assert!(lowered("session.max_hours", Changes::default(), one("session.max_hours", json!(24))));
        assert!(!lowered("session.max_hours", Changes::default(), one("session.max_hours", json!(8))));
        assert!(lowered("master_password.min_length", Changes::default(), one("master_password.min_length", json!(10))));
        // 0 = sans limite : le moins sûr.
        assert!(lowered("users.disable_after_inactive_days", one("users.disable_after_inactive_days", json!(90)), one("users.disable_after_inactive_days", json!(0))));
        assert!(!lowered("users.disable_after_inactive_days", Changes::default(), one("users.disable_after_inactive_days", json!(90))));
    }

    #[test]
    fn abaissement_enum() {
        assert!(lowered("vault.rotate_on_member_removal", Changes::default(), one("vault.rotate_on_member_removal", json!("off"))));
        assert!(!lowered("vault.rotate_on_member_removal", Changes::default(), one("vault.rotate_on_member_removal", json!("force"))));
        assert!(lowered("extension.http_fill", Changes::default(), one("extension.http_fill", json!("warn"))));
    }

    #[test]
    fn abaissement_listes() {
        // Rôles et mots : un élément retiré.
        assert!(lowered("twofa.required_roles", one("twofa.required_roles", json!(["owner", "admin"])), one("twofa.required_roles", json!(["owner"]))));
        assert!(!lowered("twofa.required_roles", one("twofa.required_roles", json!(["owner"])), one("twofa.required_roles", json!(["owner", "admin"]))));
        assert!(lowered("master_password.banned_words", one("master_password.banned_words", json!(["acme"])), one("master_password.banned_words", json!([]))));
        // Mots à sens inverse (identifiants autorisés) : un élément ajouté.
        let id = "a".repeat(32);
        assert!(lowered("extension.allowed_ids", Changes::default(), one("extension.allowed_ids", json!([id]))));
        // Liste blanche : devient vide, ou s'élargit.
        let from = one("access.allowed_email_domains", json!(["acme.fr"]));
        assert!(lowered("access.allowed_email_domains", from.clone(), one("access.allowed_email_domains", json!([]))));
        assert!(lowered("access.allowed_email_domains", from.clone(), one("access.allowed_email_domains", json!(["acme.fr", "autre.fr"]))));
        assert!(!lowered("access.allowed_email_domains", Changes::default(), one("access.allowed_email_domains", json!(["acme.fr"]))));
        // Restreindre une liste non vide n'abaisse rien.
        let large = one("access.allowed_email_domains", json!(["acme.fr", "autre.fr"]));
        assert!(!lowered("access.allowed_email_domains", large, from));
        // Adresses de secours : tout ajout élargit l'accès.
        assert!(lowered("access.ip_rescue", Changes::default(), one("access.ip_rescue", json!(["192.0.2.10"]))));
    }

    #[test]
    fn abaissement_de_mode_et_de_borne() {
        let impose = Changes::default().set_full("client.autolock_minutes", json!(5), Mode::Enforced, None, None);
        let defaut = Changes::default().set_full("client.autolock_minutes", json!(5), Mode::Default, None, Some(30));
        assert!(lowered("client.autolock_minutes", impose, defaut.clone()));
        let plus_large = Changes::default().set_full("client.autolock_minutes", json!(5), Mode::Default, None, Some(60));
        assert!(lowered("client.autolock_minutes", defaut.clone(), plus_large));
        let plus_court = Changes::default().set_full("client.autolock_minutes", json!(5), Mode::Default, None, Some(15));
        assert!(!lowered("client.autolock_minutes", defaut, plus_court));
        // Sens « plus haut » : borne basse abaissée.
        let lo = |m| Changes::default().set_full("generator.length", json!(20), Mode::Default, Some(m), None);
        assert!(lowered("generator.length", lo(16), lo(12)));
    }

    // --- Règles appliquées par le serveur.

    #[test]
    fn porte_deux_fa_avec_delai_de_grace() {
        let now = 2_000_000_000;
        let e = state_with(one("twofa.required", json!(true)));
        // updated_at = 100 (state_with), délai de 7 jours.
        assert_eq!(twofa_gate(&e, "user", true, 0, now), TwofaGate::NotRequired);
        assert_eq!(twofa_gate(&e, "user", false, 0, now), TwofaGate::Required);
        let created = now - 86_400;
        assert_eq!(twofa_gate(&e, "user", false, created, now), TwofaGate::Grace { deadline: created + 7 * 86_400 });
        let par_role = state_with(one("twofa.required_roles", json!(["admin"])));
        assert_eq!(twofa_gate(&par_role, "user", false, 0, now), TwofaGate::NotRequired);
        assert_eq!(twofa_gate(&par_role, "admin", false, 0, now), TwofaGate::Required);
        let sans_grace = state_with(one("twofa.required", json!(true)).set("twofa.grace_days", json!(0)));
        assert_eq!(twofa_gate(&sans_grace, "user", false, now, now), TwofaGate::Required);
        assert_eq!(twofa_gate(&base(), "user", false, 0, now), TwofaGate::NotRequired);
    }

    /// Deux règles visent le compte : la plus ancienne fixe l'échéance ;
    /// modifier l'autre ne rouvre pas de délai de grâce.
    #[test]
    fn porte_deux_fa_regle_la_plus_ancienne() {
        let now = 2_000_000_000;
        let mut stored = BTreeMap::new();
        stored.insert("twofa.required".to_string(), (StoredValue::plain(json!(true)), 100));
        stored.insert("twofa.required_roles".to_string(), (StoredValue::plain(json!(["admin"])), now - 60));
        let (e, _) = build_effective(&stored, &HostCaps::default(), 2);
        assert_eq!(twofa_gate(&e, "admin", false, 0, now), TwofaGate::Required);
        assert_eq!(twofa_gate(&e, "user", false, 0, now), TwofaGate::Required);
        // Règle par rôle seule, posée il y a une minute : délai pour l'admin.
        stored.remove("twofa.required");
        let (e, _) = build_effective(&stored, &HostCaps::default(), 3);
        assert_eq!(twofa_gate(&e, "admin", false, 0, now), TwofaGate::Grace { deadline: now - 60 + 7 * 86_400 });
        assert_eq!(twofa_gate(&e, "user", false, 0, now), TwofaGate::NotRequired);
    }

    #[test]
    fn liste_blanche_et_adresses_de_secours() {
        assert!(ip_allowed(&base(), ip("203.0.113.5"), "user"));
        let e = state_with(one("access.ip_allowlist", json!(["10.0.0.0/8"])).set("access.ip_rescue", json!(["203.0.113.5"])));
        assert!(ip_allowed(&e, ip("10.1.2.3"), "user"));
        assert!(!ip_allowed(&e, ip("203.0.113.5"), "user"));
        assert!(!ip_allowed(&e, ip("203.0.113.5"), "admin"));
        assert!(ip_allowed(&e, ip("203.0.113.5"), "owner"));
        assert!(ip_allowed(&e, ip("::ffff:10.0.0.1"), "user"));
    }

    #[test]
    fn politique_des_clients() {
        let e = state_with(Changes::default().set_full("client.autolock_minutes", json!(10), Mode::Default, None, Some(30)));
        let p = e.policy_json();
        assert_eq!(p["client.autolock_minutes"], json!({ "value": 10, "mode": "default", "min": 1, "max": 30 }));
        assert_eq!(p["client.lock_on_os_lock"], json!({ "value": true, "mode": "default" }));
        assert_eq!(p["share.max_views"], json!({ "value": 100 }));
        for d in REGISTRY {
            assert_eq!(p.get(d.key).is_some(), d.client, "{}", d.key);
        }
        let impose = state_with(Changes::default().set_full("client.clipboard_clear_seconds", json!(20), Mode::Enforced, None, None));
        assert_eq!(impose.bounds("client.clipboard_clear_seconds"), (Some(20), Some(20)));
    }

    #[test]
    fn contraste() {
        let r = contrast_ratio("#ffffff", "#000000").unwrap();
        assert!((r - 21.0).abs() < 0.01);
        let r = contrast_ratio("#1b6b5f", "#ffffff").unwrap();
        assert!((r - 6.33).abs() < 0.02, "{r}");
        assert!(contrast_ratio("#fff", "#000000").is_none());
    }

    #[test]
    fn images_png_et_webp() {
        let png = [b"\x89PNG\r\n\x1a\n".as_slice(), &[0u8; 16]].concat();
        let url = format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(&png));
        assert_eq!(decode_image(&url, 1024).unwrap().1, "image/png");
        assert_eq!(decode_image(&url, 10).unwrap_err().code, "image_too_large");
        let faux = format!("data:image/webp;base64,{}", base64::engine::general_purpose::STANDARD.encode(&png));
        assert_eq!(decode_image(&faux, 1024).unwrap_err().code, "invalid_image");
        let webp = [b"RIFF\0\0\0\0WEBP".as_slice(), &[0u8; 8]].concat();
        assert_eq!(image_type(&webp), Some("image/webp"));
    }

    #[test]
    fn cidr_lecture_et_appartenance() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.255.0.1")));
        assert!(!c.contains(ip("11.0.0.1")));
        assert!(!c.contains(ip("2001:db8::1")));
        let seul = Cidr::parse("192.168.1.10").unwrap();
        assert!(seul.contains(ip("192.168.1.10")));
        assert!(!seul.contains(ip("192.168.1.11")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8:1::5")));
        assert!(!v6.contains(ip("2001:db9::5")));
        assert!(Cidr::parse("::/0").unwrap().contains(ip("2001:db8::1")));
        assert_eq!(Cidr::parse("::ffff:10.0.0.0/104"), Cidr::parse("10.0.0.0/8"));
        for bad in ["", "10.0.0.0/33", "2001:db8::/129", "abc", "10.0.0.0/x", "::ffff:1.2.3.4/64"] {
            assert!(Cidr::parse(bad).is_none(), "{bad}");
        }
    }

    // --- Fichiers du dépôt lus à l'exécution (absents : test sauté).

    fn repo_file(rel: &str) -> Option<String> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel);
        match std::fs::read_to_string(&p) {
            Ok(s) => Some(s),
            Err(_) => {
                eprintln!("{} absent : test sauté", p.display());
                None
            }
        }
    }

    #[test]
    fn chaque_cle_a_ses_libelles() {
        let Some(text) = repo_file("design/i18n/fr/settings.json") else { return };
        let cat: Map<String, Value> = serde_json::from_str(&text).expect("settings.json lisible");
        let has = |k: &str| cat.get(k).is_some_and(|v| v.as_str().is_some_and(|s| !s.trim().is_empty()));
        for d in REGISTRY {
            for suffix in ["label", "help"] {
                assert!(has(&format!("settings.{}.{suffix}", d.key)), "settings.{}.{suffix} manquant", d.key);
            }
            assert!(cat.get(&format!("settings.{}.synonyms", d.key)).is_some_and(Value::is_array), "synonymes de {}", d.key);
            if let Kind::Enum(values) = d.kind {
                for v in values {
                    assert!(has(&format!("settings.{}.value.{}", d.key, v.to_lowercase())), "{} = {v}", d.key);
                }
            }
        }
        for s in Section::ALL {
            assert!(has(&format!("settings.section.{}.label", s.as_str())), "{s:?}");
        }
        for p in Profile::ALL {
            assert!(has(&format!("settings.profile.{}.label", p.as_str())) && has(&format!("settings.profile.{}.help", p.as_str())));
        }
        for m in ["free", "default", "enforced"] {
            assert!(has(&format!("settings.mode.{m}")));
        }
    }

    #[test]
    fn surfaces_identiques_aux_jetons() {
        let Some(text) = repo_file("design/tokens.json") else { return };
        let t: Value = serde_json::from_str(&text).expect("tokens.json lisible");
        assert_eq!(t["color"]["light"]["surface"], json!(SURFACE_LIGHT));
        assert_eq!(t["color"]["dark"]["surface"], json!(SURFACE_DARK));
    }
}
