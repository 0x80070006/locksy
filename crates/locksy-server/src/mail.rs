//! E-mails et notifications.
//!
//! - **File d'envoi** (`mail_queue`) : une notification est rendue (sujet et
//!   corps) puis mise en file dans la transaction de l'événement ; elle part
//!   avec son commit. Le `worker` l'envoie, avec de nouveaux essais espacés
//!   (1, 5, 15 puis 60 minutes) ; un échec définitif est gardé 30 jours et
//!   peut être renvoyé depuis l'administration.
//! - **Envoi SMTP** : derrière le trait [`MailTransport`]. L'implémentation
//!   [`SmtpTransport`] est minimale (std::net + rustls : TLS implicite ou
//!   STARTTLS, AUTH PLAIN/LOGIN) en attendant la dépendance `lettre`.
//! - **Modèles** : `templates/mail/*.txt` (texte brut, français), habillés de
//!   `branding.*` et `legal.*`.
//!
//! Règles : jamais de secret, de jeton (hors lien d'invitation) ni de nom
//! d'élément ou de coffre dans un message ; les journaux ne portent que
//! l'identifiant, le type et un code d'erreur stable, jamais le corps ni le
//! mot de passe SMTP.

use crate::error::{ApiError, ApiResult};
use crate::security::{normalize_email, uuid_path};
use crate::state::{audit, audit_user, AdminUser, AppState, ClientMeta};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use crate::error::Json;
use locksy_core::crypto::{decrypt_string, new_uuid, SecretKey};
use locksy_core::encoding::b64e;
use locksy_core::now_unix;
use locksy_core::settings::{is_private_host, Effective};
use rusqlite::{params, Connection, OptionalExtension};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use zeroize::Zeroizing;

// ------------------------------------------------------------ Notifications

/// Notification à envoyer. Aucun champ ne porte de secret ni de nom d'élément.
// Contrat C0.10 : les variantes sont construites par les lots L5 (Invite),
// L7a (NewDevice, SecurityChange) et par settings_api (SettingsLowered).
#[allow(dead_code)]
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Notification {
    Invite { invite_id: String, email: String, name: String, link: String, expires_at: i64, inviter: String },
    NewDevice { user_id: String, device: String, ip: String, at: i64 },
    SecurityChange { user_id: String, event: &'static str, at: i64 },
    SettingsLowered { revision: i64, keys: Vec<String>, actor_email: String },
    AdminDigest { period: &'static str },
    Test { to: String },
}

/// Issue d'une demande d'envoi.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyOutcome {
    /// Mise en file (`mail_queue`), envoyée par `worker`.
    Queued,
    /// Envoi désactivé (réglage `mail.enabled` ou notification coupée).
    Disabled,
}

/// Point d'entrée unique des notifications. `enqueue` est appelé dans la
/// transaction de l'événement : la notification part avec son commit.
pub trait Notifier: Send + Sync {
    fn enqueue(&self, c: &Connection, settings: &Effective, n: &Notification) -> ApiResult<NotifyOutcome>;
}

/// Implémentation sans envoi (tests des autres domaines).
#[allow(dead_code)] // contrat C2.8 : à la disposition des tests (srv_with)
#[derive(Debug, Default)]
pub struct NoopNotifier;

impl Notifier for NoopNotifier {
    fn enqueue(&self, _c: &Connection, _settings: &Effective, _n: &Notification) -> ApiResult<NotifyOutcome> {
        Ok(NotifyOutcome::Disabled)
    }
}

/// Notificateur du serveur : mise en file SMTP selon les réglages `mail.*`.
#[derive(Debug, Default)]
pub struct SmtpNotifier;

impl Notifier for SmtpNotifier {
    fn enqueue(&self, c: &Connection, settings: &Effective, n: &Notification) -> ApiResult<NotifyOutcome> {
        enqueue_at(c, settings, n, now_unix())
    }
}

/// Notificateur du serveur.
pub fn build_notifier() -> Arc<dyn Notifier> {
    Arc::new(SmtpNotifier)
}

/// Événements de sécurité notifiés (liste fermée, contrat C0.10) et leur
/// texte : première ligne = sujet, la suite = paragraphe(s) du message.
const SECURITY_EVENTS: &[(&str, &str)] = &[
    ("password.changed", include_str!("../templates/mail/security/password.changed.txt")),
    ("recovery_key.rotated", include_str!("../templates/mail/security/recovery_key.rotated.txt")),
    ("recovery.completed", include_str!("../templates/mail/security/recovery.completed.txt")),
    ("2fa.enabled", include_str!("../templates/mail/security/2fa.enabled.txt")),
    ("2fa.disabled", include_str!("../templates/mail/security/2fa.disabled.txt")),
    ("2fa.recovery_codes_generated", include_str!("../templates/mail/security/2fa.recovery_codes_generated.txt")),
    ("2fa.recovery_code_used", include_str!("../templates/mail/security/2fa.recovery_code_used.txt")),
    ("login.locked", include_str!("../templates/mail/security/login.locked.txt")),
    ("account.disabled", include_str!("../templates/mail/security/account.disabled.txt")),
    ("admin.2fa_reset", include_str!("../templates/mail/security/admin.2fa_reset.txt")),
];

const TPL_INVITE: &str = include_str!("../templates/mail/invite.txt");
const TPL_NEW_DEVICE: &str = include_str!("../templates/mail/new_device.txt");
const TPL_SECURITY_CHANGE: &str = include_str!("../templates/mail/security_change.txt");
const TPL_SETTINGS_LOWERED: &str = include_str!("../templates/mail/settings_lowered.txt");
const TPL_ADMIN_DIGEST: &str = include_str!("../templates/mail/admin_digest.txt");
const TPL_TEST: &str = include_str!("../templates/mail/test.txt");
const TPL_FOOTER: &str = include_str!("../templates/mail/_footer.txt");

/// L'alerte de blocage des connexions n'est pas renvoyée au même compte
/// avant ce délai : un attaquant qui bloque un compte en boucle ne l'inonde
/// pas. Les autres alertes partent toujours (chacune signale un changement).
const LOCKED_DEDUP_SECS: i64 = 15 * 60;

/// Compteurs du résumé des administrateurs : (variable du modèle, actions
/// du journal comptées sur la période).
const DIGEST_COUNTERS: &[(&str, &[&str])] = &[
    ("login_failed", &["login.failed", "ldap.login_failed"]),
    ("login_locked", &["login.locked"]),
    ("twofa_removed", &["2fa.disabled", "admin.2fa_reset"]),
    ("recovered", &["recovery.completed"]),
    ("role_changes", &["admin.user_role"]),
    ("settings_lowered", &["settings.lowered"]),
    ("mail_failed", &["mail.failed"]),
    ("audit_failed", &["audit.verify_failed"]),
];

impl Notification {
    fn kind(&self) -> &'static str {
        match self {
            Notification::Invite { .. } => "invite",
            Notification::NewDevice { .. } => "new_device",
            Notification::SecurityChange { .. } => "security_change",
            Notification::SettingsLowered { .. } => "settings_lowered",
            Notification::AdminDigest { .. } => "admin_digest",
            Notification::Test { .. } => "test",
        }
    }

    /// Notification voulue par les réglages de l'organisation (`mail.notify.*`).
    /// Les alertes de sécurité n'ont pas de préférence personnelle : seul
    /// l'administrateur peut les couper pour toute l'organisation.
    fn wanted(&self, eff: &Effective) -> bool {
        match self {
            Notification::Invite { .. } => eff.bool("mail.notify.invite"),
            Notification::NewDevice { .. } => eff.bool("mail.notify.new_device"),
            Notification::SecurityChange { .. } => eff.bool("mail.notify.security_change"),
            Notification::SettingsLowered { .. } => eff.bool("mail.notify.settings_lowered"),
            Notification::AdminDigest { .. } => matches!(eff.str("mail.notify.admin_digest"), "daily" | "weekly"),
            Notification::Test { .. } => true,
        }
    }
}

/// Destinataire d'une notification.
struct Recipient {
    email: String,
    user_id: Option<String>,
    invite_id: Option<String>,
}

fn active_admins(c: &Connection, roles: &str) -> ApiResult<Vec<Recipient>> {
    let sql = format!("SELECT id, email FROM users WHERE disabled = 0 AND role IN ({roles}) ORDER BY email");
    let mut st = c.prepare(&sql)?;
    let rows = st
        .query_map([], |r| Ok(Recipient { user_id: Some(r.get(0)?), email: r.get(1)?, invite_id: None }))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn recipients(c: &Connection, n: &Notification) -> ApiResult<Vec<Recipient>> {
    let user = |id: &str| -> ApiResult<Vec<Recipient>> {
        let email: Option<String> = c.query_row("SELECT email FROM users WHERE id = ?1", [id], |r| r.get(0)).optional()?;
        Ok(email.map(|email| Recipient { email, user_id: Some(id.to_string()), invite_id: None }).into_iter().collect())
    };
    let mut out = match n {
        Notification::Invite { invite_id, email, .. } => {
            vec![Recipient { email: email.clone(), user_id: None, invite_id: Some(invite_id.clone()) }]
        }
        Notification::NewDevice { user_id, .. } | Notification::SecurityChange { user_id, .. } => user(user_id)?,
        Notification::SettingsLowered { .. } => active_admins(c, "'owner'")?,
        Notification::AdminDigest { .. } => active_admins(c, "'owner', 'admin'")?,
        Notification::Test { to } => vec![Recipient { email: to.clone(), user_id: None, invite_id: None }],
    };
    // Une adresse mal formée (ou qui tenterait d'injecter un en-tête) n'est
    // jamais mise en file.
    out.retain(|r| valid_address(&r.email));
    Ok(out)
}

/// Rend et met en file une notification à l'instant `now`.
pub(crate) fn enqueue_at(c: &Connection, eff: &Effective, n: &Notification, now: i64) -> ApiResult<NotifyOutcome> {
    if !eff.bool("mail.enabled") || !n.wanted(eff) {
        return Ok(NotifyOutcome::Disabled);
    }
    let Some((subject, body)) = render_notification(c, eff, n, now)? else {
        return Ok(NotifyOutcome::Disabled);
    };
    let to = recipients(c, n)?;
    if to.is_empty() {
        return Ok(NotifyOutcome::Disabled);
    }
    let kind = n.kind();
    let dedup = matches!(n, Notification::SecurityChange { event, .. } if *event == "login.locked");
    for r in &to {
        if dedup {
            let recent: i64 = c.query_row(
                "SELECT COUNT(*) FROM mail_queue WHERE kind = 'security_change' AND related_user_id = ?1
                 AND subject = ?2 AND created_at > ?3",
                params![r.user_id, subject, now - LOCKED_DEDUP_SECS],
                |row| row.get(0),
            )?;
            if recent > 0 {
                continue;
            }
        }
        c.execute(
            "INSERT INTO mail_queue (id, kind, to_email, subject, body_text, status, attempts, next_attempt_at,
                 created_at, updated_at, related_user_id, related_invite_id)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6, ?6, ?7, ?8)",
            params![new_uuid(), kind, r.email, subject, body, now, r.user_id, r.invite_id],
        )?;
    }
    // Une alerte de blocage écartée comme doublon compte comme envoyée : la
    // personne a déjà reçu (ou va recevoir) la même alerte.
    wake_worker();
    Ok(NotifyOutcome::Queued)
}

// ------------------------------------------------------------ Modèles

/// Contexte commun des modèles : habillage de l'organisation.
struct Ctx {
    tz: String,
    vars: Vec<(&'static str, String)>,
}

impl Ctx {
    fn new(eff: &Effective) -> Self {
        let org = clean(eff.str("branding.org_name"), 60);
        let no_reply = if eff.str("mail.reply_to").is_empty() {
            "Ce message est envoyé automatiquement : merci de ne pas y répondre."
        } else {
            ""
        };
        Ctx {
            tz: eff.str("i18n.timezone").to_string(),
            vars: vec![
                ("org", if org.is_empty() { "Locksy".into() } else { org }),
                ("url", clean(eff.str("instance.public_url"), 300)),
                ("support", clean(eff.str("branding.support_contact"), 120)),
                ("dpo", clean(eff.str("legal.dpo_contact"), 120)),
                ("privacy_url", clean(eff.str("legal.privacy_url"), 300)),
                ("notice_url", clean(eff.str("legal.notice_url"), 300)),
                ("no_reply", no_reply.into()),
            ],
        }
    }

    fn date(&self, ts: i64) -> String {
        format_local(ts, &self.tz)
    }

    fn with(&self, extra: Vec<(&'static str, String)>) -> Vec<(&'static str, String)> {
        let mut v = self.vars.clone();
        v.extend(extra);
        v
    }
}

/// Texte d'une valeur insérée dans un message : sans caractère de contrôle
/// (ni retour à la ligne), tronqué.
fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_string()
}

/// Sépare un modèle : première ligne = sujet, le reste = corps.
fn split_template(tpl: &str) -> (&str, &str) {
    let (subject, body) = tpl.split_once('\n').unwrap_or((tpl, ""));
    (subject.trim_end_matches('\r'), body)
}

/// Remplace `{{nom}}` par sa valeur. Une ligne qui contient une variable
/// facultative `{{?nom}}` vide est retirée (contact absent, etc.).
fn render(tpl: &str, vars: &[(&'static str, String)]) -> String {
    let lookup = |name: &str| vars.iter().find(|(k, _)| *k == name).map(|(_, v)| v.as_str());
    let mut out = Vec::new();
    'lines: for line in tpl.replace("\r\n", "\n").lines() {
        let mut rendered = String::with_capacity(line.len());
        let mut rest = line;
        while let Some(start) = rest.find("{{") {
            rendered.push_str(&rest[..start]);
            let Some(len) = rest[start..].find("}}") else {
                rendered.push_str(&rest[start..]);
                rest = "";
                break;
            };
            let token = &rest[start + 2..start + len];
            let (optional, name) = match token.strip_prefix('?') {
                Some(n) => (true, n),
                None => (false, token),
            };
            let value = lookup(name).unwrap_or_default();
            debug_assert!(lookup(name).is_some(), "variable de modèle inconnue : {name}");
            if optional && value.is_empty() {
                continue 'lines;
            }
            rendered.push_str(value);
            rest = &rest[start + len + 2..];
        }
        rendered.push_str(rest);
        out.push(rendered);
    }
    // Pas de lignes vides en tête ni en fin.
    while out.first().is_some_and(|l| l.trim().is_empty()) {
        out.remove(0);
    }
    while out.last().is_some_and(|l| l.trim().is_empty()) {
        out.pop();
    }
    out.join("\n")
}

/// Sujet et corps (pied de page compris) d'un modèle.
fn render_full(tpl: &str, vars: &[(&'static str, String)]) -> (String, String) {
    let (subject, body) = split_template(tpl);
    let subject = clean(&render(subject, vars), 200);
    let body = format!("{}\n\n{}\n", render(body, vars), render(TPL_FOOTER, vars));
    (subject, body)
}

/// Rend une notification ; `None` : rien à envoyer (résumé vide, événement
/// inconnu).
fn render_notification(c: &Connection, eff: &Effective, n: &Notification, now: i64) -> ApiResult<Option<(String, String)>> {
    let ctx = Ctx::new(eff);
    let out = match n {
        Notification::Invite { link, expires_at, inviter, name, .. } => {
            let inviter = clean(inviter, 120);
            let name = clean(name, 120);
            let vars = ctx.with(vec![
                ("greeting", if name.is_empty() { "Bonjour,".into() } else { format!("Bonjour {name},") }),
                ("inviter", if inviter.is_empty() { "Votre administrateur".into() } else { inviter }),
                ("link", clean(link, 2000)),
                ("expires", ctx.date(*expires_at)),
            ]);
            render_full(TPL_INVITE, &vars)
        }
        Notification::NewDevice { device, ip, at, .. } => {
            let device = clean(device, 120);
            let vars = ctx.with(vec![
                ("date", ctx.date(*at)),
                ("device", if device.is_empty() { "inconnu".into() } else { device }),
                ("ip", clean(ip, 64)),
            ]);
            render_full(TPL_NEW_DEVICE, &vars)
        }
        Notification::SecurityChange { event, at, .. } => {
            let Some((_, tpl)) = SECURITY_EVENTS.iter().find(|(e, _)| e == event) else {
                tracing::warn!(event = *event, "événement de sécurité sans modèle : notification ignorée");
                return Ok(None);
            };
            let (subject, text) = split_template(tpl);
            let base = ctx.with(vec![("date", ctx.date(*at))]);
            let vars = ctx.with(vec![
                ("date", ctx.date(*at)),
                ("event_subject", render(subject, &base)),
                ("event_text", render(text, &base)),
            ]);
            render_full(TPL_SECURITY_CHANGE, &vars)
        }
        Notification::SettingsLowered { revision, keys, actor_email } => {
            let keys: Vec<String> = keys.iter().map(|k| clean(k, 64)).collect();
            let actor = clean(actor_email, 254);
            let vars = ctx.with(vec![
                ("actor", if actor.is_empty() { "Un administrateur".into() } else { actor }),
                ("revision", revision.to_string()),
                ("keys", keys.join(", ")),
            ]);
            render_full(TPL_SETTINGS_LOWERED, &vars)
        }
        Notification::AdminDigest { period } => {
            let Some((start, end)) = digest_window(period, now) else { return Ok(None) };
            let mut vars = ctx.with(vec![
                ("period", if *period == "weekly" { "hebdomadaire" } else { "quotidien" }.to_string()),
                ("from", format_local(start, &ctx.tz)),
                ("to", format_local(end, &ctx.tz)),
            ]);
            let mut any = false;
            for (name, actions) in DIGEST_COUNTERS {
                let list = actions.iter().map(|a| format!("'{a}'")).collect::<Vec<_>>().join(", ");
                let n: i64 = c.query_row(
                    &format!("SELECT COUNT(*) FROM audit WHERE at >= ?1 AND at < ?2 AND action IN ({list})"),
                    params![start, end],
                    |r| r.get(0),
                )?;
                any |= n > 0;
                vars.push((name, if n > 0 { n.to_string() } else { String::new() }));
            }
            let weak: i64 = c.query_row(
                "SELECT COUNT(*) FROM users WHERE disabled = 0 AND role IN ('owner', 'admin') AND totp_secret IS NULL",
                [],
                |r| r.get(0),
            )?;
            any |= weak > 0;
            vars.push(("admins_without_2fa", if weak > 0 { weak.to_string() } else { String::new() }));
            if !any {
                return Ok(None);
            }
            render_full(TPL_ADMIN_DIGEST, &vars)
        }
        Notification::Test { .. } => render_full(TPL_TEST, &ctx.with(vec![("date", ctx.date(now))])),
    };
    Ok(Some(out))
}

// ------------------------------------------------------------ Dates

const DAY: i64 = 86_400;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Jour (depuis 1970) du dernier dimanche d'un mois.
fn last_sunday(y: i64, m: i64) -> i64 {
    let last = if m == 12 { days_from_civil(y + 1, 1, 1) } else { days_from_civil(y, m + 1, 1) } - 1;
    // 1970-01-01 était un jeudi : (jours + 4) mod 7 = 0 un dimanche.
    last - (last + 4).rem_euclid(7)
}

/// Heure d'été de l'Union européenne : du dernier dimanche de mars au
/// dernier dimanche d'octobre, à 01:00 UTC.
fn eu_summer(ts: i64) -> bool {
    let (y, _, _) = civil_from_days(ts.div_euclid(DAY));
    let start = last_sunday(y, 3) * DAY + 3600;
    let end = last_sunday(y, 10) * DAY + 3600;
    (start..end).contains(&ts)
}

/// Décalage (minutes) d'un fuseau à l'instant `ts`. Table restreinte, sans
/// base de fuseaux : UTC, Etc/GMT±N, Europe/* (règles de l'UE), outre-mer
/// français. Fuseau inconnu : `None` (affichage en UTC).
fn tz_offset_minutes(tz: &str, ts: i64) -> Option<i64> {
    const FIXED: &[(&str, i64)] = &[
        ("UTC", 0),
        ("Etc/UTC", 0),
        ("GMT", 0),
        ("Europe/Moscow", 180),
        ("Europe/Istanbul", 180),
        ("Europe/Minsk", 180),
        ("Europe/Kaliningrad", 120),
        ("Europe/Samara", 240),
        ("Indian/Reunion", 240),
        ("Indian/Mayotte", 180),
        ("America/Martinique", -240),
        ("America/Guadeloupe", -240),
        ("America/Cayenne", -180),
        ("Pacific/Noumea", 660),
        ("Pacific/Tahiti", -600),
        ("Pacific/Marquesas", -570),
        ("Pacific/Gambier", -540),
        ("Pacific/Wallis", 720),
    ];
    const EU_WET: &[&str] = &["Europe/London", "Europe/Dublin", "Europe/Lisbon", "Atlantic/Canary", "Atlantic/Madeira"];
    const EU_EET: &[&str] = &[
        "Europe/Helsinki",
        "Europe/Athens",
        "Europe/Bucharest",
        "Europe/Sofia",
        "Europe/Kyiv",
        "Europe/Kiev",
        "Europe/Riga",
        "Europe/Tallinn",
        "Europe/Vilnius",
        "Europe/Chisinau",
        "Asia/Nicosia",
    ];
    if let Some((_, off)) = FIXED.iter().find(|(z, _)| *z == tz) {
        return Some(*off);
    }
    if let Some(rest) = tz.strip_prefix("Etc/GMT") {
        // Convention POSIX inversée : Etc/GMT-2 = UTC+2.
        let n: i64 = rest.parse().ok().filter(|n: &i64| (-14..=12).contains(n))?;
        return Some(-n * 60);
    }
    let summer = i64::from(eu_summer(ts)) * 60;
    if EU_WET.contains(&tz) {
        return Some(summer);
    }
    if EU_EET.contains(&tz) {
        return Some(120 + summer);
    }
    tz.starts_with("Europe/").then_some(60 + summer)
}

/// Date lisible dans le fuseau de l'organisation : « 18/11/2026 à 11 h 05 (UTC+1) ».
fn format_local(ts: i64, tz: &str) -> String {
    let off = tz_offset_minutes(tz, ts).unwrap_or(0);
    let local = ts + off * 60;
    let (y, m, d) = civil_from_days(local.div_euclid(DAY));
    let secs = local.rem_euclid(DAY);
    let label = match off {
        0 => "UTC".to_string(),
        o => {
            let sign = if o < 0 { '-' } else { '+' };
            let (h, mi) = (o.abs() / 60, o.abs() % 60);
            if mi == 0 {
                format!("UTC{sign}{h}")
            } else {
                format!("UTC{sign}{h}:{mi:02}")
            }
        }
    };
    format!("{d:02}/{m:02}/{y:04} à {} h {:02} ({label})", secs / 3600, secs % 3600 / 60)
}

/// Date d'en-tête RFC 5322 (UTC).
fn rfc5322_date(ts: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = ts.div_euclid(DAY);
    let secs = ts.rem_euclid(DAY);
    let (y, m, d) = civil_from_days(days);
    let wd = DAYS[days.rem_euclid(7) as usize];
    let mon = MONTHS[(m - 1) as usize];
    format!("{wd}, {d} {mon} {y:04} {:02}:{:02}:{:02} +0000", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// Période close couverte par le résumé envoyé à `now` : la veille (UTC)
/// pour le résumé quotidien, la semaine précédente (lundi à lundi) pour
/// l'hebdomadaire.
fn digest_window(period: &str, now: i64) -> Option<(i64, i64)> {
    let today = now.div_euclid(DAY) * DAY;
    match period {
        "daily" => Some((today - DAY, today)),
        "weekly" => {
            // Lundi : (jours + 3) mod 7 = 0.
            let monday = today - (now.div_euclid(DAY) + 3).rem_euclid(7) * DAY;
            Some((monday - 7 * DAY, monday))
        }
        _ => None,
    }
}

// ------------------------------------------------------------ Résumé des administrateurs

/// Met en file le résumé des administrateurs s'il est dû : une fois par
/// période (`mail.notify.admin_digest`). L'état est gardé dans `mail_queue` :
/// un résumé créé depuis le début de la période, ou une ligne « skipped »
/// quand il n'y avait rien à signaler (ce qui évite de recompter le journal
/// à chaque tour du worker).
pub(crate) fn enqueue_digest_if_due(c: &Connection, eff: &Effective, now: i64) -> ApiResult<NotifyOutcome> {
    let period: &'static str = match eff.str("mail.notify.admin_digest") {
        "daily" => "daily",
        "weekly" => "weekly",
        _ => return Ok(NotifyOutcome::Disabled),
    };
    if !eff.bool("mail.enabled") {
        return Ok(NotifyOutcome::Disabled);
    }
    let Some((_, period_start)) = digest_window(period, now) else { return Ok(NotifyOutcome::Disabled) };
    let done: i64 = c.query_row(
        "SELECT COUNT(*) FROM mail_queue WHERE kind = 'admin_digest' AND created_at >= ?1",
        [period_start],
        |r| r.get(0),
    )?;
    if done > 0 {
        return Ok(NotifyOutcome::Disabled);
    }
    let outcome = enqueue_at(c, eff, &Notification::AdminDigest { period }, now)?;
    if outcome == NotifyOutcome::Disabled {
        c.execute(
            "INSERT INTO mail_queue (id, kind, to_email, subject, body_text, status, attempts, next_attempt_at,
                 created_at, updated_at)
             VALUES (?1, 'admin_digest', '', '', '', 'skipped', 0, ?2, ?2, ?2)",
            params![new_uuid(), now],
        )?;
    }
    Ok(outcome)
}

// ------------------------------------------------------------ Envoi

/// Message prêt à partir.
#[derive(Clone, Debug)]
pub struct OutgoingMail {
    /// Identifiant de la file (sert au Message-ID).
    pub id: String,
    pub from: String,
    pub from_name: String,
    pub reply_to: String,
    pub to: String,
    pub subject: String,
    pub text: String,
    pub date: i64,
}

/// Échec d'envoi : code stable seulement (jamais le texte du serveur, qui
/// pourrait reprendre une adresse ou un identifiant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendError {
    /// smtp_connect | smtp_tls | smtp_auth | smtp_rejected | smtp_timeout | smtp_insecure
    pub code: &'static str,
}

const fn fail(code: &'static str) -> SendError {
    SendError { code }
}

/// Moyen d'envoi. Implémentation actuelle : [`SmtpTransport`] ; la bascule
/// vers `lettre` se fera derrière ce même trait.
pub trait MailTransport: Send + Sync {
    fn send(&self, m: &OutgoingMail) -> Result<(), SendError>;
}

/// Transport indisponible (configuration refusée) : chaque envoi échoue
/// avec le même code.
struct Unavailable(&'static str);

impl MailTransport for Unavailable {
    fn send(&self, _m: &OutgoingMail) -> Result<(), SendError> {
        Err(fail(self.0))
    }
}

/// Mode de sécurité de la connexion SMTP (`mail.smtp.security`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    None,
    StartTls,
    Tls,
}

/// Délai de connexion TCP.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Délai de chaque commande (lecture comme écriture).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Client SMTP minimal (RFC 5321) : EHLO, STARTTLS ou TLS implicite,
/// AUTH PLAIN/LOGIN, MAIL/RCPT/DATA.
pub struct SmtpTransport {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: String,
    password: Zeroizing<String>,
    pub ehlo: String,
    pub tls: Arc<ClientConfig>,
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
}

impl fmt::Debug for SmtpTransport {
    // Le mot de passe n'apparaît jamais, même dans un journal de débogage.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpTransport")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("security", &self.security)
            .field("username", &self.username)
            .field("password", &if self.password.is_empty() { "" } else { "***" })
            .finish_non_exhaustive()
    }
}

impl SmtpTransport {
    pub fn new(host: &str, port: u16, security: Security, username: &str, password: Zeroizing<String>) -> Self {
        SmtpTransport {
            host: host.to_string(),
            port,
            security,
            username: username.to_string(),
            password,
            ehlo: "localhost".into(),
            tls: tls_config(),
            connect_timeout: CONNECT_TIMEOUT,
            command_timeout: COMMAND_TIMEOUT,
        }
    }

    fn connect(&self) -> Result<TcpStream, SendError> {
        let addrs = (self.host.as_str(), self.port).to_socket_addrs().map_err(|_| fail("smtp_connect"))?;
        let mut last = fail("smtp_connect");
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.connect_timeout) {
                Ok(tcp) => {
                    tcp.set_read_timeout(Some(self.command_timeout)).map_err(|_| fail("smtp_connect"))?;
                    tcp.set_write_timeout(Some(self.command_timeout)).map_err(|_| fail("smtp_connect"))?;
                    return Ok(tcp);
                }
                Err(e) => last = io_fail(&e),
            }
        }
        Err(last)
    }

    fn wrap_tls(&self, tcp: TcpStream) -> Result<StreamOwned<ClientConnection, TcpStream>, SendError> {
        let host = self.host.trim_start_matches('[').trim_end_matches(']').to_string();
        let name = ServerName::try_from(host).map_err(|_| fail("smtp_tls"))?;
        let conn = ClientConnection::new(self.tls.clone(), name).map_err(|_| fail("smtp_tls"))?;
        let mut stream = StreamOwned::new(conn, tcp);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock).map_err(|e| match io_fail(&e).code {
                "smtp_timeout" => fail("smtp_timeout"),
                _ => fail("smtp_tls"),
            })?;
        }
        Ok(stream)
    }

    fn deliver<S: Read + Write>(&self, s: &mut Session<S>, caps: &[String], m: &OutgoingMail) -> Result<(), SendError> {
        if !self.username.is_empty() {
            self.authenticate(s, caps)?;
        }
        s.command(&format!("MAIL FROM:<{}>", m.from), 250, "smtp_rejected")?;
        s.command(&format!("RCPT TO:<{}>", m.to), 250, "smtp_rejected")?;
        s.command("DATA", 354, "smtp_rejected")?;
        s.write_raw(&dot_stuff(&build_message(m)))?;
        s.expect(250, "smtp_rejected")?;
        // La remise est acquise : un QUIT perdu n'y change rien.
        let _ = s.command("QUIT", 221, "smtp_rejected");
        Ok(())
    }

    fn authenticate<S: Read + Write>(&self, s: &mut Session<S>, caps: &[String]) -> Result<(), SendError> {
        let mechs: Vec<String> = caps
            .iter()
            .filter_map(|c| c.strip_prefix("AUTH ").or_else(|| c.strip_prefix("AUTH=")))
            .flat_map(|m| m.split_whitespace().map(str::to_ascii_uppercase))
            .collect();
        if mechs.iter().any(|m| m == "PLAIN") {
            let token = Zeroizing::new(std_b64(format!("\0{}\0{}", self.username, self.password.as_str()).as_bytes()));
            return s.command(&format!("AUTH PLAIN {}", token.as_str()), 235, "smtp_auth").map(drop);
        }
        if mechs.iter().any(|m| m == "LOGIN") {
            s.command("AUTH LOGIN", 334, "smtp_auth")?;
            s.command(&std_b64(self.username.as_bytes()), 334, "smtp_auth")?;
            let pass = Zeroizing::new(std_b64(self.password.as_bytes()));
            return s.command(pass.as_str(), 235, "smtp_auth").map(drop);
        }
        Err(fail("smtp_auth"))
    }
}

impl MailTransport for SmtpTransport {
    fn send(&self, m: &OutgoingMail) -> Result<(), SendError> {
        if !valid_address(&m.from) || !valid_address(&m.to) || (!m.reply_to.is_empty() && !valid_address(&m.reply_to)) {
            return Err(fail("smtp_rejected"));
        }
        let tcp = self.connect()?;
        match self.security {
            Security::Tls => {
                let mut s = Session::new(self.wrap_tls(tcp)?);
                s.expect(220, "smtp_rejected")?;
                let caps = s.ehlo(&self.ehlo)?;
                self.deliver(&mut s, &caps, m)
            }
            Security::None => {
                let mut s = Session::new(tcp);
                s.expect(220, "smtp_rejected")?;
                let caps = s.ehlo(&self.ehlo)?;
                self.deliver(&mut s, &caps, m)
            }
            Security::StartTls => {
                let mut s = Session::new(tcp);
                s.expect(220, "smtp_rejected")?;
                let caps = s.ehlo(&self.ehlo)?;
                if !caps.iter().any(|c| c.eq_ignore_ascii_case("STARTTLS")) {
                    return Err(fail("smtp_tls"));
                }
                s.command("STARTTLS", 220, "smtp_tls")?;
                // Des octets reçus avant la poignée de main seraient injectés
                // en clair dans la session chiffrée : refus.
                if !s.buf.is_empty() {
                    return Err(fail("smtp_tls"));
                }
                let mut s = Session::new(self.wrap_tls(s.stream)?);
                let caps = s.ehlo(&self.ehlo)?;
                self.deliver(&mut s, &caps, m)
            }
        }
    }
}

fn io_fail(e: &io::Error) -> SendError {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => fail("smtp_timeout"),
        io::ErrorKind::InvalidData => fail("smtp_tls"),
        _ => fail("smtp_connect"),
    }
}

/// Dialogue SMTP sur un flux (clair ou TLS).
struct Session<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: Read + Write> Session<S> {
    fn new(stream: S) -> Self {
        Session { stream, buf: Vec::new() }
    }

    fn read_line(&mut self) -> Result<String, SendError> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                return Ok(String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']).to_string());
            }
            if self.buf.len() > 4096 {
                return Err(fail("smtp_rejected"));
            }
            let mut chunk = [0u8; 1024];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(fail("smtp_connect")),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(io_fail(&e)),
            }
        }
    }

    /// Réponse complète (multiligne « 250-… » puis « 250 … ») : code et textes.
    fn reply(&mut self) -> Result<(u16, Vec<String>), SendError> {
        let mut lines = Vec::new();
        loop {
            let line = self.read_line()?;
            let code = line.get(..3).and_then(|c| c.parse::<u16>().ok()).ok_or(fail("smtp_rejected"))?;
            lines.push(line.get(4..).unwrap_or("").to_string());
            if line.as_bytes().get(3) != Some(&b'-') {
                return Ok((code, lines));
            }
            if lines.len() > 100 {
                return Err(fail("smtp_rejected"));
            }
        }
    }

    fn expect(&mut self, want: u16, code: &'static str) -> Result<Vec<String>, SendError> {
        match self.reply()? {
            (got, lines) if got == want => Ok(lines),
            _ => Err(fail(code)),
        }
    }

    fn write_raw(&mut self, data: &str) -> Result<(), SendError> {
        self.stream.write_all(data.as_bytes()).and_then(|()| self.stream.flush()).map_err(|e| io_fail(&e))
    }

    fn command(&mut self, line: &str, want: u16, code: &'static str) -> Result<Vec<String>, SendError> {
        self.write_raw(&format!("{line}\r\n"))?;
        self.expect(want, code)
    }

    /// EHLO (HELO en repli) : capacités annoncées, en majuscules.
    fn ehlo(&mut self, name: &str) -> Result<Vec<String>, SendError> {
        self.write_raw(&format!("EHLO {name}\r\n"))?;
        match self.reply()? {
            (250, lines) => Ok(lines.iter().skip(1).map(|l| l.trim().to_ascii_uppercase()).collect()),
            _ => self.command(&format!("HELO {name}"), 250, "smtp_rejected").map(|_| Vec::new()),
        }
    }
}

/// Autorités de confiance : webpki-roots, plus l'autorité interne lue par
/// [`init_tls`] au démarrage du worker.
static TLS: OnceLock<Arc<ClientConfig>> = OnceLock::new();

fn build_tls(extra: Vec<CertificateDer<'static>>) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in extra {
        roots.add(cert).map_err(|e| format!("certificat d'autorité refusé ({e})"))?;
    }
    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("configuration TLS impossible ({e})"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Configuration TLS des envois (autorités publiques si [`init_tls`] n'a
/// rien chargé).
fn tls_config() -> Arc<ClientConfig> {
    TLS.get_or_init(|| build_tls(Vec::new()).expect("configuration TLS par défaut")).clone()
}

/// Charge l'autorité interne du relais SMTP (`LOCKSY_SMTP_CA_FILE`, PEM).
fn init_tls() {
    let Some(path) = std::env::var_os("LOCKSY_SMTP_CA_FILE").filter(|p| !p.is_empty()) else { return };
    let loaded = crate::syslog::load_ca_file(std::path::Path::new(&path)).and_then(build_tls);
    match loaded {
        Ok(config) => {
            if TLS.set(config).is_ok() {
                tracing::info!("e-mails : autorité de LOCKSY_SMTP_CA_FILE ajoutée");
            }
        }
        Err(e) => tracing::error!("LOCKSY_SMTP_CA_FILE ignoré : {e}"),
    }
}

/// Base64 standard (avec remplissage) : MIME et AUTH.
fn std_b64(data: &[u8]) -> String {
    let mut s = b64e(data).replace('-', "+").replace('_', "/");
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    s
}

/// Adresse e-mail sûre pour un en-tête et une commande SMTP : ASCII visible,
/// une seule arobase, et aucun caractère qui fermerait la commande ou
/// ouvrirait un autre en-tête. Une adresse internationalisée (SMTPUTF8,
/// que le client minimal ne négocie pas) n'est pas envoyée.
fn valid_address(a: &str) -> bool {
    let Some((local, domain)) = a.split_once('@') else { return false };
    a.len() <= 254
        && !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && a.chars().all(|c| c.is_ascii_graphic() && !matches!(c, '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | ':' | '"' | '\\'))
}

/// En-tête encodé RFC 2047 si besoin (texte non ASCII).
fn header_text(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return s.to_string();
    }
    // Mots encodés d'au plus 45 octets de texte, coupés entre deux caractères.
    let mut words = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if cur.len() + ch.len_utf8() > 45 {
            words.push(std::mem::take(&mut cur));
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words.iter().map(|w| format!("=?UTF-8?B?{}?=", std_b64(w.as_bytes()))).collect::<Vec<_>>().join("\r\n ")
}

/// Message RFC 5322 complet, en texte brut UTF-8 encodé en base64.
fn build_message(m: &OutgoingMail) -> String {
    let domain = m.from.rsplit_once('@').map(|(_, d)| d).unwrap_or("localhost");
    let name = clean(&m.from_name, 80).replace('"', "");
    let from = if name.is_empty() {
        format!("<{}>", m.from)
    } else if name.is_ascii() {
        format!("\"{name}\" <{}>", m.from)
    } else {
        format!("{} <{}>", header_text(&name), m.from)
    };
    let mut h = vec![
        format!("Date: {}", rfc5322_date(m.date)),
        format!("From: {from}"),
        format!("To: <{}>", m.to),
    ];
    if !m.reply_to.is_empty() {
        h.push(format!("Reply-To: <{}>", m.reply_to));
    }
    h.extend([
        format!("Subject: {}", header_text(&clean(&m.subject, 200))),
        format!("Message-ID: <{}@{domain}>", m.id),
        "MIME-Version: 1.0".into(),
        "Content-Type: text/plain; charset=utf-8".into(),
        "Content-Transfer-Encoding: base64".into(),
        "Auto-Submitted: auto-generated".into(),
        "X-Auto-Response-Suppress: All".into(),
    ]);
    let text = m.text.replace("\r\n", "\n").replace('\n', "\r\n");
    let body = std_b64(text.as_bytes());
    let lines: Vec<&str> = body.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    format!("{}\r\n\r\n{}\r\n", h.join("\r\n"), lines.join("\r\n"))
}

/// Transparence SMTP : un point en début de ligne est doublé, puis le
/// message se termine par « CRLF . CRLF ».
fn dot_stuff(data: &str) -> String {
    let mut out = String::with_capacity(data.len() + 8);
    for line in data.split("\r\n") {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    // `split` laisse une dernière ligne vide après le CRLF final.
    if data.ends_with("\r\n") {
        out.truncate(out.len() - 2);
    }
    out.push_str(".\r\n");
    out
}

/// Transport selon les réglages effectifs. Refus : `smtp_insecure` (envoi
/// sans chiffrement vers un serveur public), `smtp_connect` (aucun
/// serveur), `smtp_auth` (mot de passe illisible).
pub(crate) fn transport_for(eff: &Effective, server_key: &SecretKey) -> Result<SmtpTransport, SendError> {
    let host = eff.str("mail.smtp.host").trim();
    if host.is_empty() {
        return Err(fail("smtp_connect"));
    }
    let security = match eff.str("mail.smtp.security") {
        "none" => Security::None,
        "tls" => Security::Tls,
        _ => Security::StartTls,
    };
    if security == Security::None && !is_private_host(host) {
        return Err(fail("smtp_insecure"));
    }
    let port = u16::try_from(eff.int("mail.smtp.port")).map_err(|_| fail("smtp_connect"))?;
    let password = smtp_password(eff, server_key)?;
    let mut t = SmtpTransport::new(host, port, security, eff.str("mail.smtp.username"), password);
    if let Some(name) = public_host(eff) {
        t.ehlo = name;
    }
    Ok(t)
}

/// Mot de passe SMTP, enregistré chiffré par la clé serveur (même AAD que
/// l'écriture des réglages secrets). Jamais journalisé.
fn smtp_password(eff: &Effective, server_key: &SecretKey) -> Result<Zeroizing<String>, SendError> {
    let stored = eff.str("mail.smtp.password");
    if stored.is_empty() {
        return Ok(Zeroizing::new(String::new()));
    }
    decrypt_string(server_key, stored, "verrou:v1:setting:mail.smtp.password").map(Zeroizing::new).map_err(|_| {
        tracing::warn!("e-mails : mot de passe SMTP indéchiffrable (clé serveur changée ?) : saisissez-le de nouveau");
        fail("smtp_auth")
    })
}

/// Nom d'hôte de `instance.public_url`.
fn public_host(eff: &Effective) -> Option<String> {
    let url = url::Url::parse(eff.str("instance.public_url")).ok()?;
    url.host_str().map(str::to_string)
}

/// Expéditeur : `mail.from`, sinon une adresse du domaine de l'instance.
fn sender(eff: &Effective) -> (String, String) {
    let org = clean(eff.str("branding.org_name"), 60);
    let name = if org.is_empty() { "Locksy".to_string() } else { org };
    let from = match eff.str("mail.from") {
        "" => format!("locksy@{}", public_host(eff).unwrap_or_else(|| "localhost".into())),
        f => f.to_string(),
    };
    (from, name)
}

fn outgoing(eff: &Effective, id: String, to: String, subject: String, text: String, now: i64) -> OutgoingMail {
    let (from, from_name) = sender(eff);
    OutgoingMail { id, from, from_name, reply_to: eff.str("mail.reply_to").to_string(), to, subject, text, date: now }
}

// ------------------------------------------------------------ File d'envoi

/// Délais avant chaque nouvel essai (après le 1er, 2e, 3e, 4e échec) ; au
/// 5e échec, le message passe en échec définitif.
const RETRY_DELAYS: [i64; 4] = [60, 5 * 60, 15 * 60, 60 * 60];
/// Messages traités par lot.
const BATCH: i64 = 20;
/// Lots au plus par tour du worker.
const MAX_BATCHES: usize = 10;
/// Un envoi resté « sending » plus longtemps (arrêt brutal) est repris.
const STALE_SENDING_SECS: i64 = 10 * 60;
const SENT_KEEP_SECS: i64 = 7 * DAY;
const FAILED_KEEP_SECS: i64 = 30 * DAY;

static WAKE: OnceLock<tokio::sync::Notify> = OnceLock::new();

fn wake() -> &'static tokio::sync::Notify {
    WAKE.get_or_init(tokio::sync::Notify::new)
}

/// Réveille le worker (nouveau message ou renvoi demandé).
fn wake_worker() {
    wake().notify_one();
}

/// Message pris en charge par le worker.
struct Claimed {
    id: String,
    kind: String,
    to: String,
    subject: String,
    body: String,
    attempts: i64,
}

/// Réserve les messages dus (statut `sending`).
fn claim(c: &mut Connection, now: i64) -> ApiResult<Vec<Claimed>> {
    let tx = c.transaction()?;
    tx.execute(
        "UPDATE mail_queue SET status = 'pending', updated_at = ?1 WHERE status = 'sending' AND updated_at < ?2",
        params![now, now - STALE_SENDING_SECS],
    )?;
    let rows = {
        let mut st = tx.prepare(
            "SELECT id, kind, to_email, subject, body_text, attempts FROM mail_queue
             WHERE status = 'pending' AND next_attempt_at <= ?1 ORDER BY next_attempt_at, created_at LIMIT ?2",
        )?;
        let rows = st
            .query_map(params![now, BATCH], |r| {
                Ok(Claimed { id: r.get(0)?, kind: r.get(1)?, to: r.get(2)?, subject: r.get(3)?, body: r.get(4)?, attempts: r.get(5)? })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for m in &rows {
        tx.execute("UPDATE mail_queue SET status = 'sending', updated_at = ?1 WHERE id = ?2", params![now, m.id])?;
    }
    tx.commit()?;
    Ok(rows)
}

fn system_meta() -> ClientMeta {
    ClientMeta { ip: String::new(), user_agent: "locksy-server".into() }
}

/// Issue enregistrée d'un envoi.
enum Recorded {
    Sent,
    /// Nouvel essai programmé (numéro de l'essai échoué).
    Retry(i64),
    /// Échec définitif.
    Failed,
}

/// Enregistre l'issue d'un envoi : envoyé, nouvel essai programmé ou échec
/// définitif (audit `mail.failed`).
fn record(c: &mut Connection, m: &Claimed, result: Result<(), SendError>, now: i64) -> ApiResult<Recorded> {
    let attempts = m.attempts + 1;
    let tx = c.transaction()?;
    let recorded = match result {
        Ok(()) => {
            tx.execute(
                "UPDATE mail_queue SET status = 'sent', attempts = ?1, sent_at = ?2, updated_at = ?2,
                     last_error_code = NULL WHERE id = ?3",
                params![attempts, now, m.id],
            )?;
            Recorded::Sent
        }
        Err(e) => match usize::try_from(attempts - 1).ok().and_then(|i| RETRY_DELAYS.get(i)) {
            Some(delay) => {
                tx.execute(
                    "UPDATE mail_queue SET status = 'pending', attempts = ?1, next_attempt_at = ?2, updated_at = ?3,
                         last_error_code = ?4 WHERE id = ?5",
                    params![attempts, now + delay, now, e.code, m.id],
                )?;
                Recorded::Retry(attempts)
            }
            None => {
                tx.execute(
                    "UPDATE mail_queue SET status = 'failed', attempts = ?1, updated_at = ?2, last_error_code = ?3
                     WHERE id = ?4",
                    params![attempts, now, e.code, m.id],
                )?;
                audit(&tx, None, "", "mail.failed", &m.id, &system_meta(), &format!("{} : {}", m.kind, e.code))?;
                Recorded::Failed
            }
        },
    };
    tx.commit()?;
    Ok(recorded)
}

/// Envoie les messages dus avec `transport`. Renvoie le nombre traité.
pub(crate) async fn deliver_due(state: &AppState, eff: &Effective, transport: Arc<dyn MailTransport>, now: i64) -> ApiResult<usize> {
    let mut done = 0;
    for _ in 0..MAX_BATCHES {
        let batch = state.db.call(move |c| claim(c, now)).await?;
        if batch.is_empty() {
            break;
        }
        let full = batch.len() as i64 == BATCH;
        for m in batch {
            let mail = outgoing(eff, m.id.clone(), m.to.clone(), m.subject.clone(), m.body.clone(), now);
            let t = transport.clone();
            let result = tokio::task::spawn_blocking(move || t.send(&mail)).await.unwrap_or(Err(fail("smtp_connect")));
            // Journal technique : identifiant, type et code stable seulement
            // (jamais l'adresse, le sujet ni le corps).
            let (id, kind, code) = (m.id.clone(), m.kind.clone(), result.err().map(|e| e.code));
            match state.db.call(move |c| record(c, &m, result, now)).await? {
                Recorded::Sent => tracing::debug!(%id, %kind, "e-mail envoyé"),
                Recorded::Retry(essai) => {
                    tracing::warn!(%id, %kind, code = code.unwrap_or(""), essai, "e-mail non envoyé : nouvel essai programmé")
                }
                Recorded::Failed => tracing::warn!(%id, %kind, code = code.unwrap_or(""), "e-mail non envoyé : échec définitif"),
            }
            done += 1;
        }
        if !full {
            break;
        }
    }
    Ok(done)
}

/// Un tour du worker : résumé des administrateurs s'il est dû, puis envoi
/// des messages dus (rien si `mail.enabled` est faux).
pub(crate) async fn run_once(state: &AppState, now: i64) -> ApiResult<usize> {
    let eff = state.effective().await?;
    if !eff.bool("mail.enabled") {
        return Ok(0);
    }
    let digest_eff = eff.clone();
    state.db.call(move |c| enqueue_digest_if_due(c, &digest_eff, now)).await?;
    let transport: Arc<dyn MailTransport> = match transport_for(&eff, &state.server_key) {
        Ok(t) => Arc::new(t),
        Err(e) => Arc::new(Unavailable(e.code)),
    };
    deliver_due(state, &eff, transport, now).await
}

/// Tâche d'envoi de la file : un tour toutes les 15 secondes, ou dès qu'un
/// message est mis en file.
pub async fn worker(state: AppState) {
    init_tls();
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = wake().notified() => {}
        }
        if let Err(e) = run_once(&state, now_unix()).await {
            tracing::warn!(code = e.code, "file d'e-mails : tour en échec");
        }
    }
}

/// Maintenance de la file : envoyés (et marques de résumé vide) gardés
/// 7 jours, échecs 30 jours ; un message resté en attente 30 jours (envoi
/// désactivé entre-temps) est retiré.
pub fn housekeeping(c: &Connection, now: i64) -> ApiResult<()> {
    c.execute(
        "DELETE FROM mail_queue WHERE (status IN ('sent', 'skipped') AND COALESCE(sent_at, updated_at) < ?1)
             OR (status = 'failed' AND updated_at < ?2)
             OR (status IN ('pending', 'sending') AND created_at < ?2)",
        params![now - SENT_KEEP_SECS, now - FAILED_KEEP_SECS],
    )?;
    Ok(())
}

// ------------------------------------------------------------ Routes

/// Routes du lot : e-mail de test, état de la file, renvoi.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/mail/test", post(send_test))
        .route("/admin/mail/queue", get(list_queue))
        .route("/admin/mail/queue/:id/retry", post(retry))
}

/// Envois de test par acteur et par fenêtre de 10 minutes.
const TEST_MAX: u32 = 5;
const TEST_WINDOW_SECS: i64 = 600;

#[derive(Deserialize, Default)]
struct TestIn {
    #[serde(default)]
    to: Option<String>,
}

/// Adresse masquée pour l'affichage et le journal : « c***@exemple.fr ».
fn mask_email(e: &str) -> String {
    match e.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        None => "***".into(),
    }
}

/// 502 email_not_sent avec le code stable de l'échec.
fn not_sent(code: &'static str) -> Response {
    let e = ApiError::new(StatusCode::BAD_GATEWAY, "email_not_sent", "L'e-mail n'a pas pu être envoyé.");
    (e.status, Json(json!({ "error": e.code, "message": e.message, "error_code": code }))).into_response()
}

fn mail_disabled() -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "mail_disabled", "L'envoi des e-mails est désactivé.")
}

/// POST /admin/mail/test : envoi immédiat (hors file) à `to` ou à l'acteur.
async fn send_test(State(state): State<AppState>, AdminUser(admin): AdminUser, body: Option<Json<TestIn>>) -> Response {
    match send_test_inner(&state, &admin, body.map(|Json(b)| b).unwrap_or_default()).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn send_test_inner(state: &AppState, admin: &crate::state::AuthUser, body: TestIn) -> ApiResult<Response> {
    state.limiter.hit(&format!("mail-test:{}", admin.id), TEST_MAX, TEST_WINDOW_SECS)?;
    let eff = state.effective().await?;
    if !eff.bool("mail.enabled") {
        return Err(mail_disabled());
    }
    let to = match body.to.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => normalize_email(t)?,
        None => admin.email.clone(),
    };
    if !valid_address(&to) {
        return Err(ApiError::bad_request("Adresse e-mail invalide."));
    }
    let transport = match transport_for(&eff, &state.server_key) {
        Ok(t) => t,
        Err(e) if e.code == "smtp_insecure" => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "smtp_insecure",
                "Un serveur d'envoi sans chiffrement n'est accepté que sur le réseau interne.",
            ))
        }
        Err(e) => return test_outcome(state, admin, &to, Err(e)).await,
    };
    let now = now_unix();
    let render_eff = eff.clone();
    let n = Notification::Test { to: to.clone() };
    let (subject, text) = state
        .db
        .read(move |c| render_notification(c, &render_eff, &n, now))
        .await?
        .ok_or_else(|| ApiError::internal("modèle de test"))?;
    let mail = outgoing(&eff, new_uuid(), to.clone(), subject, text, now);
    let result = tokio::task::spawn_blocking(move || transport.send(&mail)).await.unwrap_or(Err(fail("smtp_connect")));
    test_outcome(state, admin, &to, result).await
}

/// Journalise l'essai (adresse masquée) et forme la réponse.
async fn test_outcome(state: &AppState, admin: &crate::state::AuthUser, to: &str, result: Result<(), SendError>) -> ApiResult<Response> {
    let (target, details) = (mask_email(to), match result {
        Ok(()) => "envoyé".to_string(),
        Err(e) => format!("échec : {}", e.code),
    });
    let a = admin.clone();
    state.db.call(move |c| audit_user(c, &a, "mail.test_sent", &target, &details)).await?;
    Ok(match result {
        Ok(()) => Json(json!({ "sent": true })).into_response(),
        Err(e) => {
            tracing::warn!(code = e.code, "e-mail de test non envoyé");
            not_sent(e.code)
        }
    })
}

#[derive(Deserialize)]
struct QueueQuery {
    status: Option<String>,
}

/// Ligne de la file vue par l'administration (jamais le corps).
#[derive(Serialize, Debug)]
struct QueueRow {
    id: String,
    kind: String,
    to_email: String,
    subject: String,
    status: String,
    attempts: i64,
    last_error_code: Option<String>,
    created_at: i64,
    updated_at: i64,
    sent_at: Option<i64>,
}

/// GET /admin/mail/queue?status=pending|failed|sent (500 lignes au plus,
/// les plus récentes d'abord). « pending » comprend les envois en cours.
async fn list_queue(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<QueueQuery>,
) -> ApiResult<Json<Vec<QueueRow>>> {
    let filter = match q.status.as_deref() {
        None | Some("") => "WHERE status <> 'skipped'",
        Some("pending") => "WHERE status IN ('pending', 'sending')",
        Some("failed") => "WHERE status = 'failed'",
        Some("sent") => "WHERE status = 'sent'",
        Some(_) => return Err(ApiError::bad_request("Statut inconnu (pending, failed ou sent).")),
    };
    let sql = format!(
        "SELECT id, kind, to_email, subject, status, attempts, last_error_code, created_at, updated_at, sent_at
         FROM mail_queue {filter} ORDER BY created_at DESC, id LIMIT 500"
    );
    let rows = state
        .db
        .read(move |c| {
            let mut st = c.prepare(&sql)?;
            let rows = st
                .query_map([], |r| {
                    Ok(QueueRow {
                        id: r.get(0)?,
                        kind: r.get(1)?,
                        to_email: mask_email(&r.get::<_, String>(2)?),
                        subject: r.get(3)?,
                        status: r.get(4)?,
                        attempts: r.get(5)?,
                        last_error_code: r.get(6)?,
                        created_at: r.get(7)?,
                        updated_at: r.get(8)?,
                        sent_at: r.get(9)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(rows))
}

/// POST /admin/mail/queue/:id/retry : nouvel envoi immédiat d'un message en
/// échec (ou en attente), avec un nouveau cycle d'essais.
async fn retry(State(state): State<AppState>, AdminUser(admin): AdminUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    uuid_path(&id, "Message")?;
    if !state.effective().await?.bool("mail.enabled") {
        return Err(mail_disabled());
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let row: Option<(String, String)> = tx
                .query_row("SELECT status, kind FROM mail_queue WHERE id = ?1", [&id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            let Some((status, kind)) = row else { return Err(ApiError::not_found("Message introuvable.")) };
            if !matches!(status.as_str(), "failed" | "pending") {
                return Err(ApiError::conflict("Ce message est déjà envoyé ou en cours d'envoi."));
            }
            let now = now_unix();
            tx.execute(
                "UPDATE mail_queue SET status = 'pending', attempts = 0, next_attempt_at = ?1, updated_at = ?1 WHERE id = ?2",
                params![now, id],
            )?;
            audit_user(&tx, &admin, "mail.resent", &id, &kind)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    wake_worker();
    Ok(StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_dans_le_fuseau_de_l_organisation() {
        // 18/11/2026 10:05 UTC : heure d'hiver à Paris.
        let hiver = days_from_civil(2026, 11, 18) * DAY + 10 * 3600 + 5 * 60;
        assert_eq!(format_local(hiver, "Europe/Paris"), "18/11/2026 à 11 h 05 (UTC+1)");
        assert_eq!(format_local(hiver, "UTC"), "18/11/2026 à 10 h 05 (UTC)");
        assert_eq!(format_local(hiver, "Etc/GMT-3"), "18/11/2026 à 13 h 05 (UTC+3)");
        assert_eq!(format_local(hiver, "Pacific/Marquesas"), "18/11/2026 à 0 h 35 (UTC-9:30)");
        assert_eq!(format_local(hiver, "Mars/Olympus"), "18/11/2026 à 10 h 05 (UTC)");
        // Heure d'été : du dimanche 29 mars 2026 01:00 UTC au 25 octobre 01:00 UTC.
        let debut = days_from_civil(2026, 3, 29) * DAY + 3600;
        assert_eq!(format_local(debut - 1, "Europe/Paris"), "29/03/2026 à 1 h 59 (UTC+1)");
        assert_eq!(format_local(debut, "Europe/Paris"), "29/03/2026 à 3 h 00 (UTC+2)");
        let fin = days_from_civil(2026, 10, 25) * DAY + 3600;
        assert_eq!(format_local(fin - 1, "Europe/London"), "25/10/2026 à 1 h 59 (UTC+1)");
        assert_eq!(format_local(fin, "Europe/Helsinki"), "25/10/2026 à 3 h 00 (UTC+2)");
        assert_eq!(rfc5322_date(hiver), "Wed, 18 Nov 2026 10:05:00 +0000");
        assert_eq!(civil_from_days(days_from_civil(2024, 2, 29)), (2024, 2, 29));
    }

    #[test]
    fn periodes_du_resume() {
        // Mercredi 18/11/2026 : veille et semaine du lundi 9 au lundi 16.
        let now = days_from_civil(2026, 11, 18) * DAY + 8 * 3600;
        assert_eq!(digest_window("daily", now), Some((days_from_civil(2026, 11, 17) * DAY, days_from_civil(2026, 11, 18) * DAY)));
        assert_eq!(digest_window("weekly", now), Some((days_from_civil(2026, 11, 9) * DAY, days_from_civil(2026, 11, 16) * DAY)));
        assert_eq!(digest_window("off", now), None);
    }

    #[test]
    fn rendu_des_variables_facultatives() {
        let vars = vec![("org", "Exemple".to_string()), ("support", String::new()), ("url", "https://x".into())];
        let out = render("Bonjour {{org}}\nContact : {{?support}}\nAdresse : {{?url}}\n\n", &vars);
        assert_eq!(out, "Bonjour Exemple\nAdresse : https://x");
        assert_eq!(clean("a\r\nBcc: x\u{7}", 100), "aBcc: x");
    }

    #[test]
    fn modeles_complets_et_sans_variable_inconnue() {
        let known = [
            "org", "url", "support", "dpo", "privacy_url", "notice_url", "no_reply", "inviter", "greeting", "link", "expires", "date",
            "device", "ip", "event_subject", "event_text", "actor", "revision", "keys", "period", "from", "to",
            "admins_without_2fa",
        ];
        let mut all: Vec<&str> =
            vec![TPL_INVITE, TPL_NEW_DEVICE, TPL_SECURITY_CHANGE, TPL_SETTINGS_LOWERED, TPL_ADMIN_DIGEST, TPL_TEST, TPL_FOOTER];
        all.extend(SECURITY_EVENTS.iter().map(|(_, t)| *t));
        for tpl in all {
            let (subject, _) = split_template(tpl);
            assert!(!subject.trim().is_empty() && !subject.contains("{{?"), "sujet absent : {tpl}");
            for part in tpl.split("{{").skip(1) {
                let name = part.split("}}").next().unwrap().trim_start_matches('?');
                assert!(
                    known.contains(&name) || DIGEST_COUNTERS.iter().any(|(n, _)| *n == name),
                    "variable inconnue {name}"
                );
            }
        }
        let events: Vec<&str> = SECURITY_EVENTS.iter().map(|(e, _)| *e).collect();
        assert_eq!(
            events,
            [
                "password.changed",
                "recovery_key.rotated",
                "recovery.completed",
                "2fa.enabled",
                "2fa.disabled",
                "2fa.recovery_codes_generated",
                "2fa.recovery_code_used",
                "login.locked",
                "account.disabled",
                "admin.2fa_reset"
            ]
        );
    }

    #[test]
    fn message_mime_et_transparence() {
        let m = OutgoingMail {
            id: "abc".into(),
            from: "locksy@exemple.fr".into(),
            from_name: "Société Exemple".into(),
            reply_to: String::new(),
            to: "alice@exemple.fr".into(),
            subject: "Réglages de sécurité abaissés".into(),
            text: ".début\nfin".into(),
            date: 0,
        };
        let msg = build_message(&m);
        assert!(msg.contains("From: =?UTF-8?B?"), "{msg}");
        assert!(msg.contains("Subject: =?UTF-8?B?"), "{msg}");
        assert!(msg.contains("Message-ID: <abc@exemple.fr>"));
        assert!(!msg.contains("Reply-To"));
        assert!(msg.contains(&std_b64(".début\r\nfin".as_bytes())));
        assert_eq!(dot_stuff("a\r\n.b\r\n"), "a\r\n..b\r\n.\r\n");
        assert_eq!(header_text("Test"), "Test");
        assert_eq!(std_b64(b"\0u\0p"), "AHUAcA==");
    }

    #[test]
    fn adresses_et_hotes() {
        assert!(valid_address("alice@exemple.fr"));
        assert!(valid_address("prenom.nom+tag@sous.exemple.fr"));
        for bad in ["alice", "a@b>\r\nBcc: x@y", "<a@b.fr>", "a b@c.fr", "@exemple.fr", "a@", "a@b@c.fr", "é@exemple.fr", "a@.fr"] {
            assert!(!valid_address(bad), "{bad}");
        }
        assert_eq!(mask_email("camille@exemple.fr"), "c***@exemple.fr");
        for private in ["127.0.0.1", "10.1.2.3", "192.168.0.10", "relais", "smtp.corp", "[::1]", "fd00::1"] {
            assert!(is_private_host(private), "{private}");
        }
        for public in ["smtp.exemple.fr", "8.8.8.8", "2001:db8::1"] {
            assert!(!is_private_host(public), "{public}");
        }
    }

    #[test]
    fn mot_de_passe_jamais_affiche() {
        let t = SmtpTransport::new("relais", 25, Security::None, "compte", Zeroizing::new("PIEGE-MDP".into()));
        let shown = format!("{t:?}");
        assert!(!shown.contains("PIEGE-MDP") && shown.contains("***"), "{shown}");
    }
}
