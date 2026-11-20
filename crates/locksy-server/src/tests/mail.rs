//! E-mails et notifications : file d'envoi, nouveaux essais, échecs gardés
//! et renvoyés, e-mail de test, mot de passe SMTP, contenu des messages.
//!
//! Un faux serveur SMTP (127.0.0.1, port libre) reçoit les messages ; le
//! worker n'est pas lancé : chaque test appelle `mail::run_once` à l'instant
//! voulu, ce qui rend les délais de nouvel essai déterministes.

use super::*;
use crate::mail::{self, Notification, NotifyOutcome};
use locksy_core::encoding::b64d;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const SMTP_PASSWORD: &str = "PIEGE-MDP-SMTP";

// ------------------------------------------------------------ Faux serveur SMTP

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Accepte tout.
    Accept,
    /// Refuse le destinataire (550).
    RejectRcpt,
}

/// Message reçu : enveloppe, en-têtes bruts, texte décodé.
#[derive(Clone, Debug)]
struct Received {
    from: String,
    to: String,
    headers: String,
    text: String,
}

impl Received {
    /// Sujet décodé (mots encodés RFC 2047 en base64).
    fn subject(&self) -> String {
        let mut out = String::new();
        let mut inside = false;
        for line in self.headers.split("\r\n") {
            if let Some(v) = line.strip_prefix("Subject: ") {
                inside = true;
                out.push_str(&decode_words(v));
            } else if inside && line.starts_with(' ') {
                out.push_str(&decode_words(line.trim()));
            } else {
                inside = false;
            }
        }
        out
    }
}

#[derive(Clone)]
struct FakeSmtp {
    port: u16,
    mode: Arc<Mutex<Mode>>,
    received: Arc<Mutex<Vec<Received>>>,
    /// Identifiants reçus par AUTH PLAIN, décodés.
    auths: Arc<Mutex<Vec<String>>>,
}

fn std_b64_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace() && *c != '=').collect();
    b64d(&s.replace('+', "-").replace('/', "_")).expect("base64 standard")
}

fn decode_words(s: &str) -> String {
    match s.strip_prefix("=?UTF-8?B?").and_then(|r| r.strip_suffix("?=")) {
        Some(b) => String::from_utf8(std_b64_decode(b)).unwrap(),
        None => s.to_string(),
    }
}

fn between_brackets(line: &str) -> String {
    line.split_once('<').and_then(|(_, r)| r.split_once('>')).map(|(a, _)| a.to_string()).unwrap_or_default()
}

impl FakeSmtp {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fake = FakeSmtp {
            port: listener.local_addr().unwrap().port(),
            mode: Arc::new(Mutex::new(Mode::Accept)),
            received: Arc::default(),
            auths: Arc::default(),
        };
        let f = fake.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let f = f.clone();
                tokio::spawn(async move {
                    let _ = f.session(sock).await;
                });
            }
        });
        fake
    }

    fn set_mode(&self, m: Mode) {
        *self.mode.lock().unwrap() = m;
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    async fn session(&self, sock: tokio::net::TcpStream) -> std::io::Result<()> {
        let (r, mut w) = sock.into_split();
        let mut lines = BufReader::new(r).lines();
        w.write_all(b"220 faux.exemple.fr ESMTP\r\n").await?;
        let (mut from, mut to) = (String::new(), String::new());
        while let Some(line) = lines.next_line().await? {
            let up = line.to_ascii_uppercase();
            // STARTTLS n'est jamais annoncé : un client qui l'exige doit refuser.
            let reply = if up.starts_with("EHLO") {
                "250-faux.exemple.fr\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME".to_string()
            } else if let Some(token) = line.strip_prefix("AUTH PLAIN ") {
                self.auths.lock().unwrap().push(String::from_utf8_lossy(&std_b64_decode(token)).into_owned());
                "235 authentifié".into()
            } else if up.starts_with("MAIL FROM:") {
                from = between_brackets(&line);
                "250 ok".into()
            } else if up.starts_with("RCPT TO:") {
                if *self.mode.lock().unwrap() == Mode::RejectRcpt {
                    "550 destinataire refusé".into()
                } else {
                    to = between_brackets(&line);
                    "250 ok".into()
                }
            } else if up == "DATA" {
                w.write_all(b"354 envoyez\r\n").await?;
                let mut data = Vec::new();
                while let Some(l) = lines.next_line().await? {
                    if l == "." {
                        break;
                    }
                    data.push(l.strip_prefix('.').map(str::to_string).unwrap_or(l));
                }
                let raw = data.join("\r\n");
                let (headers, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
                let text = String::from_utf8(std_b64_decode(body)).unwrap_or_default();
                self.received.lock().unwrap().push(Received {
                    from: from.clone(),
                    to: to.clone(),
                    headers: headers.to_string(),
                    text,
                });
                "250 mis en file".into()
            } else if up == "QUIT" {
                w.write_all(b"221 au revoir\r\n").await?;
                return Ok(());
            } else {
                "502 commande inconnue".into()
            };
            w.write_all(format!("{reply}\r\n").as_bytes()).await?;
        }
        Ok(())
    }
}

/// Port local sur lequel rien n'écoute.
async fn closed_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

// ------------------------------------------------------------ Outils

/// Active l'envoi vers le faux serveur (sans chiffrement : boucle locale),
/// résumé des administrateurs coupé.
async fn enable_mail(st: &AppState, port: u16) {
    set_setting(st, "mail.smtp.host", json!("127.0.0.1")).await;
    set_setting(st, "mail.smtp.port", json!(port)).await;
    set_setting(st, "mail.smtp.security", json!("none")).await;
    set_setting(st, "mail.from", json!("locksy@exemple.fr")).await;
    set_setting(st, "mail.notify.admin_digest", json!("off")).await;
    set_setting(st, "mail.enabled", json!(true)).await;
}

/// Met une notification en file dans une transaction, comme un événement.
async fn enqueue(st: &AppState, n: Notification) -> NotifyOutcome {
    let eff = st.effective().await.unwrap();
    let notifier = st.notifier.clone();
    st.db
        .call(move |c| {
            let tx = c.transaction()?;
            let out = notifier.enqueue(&tx, &eff, &n)?;
            tx.commit()?;
            Ok(out)
        })
        .await
        .unwrap()
}

fn invite(email: &str) -> Notification {
    Notification::Invite {
        invite_id: locksy_core::crypto::new_uuid(),
        email: email.into(),
        name: "Alex Martin".into(),
        link: "https://coffre.exemple.fr/#/inscription/JETON-INVITATION".into(),
        expires_at: now_unix() + 7 * 86_400,
        inviter: "Camille Admin".into(),
    }
}

/// Ligne de la file : (id, statut, essais, code d'erreur, prochain essai).
#[derive(Debug)]
struct Row {
    id: String,
    status: String,
    attempts: i64,
    code: Option<String>,
    next: i64,
}

async fn rows(st: &AppState) -> Vec<Row> {
    st.db
        .read(|c| {
            let mut s = c.prepare(
                "SELECT id, status, attempts, last_error_code, next_attempt_at FROM mail_queue
                 WHERE status <> 'skipped' ORDER BY created_at, id",
            )?;
            let v = s
                .query_map([], |r| Ok(Row { id: r.get(0)?, status: r.get(1)?, attempts: r.get(2)?, code: r.get(3)?, next: r.get(4)? }))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(v)
        })
        .await
        .unwrap()
}

/// Tout le texte d'une table (toutes colonnes), pour y chercher un secret.
async fn dump(st: &AppState, table: &'static str) -> String {
    st.db
        .read(move |c| {
            let mut s = c.prepare(&format!("SELECT * FROM {table}"))?;
            let n = s.column_count();
            let mut out = String::new();
            let mut q = s.query([])?;
            while let Some(r) = q.next()? {
                for i in 0..n {
                    let v: rusqlite::types::Value = r.get(i)?;
                    out.push_str(&format!("{v:?}|"));
                }
                out.push('\n');
            }
            Ok(out)
        })
        .await
        .unwrap()
}

async fn admin(st: &AppState) -> Account {
    account(st, &AccountOpts { role: "admin", ..Default::default() }).await
}

/// Journaux du fil courant (le test tourne sur un exécuteur à un seul fil :
/// le serveur et le worker y écrivent aussi).
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Une capture à la fois (les tests de capture se suivent).
static CAPTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

thread_local! {
    /// Capture active sur ce fil (le test tourne sur un exécuteur à un seul fil).
    static SINK: std::cell::RefCell<Option<Capture>> = const { std::cell::RefCell::new(None) };
}

/// Écrivain de l'abonné global : vers la capture du fil courant, sinon nulle part.
struct Router;

impl std::io::Write for Router {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        SINK.with(|s| {
            if let Some(cap) = s.borrow_mut().as_mut() {
                cap.0.lock().unwrap().extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Router {
    type Writer = Router;
    fn make_writer(&'a self) -> Router {
        Router
    }
}

/// Abonné global unique des tests (installé une fois). Un abonné local par
/// test (set_default) partageait le cache d'intérêt de chaque point de
/// journalisation avec les tests parallèles : un point enregistré par un
/// autre fil au mauvais moment restait muet pour la capture.
fn install_router() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let sub = tracing_subscriber::fmt().with_writer(Router).with_max_level(tracing::Level::TRACE).with_ansi(false).finish();
        let _ = tracing::subscriber::set_global_default(sub);
    });
}

/// Capture en cours (retirée du fil avant de rendre le verrou).
struct Logs {
    cap: Capture,
    _lock: tokio::sync::MutexGuard<'static, ()>,
}

impl Logs {
    fn text(&self) -> String {
        self.cap.text()
    }
}

impl Drop for Logs {
    fn drop(&mut self) {
        SINK.with(|s| *s.borrow_mut() = None);
    }
}

async fn capture_logs() -> Logs {
    let lock = CAPTURE_LOCK.lock().await;
    install_router();
    let cap = Capture::default();
    SINK.with(|s| *s.borrow_mut() = Some(cap.clone()));
    Logs { cap, _lock: lock }
}

// ------------------------------------------------------------ File d'envoi

#[tokio::test]
async fn invitation_recue_avec_le_lien() {
    let s = srv().await;
    let smtp = FakeSmtp::start().await;
    enable_mail(&s.st, smtp.port).await;
    assert_eq!(enqueue(&s.st, invite("nouvelle@exemple.fr")).await, NotifyOutcome::Queued);
    // Mise en file seulement : rien n'est parti avant le worker.
    assert!(smtp.received().is_empty());
    assert_eq!(mail::run_once(&s.st, now_unix()).await.unwrap(), 1);

    let got = smtp.received();
    assert_eq!(got.len(), 1);
    let m = &got[0];
    assert_eq!((m.from.as_str(), m.to.as_str()), ("locksy@exemple.fr", "nouvelle@exemple.fr"));
    assert!(m.subject().starts_with("Invitation à rejoindre"), "{}", m.subject());
    assert!(m.text.contains("https://coffre.exemple.fr/#/inscription/JETON-INVITATION"), "{}", m.text);
    assert!(m.text.contains("Camille Admin vous invite"), "{}", m.text);
    assert!(m.headers.contains("Auto-Submitted: auto-generated"));
    let r = rows(&s.st).await;
    assert_eq!((r[0].status.as_str(), r[0].attempts, r[0].code.as_deref()), ("sent", 1, None));
    // Un second tour n'envoie rien de plus.
    assert_eq!(mail::run_once(&s.st, now_unix()).await.unwrap(), 0);
    assert_eq!(smtp.received().len(), 1);
}

#[tokio::test]
async fn envoi_desactive_ou_notification_coupee() {
    let s = srv().await;
    let smtp = FakeSmtp::start().await;
    // mail.enabled vaut faux par défaut.
    assert_eq!(enqueue(&s.st, invite("a@exemple.fr")).await, NotifyOutcome::Disabled);
    enable_mail(&s.st, smtp.port).await;
    set_setting(&s.st, "mail.notify.invite", json!(false)).await;
    assert_eq!(enqueue(&s.st, invite("a@exemple.fr")).await, NotifyOutcome::Disabled);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM mail_queue").await, 0);
    // Les autres notifications restent actives.
    let u = account(&s.st, &AccountOpts::default()).await;
    let n = Notification::NewDevice { user_id: u.id.clone(), device: "Firefox sur Windows".into(), ip: "203.0.113.7".into(), at: now_unix() };
    assert_eq!(enqueue(&s.st, n).await, NotifyOutcome::Queued);
    set_setting(&s.st, "mail.notify.security_change", json!(false)).await;
    let n = Notification::SecurityChange { user_id: u.id.clone(), event: "password.changed", at: now_unix() };
    assert_eq!(enqueue(&s.st, n).await, NotifyOutcome::Disabled);
    // Envoi coupé : la file attend, le worker n'envoie rien.
    set_setting(&s.st, "mail.enabled", json!(false)).await;
    assert_eq!(mail::run_once(&s.st, now_unix()).await.unwrap(), 0);
    assert!(smtp.received().is_empty());
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM mail_queue WHERE status = 'pending'").await, 1);
}

#[tokio::test]
async fn adresse_invalide_et_evenement_inconnu_non_mis_en_file() {
    let s = srv().await;
    enable_mail(&s.st, closed_port().await).await;
    assert_eq!(enqueue(&s.st, invite("victime@exemple.fr>\r\nBcc: pirate@exemple.fr")).await, NotifyOutcome::Disabled);
    let u = account(&s.st, &AccountOpts::default()).await;
    let n = Notification::SecurityChange { user_id: u.id.clone(), event: "evenement.inconnu", at: now_unix() };
    assert_eq!(enqueue(&s.st, n).await, NotifyOutcome::Disabled);
    let n = Notification::SecurityChange { user_id: crypto::new_uuid(), event: "password.changed", at: now_unix() };
    assert_eq!(enqueue(&s.st, n).await, NotifyOutcome::Disabled, "compte inconnu");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM mail_queue").await, 0);
}

#[tokio::test]
async fn echec_puis_nouvel_essai() {
    let s = srv().await;
    let smtp = FakeSmtp::start().await;
    enable_mail(&s.st, smtp.port).await;
    enqueue(&s.st, invite("lent@exemple.fr")).await;
    smtp.set_mode(Mode::RejectRcpt);
    let logs = capture_logs().await;
    let t0 = now_unix();
    assert_eq!(mail::run_once(&s.st, t0).await.unwrap(), 1);
    let r = &rows(&s.st).await[0];
    assert_eq!((r.status.as_str(), r.attempts, r.code.as_deref()), ("pending", 1, Some("smtp_rejected")));
    assert_eq!(r.next, t0 + 60, "nouvel essai dans une minute");
    // Pas encore dû.
    assert_eq!(mail::run_once(&s.st, t0 + 30).await.unwrap(), 0);
    smtp.set_mode(Mode::Accept);
    assert_eq!(mail::run_once(&s.st, t0 + 60).await.unwrap(), 1);
    let r = &rows(&s.st).await[0];
    assert_eq!((r.status.as_str(), r.attempts, r.code.as_deref()), ("sent", 2, None));
    assert_eq!(smtp.received().len(), 1);
    // Journal technique : identifiant, type et code, jamais l'adresse ni le sujet.
    let text = logs.text();
    assert!(text.contains("nouvel essai programmé") && text.contains("smtp_rejected") && text.contains(&r.id), "{text}");
    assert!(!text.contains("lent@exemple.fr") && !text.contains("Invitation"), "{text}");
}

#[tokio::test]
async fn echec_garde_puis_renvoye() {
    let s = srv().await;
    let smtp = FakeSmtp::start().await;
    enable_mail(&s.st, smtp.port).await;
    let a = admin(&s.st).await;
    enqueue(&s.st, invite("refuse@exemple.fr")).await;
    smtp.set_mode(Mode::RejectRcpt);
    // Essais à t0, +1, +5, +15 et +60 minutes : le 5e échec est définitif.
    let mut t = now_unix();
    for (i, delay) in [60, 300, 900, 3600].into_iter().enumerate() {
        mail::run_once(&s.st, t).await.unwrap();
        let r = &rows(&s.st).await[0];
        assert_eq!((r.status.as_str(), r.attempts), ("pending", i as i64 + 1));
        assert_eq!(r.next, t + delay);
        t += delay;
    }
    mail::run_once(&s.st, t).await.unwrap();
    let id = {
        let r = &rows(&s.st).await[0];
        assert_eq!((r.status.as_str(), r.attempts, r.code.as_deref()), ("failed", 5, Some("smtp_rejected")));
        r.id.clone()
    };
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'mail.failed'").await, 1);
    // Plus aucun essai automatique.
    assert_eq!(mail::run_once(&s.st, t + 86_400).await.unwrap(), 0);

    // Visible dans l'administration, puis renvoyé.
    let list = s.get("/api/admin/mail/queue?status=failed", Some(&a.token)).await;
    let body = list.expect(200, "");
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["last_error_code"], "smtp_rejected");
    assert_eq!(body[0]["to_email"], "r***@exemple.fr");
    s.post(&format!("/api/admin/mail/queue/{id}/retry"), Some(&a.token), json!({})).await.expect(202, "");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'mail.resent'").await, 1);
    let r = &rows(&s.st).await[0];
    assert_eq!((r.status.as_str(), r.attempts), ("pending", 0), "nouveau cycle d'essais");
    smtp.set_mode(Mode::Accept);
    assert_eq!(mail::run_once(&s.st, now_unix() + 1).await.unwrap(), 1);
    assert_eq!(rows(&s.st).await[0].status, "sent");
    assert_eq!(smtp.received()[0].to, "refuse@exemple.fr");
    // Un message envoyé ne se renvoie pas.
    s.post(&format!("/api/admin/mail/queue/{id}/retry"), Some(&a.token), json!({})).await.expect(409, "conflict");
}

#[tokio::test]
async fn renvoi_refuse_hors_cas_prevus() {
    let s = srv().await;
    let a = admin(&s.st).await;
    let u = account(&s.st, &AccountOpts::default()).await;
    let unknown = crypto::new_uuid();
    // Envoi désactivé.
    s.post(&format!("/api/admin/mail/queue/{unknown}/retry"), Some(&a.token), json!({})).await.expect(409, "mail_disabled");
    enable_mail(&s.st, closed_port().await).await;
    s.post(&format!("/api/admin/mail/queue/{unknown}/retry"), Some(&a.token), json!({})).await.expect(404, "not_found");
    s.post("/api/admin/mail/queue/pas-un-uuid/retry", Some(&a.token), json!({})).await.expect(404, "not_found");
    let r = s.post(&format!("/api/admin/mail/queue/{unknown}/retry"), Some(&u.token), json!({})).await;
    assert_eq!(r.status, 403);
}

#[tokio::test]
async fn liste_de_la_file_sans_corps_et_adresses_masquees() {
    let s = srv().await;
    enable_mail(&s.st, closed_port().await).await;
    let a = admin(&s.st).await;
    let u = account(&s.st, &AccountOpts::default()).await;
    enqueue(&s.st, invite("camille@exemple.fr")).await;
    let body = s.get("/api/admin/mail/queue", Some(&a.token)).await.expect(200, "").clone();
    let row = &body[0];
    assert_eq!(row["to_email"], "c***@exemple.fr");
    assert_eq!(row["kind"], "invite");
    assert_eq!(row["status"], "pending");
    assert!(row.get("body_text").is_none() && row.get("body").is_none(), "{row}");
    assert!(!body.to_string().contains("JETON-INVITATION"), "le lien d'invitation ne sort pas de la file");
    for f in ["id", "subject", "attempts", "last_error_code", "created_at", "updated_at", "sent_at"] {
        assert!(row.get(f).is_some(), "champ {f} absent : {row}");
    }
    assert_eq!(s.get("/api/admin/mail/queue?status=sent", Some(&a.token)).await.expect(200, "").as_array().unwrap().len(), 0);
    assert_eq!(s.get("/api/admin/mail/queue?status=pending", Some(&a.token)).await.expect(200, "").as_array().unwrap().len(), 1);
    s.get("/api/admin/mail/queue?status=autre", Some(&a.token)).await.expect(400, "bad_request");
    assert_eq!(s.get("/api/admin/mail/queue", Some(&u.token)).await.status, 403);
    assert_eq!(s.get("/api/admin/mail/queue", None).await.status, 401);
}

#[tokio::test]
async fn maintenance_de_la_file() {
    let s = srv().await;
    let now = now_unix();
    let day = 86_400;
    s.st.db
        .call(move |c| {
            for (id, status, age) in [
                ("envoye-recent", "sent", 6 * day),
                ("envoye-ancien", "sent", 8 * day),
                ("echec-recent", "failed", 29 * day),
                ("echec-ancien", "failed", 31 * day),
                ("attente-recente", "pending", 29 * day),
                ("attente-ancienne", "pending", 31 * day),
                ("marque-ancienne", "skipped", 8 * day),
            ] {
                let at = now - age;
                c.execute(
                    "INSERT INTO mail_queue (id, kind, to_email, subject, body_text, status, next_attempt_at,
                         created_at, updated_at, sent_at)
                     VALUES (?1, 'test', 'a@exemple.fr', 's', 'b', ?2, ?3, ?3, ?3, ?4)",
                    rusqlite::params![id, status, at, (status == "sent").then_some(at)],
                )?;
            }
            mail::housekeeping(c, now)
        })
        .await
        .unwrap();
    let left: Vec<String> = s
        .st
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT id FROM mail_queue ORDER BY id")?;
            let v = st.query_map([], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?;
            Ok(v)
        })
        .await
        .unwrap();
    assert_eq!(left, ["attente-recente", "echec-recent", "envoye-recent"]);
}

// ------------------------------------------------------------ Alertes de sécurité

#[tokio::test]
async fn alerte_de_blocage_non_repetee() {
    let s = srv().await;
    enable_mail(&s.st, closed_port().await).await;
    let u = account(&s.st, &AccountOpts::default()).await;
    let locked = || Notification::SecurityChange { user_id: u.id.clone(), event: "login.locked", at: now_unix() };
    assert_eq!(enqueue(&s.st, locked()).await, NotifyOutcome::Queued);
    assert_eq!(enqueue(&s.st, locked()).await, NotifyOutcome::Queued);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM mail_queue").await, 1, "une seule alerte de blocage par quart d'heure");
    // Chaque changement de mot de passe est signalé.
    for _ in 0..2 {
        let n = Notification::SecurityChange { user_id: u.id.clone(), event: "password.changed", at: now_unix() };
        enqueue(&s.st, n).await;
    }
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM mail_queue").await, 3);
}

#[tokio::test]
async fn resume_des_administrateurs_une_fois_par_periode() {
    let s = srv().await;
    let smtp = FakeSmtp::start().await;
    enable_mail(&s.st, smtp.port).await;
    set_setting(&s.st, "mail.notify.admin_digest", json!("daily")).await;
    let owner = account(&s.st, &AccountOpts { role: "owner", totp: true, ..Default::default() }).await;
    let adm = account(&s.st, &AccountOpts { role: "admin", totp: true, ..Default::default() }).await;
    account(&s.st, &AccountOpts::default()).await;
    let now = now_unix();
    let yesterday = (now / 86_400 - 1) * 86_400 + 3600;
    s.st.db
        .call(move |c| {
            for _ in 0..3 {
                c.execute(
                    "INSERT INTO audit (at, user_id, email, action, target, ip, user_agent, details)
                     VALUES (?1, NULL, 'x@exemple.fr', 'login.failed', 'Coffre PIEGE-NOM', '', '', 'élément PIEGE-NOM')",
                    [yesterday],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
    let digest = |st: AppState, at: i64| async move {
        let eff = st.effective().await.unwrap();
        st.db.call(move |c| mail::enqueue_digest_if_due(c, &eff, at)).await.unwrap()
    };
    assert_eq!(digest(s.st.clone(), now).await, NotifyOutcome::Queued);
    assert_eq!(digest(s.st.clone(), now + 60).await, NotifyOutcome::Disabled, "une fois par période");
    mail::run_once(&s.st, now).await.unwrap();
    let got = smtp.received();
    let mut to: Vec<String> = got.iter().map(|m| m.to.clone()).collect();
    to.sort();
    let mut want = vec![owner.email.clone(), adm.email.clone()];
    want.sort();
    assert_eq!(to, want, "propriétaires et administrateurs seulement");
    let m = &got[0];
    assert!(m.subject().starts_with("Résumé quotidien de sécurité"), "{}", m.subject());
    assert!(m.text.contains("Échecs de connexion : 3"), "{}", m.text);
    assert!(!m.text.contains("Comptes bloqués"), "compteur nul omis : {}", m.text);
    assert!(!m.text.contains("PIEGE"), "ni cible ni détail du journal : {}", m.text);

    // Période suivante sans événement : rien n'est envoyé, une seule marque.
    let tomorrow = now + 86_400;
    assert_eq!(digest(s.st.clone(), tomorrow).await, NotifyOutcome::Disabled);
    assert_eq!(digest(s.st.clone(), tomorrow + 60).await, NotifyOutcome::Disabled);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM mail_queue WHERE status = 'skipped'").await, 1);
    let a = s.get("/api/admin/mail/queue", Some(&owner.token)).await.expect(200, "").clone();
    assert_eq!(a.as_array().unwrap().len(), 2, "la marque n'apparaît pas dans la file : {a}");
    // Résumé coupé.
    set_setting(&s.st, "mail.notify.admin_digest", json!("off")).await;
    assert_eq!(digest(s.st.clone(), now + 30 * 86_400).await, NotifyOutcome::Disabled);
}

/// Toutes les notifications, rendues avec des valeurs piégées : aucune ne
/// porte de secret, de nom d'élément, de détail du journal ni d'en-tête
/// injecté ; seul le lien d'invitation porte un jeton.
#[tokio::test]
async fn aucun_secret_ni_nom_dans_les_messages() {
    let s = srv().await;
    let smtp = FakeSmtp::start().await;
    enable_mail(&s.st, smtp.port).await;
    set_setting(&s.st, "mail.smtp.username", json!("compte-smtp")).await;
    set_setting(&s.st, "mail.smtp.password", json!(SMTP_PASSWORD)).await;
    set_setting(&s.st, "mail.notify.admin_digest", json!("daily")).await;
    set_setting(&s.st, "branding.org_name", json!("Exemple SA")).await;
    let owner = account(&s.st, &AccountOpts { role: "owner", ..Default::default() }).await;
    let now = now_unix();
    let yesterday = (now / 86_400 - 1) * 86_400 + 60;
    s.st.db
        .call(move |c| {
            for action in ["login.failed", "login.locked", "2fa.disabled", "admin.user_role", "settings.lowered"] {
                c.execute(
                    "INSERT INTO audit (at, user_id, email, action, target, ip, user_agent, details)
                     VALUES (?1, NULL, '', ?2, 'Coffre PIEGE-NOM', '', '', 'élément PIEGE-NOM')",
                    rusqlite::params![yesterday, action],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();

    let mut sent = vec![invite("invitee@exemple.fr")];
    sent.push(Notification::NewDevice {
        user_id: owner.id.clone(),
        device: "Firefox\r\nBcc: pirate@exemple.fr".into(),
        ip: "203.0.113.7\r\nX-Piege: 1".into(),
        at: now,
    });
    let events = [
        "password.changed",
        "recovery_key.rotated",
        "recovery.completed",
        "2fa.enabled",
        "2fa.disabled",
        "2fa.recovery_codes_generated",
        "2fa.recovery_code_used",
        "login.locked",
        "account.disabled",
        "admin.2fa_reset",
    ];
    for event in events {
        sent.push(Notification::SecurityChange { user_id: owner.id.clone(), event, at: now });
    }
    sent.push(Notification::SettingsLowered {
        revision: 7,
        keys: vec!["kdf.min_memory_mib\nBcc: pirate@exemple.fr".into()],
        actor_email: "chef@exemple.fr".into(),
    });
    sent.push(Notification::Test { to: owner.email.clone() });
    for n in sent {
        assert_eq!(enqueue(&s.st, n).await, NotifyOutcome::Queued);
    }
    let eff = s.st.effective().await.unwrap();
    assert_eq!(s.st.db.call(move |c| mail::enqueue_digest_if_due(c, &eff, now)).await.unwrap(), NotifyOutcome::Queued);
    let logs = capture_logs().await;
    mail::run_once(&s.st, now_unix()).await.unwrap();

    let got = smtp.received();
    assert_eq!(got.len(), 15, "invitation, appareil, 10 alertes, abaissement, test, résumé : {:?}", rows(&s.st).await);
    // Le mot de passe SMTP déchiffré a bien servi à l'authentification.
    let auths = smtp.auths.lock().unwrap().clone();
    assert_eq!(auths.len(), 15);
    assert!(auths.iter().all(|a| *a == format!("\0compte-smtp\0{SMTP_PASSWORD}")));
    let cipher = s.st.effective().await.unwrap().str("mail.smtp.password").to_string();
    assert!(cipher.len() > 20, "secret chiffré enregistré");
    let mut subjects = std::collections::BTreeSet::new();
    for m in &got {
        let all = format!("{}\n{}\n{}", m.headers, m.subject(), m.text);
        for trap in [SMTP_PASSWORD, cipher.as_str(), "PIEGE-NOM", owner.token.as_str()] {
            assert!(!all.contains(trap), "« {trap} » dans : {all}");
        }
        // Les retours à la ligne piégés n'ouvrent aucun en-tête.
        for l in m.headers.lines().chain(m.text.lines()) {
            assert!(!l.starts_with("Bcc") && !l.starts_with("X-Piege"), "en-tête injecté : {all}");
        }
        let jeton = all.contains("JETON-INVITATION");
        assert_eq!(jeton, m.to == "invitee@exemple.fr", "seule l'invitation porte un jeton : {all}");
        assert!(m.text.contains("Exemple SA"), "habillage de l'organisation absent : {}", m.text);
        subjects.insert(m.subject());
    }
    assert_eq!(subjects.len(), 15, "un sujet propre à chaque message : {subjects:?}");
    // Ni les réglages, ni la file, ni le journal d'audit, ni les journaux
    // techniques ne portent le mot de passe SMTP.
    for table in ["org_settings", "settings_history", "mail_queue", "audit"] {
        assert!(!dump(&s.st, table).await.contains(SMTP_PASSWORD), "mot de passe SMTP dans {table}");
    }
    let text = logs.text();
    assert!(!text.contains(SMTP_PASSWORD) && !text.contains("compte-smtp"), "{text}");
}

// ------------------------------------------------------------ Mot de passe SMTP et sécurité de la connexion

#[tokio::test]
async fn mot_de_passe_smtp_chiffre_par_la_cle_serveur() {
    let s = srv().await;
    enable_mail(&s.st, closed_port().await).await;
    set_setting(&s.st, "mail.smtp.password", json!(SMTP_PASSWORD)).await;
    let eff = s.st.effective().await.unwrap();
    // Chiffré au repos, lisible seulement avec la clé du serveur.
    assert!(!eff.str("mail.smtp.password").contains(SMTP_PASSWORD));
    let t = mail::transport_for(&eff, &s.st.server_key).expect("transport");
    assert!(!format!("{t:?}").contains(SMTP_PASSWORD));
    let logs = capture_logs().await;
    let other = crypto::SecretKey::generate();
    assert_eq!(mail::transport_for(&eff, &other).unwrap_err().code, "smtp_auth");
    let text = logs.text();
    assert!(text.contains("indéchiffrable") && !text.contains(SMTP_PASSWORD), "{text}");
}

#[tokio::test]
async fn smtp_sans_chiffrement_refuse_vers_un_serveur_public() {
    let s = srv().await;
    let a = admin(&s.st).await;
    enable_mail(&s.st, closed_port().await).await;
    set_setting(&s.st, "mail.smtp.host", json!("smtp.exemple.fr")).await;
    s.post("/api/admin/mail/test", Some(&a.token), json!({})).await.expect(422, "smtp_insecure");
    // Le worker refuse aussi, sans se connecter.
    enqueue(&s.st, invite("x@exemple.fr")).await;
    mail::run_once(&s.st, now_unix()).await.unwrap();
    let r = &rows(&s.st).await[0];
    assert_eq!((r.status.as_str(), r.code.as_deref()), ("pending", Some("smtp_insecure")));
}

#[tokio::test]
async fn starttls_exige_n_est_jamais_abandonne() {
    let s = srv().await;
    let a = admin(&s.st).await;
    // Le faux serveur n'annonce pas STARTTLS : pas d'envoi en clair.
    let smtp = FakeSmtp::start().await;
    enable_mail(&s.st, smtp.port).await;
    set_setting(&s.st, "mail.smtp.security", json!("starttls")).await;
    let r = s.post("/api/admin/mail/test", Some(&a.token), json!({})).await;
    assert_eq!(r.expect(502, "email_not_sent")["error_code"], "smtp_tls");
    // TLS implicite vers un serveur en clair : échec de la poignée de main.
    set_setting(&s.st, "mail.smtp.security", json!("tls")).await;
    let r = s.post("/api/admin/mail/test", Some(&a.token), json!({})).await;
    assert!(["smtp_tls", "smtp_connect"].contains(&r.expect(502, "email_not_sent")["error_code"].as_str().unwrap()), "{}", r.body);
    assert!(smtp.received().is_empty());
}

// ------------------------------------------------------------ E-mail de test

#[tokio::test]
async fn email_de_test_immediat_et_limite() {
    let s = srv().await;
    let smtp = FakeSmtp::start().await;
    let a = admin(&s.st).await;
    // Envoi désactivé.
    s.post("/api/admin/mail/test", Some(&a.token), json!({})).await.expect(409, "mail_disabled");
    enable_mail(&s.st, smtp.port).await;
    // Sans destinataire : l'adresse de l'acteur.
    assert_eq!(s.post("/api/admin/mail/test", Some(&a.token), json!({})).await.expect(200, "")["sent"], true);
    let got = smtp.received();
    assert_eq!(got[0].to, a.email);
    assert!(got[0].subject().starts_with("E-mail de test"), "{}", got[0].subject());
    // Destinataire choisi (normalisé).
    s.post("/api/admin/mail/test", Some(&a.token), json!({ "to": " Autre@Exemple.FR " })).await.expect(200, "");
    assert_eq!(smtp.received()[1].to, "autre@exemple.fr");
    // Envoi hors file.
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM mail_queue").await, 0);
    // Journal : adresse masquée.
    let audit = dump(&s.st, "audit").await;
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'mail.test_sent'").await, 2);
    assert!(audit.contains("a***@exemple.fr") && !audit.contains("autre@exemple.fr"), "{audit}");
    // Adresse invalide (compte dans la limite).
    s.post("/api/admin/mail/test", Some(&a.token), json!({ "to": "pas-une-adresse" })).await.expect(400, "bad_request");
    // Échec : code stable.
    smtp.set_mode(Mode::RejectRcpt);
    let r = s.post("/api/admin/mail/test", Some(&a.token), json!({})).await;
    assert_eq!(r.expect(502, "email_not_sent")["error_code"], "smtp_rejected");
    smtp.set_mode(Mode::Accept);
    // 6e essai en 10 minutes (refus d'envoi désactivé compris) : refusé.
    let r = s.post("/api/admin/mail/test", Some(&a.token), json!({})).await;
    r.expect(429, "rate_limited");
    assert!(r.header("retry-after").is_some());
    // La limite est propre à chaque acteur.
    let b = admin(&s.st).await;
    s.post("/api/admin/mail/test", Some(&b.token), json!({})).await.expect(200, "");
    // Réservé aux administrateurs.
    let u = account(&s.st, &AccountOpts::default()).await;
    assert_eq!(s.post("/api/admin/mail/test", Some(&u.token), json!({})).await.status, 403);
}

#[tokio::test]
async fn email_de_test_serveur_injoignable() {
    let s = srv().await;
    let a = admin(&s.st).await;
    enable_mail(&s.st, closed_port().await).await;
    let r = s.post("/api/admin/mail/test", Some(&a.token), json!({})).await;
    assert_eq!(r.expect(502, "email_not_sent")["error_code"], "smtp_connect");
    // Aucun serveur configuré.
    set_setting(&s.st, "mail.smtp.host", json!("")).await;
    let r = s.post("/api/admin/mail/test", Some(&a.token), json!({})).await;
    assert_eq!(r.expect(502, "email_not_sent")["error_code"], "smtp_connect");
    let audit = dump(&s.st, "audit").await;
    assert!(audit.contains("échec : smtp_connect"), "{audit}");
}

#[tokio::test]
async fn notifications_coupees_par_reglage_et_adresse_de_reponse() {
    let s = srv().await;
    let smtp = FakeSmtp::start().await;
    enable_mail(&s.st, smtp.port).await;
    let u = account(&s.st, &AccountOpts::default()).await;
    // Destinataires des réglages abaissés : les propriétaires.
    let _proprietaire = account(&s.st, &AccountOpts { role: "owner", ..Default::default() }).await;
    let device = || Notification::NewDevice { user_id: u.id.clone(), device: "Firefox sur Windows".into(), ip: "203.0.113.7".into(), at: now_unix() };
    let lowered = || Notification::SettingsLowered { revision: 2, keys: vec!["session.max_hours".into()], actor_email: "o@exemple.fr".into() };
    // Par défaut : mises en file.
    assert_eq!(enqueue(&s.st, device()).await, NotifyOutcome::Queued);
    assert_eq!(enqueue(&s.st, lowered()).await, NotifyOutcome::Queued);
    // Chaque réglage coupe sa notification, et seulement elle.
    set_setting(&s.st, "mail.notify.new_device", json!(false)).await;
    assert_eq!(enqueue(&s.st, device()).await, NotifyOutcome::Disabled);
    assert_eq!(enqueue(&s.st, lowered()).await, NotifyOutcome::Queued);
    set_setting(&s.st, "mail.notify.settings_lowered", json!(false)).await;
    assert_eq!(enqueue(&s.st, lowered()).await, NotifyOutcome::Disabled);
    // Adresse de réponse : en-tête Reply-To des messages envoyés.
    set_setting(&s.st, "mail.reply_to", json!("support@exemple.fr")).await;
    assert_eq!(enqueue(&s.st, invite("nouvelle@exemple.fr")).await, NotifyOutcome::Queued);
    mail::run_once(&s.st, now_unix()).await.unwrap();
    let got = smtp.received();
    let inv = got.iter().find(|m| m.to == "nouvelle@exemple.fr").expect("invitation envoyée");
    assert!(inv.headers.contains("Reply-To: <support@exemple.fr>"), "{}", inv.headers);
}
