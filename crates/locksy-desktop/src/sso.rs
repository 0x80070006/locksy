//! Connexion SSO du client de bureau (RFC 8252) : le navigateur du système
//! s'ouvre sur le fournisseur d'identité, puis Locksy renvoie le ticket vers
//! une adresse locale (127.0.0.1, port choisi au hasard) écoutée ici.
//!
//! Le client tire un `client_state` aléatoire, l'envoie à /api/sso/start et
//! exige de le retrouver à l'identique au retour : un autre programme du poste
//! qui viserait le port local ne peut ni injecter son propre ticket ni faire
//! échouer la connexion (sa requête reçoit 400 et l'attente continue). Le
//! texte d'erreur éventuel n'est jamais affiché : il vient de la requête.

use crate::client::{ApiError, ApiResult, Client};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use locksy_core::api::{HealthResponse, LdapLoginRequest, LdapLoginResponse, SsoPublic, SsoRedeemRequest, SsoRedeemResponse};
use locksy_core::encoding::percent_decode;
use zeroize::Zeroize;

/// Message unique en cas de refus : le texte venu de la requête n'est jamais repris.
pub const REFUSED_MESSAGE: &str =
    "La connexion d'entreprise a été refusée ou annulée. Réessayez ; si le problème persiste, contactez votre administrateur.";

/// Durée maximale d'attente du retour du navigateur.
const WAIT: Duration = Duration::from_secs(300);

#[cfg_attr(not(test), allow(dead_code))]
pub fn sso_info(client: &Client) -> Option<SsoPublic> {
    client.get::<HealthResponse>("/health").ok().and_then(|h| h.sso)
}

/// Modes de connexion d'entreprise proposés par le serveur : (OpenID Connect, compte Windows).
pub fn login_options(client: &Client) -> (Option<SsoPublic>, Option<SsoPublic>) {
    match client.get::<HealthResponse>("/health") {
        Ok(h) => (h.sso, h.ldap),
        Err(_) => (None, None),
    }
}

/// Identifiant de la session Windows ouverte, par exemple « CORP\jdupont ».
pub fn current_windows_user() -> String {
    let user = std::env::var("USERNAME").unwrap_or_default();
    match std::env::var("USERDOMAIN") {
        Ok(d) if !d.is_empty() && !user.is_empty() && !d.eq_ignore_ascii_case(&std::env::var("COMPUTERNAME").unwrap_or_default()) => format!("{d}\\{user}"),
        _ => user,
    }
}

/// Vérifie l'identifiant et le mot de passe Windows auprès de l'annuaire (via Locksy).
pub fn windows_login(client: &Client, username: &str, password: &str) -> ApiResult<(String, SsoRedeemResponse)> {
    let mut req = LdapLoginRequest { username: username.to_string(), password: password.to_string() };
    let r: ApiResult<LdapLoginResponse> = client.send("POST", "/ldap/login", &req);
    req.password.zeroize();
    let r = r?;
    Ok((r.ticket, r.info))
}

/// Connexion SSO préparée : écoute locale, adresse à ouvrir et état attendu au retour.
pub struct SsoStart {
    pub listener: TcpListener,
    pub url: String,
    pub state: String,
}

/// Prépare l'écoute locale et l'adresse à ouvrir dans le navigateur.
pub fn prepare(client: &Client) -> ApiResult<SsoStart> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(io_err)?;
    let port = listener.local_addr().map_err(io_err)?.port();
    // base64url sur 43 caractères : rien à encoder dans l'URL.
    let state = locksy_core::crypto::random_token();
    let url = format!("{}/api/sso/start?target=desktop&port={port}&client_state={state}", client.base());
    Ok(SsoStart { listener, url, state })
}

fn io_err(e: std::io::Error) -> ApiError {
    ApiError { status: 0, code: "io".into(), message: format!("Écoute locale impossible : {e}") }
}

/// Résultat de l'analyse d'une requête reçue sur la boucle locale.
#[derive(Debug, PartialEq, Eq)]
pub enum Callback {
    /// Ticket accompagné du bon `client_state`.
    Ticket(String),
    /// Refus ou annulation côté fournisseur (avec le bon `client_state`).
    Refused,
    /// Requête étrangère, incomplète ou falsifiée : on l'ignore et on attend encore.
    Ignore,
}

/// Comparaison en temps constant (la longueur n'est pas secrète).
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Analyse l'en-tête d'une requête HTTP reçue sur la boucle locale.
///
/// Seul `GET /sso?…` est pris en compte ; `client_state` doit être présent une
/// seule fois et égal à `expected_state`, sinon la requête est ignorée.
pub fn parse_callback(request_head: &str, expected_state: &str) -> Callback {
    let mut first = request_head.lines().next().unwrap_or_default().split_whitespace();
    if first.next() != Some("GET") {
        return Callback::Ignore;
    }
    let target = first.next().unwrap_or_default();
    let Some(("/sso", query)) = target.split_once('?') else { return Callback::Ignore };
    let (mut ticket, mut error, mut state) = (None, None, None);
    for kv in query.split('&').filter(|kv| !kv.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let Ok(v) = percent_decode(v) else { return Callback::Ignore };
        let slot = match k {
            "ticket" => &mut ticket,
            "error" => &mut error,
            "client_state" => &mut state,
            _ => continue,
        };
        if slot.replace(v).is_some() {
            return Callback::Ignore; // paramètre répété : ambigu
        }
    }
    match state {
        Some(s) if !expected_state.is_empty() && same(&s, expected_state) => {}
        _ => return Callback::Ignore,
    }
    if error.is_some() {
        return Callback::Refused;
    }
    match ticket {
        Some(t) if !t.is_empty() && t.len() <= 512 => Callback::Ticket(t),
        _ => Callback::Ignore,
    }
}

const PAGE: &str = "<!doctype html><meta charset=utf-8><title>Locksy</title>\
<body style=\"font-family:Segoe UI,sans-serif;display:grid;place-items:center;height:90vh;color:#142033\">\
<div style=\"text-align:center\"><h2>{titre}</h2><p>{texte}</p></div>";

/// Répond au navigateur avec une page fixe (aucune donnée de la requête).
fn respond(stream: &mut TcpStream, status: &str, titre: &str, texte: &str) {
    let body = PAGE.replace("{titre}", titre).replace("{texte}", texte);
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
}

/// Lit l'en-tête de la requête (8 Kio au plus, 2 s au plus).
fn read_head(stream: &mut TcpStream) -> String {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while buf.len() < 8192 {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn cancelled() -> ApiError {
    ApiError { status: 0, code: "cancelled".into(), message: String::new() }
}

/// Attend le retour du navigateur (5 minutes au plus, annulable) puis
/// échange le ticket contre l'identité confirmée.
pub fn wait_ticket(client: &Client, listener: TcpListener, state: &str, cancel: &AtomicBool) -> ApiResult<(String, SsoRedeemResponse)> {
    listener.set_nonblocking(true).map_err(io_err)?;
    let deadline = Instant::now() + WAIT;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        if Instant::now() > deadline {
            return Err(ApiError { status: 0, code: "timeout".into(), message: "Connexion d'entreprise abandonnée (délai de 5 minutes dépassé).".into() });
        }
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(150));
                continue;
            }
            Err(e) => return Err(io_err(e)),
        };
        let head = read_head(&mut stream);
        match parse_callback(&head, state) {
            Callback::Ignore => {
                // favicon, préchargement, requête d'un tiers : on attend encore.
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
            Callback::Refused => {
                respond(&mut stream, "200 OK", "Connexion refusée", "Revenez dans Locksy pour réessayer.");
                return Err(ApiError { status: 0, code: "sso".into(), message: REFUSED_MESSAGE.into() });
            }
            Callback::Ticket(ticket) => {
                respond(&mut stream, "200 OK", "Identité confirmée", "Vous pouvez fermer cet onglet et revenir dans Locksy.");
                drop(stream);
                if cancel.load(Ordering::Relaxed) {
                    return Err(cancelled());
                }
                let info: SsoRedeemResponse = client.send("POST", "/sso/redeem", &SsoRedeemRequest { ticket: ticket.clone() })?;
                return Ok((ticket, info));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE: &str = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_abcde";

    fn get(target: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:5555\r\nUser-Agent: test\r\n\r\n")
    }

    #[test]
    fn ticket_with_the_right_state() {
        assert_eq!(parse_callback(&get(&format!("/sso?ticket=T0k3n&client_state={STATE}")), STATE), Callback::Ticket("T0k3n".into()));
        assert_eq!(parse_callback(&get(&format!("/sso?client_state={STATE}&ticket=abc")), STATE), Callback::Ticket("abc".into()));
    }

    #[test]
    fn wrong_or_missing_state_is_ignored() {
        assert_eq!(parse_callback(&get("/sso?ticket=abc"), STATE), Callback::Ignore);
        assert_eq!(parse_callback(&get("/sso?ticket=abc&client_state=autre"), STATE), Callback::Ignore);
        assert_eq!(parse_callback(&get("/sso?error=x"), STATE), Callback::Ignore, "un tiers ne peut pas faire échouer le flux");
        assert_eq!(parse_callback(&get("/sso?ticket=abc&client_state="), ""), Callback::Ignore);
        let twice = format!("/sso?ticket=abc&client_state={STATE}&client_state=x");
        assert_eq!(parse_callback(&get(&twice), STATE), Callback::Ignore);
        let two_tickets = format!("/sso?ticket=abc&ticket=def&client_state={STATE}");
        assert_eq!(parse_callback(&get(&two_tickets), STATE), Callback::Ignore);
    }

    #[test]
    fn error_is_refused_without_its_text() {
        let r = parse_callback(&get(&format!("/sso?error=%3Cscript%3EVotre+compte+est+bloqu%C3%A9&client_state={STATE}")), STATE);
        assert_eq!(r, Callback::Refused);
        assert!(!REFUSED_MESSAGE.contains("script"));
    }

    #[test]
    fn other_paths_and_methods_are_ignored() {
        assert_eq!(parse_callback(&get("/favicon.ico"), STATE), Callback::Ignore);
        assert_eq!(parse_callback(&get(&format!("/ssox?ticket=a&client_state={STATE}")), STATE), Callback::Ignore);
        assert_eq!(parse_callback(&get(&format!("/sso/x?ticket=a&client_state={STATE}")), STATE), Callback::Ignore);
        assert_eq!(parse_callback(&get("/sso"), STATE), Callback::Ignore);
        let post = format!("POST /sso?ticket=a&client_state={STATE} HTTP/1.1\r\n\r\n");
        assert_eq!(parse_callback(&post, STATE), Callback::Ignore);
        assert_eq!(parse_callback("", STATE), Callback::Ignore);
        assert_eq!(parse_callback(&get(&format!("/sso?ticket=&client_state={STATE}")), STATE), Callback::Ignore, "ticket vide");
        assert_eq!(parse_callback(&get(&format!("/sso?ticket={}&client_state={STATE}", "a".repeat(600))), STATE), Callback::Ignore);
    }

    #[test]
    fn percent_encoding_is_decoded() {
        let encoded_state = STATE.replace('-', "%2D");
        let r = parse_callback(&get(&format!("/sso?ticket=a%2Bb%3Dc&client_state={encoded_state}")), STATE);
        assert_eq!(r, Callback::Ticket("a+b=c".into()));
        assert_eq!(parse_callback(&get(&format!("/sso?ticket=%ZZ&client_state={STATE}")), STATE), Callback::Ignore);
    }

    #[test]
    fn prepared_url_carries_a_fresh_state() {
        let client = Client::new("http://127.0.0.1:8743").unwrap();
        let a = prepare(&client).unwrap();
        let b = prepare(&client).unwrap();
        assert_eq!(a.state.len(), 43);
        assert!(a.state.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(a.state, b.state);
        assert!(a.url.ends_with(&format!("&client_state={}", a.state)));
        assert!(a.url.starts_with("http://127.0.0.1:8743/api/sso/start?target=desktop&port="));
    }

    #[test]
    fn foreign_requests_do_not_end_the_wait() {
        // Un tiers local frappe au port avec un faux ticket : 400, l'attente
        // continue ; puis l'utilisateur annule.
        let client = Client::new("http://127.0.0.1:9").unwrap();
        let start = prepare(&client).unwrap();
        let port = start.listener.local_addr().unwrap().port();
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let waiter = std::thread::spawn(move || wait_ticket(&client, start.listener, &start.state, &flag));
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(b"GET /sso?ticket=FAUX&client_state=devine HTTP/1.1\r\n\r\n").unwrap();
        let mut answer = String::new();
        let _ = s.read_to_string(&mut answer);
        assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
        std::thread::sleep(Duration::from_millis(300));
        assert!(!waiter.is_finished(), "l'attente doit continuer");
        cancel.store(true, Ordering::Relaxed);
        let r = waiter.join().unwrap();
        assert_eq!(r.err().map(|e| e.code).as_deref(), Some("cancelled"));
    }
}

#[cfg(test)]
mod live_tests {
    //! Parcours SSO réel du client de bureau (ignoré par défaut). Le script
    //! qui joue le navigateur lit l'adresse dans LOCKSY_TEST_URL_FILE.
    use super::*;
    use crate::vault::{login_with, LoginOutcome};

    #[test]
    #[ignore]
    fn sso_loopback_login() {
        let server = std::env::var("LOCKSY_TEST_URL").expect("LOCKSY_TEST_URL");
        let password = std::env::var("LOCKSY_TEST_PASSWORD").expect("LOCKSY_TEST_PASSWORD");
        let out = std::env::var("LOCKSY_TEST_URL_FILE").expect("LOCKSY_TEST_URL_FILE");
        let client = Client::new(&server).unwrap();
        assert!(sso_info(&client).is_some(), "le serveur doit annoncer le SSO");
        let start = prepare(&client).unwrap();
        std::fs::write(&out, &start.url).unwrap();
        let (ticket, info) = wait_ticket(&client, start.listener, &start.state, &AtomicBool::new(false)).expect("ticket SSO");
        println!("ticket reçu pour {} (compte existant : {})", info.email, info.registered);
        let kdf = info.kdf.clone().expect("compte existant");
        match login_with(client.clone(), &info.email, &password, &kdf, Some(ticket.clone()), None).expect("connexion") {
            LoginOutcome::Done(c, v) => {
                println!("OK : coffre de {} déchiffré, {} élément(s)", v.profile.email, v.items.len());
                c.send_empty("POST", "/auth/logout").unwrap();
            }
            LoginOutcome::NeedTotp(..) => {
                // Légitime : la 2FA Locksy reste exigée après le SSO si elle est active.
                println!("2FA Locksy demandée après le SSO (compte avec double authentification) : test arrêté ici.");
                return;
            }
        }
        // Le ticket est à usage unique.
        let again = login_with(client, &info.email, &password, &kdf, Some(ticket), None);
        assert!(again.is_err(), "un ticket déjà utilisé doit être refusé");
        println!("OK : ticket rejoué refusé");
    }
}

#[cfg(test)]
mod live_ad_tests {
    //! Connexion Windows réelle contre un contrôleur de domaine (ignoré par défaut).
    use super::*;
    use crate::vault::{login_with, LoginOutcome};

    #[test]
    #[ignore]
    fn windows_account_login() {
        let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k}"));
        let client = Client::new(&env("LOCKSY_TEST_URL")).unwrap();
        let (_, ldap) = login_options(&client);
        println!("mode annoncé par le serveur : {:?}", ldap.as_ref().map(|l| &l.label));
        assert!(windows_login(&client, &env("LOCKSY_TEST_WIN_USER"), "mauvais-mot-de-passe").is_err());
        println!("OK : mauvais mot de passe Windows refusé");
        let (ticket, info) = windows_login(&client, &env("LOCKSY_TEST_WIN_USER"), &env("LOCKSY_TEST_WIN_PASSWORD")).expect("connexion Windows");
        println!("identité confirmée : {} (coffre existant : {})", info.email, info.registered);
        match login_with(client, &info.email, &env("LOCKSY_TEST_PASSWORD"), &info.kdf.expect("coffre"), Some(ticket), None).expect("déverrouillage") {
            LoginOutcome::Done(c, v) => {
                println!("OK : coffre de {} déchiffré ({} coffre(s))", v.profile.name, v.collections.len());
                c.send_empty("POST", "/auth/logout").unwrap();
            }
            LoginOutcome::NeedTotp(..) => {
                // Légitime : la 2FA Locksy reste exigée après la connexion Windows si elle est active.
                println!("2FA Locksy demandée après la connexion Windows : test arrêté ici.");
            }
        }
    }
}
