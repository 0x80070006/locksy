//! Connexion SSO du client de bureau (RFC 8252) : le navigateur du système
//! s'ouvre sur le fournisseur d'identité, puis Locksy renvoie le ticket vers
//! une adresse locale (127.0.0.1, port choisi au hasard) écoutée ici.

use crate::client::{ApiError, ApiResult, Client};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};
use locksy_core::api::{HealthResponse, LdapLoginRequest, LdapLoginResponse, SsoPublic, SsoRedeemRequest, SsoRedeemResponse};
use locksy_core::encoding::percent_decode;

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
    let r: LdapLoginResponse = client.send("POST", "/ldap/login", &LdapLoginRequest { username: username.to_string(), password: password.to_string() })?;
    Ok((r.ticket, r.info))
}

/// Prépare l'écoute locale et renvoie l'adresse à ouvrir dans le navigateur.
pub fn prepare(client: &Client) -> ApiResult<(TcpListener, String)> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(io_err)?;
    let port = listener.local_addr().map_err(io_err)?.port();
    let url = format!("{}/api/sso/start?target=desktop&port={port}", client.base());
    Ok((listener, url))
}

fn io_err(e: std::io::Error) -> ApiError {
    ApiError { status: 0, code: "io".into(), message: format!("Écoute locale impossible : {e}") }
}

const PAGE: &str = "<!doctype html><meta charset=utf-8><title>Locksy</title>\
<body style=\"font-family:Segoe UI,sans-serif;display:grid;place-items:center;height:90vh;color:#142033\">\
<div style=\"text-align:center\"><h2>{titre}</h2><p>{texte}</p></div>";

/// Attend le retour du navigateur (5 minutes au plus) puis lit le ticket.
pub fn wait_ticket(client: &Client, listener: TcpListener) -> ApiResult<(String, SsoRedeemResponse)> {
    listener.set_nonblocking(true).map_err(io_err)?;
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if Instant::now() > deadline {
            return Err(ApiError { status: 0, code: "timeout".into(), message: "Connexion SSO abandonnée (délai dépassé).".into() });
        }
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(150));
                continue;
            }
            Err(e) => return Err(io_err(e)),
        };
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]);
        let path = request.split_whitespace().nth(1).unwrap_or_default().to_string();
        if !path.starts_with("/sso?") {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            continue; // favicon, préchargement…
        }
        let param = |name: &str| {
            path.split_once('?')
                .map(|(_, q)| q)
                .unwrap_or_default()
                .split('&')
                .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
                .and_then(|v| percent_decode(v).ok())
        };
        let (ticket, error) = (param("ticket"), param("error"));
        let (titre, texte) = if ticket.is_some() {
            ("Identité confirmée", "Vous pouvez fermer cet onglet et revenir dans Locksy.")
        } else {
            ("Connexion refusée", "Revenez dans Locksy pour voir le détail.")
        };
        let body = PAGE.replace("{titre}", titre).replace("{texte}", texte);
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
        return match (ticket, error) {
            (Some(t), _) => {
                let info: SsoRedeemResponse = client.send("POST", "/sso/redeem", &SsoRedeemRequest { ticket: t.clone() })?;
                Ok((t, info))
            }
            (None, Some(e)) => Err(ApiError { status: 0, code: "sso".into(), message: e }),
            _ => Err(ApiError { status: 0, code: "sso".into(), message: "Réponse SSO incomplète.".into() }),
        };
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
        let (listener, url) = prepare(&client).unwrap();
        std::fs::write(&out, &url).unwrap();
        let (ticket, info) = wait_ticket(&client, listener).expect("ticket SSO");
        println!("ticket reçu pour {} (compte existant : {})", info.email, info.registered);
        let kdf = info.kdf.clone().expect("compte existant");
        match login_with(client.clone(), &info.email, &password, &kdf, Some(ticket.clone())).expect("connexion") {
            LoginOutcome::Done(c, v) => {
                println!("OK : coffre de {} déchiffré, {} élément(s)", v.profile.email, v.items.len());
                c.send_empty("POST", "/auth/logout").unwrap();
            }
            LoginOutcome::NeedTotp(..) => panic!("la 2FA locale ne doit pas être demandée après le SSO"),
        }
        // Le ticket est à usage unique.
        let again = login_with(client, &info.email, &password, &kdf, Some(ticket));
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
        match login_with(client, &info.email, &env("LOCKSY_TEST_PASSWORD"), &info.kdf.expect("coffre"), Some(ticket)).expect("délocksyillage") {
            LoginOutcome::Done(c, v) => {
                println!("OK : coffre de {} déchiffré ({} coffre(s))", v.profile.name, v.collections.len());
                c.send_empty("POST", "/auth/logout").unwrap();
            }
            LoginOutcome::NeedTotp(..) => panic!("2FA locale inattendue"),
        }
    }
}
