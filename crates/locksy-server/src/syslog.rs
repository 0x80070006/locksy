//! Envoi du journal d'audit vers un SIEM au format Syslog RFC 5424, avec le
//! détail de l'événement en JSON. Activé par `LOCKSY_SYSLOG` :
//! `udp://hote:514` ou `tcp://hote:514` (une ligne par événement).
//!
//! L'envoi ne bloque jamais l'API : les événements passent par une file
//! bornée ; si le SIEM est injoignable, ils restent dans le journal local.

use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::time::Duration;

static SENDER: OnceLock<SyncSender<String>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq)]
enum Target {
    Udp(String),
    Tcp(String),
}

fn parse(url: &str) -> Result<Target, String> {
    let url = url.trim();
    let (scheme, addr) = url.split_once("://").ok_or("format attendu : udp://hote:port ou tcp://hote:port")?;
    if addr.is_empty() || !addr.contains(':') {
        return Err("précisez l'hôte et le port, par exemple udp://siem.local:514".into());
    }
    match scheme.to_ascii_lowercase().as_str() {
        "udp" => Ok(Target::Udp(addr.to_string())),
        "tcp" => Ok(Target::Tcp(addr.to_string())),
        _ => Err("protocole inconnu (udp ou tcp)".into()),
    }
}

/// Démarre l'envoi si `LOCKSY_SYSLOG` est défini.
pub fn init_from_env() {
    let Ok(url) = std::env::var("LOCKSY_SYSLOG") else { return };
    if url.trim().is_empty() {
        return;
    }
    match parse(&url) {
        Ok(target) => {
            let (tx, rx) = sync_channel::<String>(10_000);
            if SENDER.set(tx).is_ok() {
                std::thread::Builder::new()
                    .name("syslog".into())
                    .spawn(move || run(target, rx))
                    .expect("fil syslog");
                tracing::info!("envoi du journal d'audit vers {url}");
            }
        }
        Err(e) => tracing::error!("LOCKSY_SYSLOG ignoré : {e}"),
    }
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// Met en forme et met en file un événement d'audit (sans effet si désactivé).
#[allow(clippy::too_many_arguments)]
pub fn emit(at: i64, user_id: Option<&str>, email: &str, action: &str, target: &str, ip: &str, user_agent: &str, details: &str) {
    let Some(tx) = SENDER.get() else { return };
    // Facilité « authpriv » (10) ; avertissement pour les échecs et refus.
    let severity = if action.contains("failed") || action.contains("refused") { 4 } else { 5 };
    let pri = 10 * 8 + severity;
    let ts = crate::admin::format_utc(at).replacen(' ', "T", 1) + "Z";
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "locksy".into());
    let json = serde_json::json!({
        "at": at,
        "user_id": user_id,
        "email": email,
        "action": action,
        "target": target,
        "ip": ip,
        "user_agent": user_agent,
        "details": details,
    });
    let line = format!("<{pri}>1 {ts} {} locksy - {} - {}", sanitize(&host), sanitize(action), json);
    if let Err(TrySendError::Full(_)) = tx.try_send(line) {
        tracing::warn!("file syslog pleine : événement non transmis au SIEM (il reste dans le journal local)");
    }
}

fn run(target: Target, rx: Receiver<String>) {
    match target {
        Target::Udp(addr) => {
            let sock = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => return tracing::error!("syslog UDP indisponible : {e}"),
            };
            for line in rx {
                if let Err(e) = sock.send_to(line.as_bytes(), &addr) {
                    tracing::warn!("syslog UDP : {e}");
                }
            }
        }
        Target::Tcp(addr) => {
            let mut conn: Option<TcpStream> = None;
            for line in rx {
                for attempt in 0..2 {
                    if conn.is_none() {
                        conn = addr
                            .to_socket_addrs()
                            .ok()
                            .and_then(|mut a| a.next())
                            .and_then(|a| TcpStream::connect_timeout(&a, Duration::from_secs(5)).ok());
                        if let Some(c) = &conn {
                            let _ = c.set_write_timeout(Some(Duration::from_secs(5)));
                        }
                    }
                    let ok = conn.as_mut().is_some_and(|c| c.write_all(format!("{line}\n").as_bytes()).is_ok());
                    if ok {
                        break;
                    }
                    conn = None;
                    if attempt == 1 {
                        tracing::warn!("syslog TCP : {addr} injoignable, événement non transmis");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_targets() {
        assert_eq!(parse("udp://siem:514").unwrap(), Target::Udp("siem:514".into()));
        assert_eq!(parse("TCP://10.0.0.5:6514").unwrap(), Target::Tcp("10.0.0.5:6514".into()));
        assert!(parse("siem:514").is_err());
        assert!(parse("http://siem:514").is_err());
        assert!(parse("udp://siem").is_err());
    }

    #[test]
    fn udp_delivery() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let addr = server.local_addr().unwrap().to_string();
        let (tx, rx) = sync_channel(10);
        std::thread::spawn(move || run(Target::Udp(addr), rx));
        tx.send("<85>1 2026-01-01T00:00:00Z h locksy - login.success - {}".into()).unwrap();
        let mut buf = [0u8; 512];
        let n = server.recv(&mut buf).unwrap();
        assert!(std::str::from_utf8(&buf[..n]).unwrap().contains("login.success"));
    }
}
