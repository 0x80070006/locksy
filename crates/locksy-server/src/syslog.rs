//! Envoi du journal d'audit vers un SIEM. Cible : réglage `audit.syslog.url`
//! de l'organisation, ou `LOCKSY_SYSLOG` de l'hébergeur (prioritaire, la clé
//! est alors verrouillée) :
//! - `udp://hote:514` : un datagramme par événement ;
//! - `tcp://hote:514` : une ligne par événement ;
//! - `tcp+tls://hote:6514` : TLS (RFC 5425), trames à octets comptés
//!   `<longueur> <message>`. Le certificat du SIEM est vérifié avec les
//!   autorités publiques (webpki-roots) et, le cas échéant, celle de
//!   `LOCKSY_SYSLOG_CA_FILE` (AC interne, PEM).
//!
//! Format : réglage `audit.syslog.format`, `rfc5424` (en-tête Syslog RFC 5424
//! suivi du détail de l'événement en JSON) ou `json` (l'objet JSON seul).
//! Cible et format s'appliquent à chaud, à chaque révision des réglages.
//!
//! L'envoi ne bloque jamais l'API : les événements passent par une file
//! bornée ; si le SIEM est injoignable, ils restent dans le journal local.
//! À l'arrêt, `flush` attend que la file soit vidée (avec un délai).

use locksy_core::settings::Effective;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Délai de connexion, de lecture (poignée de main TLS) et d'écriture.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Relais du processus serveur (démarré par `init`, jamais dans les tests).
static RELAY: OnceLock<Relay> = OnceLock::new();

/// Message de la file : un événement à transmettre, ou une demande d'accusé
/// une fois tous les événements précédents traités.
pub(crate) enum Msg {
    Line(String),
    Flush(Sender<()>),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Target {
    Udp(String),
    Tcp(String),
    /// `addr` : hôte et port à joindre ; `host` : nom (ou IP) attendu dans le certificat.
    TcpTls { addr: String, host: String },
}

/// Lit une cible `udp://`, `tcp://` ou `tcp+tls://hote:port`.
pub(crate) fn parse(url: &str) -> Result<Target, String> {
    let url = url.trim();
    let (scheme, addr) =
        url.split_once("://").ok_or("format attendu : udp://hote:port, tcp://hote:port ou tcp+tls://hote:port")?;
    let Some((host, port)) = addr.rsplit_once(':') else {
        return Err("précisez l'hôte et le port, par exemple udp://siem.local:514".into());
    };
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err("précisez l'hôte et un port numérique, par exemple udp://siem.local:514".into());
    }
    match scheme.to_ascii_lowercase().as_str() {
        "udp" => Ok(Target::Udp(addr.to_string())),
        "tcp" => Ok(Target::Tcp(addr.to_string())),
        "tcp+tls" => {
            let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
            ServerName::try_from(host.clone()).map_err(|_| format!("« {host} » n'est ni un nom DNS ni une adresse IP"))?;
            Ok(Target::TcpTls { addr: addr.to_string(), host })
        }
        _ => Err("protocole inconnu (udp, tcp ou tcp+tls)".into()),
    }
}

/// Lit les certificats d'une autorité supplémentaire (PEM, un ou plusieurs).
pub(crate) fn load_ca_file(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let iter = CertificateDer::pem_file_iter(path).map_err(|e| format!("illisible ({e})"))?;
    let certs = iter.collect::<Result<Vec<_>, _>>().map_err(|e| format!("PEM illisible ({e})"))?;
    if certs.is_empty() {
        return Err("aucun certificat PEM (« BEGIN CERTIFICATE ») trouvé".into());
    }
    Ok(certs)
}

/// Configuration TLS du client syslog. Elle a son propre fournisseur
/// cryptographique : elle ne dépend pas de celui installé pour le HTTPS.
fn tls_config(ca_file: Option<&Path>) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        for cert in load_ca_file(path)? {
            roots.add(cert).map_err(|e| format!("certificat d'autorité refusé ({e})"))?;
        }
    }
    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("configuration TLS impossible ({e})"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

// ------------------------------------------------------------ Relais

/// Cible lue par le fil d'envoi : changée à chaud, repérée par sa génération.
#[derive(Default)]
struct Shared {
    target: Mutex<Option<(Target, Option<Arc<ClientConfig>>)>>,
    generation: AtomicU64,
}

/// File bornée vers un fil dédié, avec une cible et un format
/// reconfigurables (réglages `audit.syslog.url` et `audit.syslog.format`).
pub(crate) struct Relay {
    tx: SyncSender<Msg>,
    shared: Arc<Shared>,
    /// Cible (texte) et format appliqués : une reconfiguration identique est ignorée.
    current: Mutex<Option<(String, bool)>>,
    active: AtomicBool,
    json: AtomicBool,
    ca_file: Option<PathBuf>,
}

impl Relay {
    /// Démarre le fil d'envoi, sans cible (rien n'est envoyé).
    pub(crate) fn start(ca_file: Option<PathBuf>) -> Relay {
        let (tx, rx) = sync_channel::<Msg>(10_000);
        let shared = Arc::new(Shared::default());
        let worker = shared.clone();
        if let Err(e) = std::thread::Builder::new().name("syslog".into()).spawn(move || run(worker, rx)) {
            tracing::error!("fil syslog impossible à démarrer : {e}");
        }
        Relay {
            tx,
            shared,
            current: Mutex::new(None),
            active: AtomicBool::new(false),
            json: AtomicBool::new(false),
            ca_file,
        }
    }

    /// Applique les réglages effectifs (`LOCKSY_SYSLOG` y figure déjà comme
    /// valeur verrouillée de `audit.syslog.url`).
    pub(crate) fn apply(&self, eff: &Effective) {
        self.configure(eff.str("audit.syslog.url"), eff.str("audit.syslog.format"));
    }

    /// Cible (vide : envoi coupé) et format (`json`, sinon RFC 5424). Sans
    /// effet si rien ne change ; une cible illisible coupe l'envoi.
    pub(crate) fn configure(&self, url: &str, format: &str) {
        let url = url.trim();
        let json = format == "json";
        let mut current = self.current.lock().unwrap_or_else(|p| p.into_inner());
        if current.as_ref().is_some_and(|(u, j)| u == url && *j == json) {
            return;
        }
        *current = Some((url.to_string(), json));
        self.json.store(json, Ordering::SeqCst);
        let target = if url.is_empty() {
            None
        } else {
            match self.resolve(url) {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::error!("envoi au SIEM désactivé, cible refusée : {e}");
                    None
                }
            }
        };
        let active = target.is_some();
        *self.shared.target.lock().unwrap_or_else(|p| p.into_inner()) = target;
        self.shared.generation.fetch_add(1, Ordering::SeqCst);
        self.active.store(active, Ordering::SeqCst);
        match (active, json) {
            (true, false) => tracing::info!("envoi du journal d'audit vers {url} (RFC 5424)"),
            (true, true) => tracing::info!("envoi du journal d'audit vers {url} (JSON)"),
            (false, _) => tracing::info!("envoi du journal d'audit au SIEM inactif"),
        }
    }

    fn resolve(&self, url: &str) -> Result<(Target, Option<Arc<ClientConfig>>), String> {
        let target = parse(url)?;
        let tls = match &target {
            Target::TcpTls { .. } => Some(tls_config(self.ca_file.as_deref())?),
            _ => None,
        };
        Ok((target, tls))
    }

    /// Met en forme et met en file un événement (sans effet sans cible).
    #[allow(clippy::too_many_arguments)]
    fn emit(&self, at: i64, user_id: Option<&str>, email: &str, action: &str, target: &str, ip: &str, user_agent: &str, details: &str) {
        if !self.active.load(Ordering::SeqCst) {
            return;
        }
        let event = Event { at, user_id, email, action, target, ip, user_agent, details };
        self.push(format_line(self.json.load(Ordering::SeqCst), &event));
    }

    fn push(&self, line: String) {
        if let Err(TrySendError::Full(_)) = self.tx.try_send(Msg::Line(line)) {
            tracing::warn!("file syslog pleine : événement non transmis au SIEM (il reste dans le journal local)");
        }
    }
}

/// Démarre le relais du serveur avec la cible de l'hébergeur (`LOCKSY_SYSLOG`,
/// déjà validée par la configuration) ; les réglages de l'organisation sont
/// appliqués ensuite par [`apply`].
pub(crate) fn init(target: Option<&str>, ca_file: Option<&Path>) {
    let relay = RELAY.get_or_init(|| Relay::start(ca_file.map(Path::to_path_buf)));
    relay.configure(target.unwrap_or(""), "rfc5424");
}

/// Applique les réglages effectifs au relais du serveur (sans effet avant
/// `init`, donc dans les tests).
pub(crate) fn apply(eff: &Effective) {
    if let Some(relay) = RELAY.get() {
        relay.apply(eff);
    }
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// Événement d'audit à transmettre.
struct Event<'a> {
    at: i64,
    user_id: Option<&'a str>,
    email: &'a str,
    action: &'a str,
    target: &'a str,
    ip: &'a str,
    user_agent: &'a str,
    details: &'a str,
}

/// Ligne transmise : objet JSON seul (`json`), ou en-tête RFC 5424 suivi du JSON.
fn format_line(json: bool, e: &Event) -> String {
    let body = serde_json::json!({
        "at": e.at,
        "user_id": e.user_id,
        "email": e.email,
        "action": e.action,
        "target": e.target,
        "ip": e.ip,
        "user_agent": e.user_agent,
        "details": e.details,
    });
    if json {
        return body.to_string();
    }
    // Facilité « authpriv » (10) ; avertissement pour les échecs et refus.
    let severity = if e.action.contains("failed") || e.action.contains("refused") { 4 } else { 5 };
    let pri = 10 * 8 + severity;
    let ts = crate::admin::format_utc(e.at).replacen(' ', "T", 1) + "Z";
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "locksy".into());
    format!("<{pri}>1 {ts} {} locksy - {} - {}", sanitize(&host), sanitize(e.action), body)
}

/// Met en forme et met en file un événement d'audit (sans effet si désactivé).
/// Ne bloque jamais : appelable depuis n'importe quel fil.
#[allow(clippy::too_many_arguments)]
pub fn emit(at: i64, user_id: Option<&str>, email: &str, action: &str, target: &str, ip: &str, user_agent: &str, details: &str) {
    if let Some(relay) = RELAY.get() {
        relay.emit(at, user_id, email, action, target, ip, user_agent, details);
    }
}

/// Attend que les événements déjà en file soient transmis (ou abandonnés),
/// au plus `timeout`. Vrai si la file est vidée, ou si le syslog est désactivé.
pub fn flush(timeout: Duration) -> bool {
    match RELAY.get() {
        Some(relay) => flush_on(&relay.tx, timeout),
        None => true,
    }
}

fn flush_on(tx: &SyncSender<Msg>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let (ack_tx, ack_rx) = channel();
    let mut msg = Msg::Flush(ack_tx);
    // File pleine : on réessaie jusqu'au délai, sans jamais bloquer au-delà.
    loop {
        match tx.try_send(msg) {
            Ok(()) => break,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(m)) => {
                if Instant::now() >= deadline {
                    return false;
                }
                msg = m;
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    ack_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())).is_ok()
}

/// Trame à octets comptés (RFC 5425 / RFC 6587 § 3.4.1) : `<longueur> <message>`,
/// la longueur étant celle du message en octets.
pub(crate) fn octet_counted(line: &str) -> String {
    format!("{} {line}", line.len())
}

/// Connexion TCP au SIEM, en clair ou en TLS.
enum Conn {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Conn {
    fn send(&mut self, line: &str) -> std::io::Result<()> {
        match self {
            // Une ligne par événement (compatibilité avec les déploiements existants).
            Conn::Plain(s) => s.write_all(format!("{line}\n").as_bytes()),
            Conn::Tls(s) => {
                s.write_all(octet_counted(line).as_bytes())?;
                s.flush()
            }
        }
    }

    fn flush(&mut self) {
        let _ = match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        };
    }
}

fn connect(addr: &str, tls: Option<(&Arc<ClientConfig>, &str)>) -> Result<Conn, String> {
    let sock_addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("résolution impossible ({e})"))?
        .next()
        .ok_or("aucune adresse")?;
    let tcp = TcpStream::connect_timeout(&sock_addr, IO_TIMEOUT).map_err(|e| e.to_string())?;
    let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
    let Some((config, host)) = tls else { return Ok(Conn::Plain(tcp)) };
    // Lecture bornée : la poignée de main ne reste pas suspendue à un pair muet.
    let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(config.clone(), name).map_err(|e| e.to_string())?;
    let mut stream = StreamOwned::new(conn, tcp);
    // Poignée de main immédiate : un certificat refusé est signalé tout de suite.
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).map_err(|e| format!("TLS : {e}"))?;
    }
    Ok(Conn::Tls(Box::new(stream)))
}

/// Destination courante du fil d'envoi.
enum Sink {
    Udp { sock: UdpSocket, addr: String },
    Stream { addr: String, label: &'static str, tls: Option<(Arc<ClientConfig>, String)>, conn: Option<Conn> },
}

impl Sink {
    fn new(target: Target, tls: Option<Arc<ClientConfig>>) -> Option<Sink> {
        match target {
            Target::Udp(addr) => match UdpSocket::bind("0.0.0.0:0") {
                Ok(sock) => Some(Sink::Udp { sock, addr }),
                Err(e) => {
                    tracing::error!("syslog UDP indisponible : {e}");
                    None
                }
            },
            Target::Tcp(addr) => Some(Sink::Stream { addr, label: "TCP", tls: None, conn: None }),
            Target::TcpTls { addr, host } => match tls {
                Some(c) => Some(Sink::Stream { addr, label: "TCP+TLS", tls: Some((c, host)), conn: None }),
                None => {
                    tracing::error!("syslog TCP+TLS : configuration TLS absente");
                    None
                }
            },
        }
    }

    fn send(&mut self, line: &str) {
        match self {
            Sink::Udp { sock, addr } => {
                if let Err(e) = sock.send_to(line.as_bytes(), addr.as_str()) {
                    tracing::warn!("syslog UDP : {e}");
                }
            }
            Sink::Stream { addr, label, tls, conn } => {
                let tls = tls.as_ref().map(|(c, h)| (c, h.as_str()));
                let mut last_err = String::new();
                for attempt in 0..2 {
                    if conn.is_none() {
                        match connect(addr, tls) {
                            Ok(c) => *conn = Some(c),
                            Err(e) => last_err = e,
                        }
                    }
                    match conn.as_mut().map(|c| c.send(line)) {
                        Some(Ok(())) => return,
                        Some(Err(e)) => last_err = e.to_string(),
                        None => {}
                    }
                    *conn = None;
                    if attempt == 1 {
                        tracing::warn!("syslog {label} : {addr} injoignable ({last_err}), événement non transmis");
                    }
                }
            }
        }
    }

    fn flush(&mut self) {
        if let Sink::Stream { conn: Some(c), .. } = self {
            c.flush();
        }
    }
}

/// Fil d'envoi : relit la cible quand sa génération change (connexion
/// refaite), puis transmet chaque événement.
fn run(shared: Arc<Shared>, rx: Receiver<Msg>) {
    let mut generation = u64::MAX;
    let mut sink: Option<Sink> = None;
    for msg in rx {
        let current = shared.generation.load(Ordering::SeqCst);
        if current != generation {
            generation = current;
            let target = shared.target.lock().unwrap_or_else(|p| p.into_inner()).clone();
            sink = target.and_then(|(t, tls)| Sink::new(t, tls));
        }
        match msg {
            Msg::Line(line) => {
                if let Some(s) = sink.as_mut() {
                    s.send(&line);
                }
            }
            Msg::Flush(ack) => {
                if let Some(s) = sink.as_mut() {
                    s.flush();
                }
                let _ = ack.send(());
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
        assert!(parse("udp://siem:syslog").is_err());
        assert!(parse("udp://:514").is_err());
    }

    #[test]
    fn parses_tls_targets() {
        assert_eq!(
            parse("tcp+tls://h:6514").unwrap(),
            Target::TcpTls { addr: "h:6514".into(), host: "h".into() }
        );
        assert_eq!(
            parse("TCP+TLS://siem.example.com:6514").unwrap(),
            Target::TcpTls { addr: "siem.example.com:6514".into(), host: "siem.example.com".into() }
        );
        // Adresse IP (v4 ou v6 entre crochets) : vérifiée comme telle dans le certificat.
        assert_eq!(
            parse("tcp+tls://10.0.0.5:6514").unwrap(),
            Target::TcpTls { addr: "10.0.0.5:6514".into(), host: "10.0.0.5".into() }
        );
        assert_eq!(
            parse("tcp+tls://[2001:db8::1]:6514").unwrap(),
            Target::TcpTls { addr: "[2001:db8::1]:6514".into(), host: "2001:db8::1".into() }
        );
        assert!(parse("tcp+tls://siem").is_err());
        assert!(parse("tcp+tls://nom invalide:6514").is_err());
    }

    #[test]
    fn trame_a_octets_comptes() {
        assert_eq!(octet_counted("<85>1 abc"), "9 <85>1 abc");
        // La longueur est en octets, pas en caractères.
        assert_eq!(octet_counted("é"), "2 é");
        assert_eq!(octet_counted(""), "0 ");
    }

    #[test]
    fn configuration_tls_et_autorite() {
        // Les autorités publiques suffisent à construire la configuration.
        assert!(tls_config(None).is_ok());
        let dir = std::env::temp_dir().join(format!("locksy-syslog-{}", locksy_core::crypto::new_uuid()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("ca.pem");
        std::fs::write(&bad, "pas un certificat").unwrap();
        assert!(load_ca_file(&bad).unwrap_err().contains("aucun certificat"));
        assert!(tls_config(Some(&bad)).is_err());
        assert!(load_ca_file(&dir.join("absent.pem")).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn udp_ecoute() -> (UdpSocket, String) {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let addr = server.local_addr().unwrap().to_string();
        (server, addr)
    }

    fn recu(server: &UdpSocket) -> String {
        let mut buf = [0u8; 2048];
        let n = server.recv(&mut buf).unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[test]
    fn udp_delivery() {
        let (server, addr) = udp_ecoute();
        let relay = Relay::start(None);
        relay.configure(&format!("udp://{addr}"), "rfc5424");
        relay.emit(1_700_000_000, None, "a@x.fr", "login.success", "", "", "", "");
        let line = recu(&server);
        assert!(line.starts_with("<85>1 2023-11-14T22:13:20Z "), "{line}");
        assert!(line.contains(" locksy - login.success - {"), "{line}");
    }

    #[test]
    fn flush_apres_livraison_udp() {
        let (server, addr) = udp_ecoute();
        let relay = Relay::start(None);
        relay.configure(&format!("udp://{addr}"), "rfc5424");
        for i in 0..3 {
            relay.push(format!("événement {i}"));
        }
        assert!(flush_on(&relay.tx, Duration::from_secs(3)));
        // Tout ce qui précédait l'accusé est parti.
        for i in 0..3 {
            assert_eq!(recu(&server), format!("événement {i}"));
        }
        // Syslog désactivé (aucun init dans les tests) : sans effet.
        assert!(flush(Duration::from_millis(10)));
        // Fil arrêté : l'accusé ne vient jamais.
        let (tx, rx) = sync_channel::<Msg>(1);
        drop(rx);
        assert!(!flush_on(&tx, Duration::from_millis(50)));
    }

    #[test]
    fn tcp_une_ligne_par_evenement() {
        use std::io::{BufRead, BufReader};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let relay = Relay::start(None);
        relay.configure(&format!("tcp://{addr}"), "rfc5424");
        relay.push("a".into());
        relay.push("b".into());
        assert!(flush_on(&relay.tx, Duration::from_secs(3)));
        let (sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let lines: Vec<String> = BufReader::new(sock).lines().take(2).map(|l| l.unwrap()).collect();
        assert_eq!(lines, ["a", "b"]);
    }

    /// `audit.syslog.url` et `audit.syslog.format`, réglés par l'organisation,
    /// sont appliqués à chaud : nouvelle cible, ligne JSON seule, puis arrêt
    /// de l'envoi quand la cible est vidée.
    #[tokio::test]
    async fn reglages_url_et_format_appliques() {
        use crate::tests::{set_setting, srv};
        use serde_json::json;
        let s = srv().await;
        let relay = Relay::start(None);
        // Défaut : aucune cible, rien n'est mis en file.
        relay.apply(&s.st.effective().await.unwrap());
        assert!(!relay.active.load(Ordering::SeqCst));

        let (server, addr) = udp_ecoute();
        set_setting(&s.st, "audit.syslog.url", json!(format!("udp://{addr}"))).await;
        relay.apply(&s.st.effective().await.unwrap());
        relay.emit(1_700_000_000, Some("u1"), "a@x.fr", "login.failed", "", "10.0.0.1", "", "");
        let line = recu(&server);
        assert!(line.starts_with("<84>1 "), "RFC 5424 par défaut, avertissement pour un échec : {line}");

        set_setting(&s.st, "audit.syslog.format", json!("json")).await;
        relay.apply(&s.st.effective().await.unwrap());
        relay.emit(1_700_000_000, Some("u1"), "a@x.fr", "login.success", "", "10.0.0.1", "", "");
        let line = recu(&server);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|e| panic!("JSON seul attendu ({e}) : {line}"));
        assert_eq!((v["action"].as_str(), v["email"].as_str(), v["at"].as_i64()), (Some("login.success"), Some("a@x.fr"), Some(1_700_000_000)));

        set_setting(&s.st, "audit.syslog.url", json!("")).await;
        relay.apply(&s.st.effective().await.unwrap());
        assert!(!relay.active.load(Ordering::SeqCst), "cible vidée : envoi coupé");
    }

    #[test]
    fn cible_illisible_coupe_l_envoi() {
        let relay = Relay::start(None);
        relay.configure("udp://127.0.0.1:9", "rfc5424");
        assert!(relay.active.load(Ordering::SeqCst));
        relay.configure("pas-une-url", "rfc5424");
        assert!(!relay.active.load(Ordering::SeqCst));
    }
}
