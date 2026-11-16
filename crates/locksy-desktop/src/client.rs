//! Client HTTP de l'API Locksy (HTTPS via le magasin de certificats Windows).

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use locksy_core::api::ErrorBody;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<locksy_core::Error> for ApiError {
    fn from(e: locksy_core::Error) -> Self {
        ApiError { status: 0, code: "crypto".into(), message: e.to_string() }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Clone)]
pub struct Client {
    base: String,
    agent: ureq::Agent,
    pub token: Option<String>,
}

/// Refuse le HTTP en clair sauf vers ce poste lui-même.
pub fn validate_server_url(url: &str) -> Result<String, String> {
    let url = url.trim().trim_end_matches('/').to_string();
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(url);
    }
    if let Some(rest) = lower.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or_default();
        if host == "localhost" || host == "127.0.0.1" || host == "[::1]" {
            return Ok(url);
        }
        return Err("Pour un serveur distant, utilisez une adresse en https://.".into());
    }
    Err("L'adresse doit commencer par https:// (ou http://localhost pour ce poste).".into())
}

impl Client {
    pub fn new(base: &str) -> Result<Self, String> {
        let base = validate_server_url(base)?;
        let tls = native_tls::TlsConnector::builder()
            .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
            .build()
            .map_err(|e| format!("TLS indisponible : {e}"))?;
        let agent = ureq::AgentBuilder::new()
            .tls_connector(Arc::new(tls))
            .timeout_connect(Duration::from_secs(8))
            .timeout(Duration::from_secs(30))
            .redirects(0)
            .user_agent(concat!("Locksy-Bureau/", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(Self { base, agent, token: None })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn request(&self, method: &str, path: &str) -> ureq::Request {
        let mut r = self.agent.request(method, &format!("{}/api{}", self.base, path));
        if let Some(t) = &self.token {
            r = r.set("Authorization", &format!("Bearer {t}"));
        }
        r
    }

    fn handle(res: Result<ureq::Response, ureq::Error>) -> ApiResult<String> {
        match res {
            Ok(r) => r.into_string().map_err(|e| ApiError { status: 0, code: "io".into(), message: e.to_string() }),
            Err(ureq::Error::Status(status, r)) => {
                let body: Option<ErrorBody> = r.into_json().ok();
                Err(match body {
                    Some(b) => ApiError { status, code: b.error, message: b.message },
                    None => ApiError { status, code: "http".into(), message: format!("Erreur du serveur ({status}).") },
                })
            }
            Err(ureq::Error::Transport(t)) => Err(ApiError {
                status: 0,
                code: "network".into(),
                message: format!("Serveur injoignable : {}", t.message().unwrap_or("connexion impossible")),
            }),
        }
    }

    fn parse<T: DeserializeOwned>(text: String) -> ApiResult<T> {
        let text = if text.trim().is_empty() { "null".to_string() } else { text };
        serde_json::from_str(&text).map_err(|e| ApiError { status: 0, code: "json".into(), message: format!("Réponse inattendue du serveur : {e}") })
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> ApiResult<T> {
        Self::parse(Self::handle(self.request("GET", path).call())?)
    }

    pub fn send<B: Serialize, T: DeserializeOwned>(&self, method: &str, path: &str, body: &B) -> ApiResult<T> {
        let json = serde_json::to_value(body).map_err(|e| ApiError { status: 0, code: "json".into(), message: e.to_string() })?;
        Self::parse(Self::handle(self.request(method, path).send_json(json))?)
    }

    pub fn send_empty(&self, method: &str, path: &str) -> ApiResult<()> {
        Self::handle(self.request(method, path).call()).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_server_url;

    #[test]
    fn only_https_or_local_http() {
        assert!(validate_server_url("http://localhost:8743/").is_ok());
        assert!(validate_server_url("http://127.0.0.1:8743").is_ok());
        assert!(validate_server_url("https://coffre.exemple.fr").is_ok());
        assert!(validate_server_url("http://coffre.exemple.fr").is_err());
        assert!(validate_server_url("http://localhost.evil.fr").is_err());
        assert!(validate_server_url("ftp://x").is_err());
    }
}
