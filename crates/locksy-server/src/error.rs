use axum::async_trait;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Erreur renvoyée au client : un code stable et un message en français.
/// Les détails techniques restent dans les journaux du serveur.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    /// Délai conseillé avant un nouvel essai, en secondes : en-tête
    /// `Retry-After` et champ `retry_after` du corps (429 et 503).
    pub retry_after: Option<i64>,
}

pub type ApiResult<T> = Result<T, ApiError>;

/// Délai conseillé quand le serveur est saturé (calculs Argon2).
const BUSY_RETRY_SECS: i64 = 2;
/// Délai conseillé quand la base est momentanément verrouillée.
const DB_BUSY_RETRY_SECS: i64 = 1;
/// Délai conseillé pour toute autre indisponibilité (démarrage, arrêt).
const UNAVAILABLE_RETRY_SECS: i64 = 5;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), retry_after: None }
    }

    /// Fixe le délai conseillé avant un nouvel essai (au moins 1 s).
    pub fn with_retry_after(mut self, secs: i64) -> Self {
        self.retry_after = Some(secs.max(1));
        self
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    pub fn rate_limited(retry_after: i64) -> Self {
        let secs = retry_after.max(1);
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!("Trop de tentatives. Réessayez dans {secs} secondes."),
        )
        .with_retry_after(secs)
    }

    /// Service momentanément indisponible (503), avec un code stable et un
    /// délai conseillé avant un nouvel essai.
    pub fn unavailable(code: &'static str, message: impl Into<String>) -> Self {
        let secs = if code == "server_busy" { BUSY_RETRY_SECS } else { UNAVAILABLE_RETRY_SECS };
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message).with_retry_after(secs)
    }

    pub fn internal(context: &str) -> Self {
        tracing::error!(context, "erreur interne");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "Erreur interne du serveur.")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Même forme que `ErrorBody` (api.rs), plus `retry_after` s'il y a lieu.
        let mut body = serde_json::json!({ "error": self.code, "message": self.message });
        if let Some(secs) = self.retry_after {
            body["retry_after"] = secs.into();
        }
        let mut res = (self.status, axum::Json(body)).into_response();
        if let Some(secs) = self.retry_after {
            res.headers_mut().insert(axum::http::header::RETRY_AFTER, HeaderValue::from(secs));
        }
        res
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        // Base momentanément verrouillée (délai d'attente dépassé) : le client
        // peut réessayer, ce n'est pas une panne.
        if let rusqlite::Error::SqliteFailure(err, _) = &e {
            if matches!(err.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) {
                tracing::warn!(error = %e, "base de données occupée");
                return ApiError::unavailable("server_busy", "Serveur momentanément occupé. Réessayez.")
                    .with_retry_after(DB_BUSY_RETRY_SECS);
            }
        }
        tracing::error!(error = %e, "base de données");
        ApiError::internal("base de données")
    }
}

/// Corps JSON d'une requête ou d'une réponse. À la lecture, un corps refusé
/// (JSON illisible, mauvais type de contenu, champ manquant ou de mauvais
/// type) donne une erreur de l'API `{error, message}` en français au lieu du
/// texte brut d'axum : 400 `invalid_body` (415 gardé pour le type de
/// contenu, 413 `payload_too_large` pour un corps trop gros). Le détail
/// technique reste dans le journal (niveau debug), jamais dans la réponse.
#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(v)) => Ok(Json(v)),
            Err(rej) => Err(json_rejection(&rej)),
        }
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

/// Erreur de l'API pour un corps JSON refusé par axum.
fn json_rejection(rej: &JsonRejection) -> ApiError {
    tracing::debug!(detail = %rej.body_text(), "corps de requête refusé");
    match rej.status() {
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "Envoi trop volumineux pour le serveur.",
        ),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_body",
            "Requête illisible : le corps doit être envoyé en JSON (Content-Type: application/json).",
        ),
        _ => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Requête illisible : vérifiez le format des données envoyées.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite(code: i32) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)
    }

    /// Réponse HTTP d'une erreur : statut, en-tête Retry-After, corps JSON.
    async fn rendu(e: ApiError) -> (StatusCode, Option<String>, serde_json::Value) {
        let res = e.into_response();
        let status = res.status();
        let header = res.headers().get("retry-after").map(|v| v.to_str().unwrap().to_string());
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 16).await.unwrap();
        (status, header, serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn base_occupee_donne_503() {
        for code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
            let e = ApiError::from(sqlite(code));
            assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(e.code, "server_busy");
            assert_eq!(e.retry_after, Some(DB_BUSY_RETRY_SECS));
        }
        let e = ApiError::from(sqlite(rusqlite::ffi::SQLITE_CORRUPT));
        assert_eq!((e.status, e.code, e.retry_after), (StatusCode::INTERNAL_SERVER_ERROR, "internal", None));
        let e = ApiError::from(rusqlite::Error::QueryReturnedNoRows);
        assert_eq!(e.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn verrou_reel_donne_503() {
        // Deux connexions sur le même fichier : la seconde attend 10 ms puis échoue.
        let path = std::env::temp_dir().join(format!("locksy-busy-{}.db", locksy_core::crypto::new_uuid()));
        let a = rusqlite::Connection::open(&path).unwrap();
        a.execute_batch("CREATE TABLE t (x INTEGER); BEGIN EXCLUSIVE; INSERT INTO t VALUES (1);").unwrap();
        let b = rusqlite::Connection::open(&path).unwrap();
        b.busy_timeout(std::time::Duration::from_millis(10)).unwrap();
        let err = b.execute("INSERT INTO t VALUES (2)", []).unwrap_err();
        let e = ApiError::from(err);
        assert_eq!((e.status, e.code), (StatusCode::SERVICE_UNAVAILABLE, "server_busy"));
        assert!(e.retry_after.is_some_and(|s| (1..=5).contains(&s)));
        drop(b);
        drop(a);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn trop_de_tentatives_porte_retry_after() {
        let (status, header, body) = rendu(ApiError::rate_limited(42)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header.as_deref(), Some("42"));
        assert_eq!(body["error"], "rate_limited");
        assert_eq!(body["retry_after"], 42);
        assert!(body["message"].as_str().unwrap().contains("42 secondes"));
        // Jamais moins d'une seconde.
        assert_eq!(ApiError::rate_limited(0).retry_after, Some(1));
        assert_eq!(ApiError::rate_limited(-5).retry_after, Some(1));
    }

    #[tokio::test]
    async fn serveur_sature_porte_retry_after() {
        let (status, header, body) = rendu(ApiError::unavailable("server_busy", "Occupé.")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let secs: i64 = header.unwrap().parse().unwrap();
        assert!((1..=5).contains(&secs));
        assert_eq!(body["retry_after"], secs);
        assert_eq!(body["error"], "server_busy");
        // Base verrouillée : même forme.
        let (status, header, _) = rendu(ApiError::from(sqlite(rusqlite::ffi::SQLITE_BUSY))).await;
        assert_eq!((status, header.as_deref()), (StatusCode::SERVICE_UNAVAILABLE, Some("1")));
    }

    #[tokio::test]
    async fn erreur_ordinaire_sans_retry_after() {
        let (status, header, body) = rendu(ApiError::forbidden("Non.")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(header.is_none());
        assert_eq!(body, serde_json::json!({ "error": "forbidden", "message": "Non." }));
    }

    /// Corps refusé par l'extracteur : erreur de l'API en français, jamais
    /// le texte brut anglais d'axum.
    #[tokio::test]
    async fn corps_json_refuse_en_erreur_de_l_api() {
        #[derive(serde::Deserialize)]
        struct Corps {
            #[allow(dead_code)]
            n: i64,
        }
        async fn lire(content_type: Option<&str>, corps: &'static str) -> (StatusCode, serde_json::Value) {
            let mut req = Request::builder().method("POST").uri("/");
            if let Some(ct) = content_type {
                req = req.header("content-type", ct);
            }
            let req = req.body(axum::body::Body::from(corps)).unwrap();
            match Json::<Corps>::from_request(req, &()).await {
                Ok(_) => (StatusCode::OK, serde_json::Value::Null),
                Err(e) => {
                    let (status, _, body) = rendu(e).await;
                    (status, body)
                }
            }
        }
        let json = Some("application/json");
        assert_eq!(lire(json, r#"{"n":1}"#).await.0, StatusCode::OK);
        for (ct, corps, statut) in [
            (json, "{pas du json", StatusCode::BAD_REQUEST),
            (json, r#"{"n":"texte"}"#, StatusCode::BAD_REQUEST),
            (json, "{}", StatusCode::BAD_REQUEST),
            (Some("text/plain"), r#"{"n":1}"#, StatusCode::UNSUPPORTED_MEDIA_TYPE),
            (None, r#"{"n":1}"#, StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ] {
            let (status, body) = lire(ct, corps).await;
            assert_eq!(status, statut, "{ct:?} {corps}");
            assert_eq!(body["error"], "invalid_body", "{body}");
            let message = body["message"].as_str().unwrap();
            assert!(message.starts_with("Requête illisible"), "{message}");
            assert!(!message.contains("Failed") && !message.contains("deserialize"), "{message}");
        }
        // Une réponse sérialise comme celle d'axum.
        let res = Json(serde_json::json!({ "a": 1 })).into_response();
        assert_eq!(res.headers()["content-type"], "application/json");
    }
}
