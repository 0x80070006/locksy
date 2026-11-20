//! Journal d'audit infalsifiable : chaque ligne porte une empreinte HMAC
//! liée à celle de la ligne précédente, et des ancrages signés
//! (`audit_anchors`) jalonnent la chaîne.
//!
//! - Empreinte d'une ligne : `audit.chain_mac` = hex HMAC-SHA256(K,
//!   empreinte précédente (32 octets) ‖ forme canonique de la ligne). La
//!   forme canonique enchaîne id, at, user_id, email, action, target, ip,
//!   user_agent et details, chacun précédé de sa longueur (u32 gros-boutiste) ;
//!   les entiers sont codés sur 8 octets gros-boutistes, un user_id NULL par
//!   la longueur `u32::MAX` sans contenu (distinct de la chaîne vide).
//! - K = `derive_subkey(clé serveur, "verrou/v1/audit-chain")` : libellé
//!   propre au journal, aucun libellé existant n'est réutilisé.
//! - Ancrage : `mac` = « v1.<tête hex>.<étiquette hex> ». La tête est
//!   l'empreinte de la chaîne juste après la ligne `last_audit_id` ;
//!   l'étiquette = HMAC(K, "anchor" ‖ reason ‖ at ‖ last_audit_id ‖ tête),
//!   champs préfixés de leur longueur. Motifs : `genesis` (début de la
//!   chaîne, tête nulle), `purge` (posé avant la suppression des lignes
//!   anciennes : la chaîne restante repart de sa tête), `seal` (scellement
//!   au plus une fois par heure : une troncature de la fin du journal
//!   devient visible).
//!
//! La vérification (`verify`) est partagée par la route d'administration et
//! la sous-commande `locksy-server verify-audit`. Les lignes antérieures au
//! début de la chaîne (journal d'avant l'activation) sont signalées comme non
//! chaînées, pas comme des anomalies.

use crate::error::{ApiError, ApiResult};
use crate::state::{self, AdminUser, AppState, ClientMeta};
use axum::extract::State;
use axum::routing::get;
use axum::Router;
use crate::error::Json;
use hmac::{Hmac, Mac};
use locksy_core::crypto::{derive_subkey, SecretKey};
use locksy_core::now_unix;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{PoisonError, RwLock};
use std::time::Duration;
use subtle::ConstantTimeEq;

/// Libellé HKDF de la clé du journal chaîné (nouveau, propre à ce module).
const KEY_LABEL: &str = "verrou/v1/audit-chain";
/// Version du format des ancrages.
const ANCHOR_VERSION: &str = "v1";
/// Tête de la chaîne avant sa première ligne.
const GENESIS_HEAD: [u8; 32] = [0; 32];
/// Intervalle minimal entre deux scellements (secondes).
const SEAL_INTERVAL: i64 = 3600;
/// Action journalisée à chaque scellement (exclue du critère « nouvelle
/// activité depuis le dernier ancrage », sans quoi chaque scellement en
/// appellerait un autre).
const SEALED_ACTION: &str = "audit.sealed";

const REASON_GENESIS: &str = "genesis";
const REASON_PURGE: &str = "purge";
const REASON_SEAL: &str = "seal";

/// Natures d'anomalie renvoyées par la vérification.
const ALTERED: &str = "altered";
const MISSING: &str = "missing";
const INSERTED: &str = "inserted";
const ANCHOR_INVALID: &str = "anchor_invalid";

type HmacSha256 = Hmac<Sha256>;

// ------------------------------------------------------------ Clé

/// Clé du journal chaîné (HMAC préparé, cloné pour chaque calcul).
#[derive(Clone)]
pub struct Key(HmacSha256);

impl Key {
    pub fn from_server_key(server_key: &SecretKey) -> Self {
        let sub = derive_subkey(server_key, KEY_LABEL);
        Self(HmacSha256::new_from_slice(sub.as_bytes()).expect("clé HMAC de 32 octets"))
    }

    /// HMAC de `prefix` suivi des champs, chacun préfixé de sa longueur.
    fn mac(&self, prefix: &[u8], fields: &[Field<'_>]) -> [u8; 32] {
        let mut m = self.0.clone();
        m.update(prefix);
        let mut buf = Vec::with_capacity(256);
        for f in fields {
            f.encode(&mut buf);
        }
        m.update(&buf);
        m.finalize().into_bytes().into()
    }

    /// Empreinte d'une ligne d'audit chaînée après `prev`.
    fn row_mac(&self, prev: &[u8; 32], r: &Row) -> [u8; 32] {
        let (id, at) = (r.id.to_be_bytes(), r.at.to_be_bytes());
        self.mac(
            prev,
            &[
                Field::Bytes(&id),
                Field::Bytes(&at),
                r.user_id.as_deref().map_or(Field::Null, |u| Field::Bytes(u.as_bytes())),
                Field::Bytes(r.email.as_bytes()),
                Field::Bytes(r.action.as_bytes()),
                Field::Bytes(r.target.as_bytes()),
                Field::Bytes(r.ip.as_bytes()),
                Field::Bytes(r.user_agent.as_bytes()),
                Field::Bytes(r.details.as_bytes()),
            ],
        )
    }

    /// Étiquette d'un ancrage.
    fn anchor_tag(&self, reason: &str, at: i64, last_audit_id: i64, head: &[u8; 32]) -> [u8; 32] {
        let (at, last) = (at.to_be_bytes(), last_audit_id.to_be_bytes());
        self.mac(
            &[],
            &[
                Field::Bytes(b"anchor"),
                Field::Bytes(reason.as_bytes()),
                Field::Bytes(&at),
                Field::Bytes(&last),
                Field::Bytes(head),
            ],
        )
    }
}

/// Champ de la forme canonique.
enum Field<'a> {
    Bytes(&'a [u8]),
    Null,
}

impl Field<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Field::Bytes(b) => {
                // Un champ de 4 Gio ou plus est impossible en SQLite (1 Gio au plus).
                out.extend_from_slice(&(b.len() as u32).to_be_bytes());
                out.extend_from_slice(b);
            }
            Field::Null => out.extend_from_slice(&u32::MAX.to_be_bytes()),
        }
    }
}

/// Clé installée au démarrage du serveur (`install_key`).
static KEY: RwLock<Option<Key>> = RwLock::new(None);
/// L'absence de clé n'est signalée qu'une fois.
static KEY_WARNED: AtomicBool = AtomicBool::new(false);

/// Installe la clé du journal, dérivée de la clé serveur. Sans elle, les
/// lignes sont écrites sans empreinte et la vérification est indisponible.
pub fn install_key(server_key: &SecretKey) {
    *KEY.write().unwrap_or_else(PoisonError::into_inner) = Some(Key::from_server_key(server_key));
}

fn current_key() -> Option<Key> {
    let key = KEY.read().unwrap_or_else(PoisonError::into_inner).clone();
    // Tests : clé fixe, indépendante de la clé serveur de chaque état de
    // test (les tests tournent en parallèle sur le même processus).
    #[cfg(test)]
    if key.is_none() {
        return Some(test_key());
    }
    key
}

fn warn_missing_key() {
    if !KEY_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!("journal d'audit : clé de chaînage absente, lignes écrites sans empreinte");
    }
}

/// Clé serveur fixe des tests (le fichier de clé de `verify-audit` en test).
#[cfg(test)]
pub(crate) const TEST_SERVER_KEY: [u8; 32] = [0x4c; 32];

#[cfg(test)]
pub(crate) fn test_key() -> Key {
    static K: std::sync::OnceLock<Key> = std::sync::OnceLock::new();
    K.get_or_init(|| {
        let sk = SecretKey::from_slice(&TEST_SERVER_KEY).unwrap_or_else(|_| unreachable!("32 octets"));
        Key::from_server_key(&sk)
    })
    .clone()
}

// ------------------------------------------------------------ Codage

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.as_bytes();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

fn eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    bool::from(a.ct_eq(b))
}

/// « v1.<tête>.<étiquette> » → (tête, étiquette).
fn parse_anchor_mac(s: &str) -> Option<([u8; 32], [u8; 32])> {
    let mut parts = s.split('.');
    let (v, head, tag) = (parts.next()?, parts.next()?, parts.next()?);
    if v != ANCHOR_VERSION || parts.next().is_some() {
        return None;
    }
    Some((parse_hex32(head)?, parse_hex32(tag)?))
}

// ------------------------------------------------------------ Lecture

/// Ligne du journal, telle qu'elle est stockée.
struct Row {
    id: i64,
    at: i64,
    user_id: Option<String>,
    email: String,
    action: String,
    target: String,
    ip: String,
    user_agent: String,
    details: String,
    chain_mac: Option<String>,
}

const ROW_COLUMNS: &str = "id, at, user_id, email, action, target, ip, user_agent, details, chain_mac";

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        id: r.get(0)?,
        at: r.get(1)?,
        user_id: r.get(2)?,
        email: r.get(3)?,
        action: r.get(4)?,
        target: r.get(5)?,
        ip: r.get(6)?,
        user_agent: r.get(7)?,
        details: r.get(8)?,
        chain_mac: r.get(9)?,
    })
}

impl Row {
    fn mac(&self) -> Option<[u8; 32]> {
        self.chain_mac.as_deref().and_then(parse_hex32)
    }
}

/// Tête de la chaîne juste après la ligne `x` : empreinte de la dernière
/// ligne chaînée d'id ≤ x, ou tête du dernier ancrage d'id ≤ x si les lignes
/// qui le suivent ont été purgées. `None` : la chaîne n'a pas commencé.
fn head_at(c: &Connection, x: i64) -> ApiResult<Option<[u8; 32]>> {
    let anchor: Option<(i64, String)> = c
        .prepare_cached(
            "SELECT last_audit_id, mac FROM audit_anchors WHERE last_audit_id <= ?1
             ORDER BY last_audit_id DESC, id DESC LIMIT 1",
        )?
        .query_row([x], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let anchor = anchor.and_then(|(last, mac)| parse_anchor_mac(&mac).map(|(head, _)| (last, head)));
    // Recherche bornée par l'ancrage : sans lui, une seule fois sur un
    // journal ancien non chaîné.
    let floor = anchor.map_or(i64::MIN, |(last, _)| last);
    let row: Option<String> = c
        .prepare_cached(
            "SELECT chain_mac FROM audit WHERE id <= ?1 AND id >= ?2 AND chain_mac IS NOT NULL
             ORDER BY id DESC LIMIT 1",
        )?
        .query_row([x, floor], |r| r.get(0))
        .optional()?;
    Ok(row.as_deref().and_then(parse_hex32).or(anchor.map(|(_, head)| head)))
}

fn insert_anchor(c: &Connection, key: &Key, reason: &str, at: i64, last_audit_id: i64, head: &[u8; 32]) -> ApiResult<()> {
    let tag = key.anchor_tag(reason, at, last_audit_id, head);
    let mac = format!("{ANCHOR_VERSION}.{}.{}", hex(head), hex(&tag));
    c.prepare_cached("INSERT INTO audit_anchors (at, last_audit_id, mac, reason) VALUES (?1, ?2, ?3, ?4)")?
        .execute(params![at, last_audit_id, mac, reason])?;
    Ok(())
}

// ------------------------------------------------------------ Écriture

/// Appelée juste après l'insertion de la ligne d'audit `audit_id`, dans la
/// même transaction : calcule et enregistre son empreinte chaînée.
pub fn on_insert(c: &Connection, audit_id: i64) -> ApiResult<()> {
    let Some(key) = current_key() else {
        warn_missing_key();
        return Ok(());
    };
    // La ligne et sa voisine précédente en une lecture.
    let rows = c
        .prepare_cached(&format!("SELECT {ROW_COLUMNS} FROM audit WHERE id <= ?1 ORDER BY id DESC LIMIT 2"))?
        .query_map([audit_id], read_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let Some(row) = rows.first().filter(|r| r.id == audit_id) else {
        return Err(ApiError::internal("journal chaîné : ligne d'audit introuvable"));
    };
    // Cas courant : la ligne précédente existe et porte son empreinte.
    let prev = match rows.get(1).filter(|p| p.id == audit_id - 1).and_then(Row::mac) {
        Some(m) => m,
        None => match head_at(c, audit_id - 1)? {
            Some(head) => head,
            None => {
                insert_anchor(c, &key, REASON_GENESIS, now_unix(), audit_id - 1, &GENESIS_HEAD)?;
                GENESIS_HEAD
            }
        },
    };
    let mac = key.row_mac(&prev, row);
    c.prepare_cached("UPDATE audit SET chain_mac = ?1 WHERE id = ?2")?.execute(params![hex(&mac), audit_id])?;
    Ok(())
}

/// Appelée avant la suppression des lignes antérieures à `cutoff_at`, dans
/// la transaction de la purge : ancre « purge » sur la dernière ligne
/// supprimée, puis scellement si le dernier ancrage a plus d'une heure.
pub fn before_purge(c: &Connection, cutoff_at: i64) -> ApiResult<()> {
    before_purge_at(c, cutoff_at, now_unix())
}

pub(crate) fn before_purge_at(c: &Connection, cutoff_at: i64, now: i64) -> ApiResult<()> {
    let Some(key) = current_key() else {
        warn_missing_key();
        return Ok(());
    };
    // Chaîne pas encore commencée : rien à protéger.
    let Some((last_anchor_at, max_last)) = c
        .query_row("SELECT MAX(at), MAX(last_audit_id) FROM audit_anchors", [], |r| {
            Ok(r.get::<_, Option<i64>>(0)?.zip(r.get::<_, Option<i64>>(1)?))
        })?
    else {
        return Ok(());
    };

    let doomed: Option<i64> = c.query_row("SELECT MAX(id) FROM audit WHERE at < ?1", [cutoff_at], |r| r.get(0))?;
    let start: i64 = c.query_row(
        "SELECT COALESCE(MAX(last_audit_id), -1) FROM audit_anchors WHERE reason IN ('genesis', 'purge')",
        [],
        |r| r.get(0),
    )?;
    if let Some(x) = doomed.filter(|&x| x > start) {
        if let Some(head) = head_at(c, x)? {
            insert_anchor(c, &key, REASON_PURGE, now, x, &head)?;
            // Les ancrages antérieurs portent sur des lignes supprimées.
            c.execute("DELETE FROM audit_anchors WHERE last_audit_id < ?1", [x])?;
        }
        return Ok(());
    }

    if now - last_anchor_at < SEAL_INTERVAL {
        return Ok(());
    }
    let last: Option<(i64, String)> = c
        .query_row(
            "SELECT id, chain_mac FROM audit WHERE id > ?1 AND chain_mac IS NOT NULL AND action <> ?2
             ORDER BY id DESC LIMIT 1",
            params![max_last, SEALED_ACTION],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    // La tête de la chaîne juste après cette ligne est sa propre empreinte.
    let Some((id, head)) = last.and_then(|(id, mac)| parse_hex32(&mac).map(|h| (id, h))) else {
        return Ok(());
    };
    insert_anchor(c, &key, REASON_SEAL, now, id, &head)?;
    // Copie de la tête dans le journal (et donc le syslog) : une
    // troncature reste visible hors du serveur. Événement du serveur : ni
    // adresse ni navigateur.
    let meta = ClientMeta { ip: String::new(), user_agent: String::new() };
    state::audit(c, None, "", SEALED_ACTION, &format!("ligne {id}"), &meta, &format!("empreinte {}", hex(&head)))
}

// ------------------------------------------------------------ Vérification

/// Anomalie : identifiant de ligne d'audit et nature (`altered`, `missing`
/// pour la première ligne manquante, `inserted`, `anchor_invalid` pour la
/// ligne visée par l'ancrage).
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Break {
    pub id: i64,
    pub kind: &'static str,
}

/// Résultat d'une vérification (contrat C1.6).
#[derive(Serialize, Debug)]
pub struct Report {
    pub ok: bool,
    /// Lignes vérifiées (celles qui suivent le début de la chaîne).
    pub checked: u64,
    pub first_id: Option<i64>,
    pub last_id: Option<i64>,
    pub anchors: u64,
    /// Les lignes d'id inférieur précèdent la chaîne et ne sont pas vérifiées.
    pub unchained_before: Option<i64>,
    pub breaks: Vec<Break>,
    pub verified_at: i64,
}

struct Anchor {
    reason: String,
    at: i64,
    last_audit_id: i64,
    mac: String,
}

/// Vérifie tout le journal.
pub fn verify(c: &Connection, key: &Key) -> ApiResult<Report> {
    verify_since(c, key, None)
}

/// Vérifie le journal ; avec `since`, les lignes d'id inférieur sont tenues
/// pour sûres (vérification rapide de la partie récente).
fn verify_since(c: &Connection, key: &Key, since: Option<i64>) -> ApiResult<Report> {
    // Instantané cohérent : une purge concurrente ne fausse pas le résultat.
    let tx = c.unchecked_transaction()?;
    let c = &*tx;
    let mut breaks = Vec::new();

    let anchors = c
        .prepare("SELECT reason, at, last_audit_id, mac FROM audit_anchors ORDER BY id")?
        .query_map([], |r| Ok(Anchor { reason: r.get(0)?, at: r.get(1)?, last_audit_id: r.get(2)?, mac: r.get(3)? }))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut valid: Vec<(&Anchor, [u8; 32])> = Vec::new();
    for a in &anchors {
        let known = [REASON_GENESIS, REASON_PURGE, REASON_SEAL].contains(&a.reason.as_str());
        match parse_anchor_mac(&a.mac) {
            Some((head, tag)) if known && eq(&key.anchor_tag(&a.reason, a.at, a.last_audit_id, &head), &tag) => {
                valid.push((a, head));
            }
            _ => breaks.push(Break { id: a.last_audit_id, kind: ANCHOR_INVALID }),
        }
    }

    // Début de la chaîne : dernier ancrage de genèse ou de purge.
    let start = valid
        .iter()
        .filter(|(a, _)| a.reason == REASON_GENESIS || a.reason == REASON_PURGE)
        .max_by_key(|(a, _)| a.last_audit_id)
        .map(|(a, head)| (a.last_audit_id, *head));
    // Sans ancrage de départ valide, l'empreinte de la première ligne
    // chaînée ne peut pas être confirmée : la chaîne repart d'elle.
    let mut trust_next = false;
    let (mut last_id, mut prev) = match start {
        Some(s) => s,
        None => {
            let first: Option<i64> =
                c.query_row("SELECT MIN(id) FROM audit WHERE chain_mac IS NOT NULL", [], |r| r.get(0))?;
            match first {
                Some(first) => {
                    // Lignes chaînées sans ancrage de départ : il a disparu.
                    breaks.push(Break { id: first, kind: ANCHOR_INVALID });
                    trust_next = true;
                    (first - 1, GENESIS_HEAD)
                }
                None => {
                    // Chaîne jamais commencée : tout le journal est ancien.
                    let max: Option<i64> = c.query_row("SELECT MAX(id) FROM audit", [], |r| r.get(0))?;
                    breaks.sort();
                    breaks.dedup();
                    return Ok(Report {
                        ok: breaks.is_empty(),
                        checked: 0,
                        first_id: None,
                        last_id: None,
                        anchors: anchors.len() as u64,
                        unchained_before: max.map(|m| m + 1),
                        breaks,
                        verified_at: now_unix(),
                    });
                }
            }
        }
    };
    let unchained: bool =
        c.query_row("SELECT EXISTS(SELECT 1 FROM audit WHERE id <= ?1)", [last_id], |r| r.get(0))?;
    let unchained_before = unchained.then_some(last_id + 1);

    if let Some(s) = since.filter(|&s| s - 1 > last_id) {
        let trusted: Option<(i64, String)> = c
            .query_row(
                "SELECT id, chain_mac FROM audit WHERE id < ?1 AND id > ?2 AND chain_mac IS NOT NULL
                 ORDER BY id DESC LIMIT 1",
                [s, last_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, m)) = trusted.and_then(|(id, mac)| parse_hex32(&mac).map(|m| (id, m))) {
            (last_id, prev) = (id, m);
        }
    }
    let walk_from = last_id;

    let anchor_ids: HashSet<i64> =
        valid.iter().map(|(a, _)| a.last_audit_id).filter(|&id| id > walk_from).collect();
    let mut heads: HashMap<i64, [u8; 32]> = HashMap::new();
    let (mut checked, mut first_id, mut seen_last) = (0u64, None, None);

    let mut stmt = c.prepare(&format!("SELECT {ROW_COLUMNS} FROM audit WHERE id > ?1 ORDER BY id"))?;
    let mut rows = stmt.query_map([walk_from], read_row)?.peekable();
    while let Some(r) = rows.next() {
        let r = r?;
        checked += 1;
        first_id.get_or_insert(r.id);
        seen_last = Some(r.id);
        let gap = r.id != last_id + 1;
        if gap {
            breaks.push(Break { id: last_id + 1, kind: MISSING });
        }
        last_id = r.id;
        let mac = r.mac();
        let trusted = std::mem::take(&mut trust_next);
        if let Some(m) = mac.filter(|m| trusted || eq(&key.row_mac(&prev, &r), m)) {
            prev = m;
        } else if gap {
            // Lignes supprimées juste avant (déjà signalé) : la chaîne repart
            // de cette ligne ; sans empreinte, elle a été ajoutée.
            match mac {
                Some(m) => prev = m,
                None => breaks.push(Break { id: r.id, kind: INSERTED }),
            }
        } else {
            // La suite de la chaîne l'ignore-t-elle ? (Une dernière ligne sans
            // empreinte n'a pas de suite : ajoutée.)
            let next_follows_prev = match rows.peek() {
                Some(Ok(n)) => n.mac().is_some_and(|nm| eq(&key.row_mac(&prev, n), &nm)),
                _ => mac.is_none(),
            };
            if next_follows_prev || mac.is_some_and(|m| eq(&m, &prev)) {
                // Ignorée par la chaîne, ou recopiant l'empreinte de sa
                // voisine : ligne ajoutée.
                breaks.push(Break { id: r.id, kind: INSERTED });
            } else {
                // Contenu ou empreinte modifiés ; la chaîne reprend à partir
                // de l'empreinte stockée. Si elle a été effacée ou remplacée,
                // la ligne suivante ne peut plus être confirmée et sera
                // signalée elle aussi.
                breaks.push(Break { id: r.id, kind: ALTERED });
                if let Some(m) = mac {
                    prev = m;
                }
            }
        }
        if anchor_ids.contains(&r.id) {
            heads.insert(r.id, prev);
        }
    }

    // Ancrages postérieurs au départ : la ligne visée existe et la chaîne
    // passe bien par la tête signée (une troncature de la fin se voit ici).
    for (a, head) in &valid {
        if a.last_audit_id <= walk_from {
            continue;
        }
        match heads.get(&a.last_audit_id) {
            Some(h) if eq(h, head) => {}
            Some(_) => breaks.push(Break { id: a.last_audit_id, kind: ALTERED }),
            None => breaks.push(Break { id: a.last_audit_id, kind: MISSING }),
        }
    }

    breaks.sort();
    breaks.dedup();
    Ok(Report {
        ok: breaks.is_empty(),
        checked,
        first_id,
        last_id: seen_last,
        anchors: anchors.len() as u64,
        unchained_before,
        breaks,
        verified_at: now_unix(),
    })
}

// ------------------------------------------------------------ Route

/// Routes du journal chaîné (sous /api).
pub fn router() -> Router<AppState> {
    Router::new().route("/admin/audit/verify", get(verify_route))
}

fn require_key(key: Option<Key>) -> ApiResult<Key> {
    key.ok_or_else(|| {
        ApiError::unavailable(
            "audit_chain_unavailable",
            "Vérification du journal indisponible : la clé de chaînage n'est pas chargée.",
        )
    })
}

/// GET /admin/audit/verify : vérifie tout le journal (propriétaire ou
/// administrateur) et journalise le résultat.
async fn verify_route(State(state): State<AppState>, AdminUser(user): AdminUser) -> ApiResult<Json<Report>> {
    let key = require_key(current_key())?;
    let report = state.db.read(move |c| verify(c, &key)).await?;
    let (action, details) = if report.ok {
        ("audit.verified", format!("{} ligne(s) vérifiée(s)", report.checked))
    } else {
        ("audit.verify_failed", format!("{} anomalie(s) sur {} ligne(s) vérifiée(s)", report.breaks.len(), report.checked))
    };
    state.db.call(move |c| state::audit_user(c, &user, action, "", &details)).await?;
    Ok(Json(report))
}

// ------------------------------------------------------------ Sous-commande

const USAGE: &str = "Usage : locksy-server verify-audit [--json] [--since-id <n>]

Vérifie le chaînage du journal d'audit (base ouverte en lecture seule, clé
serveur lue sans jamais être créée). Même configuration que le serveur
(LOCKSY_DATA, LOCKSY_SERVER_KEY_FILE...).

  --json          résultat au format JSON
  --since-id <n>  ne vérifie que les lignes à partir du n° <n>

Code de sortie : 0 journal intègre, 1 anomalie détectée, 2 configuration,
clé ou base illisible.";

#[derive(Debug, Default, PartialEq)]
pub(crate) struct Options {
    pub json: bool,
    pub since_id: Option<i64>,
    pub help: bool,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut o = Options::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => o.json = true,
            "--help" | "-h" => o.help = true,
            "--since-id" => {
                let v = it.next().ok_or("--since-id attend un numéro de ligne")?;
                let n = v.parse::<i64>().ok().filter(|n| *n >= 1);
                o.since_id = Some(n.ok_or_else(|| format!("numéro de ligne invalide : « {v} »"))?);
            }
            other => return Err(format!("option inconnue : « {other} »")),
        }
    }
    Ok(o)
}

/// Sous-commande `verify-audit` : code de sortie du processus.
pub fn verify_command(args: &[String]) -> i32 {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Erreur : {e}\n\n{USAGE}");
            return 2;
        }
    };
    if opts.help {
        println!("{USAGE}");
        return 0;
    }
    let cfg = match crate::config::from_env() {
        Ok(c) => c,
        Err(errors) => {
            eprintln!("Configuration invalide :");
            for e in errors {
                eprintln!("  - {e}");
            }
            return 2;
        }
    };
    let (code, out) = run_verify(&cfg.db_path, &cfg.server_key_file, &opts);
    if code == 2 {
        eprintln!("Erreur : {out}");
    } else {
        println!("{out}");
    }
    code
}

/// Cœur de la sous-commande, sans environnement : (code, texte à afficher).
pub(crate) fn run_verify(db_path: &Path, key_file: &Path, opts: &Options) -> (i32, String) {
    let key = match read_key(key_file) {
        Ok(k) => k,
        Err(e) => return (2, e),
    };
    let report = match open_read_only(db_path).and_then(|c| verify_since(&c, &key, opts.since_id).map_err(|e| e.message)) {
        Ok(r) => r,
        Err(e) => return (2, e),
    };
    let code = if report.ok { 0 } else { 1 };
    if opts.json {
        return (code, serde_json::to_string_pretty(&report).unwrap_or_default());
    }
    (code, render(&report))
}

/// Lit la clé serveur existante, sans jamais la créer.
fn read_key(path: &Path) -> Result<Key, String> {
    let raw = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("clé serveur {} introuvable : la vérification a besoin de la clé du serveur.", path.display())
        } else {
            format!("clé serveur {} illisible : {e}", path.display())
        }
    })?;
    let sk = SecretKey::from_slice(&raw)
        .map_err(|_| format!("clé serveur {} corrompue : 32 octets attendus, {} trouvés.", path.display(), raw.len()))?;
    Ok(Key::from_server_key(&sk))
}

/// Ouvre une base existante en lecture seule (jamais créée ni migrée).
fn open_read_only(path: &Path) -> Result<Connection, String> {
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(|e| format!("base de données {} illisible : {e}", path.display()))?;
    c.busy_timeout(Duration::from_secs(5)).map_err(|e| e.to_string())?;
    let migrated = c.prepare("SELECT chain_mac FROM audit LIMIT 0").is_ok()
        && c.prepare("SELECT mac FROM audit_anchors LIMIT 0").is_ok();
    if !migrated {
        return Err(format!(
            "base de données {} sans journal chaîné : démarrez une fois le serveur à jour pour la migrer.",
            path.display()
        ));
    }
    Ok(c)
}

fn break_label(kind: &str) -> &'static str {
    match kind {
        ALTERED => "contenu modifié",
        MISSING => "ligne supprimée (à partir de celle-ci)",
        INSERTED => "ligne ajoutée hors du serveur",
        _ => "ancrage invalide",
    }
}

/// Tous les ancrages sont rejetés : signe d'une autre clé plutôt que d'une
/// falsification (qui laisserait au moins un ancrage intact).
fn key_mismatch_likely(r: &Report) -> bool {
    r.anchors > 0 && r.breaks.iter().filter(|b| b.kind == ANCHOR_INVALID).count() as u64 >= r.anchors
}

/// Compte-rendu lisible en français.
fn render(r: &Report) -> String {
    let range = match (r.first_id, r.last_id) {
        (Some(a), Some(b)) => format!(" (n° {a} à {b})"),
        _ => String::new(),
    };
    let mut out = if r.ok {
        format!(
            "Journal d'audit intègre : {} ligne(s) vérifiée(s){range}, {} ancrage(s).",
            r.checked, r.anchors
        )
    } else if key_mismatch_likely(r) {
        // Cause probable en tête : une autre clé, pas une falsification.
        let mut s = format!(
            "Chaînage invérifiable : la clé serveur n'est pas celle qui a écrit le journal \
             ({} ligne(s){range}, aucun des {} ancrage(s) n'est valide).\n\
             Cause probable : fichier de clé différent, ou clé régénérée par LOCKSY_SERVER_KEY_RESET. \
             Relancez la vérification avec la clé d'origine pour conclure.\n\
             Détail ({} anomalie(s)) :",
            r.checked,
            r.anchors,
            r.breaks.len()
        );
        for b in &r.breaks {
            s.push_str(&format!("\n  - ligne n° {} : {}", b.id, break_label(b.kind)));
        }
        s
    } else {
        let mut s = format!(
            "Journal d'audit ALTÉRÉ : {} anomalie(s) sur {} ligne(s) vérifiée(s){range}.",
            r.breaks.len(),
            r.checked
        );
        for b in &r.breaks {
            s.push_str(&format!("\n  - ligne n° {} : {}", b.id, break_label(b.kind)));
        }
        s
    };
    if let Some(u) = r.unchained_before {
        out.push_str(&format!(
            "\nLignes antérieures au n° {u} non chaînées (écrites avant l'activation du chaînage ou déjà purgées)."
        ));
    }
    out
}

// ------------------------------------------------------------ Tests unitaires

#[cfg(test)]
mod tests {
    use super::*;

    fn row(user_id: Option<&str>, email: &str, action: &str) -> Row {
        Row {
            id: 7,
            at: 1_700_000_000,
            user_id: user_id.map(str::to_owned),
            email: email.into(),
            action: action.into(),
            target: String::new(),
            ip: String::new(),
            user_agent: String::new(),
            details: String::new(),
            chain_mac: None,
        }
    }

    #[test]
    fn forme_canonique_sans_ambiguite() {
        let k = test_key();
        let p = [1u8; 32];
        // NULL et chaîne vide diffèrent.
        assert_ne!(k.row_mac(&p, &row(None, "a", "b")), k.row_mac(&p, &row(Some(""), "a", "b")));
        // Frontière entre champs : « ab|c » ≠ « a|bc ».
        assert_ne!(k.row_mac(&p, &row(None, "ab", "c")), k.row_mac(&p, &row(None, "a", "bc")));
        // La tête précédente compte.
        assert_ne!(k.row_mac(&p, &row(None, "a", "b")), k.row_mac(&[2u8; 32], &row(None, "a", "b")));
        // Déterministe.
        assert_eq!(k.row_mac(&p, &row(None, "a", "b")), k.row_mac(&p, &row(None, "a", "b")));
    }

    #[test]
    fn cle_propre_au_journal() {
        let sk = SecretKey::from_slice(&TEST_SERVER_KEY).unwrap_or_else(|_| unreachable!());
        let other = SecretKey::from_slice(&[1u8; 32]).unwrap_or_else(|_| unreachable!());
        let p = [0u8; 32];
        let r = row(None, "a", "b");
        assert_eq!(Key::from_server_key(&sk).row_mac(&p, &r), test_key().row_mac(&p, &r));
        assert_ne!(Key::from_server_key(&other).row_mac(&p, &r), test_key().row_mac(&p, &r));
        // Le HMAC direct par la clé serveur (sans dérivation) diffère.
        let raw = HmacSha256::new_from_slice(&TEST_SERVER_KEY).unwrap();
        assert_ne!(Key(raw).row_mac(&p, &r), test_key().row_mac(&p, &r));
    }

    #[test]
    fn format_des_ancrages() {
        let head = [0xabu8; 32];
        let tag = test_key().anchor_tag("seal", 10, 42, &head);
        let mac = format!("v1.{}.{}", hex(&head), hex(&tag));
        assert_eq!(parse_anchor_mac(&mac), Some((head, tag)));
        assert_eq!(parse_anchor_mac(&mac.replacen("v1", "v2", 1)), None);
        assert_eq!(parse_anchor_mac(&format!("{mac}.00")), None);
        assert_eq!(parse_anchor_mac("v1.zz.00"), None);
        assert_ne!(tag, test_key().anchor_tag("purge", 10, 42, &head));
        assert_ne!(tag, test_key().anchor_tag("seal", 10, 43, &head));
    }

    #[test]
    fn hexadecimal() {
        let b: [u8; 32] = std::array::from_fn(|i| (i * 8) as u8);
        assert_eq!(parse_hex32(&hex(&b)), Some(b));
        assert_eq!(parse_hex32(&hex(&b).to_uppercase()), Some(b));
        assert_eq!(parse_hex32("00"), None);
        assert_eq!(parse_hex32(&"g".repeat(64)), None);
    }

    #[test]
    fn options_de_la_commande() {
        let a = |v: &[&str]| parse_args(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(a(&[]), Ok(Options::default()));
        assert_eq!(a(&["--json", "--since-id", "12"]), Ok(Options { json: true, since_id: Some(12), help: false }));
        assert!(a(&["--since-id"]).is_err());
        assert!(a(&["--since-id", "abc"]).is_err());
        assert!(a(&["--since-id", "0"]).is_err());
        assert!(a(&["--force"]).unwrap_err().contains("--force"));
    }

    #[test]
    fn cle_absente_indisponible() {
        let e = require_key(None).err().expect("refus");
        assert_eq!((e.status.as_u16(), e.code), (503, "audit_chain_unavailable"));
        assert!(require_key(Some(test_key())).is_ok());
    }

    #[test]
    fn compte_rendu_lisible() {
        let mut r = Report {
            ok: true,
            checked: 3,
            first_id: Some(5),
            last_id: Some(7),
            anchors: 1,
            unchained_before: Some(5),
            breaks: vec![],
            verified_at: 0,
        };
        let t = render(&r);
        assert!(t.starts_with("Journal d'audit intègre : 3 ligne(s) vérifiée(s) (n° 5 à 7), 1 ancrage(s)."), "{t}");
        assert!(t.contains("antérieures au n° 5"), "{t}");
        r.ok = false;
        r.breaks = vec![Break { id: 6, kind: ALTERED }, Break { id: 7, kind: MISSING }];
        let t = render(&r);
        assert!(t.contains("ALTÉRÉ : 2 anomalie(s)"), "{t}");
        assert!(t.contains("ligne n° 6 : contenu modifié"), "{t}");
        assert!(t.contains("ligne n° 7 : ligne supprimée"), "{t}");
    }
}
