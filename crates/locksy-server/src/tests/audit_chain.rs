//! Journal d'audit chaîné (lot L17) : intégrité de la chaîne, détection des
//! altérations, suppressions et insertions, purge par rétention avec
//! ancrage, scellement, sous-commande `verify-audit` et route
//! d'administration.
//!
//! La clé du journal est la clé de test fixe du module (`install_key` n'est
//! jamais appelé ici : les tests tournent en parallèle dans le même
//! processus).

use super::*;
use crate::audit_chain::{self, before_purge_at, on_insert, run_verify, test_key, Options, Report, TEST_SERVER_KEY};
use crate::state::ClientMeta;
use rusqlite::types::Value as SqlValue;
use rusqlite::Connection;
use std::path::PathBuf;
use std::time::Instant;

const VERIFY: &str = "/api/admin/audit/verify";
const HOUR: i64 = 3600;
const DAY: i64 = 86_400;

fn meta() -> ClientMeta {
    ClientMeta { ip: "192.0.2.10".into(), user_agent: "test".into() }
}

/// Écrit `n` lignes par le chemin normal du serveur (`state::audit`), en une
/// transaction ; renvoie leurs identifiants.
async fn fill(st: &AppState, n: usize) -> Vec<i64> {
    st.db
        .call(move |c| {
            let tx = c.transaction()?;
            let mut ids = Vec::with_capacity(n);
            for i in 0..n {
                crate::state::audit(&tx, Some("u-1"), "a@exemple.fr", "login.ok", &format!("cible {i}"), &meta(), "")?;
                // Pas last_insert_rowid : la genèse est insérée après la ligne.
                ids.push(tx.query_row("SELECT MAX(id) FROM audit", [], |r| r.get(0))?);
            }
            tx.commit()?;
            Ok(ids)
        })
        .await
        .unwrap()
}

/// Ligne datée de `at`, chaînée comme par `state::audit` (sans syslog).
fn put(c: &Connection, at: i64, action: &str) -> i64 {
    c.execute("INSERT INTO audit (at, user_id, email, action) VALUES (?1, NULL, '', ?2)", params![at, action]).unwrap();
    let id = c.last_insert_rowid();
    on_insert(c, id).unwrap();
    id
}

/// Ligne écrite sans empreinte (journal d'avant l'activation, ou ajout fait
/// directement dans la base).
fn put_raw(c: &Connection, at: i64, action: &str, mac: Option<&str>) -> i64 {
    c.execute(
        "INSERT INTO audit (at, user_id, email, action, chain_mac) VALUES (?1, NULL, '', ?2, ?3)",
        params![at, action, mac],
    )
    .unwrap();
    c.last_insert_rowid()
}

/// Exécute une requête SQL (altération simulée de la base).
async fn exec(st: &AppState, sql: String) {
    st.db.call(move |c| Ok(c.execute_batch(&sql)?)).await.unwrap();
}

async fn verify(st: &AppState) -> Report {
    st.db.read(|c| audit_chain::verify(c, &test_key())).await.unwrap()
}

/// Anomalies sous la forme (id, nature).
fn breaks(r: &Report) -> Vec<(i64, &'static str)> {
    r.breaks.iter().map(|b| (b.id, b.kind)).collect()
}

/// Purge comme la maintenance de main.rs : ancrage puis suppression, dans
/// une même transaction.
fn purge(c: &mut Connection, cutoff: i64, now: i64) -> usize {
    let tx = c.transaction().unwrap();
    before_purge_at(&tx, cutoff, now).unwrap();
    let n = tx.execute("DELETE FROM audit WHERE at < ?1", [cutoff]).unwrap();
    tx.commit().unwrap();
    n
}

fn anchors(c: &Connection) -> Vec<(String, i64)> {
    c.prepare("SELECT reason, last_audit_id FROM audit_anchors ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[tokio::test]
async fn chaine_intacte() {
    let st = crate::state::test_state().await;
    let ids = fill(&st, 25).await;
    assert_eq!(count(&st, "SELECT COUNT(*) FROM audit WHERE chain_mac IS NULL").await, 0);
    // Une genèse, juste avant la première ligne.
    let a = st.db.read(|c| Ok(anchors(c))).await.unwrap();
    assert_eq!(a, vec![("genesis".to_string(), ids[0] - 1)]);

    let r = verify(&st).await;
    assert!(r.ok, "{r:?}");
    assert_eq!((r.checked, r.first_id, r.last_id), (25, Some(ids[0]), Some(ids[24])));
    assert_eq!((r.anchors, r.unchained_before), (1, None));
    assert!(r.breaks.is_empty());
}

#[tokio::test]
async fn alteration_de_chaque_champ_detectee() {
    let st = crate::state::test_state().await;
    let ids = fill(&st, 8).await;
    let target = ids[4];
    let forged: &[(&str, &str)] = &[
        ("details", "'détail ajouté'"),
        ("email", "'b@exemple.fr'"),
        ("action", "'login.failed'"),
        ("target", "'autre cible'"),
        ("ip", "'198.51.100.1'"),
        ("user_agent", "'autre'"),
        ("at", "at + 1"),
        ("user_id", "NULL"),
        ("user_id", "'u-2'"),
    ];
    for &(col, value) in forged {
        let (name, col, value) = (col, col.to_string(), value.to_string());
        let (r, after) = st
            .db
            .call(move |c| {
                // Valeur d'origine, rétablie après la vérification.
                let orig: SqlValue = c.query_row(&format!("SELECT {col} FROM audit WHERE id = ?1"), [target], |r| r.get(0))?;
                c.execute(&format!("UPDATE audit SET {col} = {value} WHERE id = ?1"), [target])?;
                let r = audit_chain::verify(c, &test_key())?;
                c.execute(&format!("UPDATE audit SET {col} = ?1 WHERE id = ?2"), params![orig, target])?;
                Ok((r, audit_chain::verify(c, &test_key())?))
            })
            .await
            .unwrap();
        assert_eq!(breaks(&r), vec![(target, "altered")], "{name} modifié");
        assert!(after.ok, "rétablissement de {name} : {after:?}");
    }
}

#[tokio::test]
async fn empreinte_effacee_ou_remplacee_detectee() {
    let st = crate::state::test_state().await;
    let ids = fill(&st, 6).await;
    // La chaîne a besoin de cette empreinte : ce n'est pas une ligne
    // ajoutée. La suivante, qui en dépend, ne peut plus être confirmée.
    let expected = vec![(ids[2], "altered"), (ids[3], "altered")];
    exec(&st, format!("UPDATE audit SET chain_mac = NULL WHERE id = {}", ids[2])).await;
    assert_eq!(breaks(&verify(&st).await), expected);
    exec(&st, format!("UPDATE audit SET chain_mac = '{}' WHERE id = {}", "0".repeat(64), ids[2])).await;
    assert_eq!(breaks(&verify(&st).await), expected);
    // Dernière ligne sans empreinte : rien ne la suit, elle est tenue pour
    // ajoutée.
    exec(&st, format!("UPDATE audit SET chain_mac = NULL WHERE id >= {}", ids[2])).await;
    exec(&st, format!("DELETE FROM audit WHERE id > {}", ids[2])).await;
    assert_eq!(breaks(&verify(&st).await), vec![(ids[2], "inserted")]);
}

#[tokio::test]
async fn suppression_au_milieu_detectee() {
    let st = crate::state::test_state().await;
    let ids = fill(&st, 10).await;
    exec(&st, format!("DELETE FROM audit WHERE id IN ({}, {})", ids[3], ids[4])).await;
    let r = verify(&st).await;
    assert!(!r.ok);
    // Signalée une fois, à la première ligne disparue ; la suite est saine.
    assert_eq!(breaks(&r), vec![(ids[3], "missing")]);
    assert_eq!(r.checked, 8);
}

#[tokio::test]
async fn suppression_du_debut_detectee() {
    let st = crate::state::test_state().await;
    let ids = fill(&st, 5).await;
    exec(&st, format!("DELETE FROM audit WHERE id <= {}", ids[1])).await;
    assert_eq!(breaks(&verify(&st).await), vec![(ids[0], "missing")]);
    // Ancrage de genèse effacé avec : la chaîne n'a plus de départ signé.
    exec(&st, "DELETE FROM audit_anchors".into()).await;
    assert_eq!(breaks(&verify(&st).await), vec![(ids[2], "anchor_invalid")]);
}

#[tokio::test]
async fn insertion_forgee_detectee() {
    let st = crate::state::test_state().await;
    fill(&st, 5).await;
    // Ligne ajoutée sans empreinte.
    let forged = st.db.call(|c| Ok(put_raw(c, now_unix(), "admin.user_role", None))).await.unwrap();
    fill(&st, 1).await;
    // Ligne recopiant l'empreinte de sa voisine.
    let copied = st
        .db
        .call(|c| {
            let prev: String = c.query_row("SELECT chain_mac FROM audit ORDER BY id DESC LIMIT 1", [], |r| r.get(0))?;
            Ok(put_raw(c, now_unix(), "admin.user_role", Some(&prev)))
        })
        .await
        .unwrap();
    let after = fill(&st, 3).await;
    let r = verify(&st).await;
    assert_eq!(breaks(&r), vec![(forged, "inserted"), (copied, "inserted")]);
    // Les lignes légitimes écrites ensuite restent valides.
    assert_eq!(r.last_id, Some(after[2]));
}

#[tokio::test]
async fn ancrage_modifie_detecte() {
    let st = crate::state::test_state().await;
    let ids = fill(&st, 4).await;
    let genesis = ids[0] - 1;
    exec(&st, "UPDATE audit_anchors SET at = at + 1".into()).await;
    let r = verify(&st).await;
    assert!(breaks(&r).contains(&(genesis, "anchor_invalid")), "{r:?}");
    exec(&st, "UPDATE audit_anchors SET at = at - 1, reason = 'seal'".into()).await;
    assert!(breaks(&verify(&st).await).contains(&(genesis, "anchor_invalid")));
    exec(&st, "UPDATE audit_anchors SET reason = 'genesis', mac = 'v1.00.00'".into()).await;
    assert!(breaks(&verify(&st).await).contains(&(genesis, "anchor_invalid")));
}

#[tokio::test]
async fn transaction_annulee_sans_effet_sur_la_chaine() {
    let st = crate::state::test_state().await;
    // Première ligne (et donc genèse) dans une transaction annulée.
    st.db
        .call(|c| {
            let tx = c.transaction()?;
            crate::state::audit(&tx, None, "", "login.ok", "", &meta(), "annulée")?;
            drop(tx);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(count(&st, "SELECT COUNT(*) FROM audit_anchors").await, 0);
    fill(&st, 3).await;
    // Annulation au milieu de la chaîne.
    st.db
        .call(|c| {
            let tx = c.transaction()?;
            for _ in 0..3 {
                crate::state::audit(&tx, None, "", "login.ok", "", &meta(), "annulée")?;
            }
            drop(tx);
            Ok(())
        })
        .await
        .unwrap();
    fill(&st, 3).await;
    let r = verify(&st).await;
    assert!(r.ok, "{r:?}");
    assert_eq!((r.checked, r.anchors), (6, 1));
}

#[tokio::test]
async fn journal_ancien_non_chaine() {
    let st = crate::state::test_state().await;
    let old = st
        .db
        .call(|c| Ok((0..4).map(|_| put_raw(c, now_unix() - DAY, "login.ok", None)).collect::<Vec<_>>()))
        .await
        .unwrap();
    let r = verify(&st).await;
    // Chaînage jamais activé : rien d'anormal, tout est « non chaîné ».
    assert!(r.ok && r.checked == 0, "{r:?}");
    assert_eq!(r.unchained_before, Some(old[3] + 1));

    let ids = fill(&st, 3).await;
    let r = verify(&st).await;
    assert!(r.ok, "{r:?}");
    assert_eq!((r.checked, r.first_id, r.unchained_before), (3, Some(ids[0]), Some(ids[0])));
    // La genèse suit la dernière ligne ancienne.
    assert_eq!(st.db.read(|c| Ok(anchors(c))).await.unwrap(), vec![("genesis".to_string(), old[3])]);
}

#[tokio::test]
async fn purge_par_retention_puis_verification() {
    let st = crate::state::test_state().await;
    let now = now_unix();
    let (old, recent) = st
        .db
        .call(move |c| {
            let old: Vec<i64> = (0..6).map(|i| put(c, now - 400 * DAY + i, "login.ok")).collect();
            let recent: Vec<i64> = (0..4).map(|i| put(c, now - HOUR + i, "login.ok")).collect();
            Ok((old, recent))
        })
        .await
        .unwrap();
    let cutoff = now - 365 * DAY;
    let n = st.db.call(move |c| Ok(purge(c, cutoff, now))).await.unwrap();
    assert_eq!(n, 6);

    // Ancrage « purge » sur la dernière ligne supprimée ; la genèse, qui
    // portait sur des lignes supprimées, disparaît.
    let a = st.db.read(|c| Ok(anchors(c))).await.unwrap();
    assert_eq!(a, vec![("purge".to_string(), old[5])]);
    let r = verify(&st).await;
    assert!(r.ok, "{r:?}");
    assert_eq!((r.checked, r.first_id, r.unchained_before), (4, Some(recent[0]), None));

    // La chaîne continue après la purge.
    fill(&st, 2).await;
    assert!(verify(&st).await.ok);
    // Une seconde purge sans ligne échue ne pose pas d'ancrage.
    st.db.call(move |c| Ok(purge(c, cutoff, now))).await.unwrap();
    assert_eq!(count(&st, "SELECT COUNT(*) FROM audit_anchors").await, 1);

    // Suppression de la première ligne restante hors purge : détectée.
    exec(&st, format!("DELETE FROM audit WHERE id = {}", recent[0])).await;
    assert_eq!(breaks(&verify(&st).await), vec![(recent[0], "missing")]);
}

#[tokio::test]
async fn purge_de_tout_le_journal() {
    let st = crate::state::test_state().await;
    let now = now_unix();
    let last = st
        .db
        .call(move |c| Ok((0..3).map(|i| put(c, now - 400 * DAY + i, "login.ok")).last().unwrap()))
        .await
        .unwrap();
    st.db.call(move |c| Ok(purge(c, now - 365 * DAY, now))).await.unwrap();
    assert!(verify(&st).await.ok);
    // La chaîne repart de la tête de l'ancrage de purge.
    let ids = fill(&st, 2).await;
    assert_eq!(ids[0], last + 1);
    let r = verify(&st).await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.checked, 2);
}

#[tokio::test]
async fn scellement_horaire_et_troncature() {
    let st = crate::state::test_state().await;
    let ids = fill(&st, 5).await;
    let now = now_unix();
    let cutoff = now - 365 * DAY;
    // Moins d'une heure après la genèse : pas de scellement.
    st.db.call(move |c| Ok(purge(c, cutoff, now + 60))).await.unwrap();
    assert_eq!(count(&st, "SELECT COUNT(*) FROM audit_anchors").await, 1);

    // Plus d'une heure après : ancrage « seal » sur la dernière ligne, copié
    // dans le journal (audit.sealed).
    st.db.call(move |c| Ok(purge(c, cutoff, now + HOUR + 1))).await.unwrap();
    let a = st.db.read(|c| Ok(anchors(c))).await.unwrap();
    assert_eq!(a.last(), Some(&("seal".to_string(), ids[4])));
    let sealed: String = st
        .db
        .read(|c| Ok(c.query_row("SELECT details FROM audit WHERE action = 'audit.sealed'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert!(sealed.starts_with("empreinte "), "{sealed}");
    assert!(verify(&st).await.ok);

    // Ni dans l'heure, ni sans nouvelle activité (le scellement lui-même ne
    // compte pas).
    st.db.call(move |c| Ok(purge(c, cutoff, now + HOUR + 120))).await.unwrap();
    st.db.call(move |c| Ok(purge(c, cutoff, now + 3 * HOUR))).await.unwrap();
    assert_eq!(count(&st, "SELECT COUNT(*) FROM audit_anchors").await, 2);

    // Troncature de la fin du journal jusqu'à la ligne scellée : visible.
    exec(&st, format!("DELETE FROM audit WHERE id >= {}", ids[3])).await;
    let r = verify(&st).await;
    assert!(breaks(&r).contains(&(ids[4], "missing")), "{r:?}");
}

#[tokio::test]
async fn verification_partielle_depuis_une_ligne() {
    let st = crate::state::test_state().await;
    let ids = fill(&st, 10).await;
    exec(&st, format!("UPDATE audit SET details = 'x' WHERE id = {}", ids[1])).await;
    let dir = st.config.data_dir.clone();
    let key = key_file(&dir, &TEST_SERVER_KEY);
    let db = dir.join("locksy.db");
    // Toute la chaîne : altération vue.
    let (code, _) = run_verify(&db, &key, &Options::default());
    assert_eq!(code, 1);
    // À partir de la 6e ligne : la partie ancienne est tenue pour sûre.
    let opts = Options { json: true, since_id: Some(ids[5]), help: false };
    let (code, out) = run_verify(&db, &key, &opts);
    assert_eq!(code, 0, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!((v["checked"].as_i64(), v["first_id"].as_i64()), (Some(5), Some(ids[5])));
}

/// Écrit un fichier de clé serveur dans `dir`.
fn key_file(dir: &std::path::Path, key: &[u8]) -> PathBuf {
    let p = dir.join(format!("server-{}.key", crypto::new_uuid()));
    std::fs::write(&p, key).unwrap();
    p
}

#[tokio::test]
async fn commande_verify_audit() {
    let st = crate::state::test_state().await;
    let ids = fill(&st, 4).await;
    let dir = st.config.data_dir.clone();
    let db = dir.join("locksy.db");
    let key = key_file(&dir, &TEST_SERVER_KEY);

    // Journal intègre : code 0, texte français.
    let (code, out) = run_verify(&db, &key, &Options::default());
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("Journal d'audit intègre : 4 ligne(s) vérifiée(s)"), "{out}");
    let (code, out) = run_verify(&db, &key, &Options { json: true, ..Default::default() });
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!((v["ok"].as_bool(), v["checked"].as_i64()), (Some(true), Some(4)));
    assert!(v["breaks"].as_array().is_some_and(Vec::is_empty));

    // Altération : code 1, ligne citée.
    exec(&st, format!("UPDATE audit SET target = 'x' WHERE id = {}", ids[2])).await;
    let (code, out) = run_verify(&db, &key, &Options::default());
    assert_eq!(code, 1, "{out}");
    assert!(out.contains(&format!("ligne n° {} : contenu modifié", ids[2])), "{out}");

    // Autre clé serveur : toutes les empreintes sont fausses, et la sortie
    // oriente vers la clé plutôt que vers une falsification.
    let other = key_file(&dir, &[7u8; 32]);
    let (code, out) = run_verify(&db, &other, &Options::default());
    assert_eq!(code, 1);
    // La cause probable vient en tête, avant le détail des lignes.
    assert!(out.starts_with("Chaînage invérifiable : la clé serveur n'est pas celle qui a écrit le journal"), "{out}");
    assert!(out.contains("LOCKSY_SERVER_KEY_RESET") && !out.contains("ALTÉRÉ"), "{out}");
    // Une falsification ordinaire ne déclenche pas cette indication.
    let altere = run_verify(&db, &key, &Options::default()).1;
    assert!(altere.starts_with("Journal d'audit ALTÉRÉ") && !altere.contains("invérifiable"), "{altere}");

    // Clé absente : code 2, et la clé n'est pas créée.
    let missing = dir.join("absente.key");
    let (code, out) = run_verify(&db, &missing, &Options::default());
    assert_eq!(code, 2);
    assert!(out.contains("introuvable"), "{out}");
    assert!(!missing.exists());
    // Clé de mauvaise taille : code 2.
    let short = key_file(&dir, &[1u8; 16]);
    let (code, out) = run_verify(&db, &short, &Options::default());
    assert_eq!(code, 2);
    assert!(out.contains("corrompue"), "{out}");

    // Base absente : code 2, et aucune base n'est créée.
    let nodb = dir.join("absente.db");
    let (code, out) = run_verify(&nodb, &key, &Options::default());
    assert_eq!(code, 2, "{out}");
    assert!(!nodb.exists());
    // Base antérieure au chaînage (non migrée) : code 2, message explicite.
    let legacy = dir.join("ancienne.db");
    Connection::open(&legacy)
        .unwrap()
        .execute_batch("CREATE TABLE audit (id INTEGER PRIMARY KEY, at INTEGER, details TEXT)")
        .unwrap();
    let (code, out) = run_verify(&legacy, &key, &Options::default());
    assert_eq!(code, 2);
    assert!(out.contains("sans journal chaîné"), "{out}");
}

#[tokio::test]
async fn commande_en_lecture_seule() {
    let st = crate::state::test_state().await;
    fill(&st, 3).await;
    let dir = st.config.data_dir.clone();
    let key = key_file(&dir, &TEST_SERVER_KEY);
    let before = (
        count(&st, "SELECT COUNT(*) FROM audit").await,
        count(&st, "SELECT COUNT(*) FROM audit_anchors").await,
    );
    assert_eq!(run_verify(&dir.join("locksy.db"), &key, &Options::default()).0, 0);
    // La commande n'écrit rien (pas même la trace de sa vérification).
    let after = (
        count(&st, "SELECT COUNT(*) FROM audit").await,
        count(&st, "SELECT COUNT(*) FROM audit_anchors").await,
    );
    assert_eq!(before, after);
}

#[tokio::test]
async fn route_de_verification() {
    let s = super::srv().await;
    let admin = account(&s.st, &AccountOpts { role: "admin", ..Default::default() }).await;
    let owner = account(&s.st, &AccountOpts { role: "owner", ..Default::default() }).await;
    let user = account(&s.st, &AccountOpts::default()).await;
    let ids = fill(&s.st, 5).await;

    s.get(VERIFY, None).await.expect(401, "unauthorized");
    s.get(VERIFY, Some(&user.token)).await.expect(403, "forbidden");

    let r = s.get(VERIFY, Some(&admin.token)).await;
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let b = r.expect(200, "");
    assert_eq!(b["ok"], true, "{b}");
    assert_eq!(b["checked"], 5);
    assert_eq!(b["first_id"], ids[0]);
    assert_eq!(b["last_id"], ids[4]);
    assert_eq!(b["anchors"], 1);
    assert_eq!(b["unchained_before"], Value::Null);
    assert_eq!(b["breaks"], serde_json::json!([]));
    assert!(b["verified_at"].as_i64().is_some_and(|t| t >= now_unix() - 60));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'audit.verified'").await, 1);

    // Le propriétaire aussi ; la trace de la vérification précédente est
    // elle-même chaînée.
    let b = s.get(VERIFY, Some(&owner.token)).await.expect(200, "").clone();
    assert_eq!((b["ok"].as_bool(), b["checked"].as_i64()), (Some(true), Some(6)));

    // Altération : anomalie décrite, vérification journalisée en échec.
    exec(&s.st, format!("UPDATE audit SET details = 'falsifié' WHERE id = {}", ids[2])).await;
    let b = s.get(VERIFY, Some(&owner.token)).await.expect(200, "").clone();
    assert_eq!(b["ok"], false);
    assert_eq!(b["breaks"], serde_json::json!([{ "id": ids[2], "kind": "altered" }]));
    let (actor, details): (String, String) = s
        .st
        .db
        .read(|c| {
            Ok(c.query_row(
                "SELECT user_id, details FROM audit WHERE action = 'audit.verify_failed'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(actor, owner.id);
    assert!(details.starts_with("1 anomalie(s)"), "{details}");
}

/// Coût du chaînage : 10 000 écritures puis une vérification complète.
/// Mesure indicative (à lancer en version optimisée) :
/// `cargo test --release -p locksy-server tests::audit_chain::cout -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "mesure de performance, lancée à la demande"]
async fn cout_de_10000_ecritures() {
    // Mêmes insertions avec (`put`) et sans (`put_raw`) chaînage, chacune en
    // une transaction : l'écart est le coût de `on_insert`.
    async fn timed(f: fn(&Connection) -> i64) -> (AppState, std::time::Duration) {
        let st = crate::state::test_state().await;
        let t = Instant::now();
        st.db
            .call(move |c| {
                let tx = c.transaction()?;
                for _ in 0..10_000 {
                    f(&tx);
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .unwrap();
        (st, t.elapsed())
    }
    let (st, chained) = timed(|c| put(c, now_unix(), "login.ok")).await;
    let (_, raw) = timed(|c| put_raw(c, now_unix(), "login.ok", None)).await;
    let t = Instant::now();
    let r = verify(&st).await;
    let check = t.elapsed();
    assert!(r.ok && r.checked == 10_000, "{r:?}");
    eprintln!("journal chaîné : 10 000 écritures en {chained:?} (sans chaînage : {raw:?}), vérification en {check:?}");
}
