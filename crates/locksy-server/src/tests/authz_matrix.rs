//! Matrice d'autorisation du serveur (lot Q4, critère G9 et constat #54).
//!
//! 1. Refus par défaut. Les routes sont ÉNUMÉRÉES depuis les sources des
//!    routeurs, lues à la compilation (`include_str!`). Toute route absente de
//!    la liste `PUBLIQUES` doit refuser une requête sans session valide (401),
//!    toute route `/api/admin/*` un compte « user » (403), et `/scim/v2` un
//!    jeton de session (401). Une route ajoutée sans contrôle d'accès fait
//!    échouer le test. La couche de refus par défaut (security::refus_par_defaut)
//!    ferme déjà toute route hors de la liste ; ce test vérifie la liste et
//!    sert de filet si la couche venait à manquer.
//! 2. Matrice IDOR générée. Chaque route qui prend l'identifiant d'un objet de
//!    coffre est jouée par chaque acteur (propriétaire de l'objet, gestionnaire,
//!    éditeur, lecteur, étranger, ancien membre retiré par renouvellement de
//!    clé, compte désactivé, administrateur de l'organisation non membre). Le
//!    statut attendu est vérifié, ainsi que l'absence d'effet d'un refus.
//!    L'étranger reçoit le 404 UNIFORME : même code et même message qu'un
//!    identifiant inexistant.
//! 3. Cas propres à Locksy : déplacement d'un élément vers un coffre en
//!    lecture seule ou depuis le coffre d'autrui, identifiant d'élément ou de
//!    pièce jointe déjà pris ailleurs (409 sans rien écraser).
//!
//! Complète http_tests.rs (`acces_aux_objets_d_un_autre_utilisateur`,
//! `roles_lecteur_editeur_gestionnaire`) sans le répéter.

use super::{account, Account, AccountOpts, Rep, Srv};
use crate::state::{AppState, Config};
use crate::vault::testing::cipher;
use locksy_core::crypto::{self, new_uuid, SecretKey};
use locksy_core::now_unix;
use reqwest::Method;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;

// ====================================================================
// 1. Refus par défaut : énumération des routes
// ====================================================================

/// Routeur lu dans les sources : fichier, texte, signature de la fonction
/// qui déclare les routes et préfixe sous lequel elle est montée.
struct Source {
    fichier: &'static str,
    texte: &'static str,
    fonction: &'static str,
    prefixe: &'static str,
}

const MAIN: &str = include_str!("../main.rs");

const SOURCES: &[Source] = &[
    Source { fichier: "main.rs", texte: MAIN, fonction: "fn api_router(", prefixe: "/api" },
    Source { fichier: "main.rs", texte: MAIN, fonction: "fn build_app(", prefixe: "" },
    Source { fichier: "auth.rs", texte: include_str!("../auth.rs"), fonction: "pub fn router()", prefixe: "/api" },
    Source { fichier: "vault.rs", texte: include_str!("../vault.rs"), fonction: "pub fn router()", prefixe: "/api" },
    Source {
        fichier: "audit_chain.rs",
        texte: include_str!("../audit_chain.rs"),
        fonction: "pub fn router()",
        prefixe: "/api",
    },
    Source {
        fichier: "admin_people.rs",
        texte: include_str!("../admin_people.rs"),
        fonction: "pub fn router()",
        prefixe: "/api",
    },
    Source {
        fichier: "identity_admin.rs",
        texte: include_str!("../identity_admin.rs"),
        fonction: "pub fn router()",
        prefixe: "/api",
    },
    Source { fichier: "mail.rs", texte: include_str!("../mail.rs"), fonction: "pub fn router()", prefixe: "/api" },
    Source { fichier: "scim.rs", texte: include_str!("../scim.rs"), fonction: "pub fn router()", prefixe: "/scim/v2" },
];

/// Routeurs fusionnés dans `api_router` : chacun doit figurer dans `SOURCES`.
const FUSIONS_ANALYSEES: &[&str] = &[
    "auth::router()",
    "vault::router()",
    "audit_chain::router()",
    "admin_people::router()",
    "identity_admin::router()",
    "mail::router()",
];

// Routes servies sans session : la liste de la couche de refus par défaut
// (security::PUBLIQUES), vérifiée ici contre les routes énumérées.
use crate::security::PUBLIQUES;

/// Méthodes reconnues dans un appel `.route(…)`.
const METHODES: [&str; 5] = ["get", "post", "put", "patch", "delete"];

/// Position de la fermeture qui équilibre l'ouvrant placé en tête de `s`.
fn fermante(s: &str, ouvre: char, ferme: char) -> Option<usize> {
    let mut niveau = 0i32;
    for (i, c) in s.char_indices() {
        if c == ouvre {
            niveau += 1;
        } else if c == ferme {
            niveau -= 1;
            if niveau == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// Texte sans commentaires de fin de ligne (« // » hors d'une chaîne).
fn sans_commentaires(texte: &str) -> String {
    texte
        .lines()
        .map(|l| {
            let b = l.as_bytes();
            let (mut i, mut chaine) = (0, false);
            while i + 1 < b.len() {
                match b[i] {
                    b'\\' if chaine => i += 1,
                    b'"' => chaine = !chaine,
                    b'/' if !chaine && b[i + 1] == b'/' => return &l[..i],
                    _ => {}
                }
                i += 1;
            }
            l
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Corps (sans commentaires) de la fonction qui déclare les routes.
fn corps(src: &Source) -> String {
    let lieu = format!("{} dans {}", src.fonction, src.fichier);
    assert_eq!(src.texte.matches(src.fonction).count(), 1, "analyse des routes cassée : {lieu} absente ou en double");
    let debut = src.texte.find(src.fonction).unwrap_or_default();
    let ouvre = debut + src.texte[debut..].find('{').unwrap_or_else(|| panic!("analyse des routes cassée : {lieu} sans corps"));
    let fin = fermante(&src.texte[ouvre..], '{', '}').unwrap_or_else(|| panic!("analyse des routes cassée : {lieu} non refermée"));
    sans_commentaires(&src.texte[ouvre + 1..ouvre + fin])
}

/// Arguments de chaque appel `.<nom>(…)` d'un corps (parenthèses équilibrées).
fn appels<'a>(corps: &'a str, nom: &str) -> Vec<&'a str> {
    let motif = format!(".{nom}(");
    let mut out = Vec::new();
    let mut reste = corps;
    while let Some(i) = reste.find(&motif) {
        let appel = &reste[i + motif.len() - 1..];
        let fin = fermante(appel, '(', ')').unwrap_or_else(|| panic!("analyse des routes cassée : .{nom}( non refermé"));
        out.push(&appel[1..fin]);
        reste = &appel[fin..];
    }
    out
}

/// Premier littéral de chaîne d'une liste d'arguments, et ce qui le suit.
fn chaine_en_tete(args: &str) -> Option<(&str, &str)> {
    let (chemin, suite) = args.trim_start().strip_prefix('"')?.split_once('"')?;
    Some((chemin, suite))
}

/// Routes déclarées dans un corps : (méthode en majuscules, préfixe + chemin).
fn routes_du_corps(corps: &str, prefixe: &str, out: &mut BTreeSet<(String, String)>) {
    for args in appels(corps, "route") {
        let (chemin, gestionnaires) =
            chaine_en_tete(args).unwrap_or_else(|| panic!("analyse des routes cassée : chemin attendu ({prefixe})"));
        let mut trouve = false;
        for m in METHODES {
            for (j, _) in gestionnaires.match_indices(&format!("{m}(")) {
                // « forget( » ou « m::get_x( » ne sont pas des méthodes.
                if gestionnaires[..j].ends_with(|c: char| c.is_alphanumeric() || c == '_') {
                    continue;
                }
                out.insert((m.to_uppercase(), format!("{prefixe}{chemin}")));
                trouve = true;
            }
        }
        assert!(trouve, "analyse des routes cassée : aucune méthode pour {prefixe}{chemin}");
    }
}

/// Toutes les routes servies, lues dans les sources.
fn routes() -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for src in SOURCES {
        routes_du_corps(&corps(src), src.prefixe, &mut out);
    }
    out
}

/// Chemin concret d'un gabarit : identifiants aléatoires, jeton pour `:token`.
fn concret(gabarit: &str) -> String {
    gabarit
        .split('/')
        .map(|seg| match seg {
            ":token" => crypto::random_token(),
            ":revision" => "1".into(),
            s if s.starts_with(':') => new_uuid(),
            s => s.into(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// L'adresse cliente est lue dans X-Forwarded-For : une adresse par requête,
/// pour que le limiteur des échecs SCIM ne se déclenche pas.
fn proxy_de_confiance(st: &mut AppState) {
    let b = &st.config;
    st.config = Arc::new(Config {
        bind: b.bind.clone(),
        data_dir: b.data_dir.clone(),
        web_dir: b.web_dir.clone(),
        trust_proxy: true,
        trusted_proxies: Vec::new(),
        hsts: b.hsts,
        request_timeout: b.request_timeout,
        header_timeout: b.header_timeout,
        argon2_concurrency: b.argon2_concurrency,
        argon2_queue: b.argon2_queue,
    });
}

/// Refus attendu : statut, puis code et message (`{error,message}` de l'API,
/// `{status,detail}` du protocole SCIM).
fn verifie_refus(rep: &Rep, statut: u16, code: &str, scim: bool) -> Result<(), String> {
    let ok = rep.status == statut
        && if scim {
            rep.body["status"] == json!(statut.to_string()) && rep.body["detail"].as_str().is_some_and(|d| !d.is_empty())
        } else {
            rep.body["error"] == json!(code) && rep.body["message"].as_str().is_some_and(|m| !m.is_empty())
        };
    if ok {
        Ok(())
    } else {
        Err(format!("attendu {statut} {code}, reçu {} {}", rep.status, rep.body))
    }
}

#[test]
fn l_analyse_des_routes_couvre_tous_les_routeurs() {
    let api = corps(&SOURCES[0]);
    let fusions: BTreeSet<&str> = appels(&api, "merge").into_iter().map(str::trim).collect();
    let attendues: BTreeSet<&str> = FUSIONS_ANALYSEES.iter().copied().collect();
    assert_eq!(fusions, attendues, "un routeur fusionné dans api_router n'est pas analysé : ajoutez-le à SOURCES");
    let app = corps(&SOURCES[1]);
    let imbriques: BTreeSet<&str> = appels(&app, "nest").into_iter().filter_map(|a| chaine_en_tete(a).map(|(c, _)| c)).collect();
    assert_eq!(imbriques, BTreeSet::from(["/api", "/scim/v2"]), "un routeur imbriqué dans build_app n'est pas analysé");
    // L'extraction elle-même, sur un extrait à plusieurs lignes avec une
    // couche interne et un commentaire.
    let extrait = r#"Router::new()
        // .route("/commentaire", get(x))
        .route(
            "/a/:id",
            put(m::budget_put).layer(DefaultBodyLimit::max(f(1))),
        )
        .route("/b", get(m::forget).delete(m::efface))"#;
    let mut vues = BTreeSet::new();
    routes_du_corps(&sans_commentaires(extrait), "/p", &mut vues);
    let attendues = [("PUT", "/p/a/:id"), ("GET", "/p/b"), ("DELETE", "/p/b")];
    assert_eq!(vues, attendues.iter().map(|(m, c)| (m.to_string(), c.to_string())).collect());
}

#[tokio::test]
async fn toutes_les_routes_sauf_publiques_exigent_une_session() {
    let routes = routes();
    assert!(routes.len() >= 120, "analyse des routes cassée : {} routes extraites seulement", routes.len());
    assert!(!routes.iter().any(|(_, c)| c.contains("panique")), "une route de test est comptée parmi les routes servies");
    for (m, c) in PUBLIQUES {
        assert!(routes.contains(&(m.to_string(), c.to_string())), "liste PUBLIQUES périmée : {m} {c} n'est plus servie");
    }

    let s = super::srv_with(proxy_de_confiance).await;
    let mut n = 0u32;
    let mut xff = || {
        n += 1;
        format!("10.{}.{}.{}", (n >> 16) & 255, (n >> 8) & 255, n & 255)
    };
    let user = account(&s.st, &AccountOpts::default()).await;
    let owner = account(&s.st, &AccountOpts { role: "owner", ..AccountOpts::default() }).await;
    // Jeton SCIM réel : le refus du jeton de session ne tient pas à
    // l'absence de jeton configuré.
    let jeton_scim = s.req(Method::POST, "/api/admin/scim/token", Some(owner.token.as_str()), None, &[("x-forwarded-for", &xff())]).await;
    let jeton_scim = jeton_scim.expect(200, "")["token"].as_str().expect("jeton SCIM").to_string();
    let long = "a".repeat(200);

    let mut echecs = Vec::new();
    let mut controles = 0;
    for (methode, gabarit) in &routes {
        if PUBLIQUES.contains(&(methode.as_str(), gabarit.as_str())) {
            continue;
        }
        let chemin = concret(gabarit);
        let scim = gabarit.starts_with("/scim/v2");
        let corps = matches!(methode.as_str(), "POST" | "PUT" | "PATCH").then(|| json!({}));
        let mut essais: Vec<(&str, Option<&str>, u16, &str)> = vec![
            ("sans en-tête", None, 401, "unauthorized"),
            ("« Bearer null »", Some("null"), 401, "unauthorized"),
            ("jeton inconnu de 200 caractères", Some(long.as_str()), 401, "unauthorized"),
        ];
        if scim {
            essais.push(("jeton de session d'un propriétaire", Some(owner.token.as_str()), 401, ""));
        }
        if gabarit.starts_with("/api/admin/") {
            essais.push(("compte « user »", Some(user.token.as_str()), 403, "forbidden"));
        }
        let m = Method::from_bytes(methode.as_bytes()).expect("méthode HTTP");
        for (cas, jeton, statut, code) in essais {
            let rep = s.req(m.clone(), &chemin, jeton, corps.as_ref(), &[("x-forwarded-for", &xff())]).await;
            controles += 1;
            if let Err(e) = verifie_refus(&rep, statut, code, scim) {
                echecs.push(format!("{methode} {gabarit} ({cas}) : {e}"));
            }
        }
    }
    assert!(
        echecs.is_empty(),
        "Routes sans refus par défaut (constat #54) : toute route hors de PUBLIQUES doit exiger une session.\n{}",
        echecs.join("\n")
    );
    assert!(controles >= 3 * (routes.len() - PUBLIQUES.len()), "{controles} contrôles seulement");
    eprintln!("{} routes analysées dont {} publiques ; {controles} refus vérifiés", routes.len(), PUBLIQUES.len());
    // Témoin : le vrai jeton SCIM ouvre bien le protocole.
    let ok = s.req(Method::GET, "/scim/v2/ServiceProviderConfig", Some(jeton_scim.as_str()), None, &[("x-forwarded-for", &xff())]).await;
    assert_eq!(ok.status, 200, "jeton SCIM réel refusé : {}", ok.body);
}

// ====================================================================
// 2. Matrice IDOR générée
// ====================================================================

// ------------------------------------------------------------ Données en base
// (recopiées de tests/enforce_data.rs, dont les utilitaires sont privés)

fn jeton(a: &Account) -> Option<&str> {
    Some(a.token.as_str())
}

/// Compte « user » connecté (session d'une heure).
async fn compte(s: &Srv) -> Account {
    account(&s.st, &AccountOpts::default()).await
}

/// Coffre partagé inséré en base, dont `owner` est gestionnaire.
async fn coffre(s: &Srv, owner: &Account) -> String {
    let (id, uid) = (new_uuid(), owner.id.clone());
    let cid = id.clone();
    s.st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO collections (id, enc_name, personal, created_by, created_at, updated_at) VALUES (?1, ?2, 0, ?3, 0, 0)",
                params![cid, cipher("nom"), uid],
            )?;
            c.execute(
                "INSERT INTO memberships (collection_id, user_id, role, sealed_key, created_at) VALUES (?1, ?2, 'manager', 'scellée', 0)",
                params![cid, uid],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    id
}

async fn membre(s: &Srv, collection_id: &str, user: &Account, role: &'static str) {
    let (cid, uid) = (collection_id.to_string(), user.id.clone());
    s.st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO memberships (collection_id, user_id, role, sealed_key, created_at) VALUES (?1, ?2, ?3, 'scellée', 0)",
                params![cid, uid, role],
            )?;
            Ok(())
        })
        .await
        .unwrap();
}

/// Élément inséré en base (révision 1).
async fn element(s: &Srv, collection_id: &str) -> String {
    let (id, cid) = (new_uuid(), collection_id.to_string());
    let iid = id.clone();
    s.st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO items (id, collection_id, data, revision, created_at, updated_at) VALUES (?1, ?2, ?3, 1, 0, 0)",
                params![iid, cid, cipher("élément")],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    id
}

/// Pièce jointe insérée en base.
async fn piece_jointe(s: &Srv, item_id: &str, auteur: &Account) -> String {
    let (id, iid, uid) = (new_uuid(), item_id.to_string(), auteur.id.clone());
    let pid = id.clone();
    s.st.db
        .call(move |c| {
            let data = cipher("pièce jointe");
            c.execute(
                "INSERT INTO attachments (id, item_id, data, size, created_at, created_by) VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                params![pid, iid, data, data.len() as i64, uid],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    id
}

/// Lien de partage d'un élément, créé par l'API.
async fn lien(s: &Srv, auteur: &Account, item_id: &str) -> String {
    let corps = json!({ "data": cipher("secret du lien"), "expires_in_minutes": 60, "max_views": 3, "item_id": item_id });
    let rep = s.post("/api/shares", jeton(auteur), corps).await;
    rep.expect(200, "")["id"].as_str().expect("identifiant du lien").to_string()
}

/// Valeur texte d'une requête à un paramètre (vide si NULL ou aucune ligne).
async fn ligne(s: &Srv, sql: &'static str, arg: &str) -> String {
    let a = arg.to_string();
    s.st.db
        .read(move |c| Ok(c.query_row(sql, [a], |r| r.get::<_, Option<String>>(0)).optional()?.flatten().unwrap_or_default()))
        .await
        .unwrap()
}

/// Valeur entière d'une requête à un paramètre.
async fn nombre(s: &Srv, sql: &'static str, arg: &str) -> i64 {
    let a = arg.to_string();
    s.st.db.read(move |c| Ok(c.query_row(sql, [a], |r| r.get(0))?)).await.unwrap()
}

/// Clé de coffre scellée bien formée (pour un destinataire quelconque).
fn scellee() -> String {
    let (_, public) = crypto::generate_keypair();
    crypto::seal_key(&public, &SecretKey::generate(), "contexte").unwrap()
}

/// Corps d'un renouvellement de clé : membres restants et éléments du coffre,
/// lus en base au moment de l'appel.
async fn corps_rotation(s: &Srv, coffre: &str, retires: &[String]) -> Value {
    let c = coffre.to_string();
    let (membres, elements) = s
        .st
        .db
        .read(move |db| {
            let liste = |sql: &str| -> rusqlite::Result<Vec<String>> {
                let mut st = db.prepare(sql)?;
                let lignes = st.query_map([&c], |r| r.get(0))?;
                lignes.collect()
            };
            Ok((
                liste("SELECT user_id FROM memberships WHERE collection_id = ?1")?,
                liste("SELECT id FROM items WHERE collection_id = ?1")?,
            ))
        })
        .await
        .unwrap();
    json!({
        "remove_user_ids": retires,
        "enc_name": cipher("coffre renouvelé"),
        "members": membres.iter().filter(|m| !retires.contains(m)).map(|m| json!({ "user_id": m, "sealed_key": scellee() })).collect::<Vec<_>>(),
        "items": elements.iter().map(|i| json!({ "id": i, "data": cipher("élément rechiffré") })).collect::<Vec<_>>(),
    })
}

// ------------------------------------------------------------ Acteurs et routes

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Acteur {
    /// Créateur du coffre (seul gestionnaire), de l'élément et du lien.
    Proprietaire,
    Gestionnaire,
    Editeur,
    Lecteur,
    /// Compte de l'organisation sans aucun lien avec le coffre.
    Etranger,
    /// Éditeur retiré par un renouvellement de clé.
    AncienMembre,
    /// Éditeur dont le compte est désactivé.
    Desactive,
    /// Administrateur de l'organisation, non membre du coffre.
    AdminNonMembre,
}

const ACTEURS: [Acteur; 8] = [
    Acteur::Proprietaire,
    Acteur::Gestionnaire,
    Acteur::Editeur,
    Acteur::Lecteur,
    Acteur::Etranger,
    Acteur::AncienMembre,
    Acteur::Desactive,
    Acteur::AdminNonMembre,
];

impl Acteur {
    /// Rang dans le coffre : 3 gestionnaire, 2 éditeur, 1 lecteur.
    fn rang(self) -> u8 {
        match self {
            Acteur::Proprietaire | Acteur::Gestionnaire => 3,
            Acteur::Editeur => 2,
            Acteur::Lecteur => 1,
            _ => 0,
        }
    }
}

/// Routes qui prennent l'identifiant d'un objet de coffre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    ModifierElement,
    CorbeilleElement,
    RestaurerElement,
    PurgerElement,
    AjouterPieceJointe,
    LirePieceJointe,
    SupprimerPieceJointe,
    RenommerCoffre,
    SupprimerCoffre,
    ListerMembres,
    AjouterMembre,
    ModifierMembre,
    QuitterCoffre,
    RenouvelerCle,
    RevoquerLien,
}

const OPS: [Op; 15] = [
    Op::ModifierElement,
    Op::CorbeilleElement,
    Op::RestaurerElement,
    Op::PurgerElement,
    Op::AjouterPieceJointe,
    Op::LirePieceJointe,
    Op::SupprimerPieceJointe,
    Op::RenommerCoffre,
    Op::SupprimerCoffre,
    Op::ListerMembres,
    Op::AjouterMembre,
    Op::ModifierMembre,
    Op::QuitterCoffre,
    Op::RenouvelerCle,
    Op::RevoquerLien,
];

/// Ce qu'une route exige d'un membre du coffre.
enum Exigence {
    /// Rang minimal (1 lecture, 2 écriture, 3 gestion).
    Rang(u8),
    /// Créateur du lien seulement.
    Createur,
    /// Quitter le coffre : tout membre, sauf son dernier gestionnaire.
    Quitter,
}

impl Op {
    fn exigence(self) -> Exigence {
        match self {
            Op::LirePieceJointe | Op::ListerMembres => Exigence::Rang(1),
            Op::ModifierElement
            | Op::CorbeilleElement
            | Op::RestaurerElement
            | Op::PurgerElement
            | Op::AjouterPieceJointe
            | Op::SupprimerPieceJointe => Exigence::Rang(2),
            Op::RenommerCoffre | Op::SupprimerCoffre | Op::AjouterMembre | Op::ModifierMembre | Op::RenouvelerCle => {
                Exigence::Rang(3)
            }
            Op::QuitterCoffre => Exigence::Quitter,
            Op::RevoquerLien => Exigence::Createur,
        }
    }

    /// Statut d'une réussite.
    fn succes(self) -> u16 {
        match self {
            Op::ModifierElement | Op::LirePieceJointe | Op::ListerMembres => 200,
            Op::AjouterPieceJointe | Op::AjouterMembre => 201,
            _ => 204,
        }
    }

    /// Une réussite modifie-t-elle les données ?
    fn ecrit(self) -> bool {
        !matches!(self, Op::LirePieceJointe | Op::ListerMembres)
    }

    /// L'élément doit-il être dans la corbeille avant l'appel ?
    fn corbeille(self) -> bool {
        matches!(self, Op::RestaurerElement | Op::PurgerElement)
    }
}

/// Réponse attendue ; `uniforme` : le 404 doit égaler celui d'un identifiant
/// inexistant (code ET message).
struct Attendu {
    statut: u16,
    code: &'static str,
    uniforme: bool,
}

fn attendu(op: Op, acteur: Acteur) -> Attendu {
    let ok = Attendu { statut: op.succes(), code: "", uniforme: false };
    let introuvable = Attendu { statut: 404, code: "not_found", uniforme: true };
    match acteur {
        Acteur::Desactive => Attendu { statut: 403, code: "account_disabled", uniforme: false },
        Acteur::Etranger | Acteur::AncienMembre | Acteur::AdminNonMembre => introuvable,
        _ => match op.exigence() {
            Exigence::Createur if acteur == Acteur::Proprietaire => ok,
            Exigence::Createur => introuvable,
            Exigence::Quitter if acteur == Acteur::Proprietaire => Attendu { statut: 400, code: "bad_request", uniforme: false },
            Exigence::Quitter => ok,
            Exigence::Rang(n) if acteur.rang() >= n => ok,
            Exigence::Rang(_) => Attendu { statut: 403, code: "forbidden", uniforme: false },
        },
    }
}

/// Un coffre et ses objets, vus par un acteur.
struct Monde {
    proprietaire: Account,
    /// Compte de l'acteur (`None` : le propriétaire lui-même).
    acteur: Option<Account>,
    /// Lecteur du coffre, dont `ModifierMembre` change le rôle.
    cible: Account,
    /// Compte hors du coffre, qu'`AjouterMembre` y ajoute.
    candidat: Account,
    coffre: String,
    element: String,
    piece: String,
    lien: String,
}

impl Monde {
    fn compte(&self) -> &Account {
        self.acteur.as_ref().unwrap_or(&self.proprietaire)
    }
}

async fn monde(s: &Srv, acteur: Acteur, corbeille: bool) -> Monde {
    let proprietaire = compte(s).await;
    let coffre = coffre(s, &proprietaire).await;
    let element = element(s, &coffre).await;
    let piece = piece_jointe(s, &element, &proprietaire).await;
    let cible = compte(s).await;
    membre(s, &coffre, &cible, "reader").await;
    let candidat = compte(s).await;
    let membre_de_role = |role: &'static str, opts: AccountOpts| {
        let coffre = coffre.clone();
        async move {
            let a = account(&s.st, &opts).await;
            membre(s, &coffre, &a, role).await;
            a
        }
    };
    let acteur_compte = match acteur {
        Acteur::Proprietaire => None,
        Acteur::Gestionnaire => Some(membre_de_role("manager", AccountOpts::default()).await),
        Acteur::Editeur | Acteur::AncienMembre => Some(membre_de_role("editor", AccountOpts::default()).await),
        Acteur::Lecteur => Some(membre_de_role("reader", AccountOpts::default()).await),
        Acteur::Desactive => Some(membre_de_role("editor", AccountOpts { disabled: true, ..AccountOpts::default() }).await),
        Acteur::Etranger => Some(compte(s).await),
        Acteur::AdminNonMembre => Some(account(&s.st, &AccountOpts { role: "admin", ..AccountOpts::default() }).await),
    };
    if acteur == Acteur::AncienMembre {
        let retire = acteur_compte.as_ref().map(|a| a.id.clone()).into_iter().collect::<Vec<_>>();
        let corps = corps_rotation(s, &coffre, &retire).await;
        s.post(&format!("/api/collections/{coffre}/rotate"), jeton(&proprietaire), corps).await.expect(204, "");
    }
    let lien = lien(s, &proprietaire, &element).await;
    if corbeille {
        let iid = element.clone();
        s.st.db
            .call(move |c| Ok(c.execute("UPDATE items SET deleted_at = ?1 WHERE id = ?2", params![now_unix(), iid])?))
            .await
            .unwrap();
    }
    Monde { proprietaire, acteur: acteur_compte, cible, candidat, coffre, element, piece, lien }
}

/// Identifiant de l'objet visé par la route.
fn objet(op: Op, m: &Monde) -> &str {
    match op {
        Op::ModifierElement | Op::CorbeilleElement | Op::RestaurerElement | Op::PurgerElement | Op::AjouterPieceJointe => &m.element,
        Op::LirePieceJointe | Op::SupprimerPieceJointe => &m.piece,
        Op::RevoquerLien => &m.lien,
        _ => &m.coffre,
    }
}

/// Identifiant inexistant de même forme que celui de l'objet.
fn fantome(op: Op) -> String {
    if op == Op::RevoquerLien {
        crypto::random_token()
    } else {
        new_uuid()
    }
}

/// Requête de la route pour l'objet `id` (réel ou fantôme).
async fn requete(s: &Srv, op: Op, m: &Monde, id: &str) -> (Method, String, Option<Value>) {
    let col = |suite: &str| format!("/api/collections/{id}{suite}");
    match op {
        Op::ModifierElement => {
            let revision = nombre(s, "SELECT revision FROM items WHERE id = ?1", &m.element).await;
            let corps = json!({ "collection_id": m.coffre, "data": cipher("élément modifié"), "revision": revision });
            (Method::PUT, format!("/api/items/{id}"), Some(corps))
        }
        Op::CorbeilleElement => (Method::DELETE, format!("/api/items/{id}"), None),
        Op::RestaurerElement => (Method::POST, format!("/api/items/{id}/restore"), None),
        Op::PurgerElement => (Method::DELETE, format!("/api/items/{id}/purge"), None),
        Op::AjouterPieceJointe => {
            (Method::PUT, format!("/api/items/{id}/attachments/{}", new_uuid()), Some(json!({ "data": cipher("pièce jointe") })))
        }
        Op::LirePieceJointe => (Method::GET, format!("/api/attachments/{id}"), None),
        Op::SupprimerPieceJointe => (Method::DELETE, format!("/api/attachments/{id}"), None),
        Op::RenommerCoffre => (Method::PUT, col(""), Some(json!({ "enc_name": cipher("coffre renommé") }))),
        Op::SupprimerCoffre => (Method::DELETE, col(""), None),
        Op::ListerMembres => (Method::GET, col("/members"), None),
        Op::AjouterMembre => {
            let corps = json!({ "user_id": m.candidat.id, "role": "reader", "sealed_key": scellee() });
            (Method::POST, col("/members"), Some(corps))
        }
        Op::ModifierMembre => (Method::PUT, col(&format!("/members/{}", m.cible.id)), Some(json!({ "role": "editor" }))),
        Op::QuitterCoffre => (Method::DELETE, col(&format!("/members/{}", m.compte().id)), None),
        Op::RenouvelerCle => (Method::POST, col("/rotate"), Some(corps_rotation(s, &m.coffre, &[]).await)),
        Op::RevoquerLien => (Method::DELETE, format!("/api/shares/{id}"), None),
    }
}

/// Empreinte de tout ce qu'une route de la matrice peut modifier.
async fn empreinte(s: &Srv, m: &Monde) -> String {
    let (c, i, p) = (m.coffre.clone(), m.element.clone(), m.proprietaire.id.clone());
    s.st.db
        .read(move |db| {
            let lire = |sql: &str, arg: &str| -> rusqlite::Result<String> {
                db.query_row(sql, [arg], |r| r.get::<_, Option<String>>(0)).map(Option::unwrap_or_default)
            };
            Ok([
                lire(
                    "SELECT group_concat(collection_id || ':' || data || ':' || revision || ':' || ifnull(deleted_at, '-'), '|')
                     FROM items WHERE id = ?1",
                    &i,
                )?,
                lire("SELECT group_concat(enc_name || ':' || key_version, '|') FROM collections WHERE id = ?1", &c)?,
                lire(
                    "SELECT group_concat(user_id || ':' || role || ':' || sealed_key, '|')
                     FROM (SELECT * FROM memberships WHERE collection_id = ?1 ORDER BY user_id)",
                    &c,
                )?,
                lire("SELECT group_concat(id || ':' || data, '|') FROM (SELECT * FROM attachments WHERE item_id = ?1 ORDER BY id)", &i)?,
                lire("SELECT group_concat(id || ':' || state, '|') FROM (SELECT * FROM shares WHERE owner_id = ?1 ORDER BY id)", &p)?,
            ]
            .join("#"))
        })
        .await
        .unwrap()
}

/// Statut, code et message d'une réponse.
fn forme(r: &Rep) -> (u16, String, String) {
    let txt = |k: &str| r.body[k].as_str().unwrap_or("").to_string();
    (r.status, txt("error"), txt("message"))
}

#[tokio::test]
async fn matrice_idor_generee() {
    let s = super::srv().await;
    let mut echecs = Vec::new();
    for op in OPS {
        for acteur in ACTEURS {
            let m = monde(&s, acteur, op.corbeille()).await;
            let att = attendu(op, acteur);
            let qui = m.compte();
            let avant = empreinte(&s, &m).await;
            let (methode, chemin, corps) = requete(&s, op, &m, objet(op, &m)).await;
            let rep = s.req(methode.clone(), &chemin, jeton(qui), corps.as_ref(), &[]).await;
            let apres = empreinte(&s, &m).await;
            let cas = format!("{op:?} par {acteur:?} ({methode} {})", chemin.replace(&qui.id, ":moi"));
            let (statut, code, message) = forme(&rep);
            if (statut, code.as_str()) != (att.statut, att.code) || (!att.code.is_empty() && message.is_empty()) {
                echecs.push(format!("{cas} : attendu {} « {} », reçu {statut} {}", att.statut, att.code, rep.body));
            }
            if att.uniforme {
                let (mf, cf, bf) = requete(&s, op, &m, &fantome(op)).await;
                let f = s.req(mf, &cf, jeton(qui), bf.as_ref(), &[]).await;
                if forme(&f) != forme(&rep) {
                    echecs.push(format!("{cas} : 404 non uniforme ({} contre {} pour un identifiant inexistant)", rep.body, f.body));
                }
            }
            let doit_changer = op.ecrit() && (200..300).contains(&att.statut);
            if doit_changer == (avant == apres) {
                let effet = if doit_changer { "aucun effet malgré la réussite" } else { "données modifiées malgré le refus" };
                echecs.push(format!("{cas} : {effet}"));
            }
        }
    }
    assert!(echecs.is_empty(), "Matrice IDOR : {} écart(s)\n{}", echecs.len(), echecs.join("\n"));
    eprintln!("Matrice IDOR : {} routes × {} acteurs = {} cas", OPS.len(), ACTEURS.len(), OPS.len() * ACTEURS.len());
}

// ====================================================================
// 3. Cas propres à Locksy
// ====================================================================

const LIGNE_ELEMENT: &str = "SELECT collection_id || ':' || data || ':' || revision FROM items WHERE id = ?1";

#[tokio::test]
async fn deplacer_un_element_vers_un_coffre_en_lecture_ou_depuis_celui_d_autrui_est_refuse() {
    let s = super::srv().await;
    let (a, b, e) = (compte(&s).await, compte(&s).await, compte(&s).await);
    let (c1, c2, ce, cb) = (coffre(&s, &a).await, coffre(&s, &a).await, coffre(&s, &e).await, coffre(&s, &b).await);
    membre(&s, &c1, &b, "editor").await;
    membre(&s, &c2, &b, "reader").await;
    let i1 = element(&s, &c1).await;
    let vers = |cid: &str| json!({ "collection_id": cid, "data": cipher("élément déplacé"), "revision": 1 });
    let avant = ligne(&s, LIGNE_ELEMENT, &i1).await;

    // B, éditeur du coffre d'origine et lecteur du coffre visé : 403.
    s.put(&format!("/api/items/{i1}"), jeton(&b), vers(&c2)).await.expect(403, "forbidden");
    // B vers un coffre dont il n'est pas membre : même 404 qu'un coffre inexistant.
    let v = s.put(&format!("/api/items/{i1}"), jeton(&b), vers(&ce)).await;
    let f = s.put(&format!("/api/items/{i1}"), jeton(&b), vers(&new_uuid())).await;
    assert_eq!(forme(&v), forme(&f), "déplacement vers un coffre étranger");
    v.expect(404, "not_found");
    // L'étranger prend l'élément d'autrui pour le ranger chez lui : 404 uniforme.
    let v = s.put(&format!("/api/items/{i1}"), jeton(&e), vers(&ce)).await;
    let f = s.put(&format!("/api/items/{}", new_uuid()), jeton(&e), vers(&ce)).await;
    assert_eq!(forme(&v), forme(&f), "élément pris dans le coffre d'autrui");
    v.expect(404, "not_found");
    assert_eq!(ligne(&s, LIGNE_ELEMENT, &i1).await, avant, "un refus a modifié l'élément");

    // Témoin : B le déplace vers son propre coffre.
    s.put(&format!("/api/items/{i1}"), jeton(&b), vers(&cb)).await.expect(200, "");
    assert_eq!(ligne(&s, "SELECT collection_id FROM items WHERE id = ?1", &i1).await, cb);
}

#[tokio::test]
async fn creer_un_element_avec_un_identifiant_pris_ailleurs_donne_409_sans_rien_ecraser() {
    let s = super::srv().await;
    let (a, e) = (compte(&s).await, compte(&s).await);
    let (c1, ce) = (coffre(&s, &a).await, coffre(&s, &e).await);
    let i1 = element(&s, &c1).await;
    let avant = ligne(&s, LIGNE_ELEMENT, &i1).await;
    let nouveau = |id: &str| json!({ "id": id, "collection_id": ce, "data": cipher("écrasement") });

    s.post("/api/items", jeton(&e), nouveau(&i1)).await.expect(409, "conflict");
    // Import : même refus, et l'élément neuf du même lot n'est pas créé.
    let neuf = new_uuid();
    s.post("/api/items/batch", jeton(&e), json!({ "items": [nouveau(&neuf), nouveau(&i1)] })).await.expect(409, "conflict");

    assert_eq!(ligne(&s, LIGNE_ELEMENT, &i1).await, avant, "l'élément d'autrui a été écrasé");
    assert_eq!(nombre(&s, "SELECT COUNT(*) FROM items WHERE id = ?1", &neuf).await, 0, "import partiel");
    assert_eq!(super::count(&s.st, "SELECT COUNT(*) FROM items WHERE data LIKE '%écrasement%'").await, 0);
}

#[tokio::test]
async fn piece_jointe_avec_l_identifiant_d_autrui_donne_409_sans_rien_ecraser() {
    let s = super::srv().await;
    let (a, e) = (compte(&s).await, compte(&s).await);
    let (c1, ce) = (coffre(&s, &a).await, coffre(&s, &e).await);
    let (i1, ie) = (element(&s, &c1).await, element(&s, &ce).await);
    let p1 = piece_jointe(&s, &i1, &a).await;
    const LIGNE: &str = "SELECT item_id || ':' || data || ':' || size FROM attachments WHERE id = ?1";
    let avant = ligne(&s, LIGNE, &p1).await;

    let corps = json!({ "data": cipher("pièce jointe de remplacement") });
    s.put(&format!("/api/items/{ie}/attachments/{p1}"), jeton(&e), corps).await.expect(409, "conflict");

    assert_eq!(ligne(&s, LIGNE, &p1).await, avant, "la pièce jointe d'autrui a été écrasée");
    assert_eq!(nombre(&s, "SELECT COUNT(*) FROM attachments WHERE item_id = ?1", &ie).await, 0, "pièce jointe ajoutée");
}
