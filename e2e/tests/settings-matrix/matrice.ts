// Matrice du paramétrage (cahier §6.4 « settings-matrix », critère G2,
// contrat V2.2) : pour CHAQUE clé du registre, comment elle se modifie dans
// l'interface et où son APPLICATION est prouvée.
//
//   ui : "modifiable"            la clé se change dans Réglages, est conservée
//                                après rechargement (reglages.isole.ts) ;
//        { refus: "<code>" }     garde-fou : le serveur refuse la valeur dans
//                                cet environnement, et le refus s'affiche en
//                                français à côté du champ (reglages.isole.ts).
//   preuves :
//     { rust: "<fichier>.rs::<fn>" }           test Rust qui règle la clé puis
//                                              constate son effet ;
//     { e2e: "ici" }                           effet vérifié par
//                                              reglages.isole.ts (fichier effets.ts) ;
//     { e2e: "tests/<f>.spec.ts", titre }      test de bout en bout existant ;
//     { extension: "extension/src/test/<f>", titre } test unitaire de l'extension ;
//     { windows: "crates/locksy-desktop/src/config.rs::<fn>" | "v1.2" }
//                                              client Windows (V1.5 : il ne lit
//                                              que sa politique locale) ;
//     { manquant: "Q3b-H<n>" }                 aucune preuve : handoff ouvert.
//
// Le garde-fou (garde-fou.isole.ts) compare ces clés à GET
// /api/admin/settings/schema : une clé ajoutée au registre sans entrée ici
// fait échouer la suite. Le nombre de clés n'est jamais écrit en dur.

export type Preuve =
  | { rust: string }
  | { e2e: "ici" }
  | { e2e: string; titre: string }
  | { extension: string; titre: string }
  | { windows: string }
  | { manquant: string };

export interface Entree {
  ui: "modifiable" | { refus: string };
  preuves: Preuve[];
}

// ------------------------------------------------------------------ Références

const T = "crates/locksy-server/src/tests";
const S = "crates/locksy-server/src";
const rust = (fichier: string, fn: string): Preuve => ({ rust: `${fichier}.rs::${fn}` });
const ICI: Preuve = { e2e: "ici" };
const V12: Preuve = { windows: "v1.2" };
const win = (fn: string): Preuve => ({ windows: `crates/locksy-desktop/src/config.rs::${fn}` });
const EXT_REGLES: Preuve = {
  extension: "extension/src/test/settings.test.js",
  titre: "règles effectives : bloquer et interdire gagnent, listes réunies",
};
const EXT_ECHEANCES: Preuve = {
  extension: "extension/src/test/settings.test.js",
  titre: "échéances de verrouillage : jamais prolongées par le poste",
};
const PUBLICS = rust(`${T}/settings`, "reglages_publics_suivent_le_registre");
const MAIL_ENVOI = rust(`${T}/mail`, "invitation_recue_avec_le_lien");

const ok = (...preuves: Preuve[]): Entree => ({ ui: "modifiable", preuves });
const refus = (code: string, ...preuves: Preuve[]): Entree => ({ ui: { refus: code }, preuves });

export const MATRICE: Record<string, Entree> = {
  // ---------------------------------------------------------------- Sécurité de connexion
  // Le propriétaire de test n'a pas la double authentification : l'imposer à
  // tous le bloquerait, le serveur refuse (garde-fou §4.6.4).
  "twofa.required": refus("actor_without_2fa", rust(`${S}/state`, "deux_fa_pendant_le_delai_de_grace"), rust(`${S}/state`, "deux_fa_apres_l_echeance")),
  "twofa.required_roles": ok(rust(`${S}/state`, "deux_fa_exigee_par_role"), rust(`${T}/enforce_auth`, "deux_fa_imposee_par_role_dans_le_profil")),
  "twofa.grace_days": ok(rust(`${S}/state`, "deux_fa_apres_l_echeance")),
  // Aucun annuaire ni SSO configuré : « Compte Windows » ou « SSO » sont refusés.
  "auth.primary_method": refus("method_not_enabled", {
    e2e: "tests/auth/connexion.spec.ts",
    titre: "méthode principale Windows : le mot de passe maître est replié sous « Utiliser une autre méthode »",
  }),
  "access.allowed_email_domains": ok(rust(`${T}/enforce_auth`, "inscription_domaines_et_planchers_kdf"), rust(`${T}/identity`, "annuaire_applique_les_domaines_autorises")),
  "access.ip_allowlist": ok(rust(`${T}/enforce_auth`, "liste_blanche_ip_a_la_connexion"), rust(`${S}/state`, "adresse_hors_liste_blanche")),
  "access.ip_rescue": ok(rust(`${T}/enforce_auth`, "liste_blanche_ip_a_la_connexion")),
  "session.max_per_user": ok(rust(`${T}/enforce_auth`, "sessions_par_compte_plafonnees")),
  "lockout.pair_threshold": ok(rust(`${T}/enforce_auth`, "seuil_par_paire_regle")),
  "lockout.account_threshold": ok(rust(`${T}/enforce_auth`, "seuil_par_compte_regle")),
  "lockout.base_delay_seconds": ok(rust(`${T}/enforce_auth`, "delai_de_base_regle")),
  "lockout.max_delay_seconds": ok(rust(`${T}/enforce_auth`, "delai_maximal_regle")),

  // ---------------------------------------------------------------- Sessions et verrouillage
  "session.idle_minutes": ok(rust(`${S}/state`, "inactivite_lue_dans_le_registre")),
  "session.max_hours": ok(rust(`${T}/enforce_auth`, "duree_de_session_reglee")),
  "client.autolock_minutes": ok(
    ICI,
    { e2e: "tests/auth/verrouillage.spec.ts", titre: "verrouillage automatique : préavis de 60 s, « Rester déverrouillé », puis verrouillage" },
    EXT_ECHEANCES,
    win("auto_lock_is_bounded_and_never_forbidden_under_policy"),
  ),
  "client.autolock_allow_never": ok(
    ICI,
    { e2e: "tests/auth/verrouillage.spec.ts", titre: "« Jamais » interdit par l'organisation : la préférence est ramenée et signalée" },
    V12,
  ),
  // Windows : approché par LockOnFocusLossMinutes (politique locale, V1.5).
  "client.lock_on_hide": ok(ICI, win("clipboard_and_focus_lock")),
  "client.lock_on_os_lock": ok(ICI, EXT_REGLES, V12),
  "client.clipboard_clear_seconds": ok(ICI, EXT_REGLES, win("clipboard_and_focus_lock")),
  "client.remember_email": ok(ICI, V12),
  "client.single_key_shortcuts": ok(ICI, V12),

  // ---------------------------------------------------------------- Mots de passe
  "master_password.min_length": ok(ICI),
  "master_password.min_score": ok(PUBLICS, ICI),
  "master_password.forbid_identity": ok(PUBLICS, ICI),
  "master_password.banned_words": ok(ICI),
  "generator.length": ok(ICI, V12),
  "generator.min_length": ok(ICI, { e2e: "tests/tools/generateur.spec.ts", titre: "minimum imposé : curseur borné, mention visible, annonce sans le secret" }, V12),
  "generator.require_classes": ok(ICI, V12),
  "generator.avoid_ambiguous": ok(ICI, V12),
  "generator.symbols": ok(ICI, V12),
  "generator.words": ok(ICI, V12),
  "generator.min_words": ok(ICI, V12),
  "health.weak_below_score": ok(ICI, V12),
  "health.max_password_age_days": ok(ICI, V12),

  // ---------------------------------------------------------------- Partage et coffres
  "share.enabled": ok(rust(`${T}/enforce_data`, "partage_desactive_par_l_organisation"), ICI, V12),
  "share.max_expiry_minutes": ok(rust(`${T}/enforce_data`, "partage_duree_et_ouvertures_plafonnees"), ICI, V12),
  "share.default_expiry_minutes": ok(ICI, V12),
  "share.max_views": ok(rust(`${T}/enforce_data`, "partage_duree_et_ouvertures_plafonnees"), ICI, V12),
  "share.default_views": ok(ICI, V12),
  "share.max_per_hour": ok(rust(`${T}/enforce_data`, "partage_cadence_par_heure")),
  "vault.users_can_create_shared": ok(rust(`${T}/enforce_data`, "creation_de_coffre_partage_reservee_aux_administrateurs"), ICI, V12),
  "vault.rotate_on_member_removal": ok(ICI, V12),
  "vault.personal_enabled": ok(rust(`${T}/enforce_data`, "espace_personnel_bloquable"), ICI, V12),
  "attachment.enabled": ok(rust(`${T}/enforce_data`, "pieces_jointes_desactivables"), ICI, V12),
  "attachment.max_file_mib": ok(rust(`${T}/enforce_data`, "piece_jointe_taille_maximale"), ICI, V12),
  "attachment.max_per_item": ok(rust(`${T}/enforce_data`, "piece_jointe_nombre_par_element"), ICI, V12),
  "attachment.quota_user_mib": ok(rust(`${T}/enforce_data`, "piece_jointe_quota_utilisateur")),
  "attachment.quota_total_mib": ok(rust(`${T}/enforce_data`, "piece_jointe_quota_total")),
  "export.enabled": ok(
    rust(`${T}/enforce_auth`, "export_desactivable"),
    { e2e: "tests/tools/donnees.spec.ts", titre: "export désactivé par l'organisation : section désactivée avec la raison" },
    ICI,
    V12,
  ),
  "export.min_password_length": ok(ICI, V12),
  "import.max_file_mib": ok(ICI, V12),

  // ---------------------------------------------------------------- Applications et extension
  "extension.http_fill": ok(ICI, EXT_REGLES, V12),
  "extension.allow_mismatch_fill": ok(ICI, EXT_REGLES, V12),
  "extension.offer_save": ok(ICI, EXT_REGLES, V12),
  "extension.copy_totp_after_fill": ok(ICI, EXT_REGLES, V12),
  "extension.excluded_sites": ok(ICI, EXT_REGLES, V12),
  "extension.allowed_ids": ok(rust(`${T}/identity`, "extension_autorisee")),

  // ---------------------------------------------------------------- Conservation des données
  "retention.trash_days": ok(rust(`${T}/enforce_data`, "corbeille_auteur_et_date_de_purge"), ICI, V12),
  // Appliqués par la maintenance (main.rs).
  "retention.audit_days": ok(rust(`${T}/settings`, "maintenance_purge_selon_retention_du_journal")),
  "retention.expired_invites_days": ok(rust(`${T}/settings`, "maintenance_supprime_invitations_echues")),
  "invite.ttl_days": ok(rust(`${T}/admin`, "invitations_par_lot_et_renvoi"), ICI),
  "users.inactive_alert_days": ok(rust(`${T}/settings`, "seuil_d_inactivite_reglable")),
  "users.disable_after_inactive_days": ok(rust(`${T}/settings`, "maintenance_liens_corbeille_et_comptes_inactifs")),
  "directory.deprovision": ok(rust(`${T}/identity`, "scim_desactivation_seule_selon_la_politique")),
  "directory.delete_after_days": ok(rust(`${T}/identity`, "delai_de_suppression_reglable")),
  "directory.max_deprovision_percent": ok(rust(`${T}/identity`, "synchronisation_refusee_au_dela_du_seuil")),

  // ---------------------------------------------------------------- Apparence et textes
  "branding.org_name": ok(rust(`${T}/settings`, "etag_et_304_de_la_politique_et_de_la_page_publique"), ICI),
  "branding.logo": ok(rust(`${T}/settings`, "logo_de_l_organisation"), ICI),
  "branding.accent_color": ok(ICI),
  "branding.login_message": ok(PUBLICS, ICI),
  "branding.support_contact": ok(PUBLICS, ICI),
  "branding.totp_issuer": ok(rust(`${T}/enforce_auth`, "emetteur_totp_regle")),
  "legal.notice_url": ok(ICI),
  "legal.privacy_url": ok(PUBLICS, ICI),
  "legal.accessibility_url": ok(PUBLICS, ICI),
  "legal.login_banner": ok(PUBLICS, ICI),
  "legal.charter_text": ok(
    ICI,
    { e2e: "tests/auth/charte.spec.ts", titre: "nouvelle version de la charte : lecture, échec d'enregistrement, puis acceptation" },
    V12,
  ),
  "legal.charter_version": ok(rust(`${T}/settings`, "charte_d_utilisation"), ICI),
  "legal.dpo_contact": ok(PUBLICS, ICI),
  "i18n.default_locale": ok(PUBLICS, ICI),
  "i18n.timezone": ok(ICI),

  // ---------------------------------------------------------------- E-mails
  "mail.enabled": ok(rust(`${T}/mail`, "envoi_desactive_ou_notification_coupee")),
  "mail.smtp.host": ok(rust(`${T}/mail`, "email_de_test_serveur_injoignable")),
  "mail.smtp.port": ok(MAIL_ENVOI),
  "mail.smtp.security": ok(rust(`${T}/mail`, "starttls_exige_n_est_jamais_abandonne")),
  "mail.smtp.username": ok(rust(`${T}/mail`, "aucun_secret_ni_nom_dans_les_messages")),
  "mail.smtp.password": ok(rust(`${T}/mail`, "mot_de_passe_smtp_chiffre_par_la_cle_serveur")),
  "mail.from": ok(MAIL_ENVOI),
  "mail.reply_to": ok(rust(`${T}/mail`, "notifications_coupees_par_reglage_et_adresse_de_reponse")),
  "mail.notify.invite": ok(rust(`${T}/mail`, "envoi_desactive_ou_notification_coupee")),
  "mail.notify.new_device": ok(rust(`${T}/mail`, "notifications_coupees_par_reglage_et_adresse_de_reponse")),
  "mail.notify.security_change": ok(rust(`${T}/mail`, "envoi_desactive_ou_notification_coupee")),
  "mail.notify.settings_lowered": ok(rust(`${T}/mail`, "notifications_coupees_par_reglage_et_adresse_de_reponse")),
  "mail.notify.admin_digest": ok(rust(`${T}/mail`, "resume_des_administrateurs_une_fois_par_periode")),

  // ---------------------------------------------------------------- Avancé
  "instance.public_url": ok(rust(`${T}/identity`, "etat_de_la_connexion_d_entreprise")),
  "kdf.memory_mib": ok(rust(`${T}/enforce_auth`, "kdf_factice_suit_la_politique"), ICI),
  "kdf.iterations": ok(rust(`${T}/enforce_auth`, "kdf_factice_suit_la_politique"), ICI),
  "kdf.parallelism": ok(rust(`${T}/enforce_auth`, "kdf_factice_suit_la_politique"), ICI),
  "kdf.min_memory_mib": ok(rust(`${T}/enforce_auth`, "inscription_domaines_et_planchers_kdf")),
  "kdf.min_iterations": ok(rust(`${T}/enforce_auth`, "inscription_domaines_et_planchers_kdf")),
  "kdf.upgrade_on_login": ok(rust(`${T}/enforce_auth`, "montee_du_kdf_client"), ICI),
  // Appliqués à chaud par l'envoi au SIEM (syslog.rs, à chaque révision).
  "audit.syslog.url": ok(rust("crates/locksy-server/src/syslog", "reglages_url_et_format_appliques")),
  "audit.syslog.format": ok(rust("crates/locksy-server/src/syslog", "reglages_url_et_format_appliques")),
  "audit.csv_separator": ok(rust(`${T}/admin`, "journal_filtre_par_gravite_acteur_type_et_curseur")),
  "scim.token_ttl_days": ok(rust(`${T}/identity`, "scim_jeton_expire_refuse")),

  // ---------------------------------------------------------------- Connexion d'entreprise
  // Sans SSO ni annuaire configuré (et sans test réussi), l'imposition est refusée.
  "sso.enforce": refus("method_not_enabled", rust(`${T}/settings`, "imposer_le_sso_exige_un_test_recent"), rust(`${T}/identity`, "test_sso_reel_enregistre_par_acteur_et_garde_d_imposition")),
  "ldap.enforce": refus("method_not_enabled", rust(`${T}/identity`, "imposition_ldap_exige_un_test_de_l_acteur")),
};
