//! Interface du client de bureau (egui).
//!
//! Hygiène mémoire : les mots de passe saisis, le jeton, le ticket SSO et la
//! copie du presse-papiers sont en `Zeroizing` ; le détail d'un élément est
//! affiché par référence (aucun clone des données déchiffrées à chaque image) ;
//! le verrouillage efface aussi l'état interne d'egui (contenu et historique
//! d'annulation des champs de saisie).

use crate::client::{validate_server_url, ApiResult, Client};
use crate::config::{choices, Config, Policy};
use crate::vault::{self, LoginOutcome, PendingLogin, Vault};
use eframe::egui::{self, Color32, RichText};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use locksy_core::api::{CreateItemRequest, SsoPublic, SsoRedeemResponse, SyncResponse, UpdateItemRequest};
use locksy_core::generator::{self, PassphraseOptions, PasswordOptions};
use locksy_core::model::{Attachment, ItemData, ItemKind};
use locksy_core::{now_unix, strength, totp};
use zeroize::{Zeroize, Zeroizing};

const ACCENT: Color32 = Color32::from_rgb(27, 107, 95);
const ACCENT_LIGHT: Color32 = Color32::from_rgb(92, 194, 174);
const WARN: Color32 = Color32::from_rgb(214, 150, 40);
const BAD: Color32 = Color32::from_rgb(214, 72, 64);
const OK: Color32 = Color32::from_rgb(52, 168, 106);

/// Écart d'horloge murale entre deux images, fenêtre au premier plan, au-delà
/// duquel on considère que le poste a été mis en veille ou en hibernation.
const SLEEP_GAP: Duration = Duration::from_secs(90);

const IMPOSED: &str = "imposé par votre organisation";

/// Réponse de la sonde des modes de connexion : (adresse sondée, (SSO, compte Windows)).
type SsoProbe = (String, (Option<SsoPublic>, Option<SsoPublic>));

enum Msg {
    Login(ApiResult<LoginOutcome>),
    Synced(ApiResult<SyncResponse>, Option<String>),
    Saved(ApiResult<Option<String>>, String),
    SsoTicket(Client, ApiResult<(String, SsoRedeemResponse)>),
    /// `None` : enregistrement annulé, aucun message.
    Downloaded(ApiResult<Option<PathBuf>>),
}

#[derive(PartialEq, Clone)]
enum Nav {
    All,
    Favorites,
    Collection(String),
    Trash,
}

enum Screen {
    Login,
    Totp,
    SsoPassword,
    Unlocked,
}

#[derive(Clone, Copy, PartialEq)]
enum Tone {
    Info,
    Warn,
    Bad,
}

struct Editor {
    item_id: Option<String>,
    collection_id: String,
    data: ItemData,
    password: String,
    urls: String,
    tags: String,
    show_password: bool,
}

impl Drop for Editor {
    fn drop(&mut self) {
        self.data.zeroize();
        self.password.zeroize();
        self.urls.zeroize();
    }
}

struct Generator {
    open: bool,
    passphrase: bool,
    pw: PasswordOptions,
    phrase: PassphraseOptions,
    value: String,
}

pub struct App {
    config: Config,
    policy: Policy,
    screen: Screen,
    server: String,
    email: String,
    password: Zeroizing<String>,
    totp_code: Zeroizing<String>,
    error: Option<String>,
    busy: Option<String>,
    rx: Option<Receiver<Msg>>,
    client: Option<Client>,
    vault: Option<Box<Vault>>,
    pending: Option<PendingLogin>,
    nav: Nav,
    search: String,
    selected: Option<String>,
    revealed: bool,
    editor: Option<Editor>,
    generator: Generator,
    settings_open: bool,
    last_activity: Instant,
    /// Horloge murale de l'image précédente (détection de la mise en veille).
    last_wall: SystemTime,
    was_focused: bool,
    unfocused_since: Option<Instant>,
    /// Secret copié et échéance de son effacement (`None` : jamais, sauf au verrouillage).
    clipboard: Option<(Option<Instant>, Zeroizing<String>)>,
    toast: Option<(String, Instant, Tone)>,
    confirm_trash: Option<String>,
    save_request: Option<Attachment>,
    sso_info: Option<SsoPublic>,
    sso_probed_for: String,
    sso_probe: Option<Receiver<SsoProbe>>,
    ldap_info: Option<SsoPublic>,
    win_user: String,
    win_password: Zeroizing<String>,
    sso_pending: Option<(Zeroizing<String>, SsoRedeemResponse)>,
    sso_cancel: Option<Arc<AtomicBool>>,
    /// Effacer la mémoire d'egui au début de la prochaine image.
    purge_ui: bool,
    logo: egui::TextureHandle,
}

fn style(ctx: &egui::Context) {
    ctx.all_styles_mut(|s| {
        s.text_styles.insert(egui::TextStyle::Body, egui::FontId::proportional(15.0));
        s.text_styles.insert(egui::TextStyle::Button, egui::FontId::proportional(14.5));
        s.text_styles.insert(egui::TextStyle::Heading, egui::FontId::proportional(22.0));
        s.text_styles.insert(egui::TextStyle::Monospace, egui::FontId::monospace(14.5));
        s.text_styles.insert(egui::TextStyle::Small, egui::FontId::proportional(12.5));
        s.spacing.item_spacing = egui::vec2(8.0, 8.0);
        s.spacing.button_padding = egui::vec2(12.0, 6.0);
        s.spacing.interact_size.y = 30.0;
        let accent = if s.visuals.dark_mode { ACCENT_LIGHT } else { ACCENT };
        s.visuals.selection.bg_fill = accent.gamma_multiply(0.35_f32);
        s.visuals.selection.stroke = egui::Stroke::new(1.0_f32, accent);
        s.visuals.hyperlink_color = accent;
        s.visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(6);
        s.visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(6);
        s.visuals.widgets.active.corner_radius = egui::CornerRadius::same(6);
    });
}

fn accent(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode { ACCENT_LIGHT } else { ACCENT }
}

fn primary(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let fill = accent(ui);
    let fg = if ui.visuals().dark_mode { Color32::from_rgb(11, 26, 23) } else { Color32::WHITE };
    ui.add(egui::Button::new(RichText::new(text).color(fg).strong()).fill(fill))
}

fn kind_label(k: ItemKind) -> &'static str {
    k.label()
}

/// Vide un champ secret en rendant son contenu (effacé à la libération).
fn take_secret(s: &mut Zeroizing<String>) -> Zeroizing<String> {
    std::mem::replace(s, Zeroizing::new(String::new()))
}

/// Vrai si l'horloge murale a sauté alors que la fenêtre était au premier
/// plan (elle est alors redessinée chaque seconde) : veille ou hibernation.
fn slept(gap: Duration, was_focused: bool) -> bool {
    was_focused && gap > SLEEP_GAP
}

fn fmt_minutes(m: u64) -> String {
    if m == 0 { "Jamais".into() } else { format!("{m} min") }
}

fn fmt_seconds(s: u64) -> String {
    match s {
        0 => "Jamais".into(),
        s if s >= 60 && s % 60 == 0 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

/// Liste déroulante de réglage ; renvoie la valeur choisie, le cas échéant.
fn setting_combo(ui: &mut egui::Ui, id: &str, current: u64, options: &[u64], fmt: fn(u64) -> String) -> Option<u64> {
    let mut picked = None;
    egui::ComboBox::from_id_salt(id).width(150.0).selected_text(fmt(current)).show_ui(ui, |ui| {
        for &v in options {
            if ui.selectable_label(v == current, fmt(v)).clicked() && v != current {
                picked = Some(v);
            }
        }
    });
    picked
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        style(&cc.egui_ctx);
        let config = Config::load();
        let policy = Policy::load();
        let logo = cc.egui_ctx.load_texture(
            "logo",
            egui::ColorImage::from_rgba_unmultiplied([64, 64], crate::LOGO_64),
            egui::TextureOptions::LINEAR,
        );
        Self {
            server: config.effective_server(&policy),
            email: config.last_email.clone(),
            config,
            policy,
            screen: Screen::Login,
            password: Zeroizing::new(String::new()),
            totp_code: Zeroizing::new(String::new()),
            error: None,
            busy: None,
            rx: None,
            client: None,
            vault: None,
            pending: None,
            nav: Nav::All,
            search: String::new(),
            selected: None,
            revealed: false,
            editor: None,
            generator: Generator {
                open: false,
                passphrase: false,
                pw: PasswordOptions::default(),
                phrase: PassphraseOptions::default(),
                value: String::new(),
            },
            settings_open: false,
            last_activity: Instant::now(),
            last_wall: SystemTime::now(),
            was_focused: true,
            unfocused_since: None,
            clipboard: None,
            toast: None,
            confirm_trash: None,
            save_request: None,
            sso_info: None,
            sso_probed_for: String::new(),
            sso_probe: None,
            ldap_info: None,
            win_user: crate::sso::current_windows_user(),
            win_password: Zeroizing::new(String::new()),
            sso_pending: None,
            sso_cancel: None,
            purge_ui: false,
            logo,
        }
    }

    fn notify(&mut self, msg: impl Into<String>, bad: bool) {
        self.toast = Some((msg.into(), Instant::now(), if bad { Tone::Bad } else { Tone::Info }));
    }

    fn warn(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now(), Tone::Warn));
    }

    fn spawn(&mut self, label: &str, ctx: &egui::Context, job: impl FnOnce() -> Msg + Send + 'static) {
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(job());
            ctx.request_repaint();
        });
        self.rx = Some(rx);
        self.busy = Some(label.to_string());
    }

    // ------------------------------------------------------------ Tâches

    fn start_login(&mut self, ctx: &egui::Context) {
        self.error = None;
        let client = match Client::new(&self.server) {
            Ok(c) => c,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        if self.email.trim().is_empty() || self.password.is_empty() {
            self.error = Some("Saisissez votre adresse e-mail et votre mot de passe maître.".into());
            return;
        }
        let email = self.email.trim().to_string();
        let pin = self.config.kdf_pin(&email);
        let password = take_secret(&mut self.password);
        self.spawn("Dérivation de la clé et déchiffrement…", ctx, move || Msg::Login(vault::login(client, &email, &password, pin)));
    }

    fn submit_totp(&mut self, ctx: &egui::Context) {
        let (Some(client), Some(pending)) = (self.client.take(), self.pending.take()) else { return };
        let code = take_secret(&mut self.totp_code).trim().to_string();
        self.spawn("Vérification du code…", ctx, move || Msg::Login(vault::finish_login(client, pending, Some(code))));
    }

    fn start_sync(&mut self, ctx: &egui::Context, notice: Option<String>) {
        let Some(client) = self.client.clone() else { return };
        self.spawn("Synchronisation…", ctx, move || Msg::Synced(Vault::fetch(&client), notice));
    }

    fn send_create(&mut self, ctx: &egui::Context, req: CreateItemRequest) {
        let Some(client) = self.client.clone() else { return };
        self.spawn("Enregistrement…", ctx, move || {
            let id = req.id.clone();
            Msg::Saved(client.send::<_, serde_json::Value>("POST", "/items", &req).map(|_| Some(id)), "Élément enregistré.".into())
        });
    }

    fn send_update(&mut self, ctx: &egui::Context, path: String, req: UpdateItemRequest, notice: &str) {
        let Some(client) = self.client.clone() else { return };
        let notice = notice.to_string();
        self.spawn("Enregistrement…", ctx, move || Msg::Saved(client.send::<_, i64>("PUT", &path, &req).map(|_| None), notice));
    }

    fn send_simple(&mut self, ctx: &egui::Context, method: &'static str, path: String, notice: &str) {
        let Some(client) = self.client.clone() else { return };
        let notice = notice.to_string();
        self.spawn("Enregistrement…", ctx, move || Msg::Saved(client.send_empty(method, &path).map(|_| None), notice));
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.rx else { return };
        let Ok(msg) = rx.try_recv() else { return };
        self.rx = None;
        self.busy = None;
        match msg {
            Msg::Login(Ok(LoginOutcome::Done(client, vault))) => {
                self.client = Some(client);
                if self.policy.server_url.is_none() {
                    self.config.server_url = self.server.trim().trim_end_matches('/').to_string();
                }
                self.config.last_email = self.email.trim().to_string();
                self.config.update_kdf_pin(&self.email, vault.kdf);
                self.config.save(&self.policy);
                self.vault = Some(vault);
                self.screen = Screen::Unlocked;
                self.error = None;
                self.last_activity = Instant::now();
                self.last_wall = SystemTime::now();
                self.unfocused_since = None;
                self.nav = Nav::All;
                self.selected = None;
            }
            Msg::Login(Ok(LoginOutcome::NeedTotp(client, pending, err))) => {
                self.client = Some(client);
                self.pending = Some(pending);
                self.screen = Screen::Totp;
                self.error = err;
            }
            Msg::SsoTicket(client, Ok((ticket, info))) => {
                self.sso_cancel = None;
                if info.registered && info.kdf.is_some() {
                    self.client = Some(client);
                    self.email = info.email.clone();
                    self.sso_pending = Some((Zeroizing::new(ticket), info));
                    self.error = None;
                    self.screen = Screen::SsoPassword;
                } else {
                    self.error = Some(format!(
                        "Identité confirmée ({}), mais vous n'avez pas encore de coffre : créez-le depuis l'interface web de Locksy (même connexion d'entreprise).",
                        info.email
                    ));
                }
            }
            Msg::SsoTicket(_, Err(e)) => {
                self.sso_cancel = None;
                // Annulation par l'utilisateur : aucun message.
                self.error = if e.code == "cancelled" { None } else { Some(e.message) };
            }
            Msg::Downloaded(Ok(Some(path))) => {
                if vault::is_onedrive(&path) {
                    self.warn(format!(
                        "Enregistré : {}\nCe dossier est synchronisé avec OneDrive : le fichier déchiffré y sera copié.",
                        path.display()
                    ));
                } else {
                    self.notify(format!("Enregistré : {}", path.display()), false);
                }
            }
            Msg::Downloaded(Ok(None)) => {}
            Msg::Downloaded(Err(e)) => {
                if e.status == 401 {
                    self.lock("Session expirée. Reconnectez-vous.");
                } else {
                    self.notify(e.message, true);
                }
            }
            Msg::Login(Err(e)) => {
                self.screen = Screen::Login;
                self.error = Some(e.message);
            }
            Msg::Synced(Ok(data), notice) => {
                if let Some(v) = &mut self.vault {
                    v.apply_sync(data);
                }
                if let Some(n) = notice {
                    self.notify(n, false);
                }
            }
            Msg::Synced(Err(e), _) | Msg::Saved(Err(e), _) => {
                if e.status == 401 {
                    self.lock("Session expirée. Reconnectez-vous.");
                } else {
                    self.notify(e.message, true);
                }
            }
            Msg::Saved(Ok(new_id), notice) => {
                if let Some(id) = new_id {
                    self.selected = Some(id);
                }
                self.editor = None;
                self.start_sync(ctx, Some(notice));
            }
        }
    }

    /// Verrouille : efface les clés, les données déchiffrées, les saisies,
    /// le presse-papiers (s'il contient encore notre secret) et l'état d'egui.
    fn lock(&mut self, reason: &str) {
        if let Some(client) = self.client.take() {
            std::thread::spawn(move || {
                let _ = client.send_empty("POST", "/auth/logout");
            });
        }
        self.vault = None; // l'effacement des données a lieu dans Drop
        self.pending = None;
        self.editor = None; // idem (Drop d'Editor)
        self.selected = None;
        self.revealed = false;
        self.confirm_trash = None;
        self.save_request = None;
        self.generator.value.zeroize();
        self.generator.open = false;
        self.settings_open = false;
        self.search.zeroize();
        self.password.zeroize();
        self.totp_code.zeroize();
        self.win_password.zeroize();
        self.sso_pending = None;
        if let Some(c) = self.sso_cancel.take() {
            c.store(true, Ordering::Relaxed);
        }
        // Un résultat encore en route (synchronisation…) est abandonné.
        self.rx = None;
        self.busy = None;
        self.clear_clipboard();
        self.unfocused_since = None;
        self.purge_ui = true;
        self.screen = Screen::Login;
        self.error = if reason.is_empty() { None } else { Some(reason.to_string()) };
    }

    fn clear_clipboard(&mut self) {
        if let Some((_, text)) = self.clipboard.take() {
            crate::clip::clear_if(&text);
        }
    }

    fn copy(&mut self, text: &str, label: &str) {
        match crate::clip::set_secret(text) {
            Ok(()) => {
                let secs = self.config.effective_clipboard(&self.policy);
                let when = (secs > 0).then(|| Instant::now() + Duration::from_secs(secs));
                self.clipboard = Some((when, Zeroizing::new(text.to_string())));
                if secs > 0 {
                    self.notify(format!("{label} copié · effacé dans {}", fmt_seconds(secs)), false);
                } else {
                    self.notify(format!("{label} copié · effacé au verrouillage"), false);
                }
            }
            Err(_) => self.notify("Presse-papiers indisponible.", true),
        }
    }

    fn housekeeping(&mut self, ctx: &egui::Context) {
        let (active, focused) = ctx.input(|i| (!i.events.is_empty() || i.pointer.delta() != egui::Vec2::ZERO, i.viewport().focused));
        if active {
            self.last_activity = Instant::now();
        }
        let now_wall = SystemTime::now();
        let gap = now_wall.duration_since(self.last_wall).unwrap_or_default();
        if matches!(self.screen, Screen::Unlocked) {
            let auto = self.config.effective_auto_lock(&self.policy);
            let focus_lock = self.config.effective_focus_lock(&self.policy);
            if focused == Some(false) {
                if self.unfocused_since.is_none() {
                    self.unfocused_since = Some(Instant::now());
                }
            } else {
                self.unfocused_since = None;
            }
            if slept(gap, self.was_focused) {
                self.lock("Coffre verrouillé après la mise en veille.");
            } else if auto > 0 && self.last_activity.elapsed() > Duration::from_secs(auto * 60) {
                self.lock("Coffre verrouillé après inactivité.");
            } else if focus_lock > 0 && self.unfocused_since.is_some_and(|t| t.elapsed() > Duration::from_secs(focus_lock * 60)) {
                // Le verrouillage de session Windows (Win+L) retire le focus : il
                // est couvert ici. WTSRegisterSessionNotification exigerait du
                // code unsafe (interdit dans ce crate) pour un gain minime.
                self.lock("Coffre verrouillé : Locksy est resté en arrière-plan.");
            }
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        self.last_wall = now_wall;
        self.was_focused = focused != Some(false);
        match self.clipboard.as_ref().and_then(|(when, _)| *when) {
            Some(w) if Instant::now() >= w => self.clear_clipboard(),
            Some(_) => ctx.request_repaint_after(Duration::from_millis(500)),
            None => {}
        }
        if let Some((_, at, tone)) = &self.toast {
            let keep = if *tone == Tone::Info { 4 } else { 8 };
            if at.elapsed() > Duration::from_secs(keep) {
                self.toast = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }
    }

    /// Demande l'emplacement puis déchiffre la pièce jointe en arrière-plan.
    fn save_attachment(&mut self, ctx: &egui::Context, frame: &eframe::Frame, att: Attachment) {
        let Some(client) = self.client.clone() else { return };
        let picked = pick_save_path(frame, &att.name);
        // Le dialogue est modal : le temps passé dedans n'est ni de la veille
        // ni de l'inactivité.
        self.last_wall = SystemTime::now();
        self.last_activity = Instant::now();
        let path = match picked {
            Ok(Some(p)) => p,
            Ok(None) => return, // annulé : aucun message
            Err(e) => {
                self.notify(e, true);
                return;
            }
        };
        self.spawn("Déchiffrement de la pièce jointe…", ctx, move || {
            Msg::Downloaded(vault::save_attachment_to(&client, &att, &path).map(|()| Some(path)))
        });
    }
}

/// Dialogue « Enregistrer sous » de Windows, ouvert depuis le fil d'interface
/// et rattaché à la fenêtre de Locksy ; dossier Documents par défaut.
#[cfg(windows)]
fn pick_save_path(frame: &eframe::Frame, name: &str) -> Result<Option<PathBuf>, String> {
    let mut dialog = rfd::FileDialog::new()
        .set_title("Enregistrer la pièce jointe déchiffrée")
        .set_file_name(vault::sanitize_file_name(name))
        .set_parent(frame);
    if let Some(dir) = dirs::document_dir() {
        dialog = dialog.set_directory(dir);
    }
    Ok(dialog.save_file())
}

/// Hors Windows (tests, développement) : dossier Téléchargements, sans dialogue.
#[cfg(not(windows))]
fn pick_save_path(_frame: &eframe::Frame, name: &str) -> Result<Option<PathBuf>, String> {
    vault::default_download_path(name).map(Some).map_err(|e| e.message)
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if self.purge_ui {
            // Contenu et historique d'annulation des champs de saisie, états
            // des panneaux : rien ne doit survivre au verrouillage.
            ctx.memory_mut(|m| m.data.clear());
            self.purge_ui = false;
        }
        self.poll(ctx);
        self.housekeeping(ctx);
        match self.screen {
            Screen::Login => self.ui_login(ctx),
            Screen::Totp => self.ui_totp(ctx),
            Screen::SsoPassword => self.ui_sso_password(ctx),
            Screen::Unlocked => self.ui_main(ctx),
        }
        self.ui_generator(ctx);
        self.ui_settings(ctx);
        if let Some((msg, _, tone)) = &self.toast {
            egui::Area::new(egui::Id::new("toast"))
                .anchor(egui::Align2::RIGHT_BOTTOM, [-16.0, -16.0])
                .show(ctx, |ui| {
                    let (fill, fg) = match tone {
                        Tone::Info => (ui.visuals().extreme_bg_color, ui.visuals().text_color()),
                        Tone::Warn => (WARN, Color32::BLACK),
                        Tone::Bad => (BAD, Color32::WHITE),
                    };
                    egui::Frame::popup(ui.style()).fill(fill).show(ui, |ui| {
                        ui.set_max_width(460.0);
                        ui.label(RichText::new(msg).color(fg));
                    });
                });
        }
        if let Some(att) = self.save_request.take() {
            if matches!(self.screen, Screen::Unlocked) {
                self.save_attachment(ctx, frame, att);
            }
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Le verrouillage vide aussi le presse-papiers s'il contient notre secret.
        self.lock("");
    }
}

// ================================================================ Écrans d'accès

fn card(ctx: &egui::Context, logo: &egui::TextureHandle, add: impl FnOnce(&mut egui::Ui)) {
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space((ui.available_height() * 0.12).max(20.0));
            egui::Frame::group(ui.style())
                .inner_margin(egui::Margin::same(28))
                .corner_radius(egui::CornerRadius::same(12))
                .show(ui, |ui| {
                    ui.set_width(380.0);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.add(egui::Image::new((logo.id(), egui::vec2(30.0, 30.0))));
                            ui.label(RichText::new("Locksy").size(20.0).strong());
                        });
                        ui.add_space(6.0);
                        add(ui);
                    });
                });
        });
    });
}

impl App {
    fn probe_sso(&mut self) {
        if let Some(rx) = &self.sso_probe {
            if let Ok((url, (sso, ldap))) = rx.try_recv() {
                if url == self.server {
                    self.sso_info = sso;
                    self.ldap_info = ldap;
                }
                self.sso_probe = None;
            }
        }
        if self.sso_probe.is_none() && self.sso_probed_for != self.server {
            self.sso_probed_for = self.server.clone();
            self.sso_info = None;
            self.ldap_info = None;
            if let Ok(client) = Client::new(&self.server) {
                let (tx, rx) = channel();
                let url = self.server.clone();
                std::thread::spawn(move || {
                    let _ = tx.send((url, crate::sso::login_options(&client)));
                });
                self.sso_probe = Some(rx);
            }
        }
    }

    fn start_sso(&mut self, ctx: &egui::Context) {
        self.error = None;
        let client = match Client::new(&self.server) {
            Ok(c) => c,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        let start = match crate::sso::prepare(&client) {
            Ok(x) => x,
            Err(e) => {
                self.error = Some(e.message);
                return;
            }
        };
        let cancel = Arc::new(AtomicBool::new(false));
        self.sso_cancel = Some(cancel.clone());
        ctx.open_url(egui::OpenUrl::new_tab(&start.url));
        let crate::sso::SsoStart { listener, state, .. } = start;
        self.spawn("Connexion dans votre navigateur…", ctx, move || {
            let r = crate::sso::wait_ticket(&client, listener, &state, &cancel);
            Msg::SsoTicket(client, r)
        });
    }

    fn start_windows_login(&mut self, ctx: &egui::Context) {
        self.error = None;
        let client = match Client::new(&self.server) {
            Ok(c) => c,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        if self.win_user.trim().is_empty() || self.win_password.is_empty() {
            self.error = Some("Saisissez votre identifiant et votre mot de passe Windows.".into());
            return;
        }
        let user = self.win_user.trim().to_string();
        let password = take_secret(&mut self.win_password);
        self.spawn("Vérification auprès de l'annuaire…", ctx, move || {
            let r = crate::sso::windows_login(&client, &user, &password);
            Msg::SsoTicket(client, r)
        });
    }

    fn ui_login(&mut self, ctx: &egui::Context) {
        self.probe_sso();
        let mut submit = false;
        let mut sso_click = false;
        let mut win_click = false;
        let mut cancel_sso = false;
        let busy = self.busy.clone();
        let sso_waiting = busy.is_some() && self.sso_cancel.is_some();
        let sso = self.sso_info.clone();
        let ldap = self.ldap_info.clone();
        let imposed_server = self.policy.server_url.clone();
        card(ctx, &self.logo.clone(), |ui| {
            ui.heading("Connexion");
            ui.label(RichText::new("Le mot de passe maître ne quitte jamais ce poste : le coffre est déchiffré ici.").weak());
            ui.add_space(8.0);
            ui.label("Serveur");
            if let Some(url) = &imposed_server {
                ui.label(RichText::new(url).monospace());
                ui.label(RichText::new(format!("Adresse {IMPOSED}.")).small().weak());
            } else {
                ui.add(egui::TextEdit::singleline(&mut self.server).desired_width(f32::INFINITY).hint_text("https://coffre.entreprise.fr"));
                if let Err(e) = validate_server_url(&self.server) {
                    ui.label(RichText::new(e).color(WARN).small());
                }
            }
            if let Some(l) = &ldap {
                ui.add_space(4.0);
                ui.label(RichText::new(format!("Connexion avec votre {}", l.label.to_lowercase())).strong());
                ui.label("Identifiant Windows");
                ui.add(egui::TextEdit::singleline(&mut self.win_user).desired_width(f32::INFINITY).hint_text("DOMAINE\\identifiant"));
                ui.label("Mot de passe Windows");
                let wp = ui.add(egui::TextEdit::singleline(&mut *self.win_password).password(true).desired_width(f32::INFINITY));
                if self.win_password.is_empty() && busy.is_none() && !wp.has_focus() && self.error.is_none() {
                    wp.request_focus();
                }
                if wp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    win_click = true;
                }
                if busy.is_none() && primary(ui, "🛡  Se connecter").clicked() {
                    win_click = true;
                }
                ui.label(RichText::new("Votre mot de passe maître sera ensuite demandé pour déchiffrer le coffre.").small().weak());
                ui.separator();
                if l.enforced {
                    ui.label(RichText::new("Accès de secours (propriétaires) :").small().weak());
                }
            }
            if let Some(s) = &sso {
                ui.add_space(4.0);
                let label = format!("🛡  Se connecter avec {}", s.label);
                let clicked = if s.enforced { primary(ui, &label).clicked() } else { ui.button(label).clicked() };
                if clicked && busy.is_none() {
                    sso_click = true;
                }
                if s.enforced {
                    ui.label(RichText::new("Votre organisation impose cette connexion (sauf accès de secours des propriétaires).").small().weak());
                }
                ui.separator();
            }
            ui.label("Adresse e-mail");
            let email = ui.add(egui::TextEdit::singleline(&mut self.email).desired_width(f32::INFINITY));
            ui.label("Mot de passe maître");
            let pw = ui.add(egui::TextEdit::singleline(&mut *self.password).password(true).desired_width(f32::INFINITY));
            if ldap.is_some() {
                // Le formulaire Windows a la priorité.
            } else if self.email.is_empty() {
                email.request_focus();
            } else if self.password.is_empty() && !pw.has_focus() && !email.has_focus() && busy.is_none() {
                pw.request_focus();
            }
            if pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                submit = true;
            }
            if let Some(err) = &self.error {
                ui.label(RichText::new(err).color(BAD));
            }
            ui.add_space(6.0);
            if let Some(b) = &busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(b);
                });
                if sso_waiting {
                    ui.label(RichText::new("Terminez la connexion dans le navigateur qui vient de s'ouvrir.").small().weak());
                    if ui.button("Annuler la connexion SSO").clicked() {
                        cancel_sso = true;
                    }
                }
            } else if primary(ui, "   Se connecter   ").clicked() {
                submit = true;
            }
            ui.add_space(4.0);
            ui.label(RichText::new("Mot de passe oublié ou création de compte : utilisez l'interface web du serveur.").small().weak());
        });
        if cancel_sso {
            if let Some(c) = &self.sso_cancel {
                c.store(true, Ordering::Relaxed);
            }
        }
        if submit && self.busy.is_none() {
            self.start_login(ctx);
        }
        if sso_click {
            self.start_sso(ctx);
        }
        if win_click && self.busy.is_none() {
            self.start_windows_login(ctx);
        }
    }

    fn ui_sso_password(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        let busy = self.busy.clone();
        let who = self.sso_pending.as_ref().map(|(_, i)| if i.name.is_empty() { i.email.clone() } else { i.name.clone() }).unwrap_or_default();
        let email = self.email.clone();
        card(ctx, &self.logo.clone(), |ui| {
            ui.heading(format!("Bonjour {who}"));
            ui.label(RichText::new(format!("Identité confirmée par votre entreprise : {email}")).color(OK));
            ui.label("Saisissez votre mot de passe maître : lui seul déchiffre votre coffre, l'entreprise ne le connaît pas.");
            let pw = ui.add(egui::TextEdit::singleline(&mut *self.password).password(true).desired_width(f32::INFINITY));
            if busy.is_none() && !pw.has_focus() {
                pw.request_focus();
            }
            if pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                submit = true;
            }
            if let Some(err) = &self.error {
                ui.label(RichText::new(err).color(BAD));
            }
            if let Some(b) = &busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(b);
                });
            } else {
                ui.horizontal(|ui| {
                    if primary(ui, "Déverrouiller").clicked() {
                        submit = true;
                    }
                    if ui.button("Annuler").clicked() {
                        cancel = true;
                    }
                });
            }
        });
        if cancel {
            self.sso_pending = None;
            self.client = None;
            self.password.zeroize();
            self.error = None;
            self.screen = Screen::Login;
        } else if submit && self.busy.is_none() && !self.password.is_empty() {
            let (Some(client), Some((ticket, info))) = (self.client.take(), self.sso_pending.take()) else { return };
            let Some(kdf) = info.kdf.clone() else { return };
            let password = take_secret(&mut self.password);
            let email = info.email.clone();
            let pin = self.config.kdf_pin(&email);
            self.spawn("Déchiffrement du coffre…", ctx, move || {
                Msg::Login(vault::login_with(client, &email, &password, &kdf, Some(ticket.to_string()), pin))
            });
        }
    }

    fn ui_totp(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        let busy = self.busy.clone();
        let via_sso = self.pending.as_ref().is_some_and(|p| p.via_sso());
        card(ctx, &self.logo.clone(), |ui| {
            ui.heading("Double authentification");
            if via_sso {
                ui.label(RichText::new("Identité d'entreprise confirmée ; saisissez le code dans les 5 minutes, sinon recommencez la connexion d'entreprise.").color(OK));
            }
            ui.label("Saisissez le code à 6 chiffres affiché par votre application d'authentification, ou l'un de vos codes de secours (XXXXX-XXXXX).");
            // 16 caractères : un code de secours (10 caractères et un tiret) tapé avec des espaces.
            let r = ui.add(egui::TextEdit::singleline(&mut *self.totp_code).font(egui::TextStyle::Heading).desired_width(f32::INFINITY).char_limit(16));
            if busy.is_none() {
                r.request_focus();
            }
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                submit = true;
            }
            if let Some(err) = &self.error {
                ui.label(RichText::new(err).color(BAD));
            }
            if let Some(b) = &busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(b);
                });
            } else {
                ui.horizontal(|ui| {
                    if primary(ui, "Valider").clicked() {
                        submit = true;
                    }
                    if ui.button("Annuler").clicked() {
                        cancel = true;
                    }
                });
            }
        });
        if cancel {
            self.pending = None;
            self.client = None;
            self.totp_code.zeroize();
            self.error = None;
            self.screen = Screen::Login;
        } else if submit && self.busy.is_none() {
            self.submit_totp(ctx);
        }
    }

    // ------------------------------------------------------------ Réglages

    fn ui_settings(&mut self, ctx: &egui::Context) {
        if !self.settings_open {
            return;
        }
        let mut open = true;
        let mut changed = false;
        let p = self.policy.clone();
        egui::Window::new("Réglages").open(&mut open).resizable(false).collapsible(false).default_width(460.0).show(ctx, |ui| {
            let note = |ui: &mut egui::Ui, text: String| {
                ui.label("");
                ui.label(RichText::new(text).small().weak());
                ui.end_row();
            };
            egui::Grid::new("settings").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                ui.label("Verrouillage automatique");
                let cur = self.config.effective_auto_lock(&p);
                if let Some(v) = setting_combo(ui, "set-autolock", cur, &choices(&[1, 5, 10, 30, 60, 0], p.max_auto_lock_minutes), fmt_minutes) {
                    self.config.auto_lock_minutes = v;
                    changed = true;
                }
                ui.end_row();
                match p.max_auto_lock_minutes {
                    Some(m) => note(ui, format!("Après {} d'inactivité au plus : {IMPOSED}.", fmt_minutes(m))),
                    None => note(ui, "Après cette durée sans activité dans Locksy.".into()),
                }

                ui.label("Effacement du presse-papiers");
                let cur = self.config.effective_clipboard(&p);
                if let Some(v) = setting_combo(ui, "set-clip", cur, &choices(&[15, 30, 60, 120, 0], p.clipboard_seconds), fmt_seconds) {
                    self.config.clipboard_seconds = v;
                    changed = true;
                }
                ui.end_row();
                match p.clipboard_seconds {
                    Some(s) => note(ui, format!("{} au plus : {IMPOSED}.", fmt_seconds(s))),
                    None => note(ui, "Le presse-papiers est aussi vidé au verrouillage et à la fermeture.".into()),
                }

                ui.label("Verrouillage en arrière-plan");
                match p.lock_on_focus_loss_minutes {
                    Some(0) => {
                        ui.label(RichText::new("Désactivé").weak());
                        ui.end_row();
                        note(ui, format!("Désactivé : {IMPOSED}."));
                    }
                    max => {
                        let cur = self.config.effective_focus_lock(&p);
                        if let Some(v) = setting_combo(ui, "set-focus", cur, &choices(&[1, 5, 15, 0], max), fmt_minutes) {
                            self.config.lock_on_focus_loss_minutes = v;
                            changed = true;
                        }
                        ui.end_row();
                        match max {
                            Some(m) => note(ui, format!("{} au plus : {IMPOSED}.", fmt_minutes(m))),
                            None => note(ui, "Quand Locksy n'est plus au premier plan (autre fenêtre, session Windows verrouillée).".into()),
                        }
                    }
                }
            });
            ui.separator();
            ui.label(
                RichText::new("Les secrets copiés sont exclus de l'historique du presse-papiers (Win+V) et de sa synchronisation cloud. Le coffre se verrouille aussi après une mise en veille.")
                    .small()
                    .weak(),
            );
        });
        if changed {
            self.config.save(&self.policy);
            // Un délai raccourci s'applique aussi au secret déjà copié.
            let secs = self.config.effective_clipboard(&self.policy);
            if let Some((when, _)) = &mut self.clipboard {
                if secs > 0 {
                    let limit = Instant::now() + Duration::from_secs(secs);
                    if when.is_none_or(|w| w > limit) {
                        *when = Some(limit);
                    }
                }
            }
        }
        self.settings_open = open;
    }
}

// ================================================================ Coffre

struct Row {
    id: String,
    name: String,
    subtitle: String,
    favorite: bool,
}

impl App {
    fn rows(&self) -> Vec<Row> {
        let Some(v) = &self.vault else { return vec![] };
        let q = self.search.to_lowercase();
        let words: Vec<&str> = q.split_whitespace().collect();
        let mut rows: Vec<Row> = v
            .items
            .iter()
            .filter_map(|i| i.data.as_ref().map(|d| (i, d)))
            .filter(|(i, d)| match &self.nav {
                Nav::All => i.deleted_at.is_none(),
                Nav::Favorites => i.deleted_at.is_none() && d.favorite,
                Nav::Collection(c) => i.deleted_at.is_none() && &i.collection_id == c,
                Nav::Trash => i.deleted_at.is_some(),
            })
            .filter(|(_, d)| {
                if words.is_empty() {
                    return true;
                }
                let hay = Zeroizing::new(format!("{} {} {} {} {}", d.name, d.username, d.urls.join(" "), d.tags.join(" "), d.notes).to_lowercase());
                words.iter().all(|w| hay.contains(w))
            })
            .map(|(i, d)| Row { id: i.id.clone(), name: d.name.clone(), subtitle: d.subtitle(), favorite: d.favorite })
            .collect();
        rows.sort_by(|a, b| b.favorite.cmp(&a.favorite).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        rows
    }

    /// Copie des données d'un élément, uniquement quand une action en a besoin.
    fn item_data(&self, id: &str) -> Option<ItemData> {
        self.vault.as_ref()?.items.iter().find(|i| i.id == id)?.data.clone()
    }

    fn ui_main(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::L)) {
            self.lock("Coffre verrouillé.");
            return;
        }
        let mut do_sync = false;
        let mut do_lock = false;

        egui::TopBottomPanel::top("top").frame(egui::Frame::side_top_panel(&ctx.style()).inner_margin(egui::Margin::symmetric(12, 8))).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::Image::new((self.logo.id(), egui::vec2(24.0, 24.0))));
                ui.label(RichText::new("Locksy").size(18.0).strong().color(accent(ui)));
                ui.add_space(16.0);
                ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("🔎 Rechercher (nom, identifiant, site, étiquette)…").desired_width(380.0));
                if !self.search.is_empty() && ui.small_button("✕").clicked() {
                    self.search.zeroize();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔒 Verrouiller").on_hover_text("Ctrl+L").clicked() {
                        do_lock = true;
                    }
                    if ui.button("⚙ Réglages").clicked() {
                        self.settings_open = true;
                    }
                    if ui.button("🎲 Générateur").clicked() {
                        self.generator.open = true;
                    }
                    if ui.add_enabled(self.busy.is_none(), egui::Button::new("⟳ Synchroniser")).clicked() {
                        do_sync = true;
                    }
                    if let Some(b) = &self.busy {
                        ui.spinner();
                        ui.label(RichText::new(b).weak());
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            if let Some(v) = &self.vault {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{} · {}", v.profile.name, v.profile.email)).small().weak());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let base = self.client.as_ref().map(|c| c.base().to_string()).unwrap_or_default();
                        ui.label(RichText::new(format!("Chiffrement local XChaCha20-Poly1305 · {base}")).small().weak());
                    });
                });
            }
        });

        self.ui_nav(ctx);
        self.ui_list(ctx);
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.editor.is_some() {
                self.ui_editor(ui, ctx);
            } else {
                self.ui_detail(ui, ctx);
            }
        });

        if do_sync {
            self.start_sync(ctx, Some("Coffre synchronisé.".into()));
        }
        if do_lock {
            self.lock("Coffre verrouillé.");
        }
    }

    fn ui_nav(&mut self, ctx: &egui::Context) {
        let Some(v) = &self.vault else { return };
        let live = |f: &dyn Fn(&vault::Item) -> bool| v.items.iter().filter(|i| i.data.is_some() && i.deleted_at.is_none() && f(i)).count();
        let entries: Vec<(Nav, String)> = {
            let mut e = vec![
                (Nav::All, format!("🗂  Tous les éléments  ({})", live(&|_| true))),
                (Nav::Favorites, format!("⭐  Favoris  ({})", live(&|i| i.data.as_ref().is_some_and(|d| d.favorite)))),
            ];
            for c in &v.collections {
                let icon = if c.personal { "🔒" } else { "👥" };
                e.push((Nav::Collection(c.id.clone()), format!("{icon}  {}  ({})", c.label(), live(&|i| i.collection_id == c.id))));
            }
            let trash = v.items.iter().filter(|i| i.deleted_at.is_some()).count();
            e.push((Nav::Trash, format!("🗑  Corbeille  ({trash})")));
            e
        };
        let summary = format!(
            "Verrouillage : {} · presse-papiers : {}",
            fmt_minutes(self.config.effective_auto_lock(&self.policy)).to_lowercase(),
            fmt_seconds(self.config.effective_clipboard(&self.policy)).to_lowercase()
        );
        let mut new_nav = None;
        let mut open_settings = false;
        egui::SidePanel::left("nav").resizable(false).exact_width(230.0).show(ctx, |ui| {
            ui.add_space(8.0);
            ui.label(RichText::new("COFFRES").small().strong().weak());
            for (nav, label) in entries {
                if ui.add_sized([ui.available_width(), 30.0], egui::SelectableLabel::new(self.nav == nav, label)).clicked() {
                    new_nav = Some(nav);
                }
            }
            ui.add_space(12.0);
            ui.separator();
            ui.label(RichText::new("Les coffres partagés, les membres, l'administration et le journal d'audit se gèrent dans l'interface web.").small().weak());
            if let Some(c) = &self.client {
                ui.hyperlink_to("Ouvrir l'interface web", c.base());
            }
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.add_space(6.0);
                ui.label(RichText::new(&summary).small().weak());
                if ui.button("⚙  Réglages").clicked() {
                    open_settings = true;
                }
            });
        });
        if open_settings {
            self.settings_open = true;
        }
        if let Some(n) = new_nav {
            if n != self.nav {
                self.nav = n;
                self.selected = None;
                self.revealed = false;
                self.confirm_trash = None;
                self.editor = None; // Drop efface les données de l'éditeur
            }
        }
    }

    fn ui_list(&mut self, ctx: &egui::Context) {
        let rows = self.rows();
        let writable_target = self.default_collection();
        let mut new_kind: Option<ItemKind> = None;
        let mut pick = None;
        egui::SidePanel::left("list").resizable(true).default_width(320.0).width_range(240.0..=520.0).show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let title = match &self.nav {
                    Nav::All => "Tous les éléments".to_string(),
                    Nav::Favorites => "Favoris".to_string(),
                    Nav::Trash => "Corbeille".to_string(),
                    Nav::Collection(id) => self.vault.as_ref().and_then(|v| v.collection(id)).map(|c| c.label().to_string()).unwrap_or_default(),
                };
                ui.heading(title);
                if self.nav != Nav::Trash && writable_target.is_some() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.menu_button("＋ Ajouter", |ui| {
                            for k in ItemKind::ALL {
                                if ui.button(kind_label(k)).clicked() {
                                    new_kind = Some(k);
                                    ui.close_menu();
                                }
                            }
                        });
                    });
                }
            });
            ui.label(RichText::new(format!("{} élément(s)", rows.len())).small().weak());
            ui.separator();
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                if rows.is_empty() {
                    ui.add_space(30.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new(if self.search.is_empty() { "Aucun élément ici." } else { "Aucun résultat." }).weak());
                    });
                }
                for r in &rows {
                    let selected = self.selected.as_deref() == Some(&r.id);
                    let text = RichText::new(format!("{}{}", if r.favorite { "⭐ " } else { "" }, if r.name.is_empty() { "(sans nom)" } else { &r.name })).strong();
                    let resp = ui.add_sized([ui.available_width(), 22.0], egui::SelectableLabel::new(selected, text));
                    ui.label(RichText::new(&r.subtitle).small().weak());
                    ui.add_space(2.0);
                    if resp.clicked() {
                        pick = Some(r.id.clone());
                    }
                }
            });
        });
        if let Some(id) = pick {
            if self.selected.as_deref() != Some(id.as_str()) {
                self.selected = Some(id);
                self.revealed = false;
                self.editor = None; // Drop efface les données de l'éditeur
                self.confirm_trash = None;
            }
        }
        if let (Some(k), Some(cid)) = (new_kind, writable_target) {
            let data = ItemData { kind: k, ..Default::default() };
            self.editor = Some(Editor { item_id: None, collection_id: cid, data, password: String::new(), urls: String::new(), tags: String::new(), show_password: false });
        }
    }

    fn default_collection(&self) -> Option<String> {
        let v = self.vault.as_ref()?;
        if let Nav::Collection(id) = &self.nav {
            if v.collection(id).is_some_and(|c| c.writable()) {
                return Some(id.clone());
            }
        }
        v.collections.iter().find(|c| c.writable()).map(|c| c.id.clone())
    }

    /// Détail d'un élément, rendu par référence : les données déchiffrées ne
    /// sont jamais copiées pour l'affichage. Les actions sont collectées puis
    /// appliquées après la fin de l'emprunt du coffre.
    fn ui_detail(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(id) = self.selected.clone() else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Sélectionnez un élément pour l'afficher.").weak());
            });
            return;
        };
        let Some(v) = self.vault.as_deref() else { return };
        let Some(item) = v.items.iter().find(|i| i.id == id) else {
            self.selected = None;
            return;
        };
        let Some(d) = item.data.as_ref() else { return };
        let col = v.collection(&item.collection_id);
        let writable = col.is_some_and(|c| c.writable());
        let col_label = col.map(|c| c.label().to_string()).unwrap_or_default();
        let in_trash = item.deleted_at.is_some();
        let (revision, created, updated) = (item.revision, item.created_at, item.updated_at);
        let collection_id = item.collection_id.clone();
        let reused = !d.password.is_empty()
            && v.items.iter().any(|o| o.id != id && o.deleted_at.is_none() && o.data.as_ref().is_some_and(|x| x.password == d.password));
        let revealed = self.revealed;
        let confirming = self.confirm_trash.as_deref() == Some(id.as_str());

        let copy: std::cell::RefCell<Option<(Zeroizing<String>, String)>> = std::cell::RefCell::new(None);
        let mut download: Option<Attachment> = None;
        let mut action: Option<&str> = None;
        let mut toggle_reveal = false;

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(8.0);
            ui.heading(if d.name.is_empty() { "(sans nom)" } else { &d.name });
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{} · {}", kind_label(d.kind), col_label)).weak());
                if !writable {
                    ui.label(RichText::new("Lecture seule").small().color(WARN));
                }
                for t in &d.tags {
                    ui.label(RichText::new(format!("#{t}")).small().color(accent(ui)));
                }
            });
            if d.expires_at > 0 && d.expires_at < now_unix() {
                ui.label(RichText::new("⚠ Ce mot de passe a dépassé sa date de renouvellement.").color(WARN));
            }
            ui.add_space(8.0);

            let field = |ui: &mut egui::Ui, label: &str, value: &str, secret: bool, revealed: bool, mono: bool| {
                if value.is_empty() {
                    return;
                }
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new(label).small().strong().weak());
                            let mut txt = if secret && !revealed { RichText::new("••••••••••••") } else { RichText::new(value) };
                            if mono || (secret && revealed) {
                                txt = txt.monospace();
                            }
                            ui.add(egui::Label::new(txt).wrap());
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("📋 Copier").clicked() {
                                *copy.borrow_mut() = Some((Zeroizing::new(value.to_string()), label.to_string()));
                            }
                        });
                    });
                });
            };
            let reveal_button = |ui: &mut egui::Ui, toggle: &mut bool| {
                if ui.small_button(if revealed { "🙈 Masquer" } else { "👁 Afficher" }).clicked() {
                    *toggle = true;
                }
            };

            match d.kind {
                ItemKind::Login => {
                    field(ui, "Identifiant", &d.username, false, true, false);
                    if !d.password.is_empty() {
                        field(ui, "Mot de passe", &d.password, true, revealed, true);
                        ui.horizontal(|ui| {
                            reveal_button(ui, &mut toggle_reveal);
                            let s = strength::estimate(&d.password);
                            let color = match s.score { 4 => OK, 3 => accent(ui), 2 => WARN, _ => BAD };
                            ui.label(RichText::new(format!("{} · {} bits", s.label, s.entropy_bits.round())).small().color(color));
                            if reused {
                                ui.label(RichText::new("Réutilisé ailleurs").small().color(WARN));
                            }
                        });
                    }
                    if !d.totp.is_empty() {
                        match totp::parse(&d.totp) {
                            Ok(cfg) => {
                                let t = now_unix() as u64;
                                let code = Zeroizing::new(totp::code_at(&cfg, t));
                                let left = totp::seconds_remaining(&cfg, t);
                                egui::Frame::group(ui.style()).show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.vertical(|ui| {
                                            ui.label(RichText::new("Code de double authentification").small().strong().weak());
                                            let half = code.len() / 2;
                                            ui.label(RichText::new(format!("{} {}", &code[..half], &code[half..])).monospace().size(22.0).color(accent(ui)));
                                            ui.add(egui::ProgressBar::new(left as f32 / cfg.period as f32).desired_width(160.0).text(format!("{left} s")));
                                        });
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if ui.button("📋 Copier").clicked() {
                                                *copy.borrow_mut() = Some((code.clone(), "Code".into()));
                                            }
                                        });
                                    });
                                });
                                ctx.request_repaint_after(Duration::from_millis(500));
                            }
                            Err(e) => {
                                ui.label(RichText::new(format!("Secret TOTP invalide : {e}")).color(BAD));
                            }
                        }
                    }
                    for u in &d.urls {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(RichText::new("Site").small().strong().weak());
                                    ui.label(u);
                                });
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button("📋 Copier").clicked() {
                                        *copy.borrow_mut() = Some((Zeroizing::new(u.clone()), "Adresse".into()));
                                    }
                                    let lower = u.to_lowercase();
                                    if (lower.starts_with("https://") || lower.starts_with("http://")) && ui.button("↗ Ouvrir").clicked() {
                                        ctx.open_url(egui::OpenUrl::new_tab(u));
                                    }
                                });
                            });
                        });
                    }
                }
                ItemKind::Card => {
                    field(ui, "Titulaire", &d.card.holder, false, true, false);
                    field(ui, "Numéro", &d.card.number, true, revealed, true);
                    field(ui, "Expiration", &d.card.expiry, false, true, false);
                    field(ui, "Cryptogramme", &d.card.cvv, true, revealed, true);
                    field(ui, "Code PIN", &d.card.pin, true, revealed, true);
                    reveal_button(ui, &mut toggle_reveal);
                }
                ItemKind::Identity => {
                    let i = &d.identity;
                    field(ui, "Prénom", &i.first_name, false, true, false);
                    field(ui, "Nom", &i.last_name, false, true, false);
                    field(ui, "E-mail", &i.email, false, true, false);
                    field(ui, "Téléphone", &i.phone, false, true, false);
                    field(ui, "Adresse", &i.address, false, true, false);
                    field(ui, "Société", &i.company, false, true, false);
                    field(ui, "N° de document", &i.document_number, true, revealed, true);
                    if !i.document_number.is_empty() {
                        reveal_button(ui, &mut toggle_reveal);
                    }
                }
                ItemKind::Ssh => {
                    field(ui, "Clé publique", &d.ssh.public_key, false, true, true);
                    field(ui, "Clé privée", &d.ssh.private_key, true, revealed, true);
                    field(ui, "Phrase de passe", &d.ssh.passphrase, true, revealed, true);
                    reveal_button(ui, &mut toggle_reveal);
                }
                ItemKind::Note => {}
            }
            for f in &d.fields {
                let label = if f.label.is_empty() { "Champ" } else { &f.label };
                field(ui, label, &f.value, f.hidden, revealed, false);
            }
            field(ui, "Notes", &d.notes, false, true, false);

            if !d.attachments.is_empty() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!("Pièces jointes ({})", d.attachments.len())).small().strong().weak());
                    for a in &d.attachments {
                        ui.horizontal(|ui| {
                            let size = if a.size < 1024 * 1024 { format!("{} Ko", a.size.div_ceil(1024)) } else { format!("{:.1} Mo", a.size as f64 / 1_048_576.0) };
                            ui.label(format!("📎 {}", a.name));
                            ui.label(RichText::new(size).small().weak());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("⬇ Enregistrer sous…").on_hover_text("Enregistrer sous…").clicked() {
                                    download = Some(a.clone());
                                }
                            });
                        });
                    }
                });
            }
            if !d.password_history.is_empty() {
                egui::CollapsingHeader::new(format!("Historique des mots de passe ({})", d.password_history.len())).show(ui, |ui| {
                    for h in &d.password_history {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format_date(h.changed_at)).small().weak());
                            if ui.small_button("📋").on_hover_text("Copier cet ancien mot de passe").clicked() {
                                *copy.borrow_mut() = Some((Zeroizing::new(h.password.clone()), "Ancien mot de passe".into()));
                            }
                        });
                    }
                });
            }

            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                if in_trash {
                    if writable && ui.button("↩ Restaurer").clicked() {
                        action = Some("restore");
                    }
                } else if writable {
                    if primary(ui, "✏ Modifier").clicked() {
                        action = Some("edit");
                    }
                    if ui.button(if d.favorite { "☆ Retirer des favoris" } else { "⭐ Favori" }).clicked() {
                        action = Some("favorite");
                    }
                    if confirming {
                        ui.label(RichText::new("Mettre à la corbeille ?").color(BAD));
                        if ui.button("Oui").clicked() {
                            action = Some("trash");
                        }
                        if ui.button("Non").clicked() {
                            action = Some("cancel_trash");
                        }
                    } else if ui.button("🗑 Corbeille").clicked() {
                        action = Some("ask_trash");
                    }
                }
            });
            ui.add_space(6.0);
            ui.label(RichText::new(format!("Créé le {} · modifié le {} · révision {revision}", format_date(created), format_date(updated))).small().weak());
        });

        // Fin de l'emprunt du coffre : on applique les actions.
        if toggle_reveal {
            self.revealed = !self.revealed;
        }
        if let Some((value, label)) = copy.into_inner() {
            self.copy(&value, &label);
        }
        if download.is_some() {
            self.save_request = download;
        }
        match action {
            Some("edit") => {
                if let Some(data) = self.item_data(&id) {
                    self.editor = Some(Editor {
                        item_id: Some(id.clone()),
                        collection_id,
                        password: data.password.clone(),
                        urls: data.urls.join("\n"),
                        tags: data.tags.join(", "),
                        data,
                        show_password: false,
                    });
                }
            }
            Some("favorite") => {
                if let Some(mut nd) = self.item_data(&id) {
                    nd.favorite = !nd.favorite;
                    let prepared = self.vault.as_ref().map(|v| v.prepare_update(&id, &collection_id, &nd));
                    nd.zeroize();
                    match prepared {
                        Some(Ok((path, req))) => self.send_update(ctx, path, req, "Favoris mis à jour."),
                        Some(Err(e)) => self.notify(e.message, true),
                        None => {}
                    }
                }
            }
            Some("ask_trash") => self.confirm_trash = Some(id),
            Some("cancel_trash") => self.confirm_trash = None,
            Some("trash") => {
                self.confirm_trash = None;
                self.selected = None;
                self.send_simple(ctx, "DELETE", format!("/items/{id}"), "Élément placé dans la corbeille.");
            }
            Some("restore") => self.send_simple(ctx, "POST", format!("/items/{id}/restore"), "Élément restauré."),
            _ => {}
        }
    }

    fn ui_editor(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let collections: Vec<(String, String)> = self
            .vault
            .as_ref()
            .map(|v| v.collections.iter().filter(|c| c.writable()).map(|c| (c.id.clone(), c.label().to_string())).collect())
            .unwrap_or_default();
        let Some(ed) = &mut self.editor else { return };
        let mut save = false;
        let mut cancel = false;
        let mut gen = false;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(8.0);
            ui.heading(if ed.item_id.is_some() { "Modifier l'élément" } else { "Nouvel élément" });
            ui.add_space(6.0);
            egui::Grid::new("editor").num_columns(2).spacing([14.0, 10.0]).min_col_width(130.0).show(ui, |ui| {
                ui.label("Type");
                ui.label(RichText::new(kind_label(ed.data.kind)).strong());
                ui.end_row();
                ui.label("Coffre");
                let current = collections.iter().find(|(id, _)| *id == ed.collection_id).map(|(_, n)| n.clone()).unwrap_or_default();
                egui::ComboBox::from_id_salt("col").selected_text(current).show_ui(ui, |ui| {
                    for (id, name) in &collections {
                        ui.selectable_value(&mut ed.collection_id, id.clone(), name);
                    }
                });
                ui.end_row();
                let wide = |ui: &mut egui::Ui, s: &mut String| {
                    ui.add(egui::TextEdit::singleline(s).desired_width(f32::INFINITY));
                };
                ui.label("Nom *");
                wide(ui, &mut ed.data.name);
                ui.end_row();
                match ed.data.kind {
                    ItemKind::Login => {
                        ui.label("Identifiant");
                        wide(ui, &mut ed.data.username);
                        ui.end_row();
                        ui.label("Mot de passe");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut ed.password).password(!ed.show_password).font(egui::TextStyle::Monospace).desired_width(ui.available_width() - 190.0));
                            if ui.small_button(if ed.show_password { "🙈" } else { "👁" }).clicked() {
                                ed.show_password = !ed.show_password;
                            }
                            if ui.button("🎲 Générer").clicked() {
                                gen = true;
                            }
                        });
                        ui.end_row();
                        if !ed.password.is_empty() {
                            let s = strength::estimate(&ed.password);
                            let color = match s.score { 4 => OK, 3 => ACCENT_LIGHT, 2 => WARN, _ => BAD };
                            ui.label("");
                            ui.label(RichText::new(format!("{} · {} bits", s.label, s.entropy_bits.round())).small().color(color));
                            ui.end_row();
                        }
                        ui.label("Sites (un par ligne)");
                        ui.add(egui::TextEdit::multiline(&mut ed.urls).desired_rows(2).desired_width(f32::INFINITY));
                        ui.end_row();
                        ui.label("Clé TOTP");
                        ui.add(egui::TextEdit::singleline(&mut ed.data.totp).hint_text("Secret base32 ou otpauth://").font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                        ui.end_row();
                    }
                    ItemKind::Card => {
                        for (label, val) in [("Titulaire", &mut ed.data.card.holder), ("Numéro", &mut ed.data.card.number), ("Expiration", &mut ed.data.card.expiry), ("Cryptogramme", &mut ed.data.card.cvv), ("Code PIN", &mut ed.data.card.pin)] {
                            ui.label(label);
                            wide(ui, val);
                            ui.end_row();
                        }
                    }
                    ItemKind::Identity => {
                        let i = &mut ed.data.identity;
                        for (label, val) in [("Prénom", &mut i.first_name), ("Nom", &mut i.last_name), ("E-mail", &mut i.email), ("Téléphone", &mut i.phone), ("Adresse", &mut i.address), ("Société", &mut i.company), ("N° de document", &mut i.document_number)] {
                            ui.label(label);
                            wide(ui, val);
                            ui.end_row();
                        }
                    }
                    ItemKind::Ssh => {
                        ui.label("Clé publique");
                        ui.add(egui::TextEdit::multiline(&mut ed.data.ssh.public_key).desired_rows(2).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                        ui.end_row();
                        ui.label("Clé privée");
                        ui.add(egui::TextEdit::multiline(&mut ed.data.ssh.private_key).desired_rows(6).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                        ui.end_row();
                        ui.label("Phrase de passe");
                        ui.add(egui::TextEdit::singleline(&mut ed.data.ssh.passphrase).password(true).desired_width(f32::INFINITY));
                        ui.end_row();
                    }
                    ItemKind::Note => {}
                }
                ui.label("Notes");
                ui.add(egui::TextEdit::multiline(&mut ed.data.notes).desired_rows(4).desired_width(f32::INFINITY));
                ui.end_row();
                ui.label("Étiquettes");
                ui.add(egui::TextEdit::singleline(&mut ed.tags).hint_text("séparées par des virgules").desired_width(f32::INFINITY));
                ui.end_row();
                ui.label("");
                ui.checkbox(&mut ed.data.favorite, "Afficher dans les favoris");
                ui.end_row();
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if primary(ui, "💾 Enregistrer").clicked() {
                    save = true;
                }
                if ui.button("Annuler").clicked() {
                    cancel = true;
                }
            });
        });

        if gen {
            if let Ok(g) = generator::generate_password(&self.generator.pw) {
                ed.password.zeroize();
                ed.password = g.value;
                ed.show_password = true;
            }
        }
        if cancel {
            self.editor = None; // Drop efface les données de l'éditeur
            return;
        }
        if save {
            if ed.data.name.trim().is_empty() {
                self.notify("Le nom est obligatoire.", true);
                return;
            }
            if !ed.data.totp.trim().is_empty() {
                if let Err(e) = totp::parse(&ed.data.totp) {
                    self.notify(e.to_string(), true);
                    return;
                }
            }
            let mut data = ed.data.clone();
            data.name = data.name.trim().to_string();
            data.urls = ed.urls.lines().map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
            data.tags = ed.tags.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
            data.totp = data.totp.trim().to_string();
            if data.kind == ItemKind::Login {
                data.set_password(ed.password.clone(), now_unix());
            }
            let collection_id = ed.collection_id.clone();
            let item_id = ed.item_id.clone();
            let Some(v) = &self.vault else { return };
            match item_id {
                None => match v.prepare_create(&collection_id, &data) {
                    Ok(req) => self.send_create(ctx, req),
                    Err(e) => self.notify(e.message, true),
                },
                Some(id) => match v.prepare_update(&id, &collection_id, &data) {
                    Ok((path, req)) => self.send_update(ctx, path, req, "Modifications enregistrées."),
                    Err(e) => self.notify(e.message, true),
                },
            }
            data.zeroize();
        }
    }

    fn ui_generator(&mut self, ctx: &egui::Context) {
        if !self.generator.open {
            return;
        }
        let mut open = true;
        let mut copy: Option<Zeroizing<String>> = None;
        egui::Window::new("Générateur").open(&mut open).resizable(false).default_width(440.0).show(ctx, |ui| {
            let g = &mut self.generator;
            let before = (g.passphrase, g.pw.clone().length, g.phrase.words);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut g.passphrase, false, "Mot de passe");
                ui.selectable_value(&mut g.passphrase, true, "Phrase de passe");
            });
            let mut changed = false;
            if g.passphrase {
                changed |= ui.add(egui::Slider::new(&mut g.phrase.words, 3..=12).text("mots")).changed();
                changed |= ui.checkbox(&mut g.phrase.capitalize, "Majuscule à chaque mot").changed();
                changed |= ui.checkbox(&mut g.phrase.include_number, "Ajouter un nombre").changed();
            } else {
                changed |= ui.add(egui::Slider::new(&mut g.pw.length, 8..=128).text("caractères")).changed();
                changed |= ui.checkbox(&mut g.pw.lower, "Minuscules").changed();
                changed |= ui.checkbox(&mut g.pw.upper, "Majuscules").changed();
                changed |= ui.checkbox(&mut g.pw.digits, "Chiffres").changed();
                changed |= ui.checkbox(&mut g.pw.symbols, "Symboles").changed();
                changed |= ui.checkbox(&mut g.pw.avoid_ambiguous, "Éviter les caractères ambigus").changed();
            }
            let regenerate = ui.button("⟳ Régénérer").clicked();
            if changed || regenerate || g.value.is_empty() || before != (g.passphrase, g.pw.length, g.phrase.words) {
                let r = if g.passphrase { generator::generate_passphrase(&g.phrase) } else { generator::generate_password(&g.pw) };
                g.value.zeroize();
                g.value = match r {
                    Ok(x) => x.value,
                    Err(e) => e.to_string(),
                };
            }
            ui.separator();
            ui.add(egui::Label::new(RichText::new(&g.value).monospace().size(18.0)).wrap());
            let s = strength::estimate(&g.value);
            ui.label(RichText::new(format!("{} · {} bits", s.label, s.entropy_bits.round())).small().weak());
            if primary(ui, "📋 Copier").clicked() {
                copy = Some(Zeroizing::new(g.value.clone()));
            }
        });
        if let Some(v) = copy {
            self.copy(&v, "Mot de passe");
        }
        if !open {
            self.generator.value.zeroize();
        }
        self.generator.open = open;
    }
}

fn format_date(ts: i64) -> String {
    if ts <= 0 {
        return "—".into();
    }
    let days = ts.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{d:02}/{m:02}/{y}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_detection_needs_a_focused_window() {
        assert!(slept(Duration::from_secs(91), true));
        assert!(!slept(Duration::from_secs(91), false), "fenêtre réduite : pas d'image, pas de faux positif");
        assert!(!slept(Duration::from_secs(5), true));
    }

    #[test]
    fn durations_are_readable() {
        assert_eq!(fmt_minutes(0), "Jamais");
        assert_eq!(fmt_minutes(15), "15 min");
        assert_eq!(fmt_seconds(30), "30 s");
        assert_eq!(fmt_seconds(120), "2 min");
        assert_eq!(fmt_seconds(90), "90 s");
    }

    #[test]
    fn secrets_are_taken_not_copied() {
        let mut field = Zeroizing::new(String::from("mot de passe maître"));
        let taken = take_secret(&mut field);
        assert!(field.is_empty());
        assert_eq!(taken.as_str(), "mot de passe maître");
    }
}
