//! Interface du client de bureau (egui).

use crate::client::{validate_server_url, ApiResult, Client};
use crate::config::Config;
use crate::vault::{self, LoginOutcome, PendingLogin, Vault};
use eframe::egui::{self, Color32, RichText};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};
use locksy_core::api::{CreateItemRequest, SsoPublic, SsoRedeemResponse, SyncResponse, UpdateItemRequest};
use locksy_core::generator::{self, PassphraseOptions, PasswordOptions};
use locksy_core::model::{ItemData, ItemKind};
use locksy_core::{now_unix, strength, totp};
use zeroize::Zeroize;

const ACCENT: Color32 = Color32::from_rgb(27, 107, 95);
const ACCENT_LIGHT: Color32 = Color32::from_rgb(92, 194, 174);
const WARN: Color32 = Color32::from_rgb(214, 150, 40);
const BAD: Color32 = Color32::from_rgb(214, 72, 64);
const OK: Color32 = Color32::from_rgb(52, 168, 106);

enum Msg {
    Login(ApiResult<LoginOutcome>),
    Synced(ApiResult<SyncResponse>, Option<String>),
    Saved(ApiResult<Option<String>>, String),
    SsoTicket(Client, ApiResult<(String, SsoRedeemResponse)>),
    Downloaded(ApiResult<std::path::PathBuf>),
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

struct Editor {
    item_id: Option<String>,
    collection_id: String,
    data: ItemData,
    password: String,
    urls: String,
    tags: String,
    show_password: bool,
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
    screen: Screen,
    server: String,
    email: String,
    password: String,
    totp_code: String,
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
    last_activity: Instant,
    clipboard: Option<(Instant, String)>,
    toast: Option<(String, Instant, bool)>,
    confirm_trash: Option<String>,
    sso_info: Option<SsoPublic>,
    sso_probed_for: String,
    sso_probe: Option<Receiver<(String, (Option<SsoPublic>, Option<SsoPublic>))>>,
    ldap_info: Option<SsoPublic>,
    win_user: String,
    win_password: String,
    sso_pending: Option<(String, SsoRedeemResponse)>,
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

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        style(&cc.egui_ctx);
        let config = Config::load();
        let logo = cc.egui_ctx.load_texture(
            "logo",
            egui::ColorImage::from_rgba_unmultiplied([64, 64], crate::LOGO_64),
            egui::TextureOptions::LINEAR,
        );
        Self {
            server: config.server_url.clone(),
            email: config.last_email.clone(),
            config,
            screen: Screen::Login,
            password: String::new(),
            totp_code: String::new(),
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
            last_activity: Instant::now(),
            clipboard: None,
            toast: None,
            confirm_trash: None,
            sso_info: None,
            sso_probed_for: String::new(),
            sso_probe: None,
            ldap_info: None,
            win_user: crate::sso::current_windows_user(),
            win_password: String::new(),
            sso_pending: None,
            logo,
        }
    }

    fn notify(&mut self, msg: impl Into<String>, bad: bool) {
        self.toast = Some((msg.into(), Instant::now(), bad));
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
        let mut password = std::mem::take(&mut self.password);
        self.spawn("Dérivation de la clé et déchiffrement…", ctx, move || {
            let r = vault::login(client, &email, &password);
            password.zeroize();
            Msg::Login(r)
        });
    }

    fn submit_totp(&mut self, ctx: &egui::Context) {
        let (Some(client), Some(pending)) = (self.client.take(), self.pending.take()) else { return };
        let code = std::mem::take(&mut self.totp_code).trim().to_string();
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
                self.vault = Some(vault);
                self.screen = Screen::Unlocked;
                self.config.server_url = self.server.trim().trim_end_matches('/').to_string();
                self.config.last_email = self.email.trim().to_string();
                self.config.save();
                self.last_activity = Instant::now();
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
                if info.registered && info.kdf.is_some() {
                    self.client = Some(client);
                    self.email = info.email.clone();
                    self.sso_pending = Some((ticket, info));
                    self.error = None;
                    self.screen = Screen::SsoPassword;
                } else {
                    self.error = Some(format!(
                        "Identité confirmée ({}), mais vous n'avez pas encore de coffre : créez-le depuis l'interface web de Locksy (même connexion d'entreprise).",
                        info.email
                    ));
                }
            }
            Msg::Downloaded(Ok(path)) => {
                self.notify(format!("Enregistré : {}", path.display()), false);
            }
            Msg::Downloaded(Err(e)) => {
                self.notify(e.message, true);
            }
            Msg::SsoTicket(_, Err(e)) => {
                self.error = Some(e.message);
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

    fn lock(&mut self, reason: &str) {
        if let Some(client) = self.client.take() {
            std::thread::spawn(move || {
                let _ = client.send_empty("POST", "/auth/logout");
            });
        }
        self.vault = None; // l'effacement des données a lieu dans Drop
        self.pending = None;
        if let Some(e) = &mut self.editor {
            e.data.zeroize();
            e.password.zeroize();
        }
        self.editor = None;
        self.selected = None;
        self.revealed = false;
        self.generator.value.zeroize();
        self.screen = Screen::Login;
        self.error = Some(reason.to_string());
    }

    fn copy(&mut self, text: &str, label: &str) {
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text.to_string())) {
            Ok(()) => {
                let secs = self.config.clipboard_seconds;
                if secs > 0 {
                    self.clipboard = Some((Instant::now() + Duration::from_secs(secs), text.to_string()));
                    self.notify(format!("{label} copié · effacé dans {secs} s"), false);
                } else {
                    self.notify(format!("{label} copié"), false);
                }
            }
            Err(_) => self.notify("Presse-papiers indisponible.", true),
        }
    }

    fn housekeeping(&mut self, ctx: &egui::Context) {
        let active = ctx.input(|i| !i.events.is_empty() || i.pointer.delta() != egui::Vec2::ZERO);
        if active {
            self.last_activity = Instant::now();
        }
        if matches!(self.screen, Screen::Unlocked) && self.config.auto_lock_minutes > 0 {
            let limit = Duration::from_secs(self.config.auto_lock_minutes * 60);
            if self.last_activity.elapsed() > limit {
                self.lock("Coffre locksyillé après inactivité.");
            }
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        if let Some((when, text)) = &self.clipboard {
            if Instant::now() >= *when {
                if let Ok(mut c) = arboard::Clipboard::new() {
                    if c.get_text().map(|t| &t == text).unwrap_or(false) {
                        let _ = c.set_text(String::new());
                    }
                }
                if let Some((_, mut t)) = self.clipboard.take() {
                    t.zeroize();
                }
            } else {
                ctx.request_repaint_after(Duration::from_millis(500));
            }
        }
        if let Some((_, at, _)) = &self.toast {
            if at.elapsed() > Duration::from_secs(4) {
                self.toast = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        self.housekeeping(ctx);
        match self.screen {
            Screen::Login => self.ui_login(ctx),
            Screen::Totp => self.ui_totp(ctx),
            Screen::SsoPassword => self.ui_sso_password(ctx),
            Screen::Unlocked => self.ui_main(ctx),
        }
        self.ui_generator(ctx);
        if let Some((msg, _, bad)) = &self.toast {
            egui::Area::new(egui::Id::new("toast"))
                .anchor(egui::Align2::RIGHT_BOTTOM, [-16.0, -16.0])
                .show(ctx, |ui| {
                    egui::Frame::popup(ui.style())
                        .fill(if *bad { BAD } else { ui.visuals().extreme_bg_color })
                        .show(ui, |ui| {
                            ui.label(RichText::new(msg).color(if *bad { Color32::WHITE } else { ui.visuals().text_color() }));
                        });
                });
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.lock("");
        if let Some((_, mut t)) = self.clipboard.take() {
            if let Ok(mut c) = arboard::Clipboard::new() {
                if c.get_text().map(|x| x == t).unwrap_or(false) {
                    let _ = c.set_text(String::new());
                }
            }
            t.zeroize();
        }
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
        let (listener, url) = match crate::sso::prepare(&client) {
            Ok(x) => x,
            Err(e) => {
                self.error = Some(e.message);
                return;
            }
        };
        ctx.open_url(egui::OpenUrl::new_tab(url));
        self.spawn("Connexion dans votre navigateur…", ctx, move || {
            let r = crate::sso::wait_ticket(&client, listener);
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
        let mut password = std::mem::take(&mut self.win_password);
        self.spawn("Vérification auprès de l'annuaire…", ctx, move || {
            let r = crate::sso::windows_login(&client, &user, &password);
            password.zeroize();
            Msg::SsoTicket(client, r)
        });
    }

    fn ui_login(&mut self, ctx: &egui::Context) {
        self.probe_sso();
        let mut submit = false;
        let mut sso_click = false;
        let mut win_click = false;
        let busy = self.busy.clone();
        let sso = self.sso_info.clone();
        let ldap = self.ldap_info.clone();
        card(ctx, &self.logo.clone(), |ui| {
            ui.heading("Connexion");
            ui.label(RichText::new("Le mot de passe maître ne quitte jamais ce poste : le coffre est déchiffré ici.").weak());
            ui.add_space(8.0);
            ui.label("Serveur");
            ui.add(egui::TextEdit::singleline(&mut self.server).desired_width(f32::INFINITY).hint_text("https://coffre.entreprise.fr"));
            if let Err(e) = validate_server_url(&self.server) {
                ui.label(RichText::new(e).color(WARN).small());
            }
            if let Some(l) = &ldap {
                ui.add_space(4.0);
                ui.label(RichText::new(format!("Connexion avec votre {}", l.label.to_lowercase())).strong());
                ui.label("Identifiant Windows");
                ui.add(egui::TextEdit::singleline(&mut self.win_user).desired_width(f32::INFINITY).hint_text("DOMAINE\\identifiant"));
                ui.label("Mot de passe Windows");
                let wp = ui.add(egui::TextEdit::singleline(&mut self.win_password).password(true).desired_width(f32::INFINITY));
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
            let pw = ui.add(egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY));
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
            } else if primary(ui, "   Se connecter   ").clicked() {
                submit = true;
            }
            ui.add_space(4.0);
            ui.label(RichText::new("Mot de passe oublié ou création de compte : utilisez l'interface web du serveur.").small().weak());
        });
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
            let pw = ui.add(egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY));
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
                    if primary(ui, "Délocksyiller").clicked() {
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
            let mut password = std::mem::take(&mut self.password);
            let email = info.email.clone();
            self.spawn("Déchiffrement du coffre…", ctx, move || {
                let r = vault::login_with(client, &email, &password, &kdf, Some(ticket));
                password.zeroize();
                Msg::Login(r)
            });
        }
    }

    fn ui_totp(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        let busy = self.busy.clone();
        card(ctx, &self.logo.clone(), |ui| {
            ui.heading("Double authentification");
            ui.label("Saisissez le code à 6 chiffres affiché par votre application d'authentification.");
            let r = ui.add(egui::TextEdit::singleline(&mut self.totp_code).font(egui::TextStyle::Heading).desired_width(f32::INFINITY).char_limit(8));
            r.request_focus();
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
            self.error = None;
            self.screen = Screen::Login;
        } else if submit && self.busy.is_none() {
            self.submit_totp(ctx);
        }
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
                let hay = format!("{} {} {} {} {}", d.name, d.username, d.urls.join(" "), d.tags.join(" "), d.notes).to_lowercase();
                words.iter().all(|w| hay.contains(w))
            })
            .map(|(i, d)| Row { id: i.id.clone(), name: d.name.clone(), subtitle: d.subtitle(), favorite: d.favorite })
            .collect();
        rows.sort_by(|a, b| b.favorite.cmp(&a.favorite).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        rows
    }

    fn ui_main(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::L)) {
            self.lock("Coffre locksyillé.");
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
                    self.search.clear();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔒 Locksyiller").on_hover_text("Ctrl+L").clicked() {
                        do_lock = true;
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
            self.lock("Coffre locksyillé.");
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
        let mut new_nav = None;
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
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Locksyillage auto").small());
                    egui::ComboBox::from_id_salt("autolock")
                        .selected_text(match self.config.auto_lock_minutes { 0 => "jamais".to_string(), m => format!("{m} min") })
                        .show_ui(ui, |ui| {
                            for m in [1u64, 5, 10, 30, 60, 0] {
                                let label = if m == 0 { "jamais".to_string() } else { format!("{m} min") };
                                if ui.selectable_value(&mut self.config.auto_lock_minutes, m, label).changed() {
                                    self.config.save();
                                }
                            }
                        });
                });
            });
        });
        if let Some(n) = new_nav {
            self.nav = n;
            self.selected = None;
            self.editor = None;
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
            self.selected = Some(id);
            self.revealed = false;
            self.editor = None;
            self.confirm_trash = None;
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

    fn ui_detail(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(v) = &self.vault else { return };
        let Some(id) = self.selected.clone() else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Sélectionnez un élément pour l'afficher.").weak());
            });
            return;
        };
        let Some(item) = v.items.iter().find(|i| i.id == id) else {
            self.selected = None;
            return;
        };
        let Some(d) = item.data.clone() else { return };
        let col = v.collection(&item.collection_id);
        let writable = col.is_some_and(|c| c.writable());
        let col_label = col.map(|c| c.label().to_string()).unwrap_or_default();
        let in_trash = item.deleted_at.is_some();
        let (revision, created, updated) = (item.revision, item.created_at, item.updated_at);
        let collection_id = item.collection_id.clone();
        let reused = !d.password.is_empty()
            && v.items.iter().any(|o| o.id != id && o.deleted_at.is_none() && o.data.as_ref().is_some_and(|x| x.password == d.password));

        let copy: std::cell::RefCell<Option<(String, String)>> = std::cell::RefCell::new(None);
        let mut download: Option<locksy_core::model::Attachment> = None;
        let mut action: Option<&str> = None;

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
                            let shown = if secret && !revealed { "••••••••••••".to_string() } else { value.to_string() };
                            let mut txt = RichText::new(shown);
                            if mono || (secret && revealed) {
                                txt = txt.monospace();
                            }
                            ui.add(egui::Label::new(txt).wrap());
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("📋 Copier").clicked() {
                                *copy.borrow_mut() = Some((value.to_string(), label.to_string()));
                            }
                        });
                    });
                });
            };

            match d.kind {
                ItemKind::Login => {
                    field(ui, "Identifiant", &d.username, false, true, false);
                    if !d.password.is_empty() {
                        field(ui, "Mot de passe", &d.password, true, self.revealed, true);
                        ui.horizontal(|ui| {
                            let label = if self.revealed { "🙈 Masquer" } else { "👁 Afficher" };
                            if ui.small_button(label).clicked() {
                                self.revealed = !self.revealed;
                            }
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
                                let code = totp::code_at(&cfg, t);
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
                                        *copy.borrow_mut() = Some((u.clone(), "Adresse".into()));
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
                    field(ui, "Numéro", &d.card.number, true, self.revealed, true);
                    field(ui, "Expiration", &d.card.expiry, false, true, false);
                    field(ui, "Cryptogramme", &d.card.cvv, true, self.revealed, true);
                    field(ui, "Code PIN", &d.card.pin, true, self.revealed, true);
                    if ui.small_button(if self.revealed { "🙈 Masquer" } else { "👁 Afficher" }).clicked() {
                        self.revealed = !self.revealed;
                    }
                }
                ItemKind::Identity => {
                    let i = &d.identity;
                    field(ui, "Prénom", &i.first_name, false, true, false);
                    field(ui, "Nom", &i.last_name, false, true, false);
                    field(ui, "E-mail", &i.email, false, true, false);
                    field(ui, "Téléphone", &i.phone, false, true, false);
                    field(ui, "Adresse", &i.address, false, true, false);
                    field(ui, "Société", &i.company, false, true, false);
                    field(ui, "N° de document", &i.document_number, true, self.revealed, true);
                }
                ItemKind::Ssh => {
                    field(ui, "Clé publique", &d.ssh.public_key, false, true, true);
                    field(ui, "Clé privée", &d.ssh.private_key, true, self.revealed, true);
                    field(ui, "Phrase de passe", &d.ssh.passphrase, true, self.revealed, true);
                    if ui.small_button(if self.revealed { "🙈 Masquer" } else { "👁 Afficher" }).clicked() {
                        self.revealed = !self.revealed;
                    }
                }
                ItemKind::Note => {}
            }
            for f in &d.fields {
                let label = if f.label.is_empty() { "Champ" } else { &f.label };
                field(ui, label, &f.value, f.hidden, self.revealed, false);
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
                                if ui.button("⬇ Enregistrer").on_hover_text("Déchiffré et enregistré dans Téléchargements").clicked() {
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
                                *copy.borrow_mut() = Some((h.password.clone(), "Ancien mot de passe".into()));
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
                    if self.confirm_trash.as_deref() == Some(&id) {
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

        if let Some((value, label)) = copy.into_inner() {
            self.copy(&value, &label);
        }
        if let (Some(att), Some(client)) = (download, self.client.clone()) {
            self.spawn("Déchiffrement de la pièce jointe…", ctx, move || Msg::Downloaded(vault::save_attachment(&client, &att)));
        }
        match action {
            Some("edit") => {
                self.editor = Some(Editor {
                    item_id: Some(id.clone()),
                    collection_id,
                    password: d.password.clone(),
                    urls: d.urls.join("\n"),
                    tags: d.tags.join(", "),
                    data: d,
                    show_password: false,
                });
            }
            Some("favorite") => {
                let mut nd = d;
                nd.favorite = !nd.favorite;
                if let Some(v) = &self.vault {
                    match v.prepare_update(&id, &collection_id, &nd) {
                        Ok((path, req)) => self.send_update(ctx, path, req, "Favoris mis à jour."),
                        Err(e) => self.notify(e.message, true),
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
                ed.password = g.value;
                ed.show_password = true;
            }
        }
        if cancel {
            if let Some(mut e) = self.editor.take() {
                e.data.zeroize();
                e.password.zeroize();
            }
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
        let mut copy = None;
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
                match r {
                    Ok(x) => {
                        g.value.zeroize();
                        g.value = x.value;
                    }
                    Err(e) => g.value = e.to_string(),
                }
            }
            ui.separator();
            ui.add(egui::Label::new(RichText::new(&g.value).monospace().size(18.0)).wrap());
            let s = strength::estimate(&g.value);
            ui.label(RichText::new(format!("{} · {} bits", s.label, s.entropy_bits.round())).small().weak());
            if primary(ui, "📋 Copier").clicked() {
                copy = Some(g.value.clone());
            }
        });
        if let Some(v) = copy {
            self.copy(&v, "Mot de passe");
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
