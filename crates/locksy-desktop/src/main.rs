//! Locksy : client de bureau Windows.
//!
//! Se connecte au serveur Locksy, déchiffre le coffre localement avec le même
//! noyau Rust que le serveur et l'interface web, et ne conserve rien de
//! secret sur le disque (seuls l'adresse du serveur et l'e-mail sont mémorisés).

#![windows_subsystem = "windows"]
#![forbid(unsafe_code)]

mod app;
mod client;
mod config;
mod sso;
mod vault;

use eframe::egui;
use std::sync::Arc;

/// Logo officiel (branding/locksy.svg), en pixels RGBA 256 × 256.
pub const LOGO_256: &[u8] = include_bytes!("../../../branding/locksy-256.rgba");
pub const LOGO_64: &[u8] = include_bytes!("../../../branding/locksy-64.rgba");

fn icon() -> egui::IconData {
    egui::IconData { rgba: LOGO_256.to_vec(), width: 256, height: 256 }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Locksy")
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([820.0, 520.0])
            .with_icon(Arc::new(icon())),
        ..Default::default()
    };
    eframe::run_native("Locksy", options, Box::new(|cc| Ok(Box::new(app::App::new(cc)))))
}
