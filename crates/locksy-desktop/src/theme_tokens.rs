// Fichier généré par tools/gen-tokens.mjs, ne pas modifier. Source : design/tokens.json.
// Couleurs et dimensions du design system pour le client Windows (egui), cahier 00, §2.7.
#![allow(dead_code)]

use eframe::egui::Color32;

/// Palette claire.
pub mod light {
    use super::Color32;

    pub const BG: Color32 = Color32::from_rgb(244, 246, 249);
    pub const SURFACE: Color32 = Color32::from_rgb(255, 255, 255);
    pub const SUNKEN: Color32 = Color32::from_rgb(238, 242, 246);
    pub const SEL: Color32 = Color32::from_rgb(226, 241, 238);
    pub const TEXT: Color32 = Color32::from_rgb(20, 32, 51);
    pub const TEXT_MUTED: Color32 = Color32::from_rgb(79, 94, 114);
    pub const BORDER: Color32 = Color32::from_rgb(228, 232, 238);
    pub const BORDER_STRONG: Color32 = Color32::from_rgb(123, 136, 153);
    pub const ACCENT: Color32 = Color32::from_rgb(13, 107, 100);
    pub const ACCENT_HOVER: Color32 = Color32::from_rgb(10, 85, 79);
    pub const ON_ACCENT: Color32 = Color32::from_rgb(255, 255, 255);
    pub const ACCENT_SOFT: Color32 = Color32::from_rgb(217, 240, 236);
    pub const ACCENT_TEXT: Color32 = Color32::from_rgb(10, 88, 81);
    pub const OK: Color32 = Color32::from_rgb(23, 106, 66);
    pub const OK_BG: Color32 = Color32::from_rgb(227, 244, 234);
    pub const WARN: Color32 = Color32::from_rgb(138, 88, 0);
    pub const WARN_BG: Color32 = Color32::from_rgb(251, 240, 216);
    pub const DANGER: Color32 = Color32::from_rgb(179, 38, 30);
    pub const DANGER_BG: Color32 = Color32::from_rgb(251, 230, 228);
    pub const INFO: Color32 = Color32::from_rgb(31, 95, 168);
    pub const INFO_BG: Color32 = Color32::from_rgb(228, 238, 250);
    pub const FOCUS: Color32 = Color32::from_rgb(29, 95, 209);
    pub const SCRIM: Color32 = Color32::from_rgba_premultiplied(9, 14, 23, 115);
    pub const ON_TILE: Color32 = Color32::from_rgb(255, 255, 255);
    pub const QR_BG: Color32 = Color32::from_rgb(255, 255, 255);
}

/// Palette sombre.
pub mod dark {
    use super::Color32;

    pub const BG: Color32 = Color32::from_rgb(11, 16, 22);
    pub const SURFACE: Color32 = Color32::from_rgb(18, 25, 34);
    pub const SUNKEN: Color32 = Color32::from_rgb(24, 33, 44);
    pub const SEL: Color32 = Color32::from_rgb(19, 48, 44);
    pub const TEXT: Color32 = Color32::from_rgb(230, 237, 243);
    pub const TEXT_MUTED: Color32 = Color32::from_rgb(154, 167, 180);
    pub const BORDER: Color32 = Color32::from_rgb(36, 48, 64);
    pub const BORDER_STRONG: Color32 = Color32::from_rgb(102, 118, 138);
    pub const ACCENT: Color32 = Color32::from_rgb(45, 212, 191);
    pub const ACCENT_HOVER: Color32 = Color32::from_rgb(94, 234, 212);
    pub const ON_ACCENT: Color32 = Color32::from_rgb(4, 32, 28);
    pub const ACCENT_SOFT: Color32 = Color32::from_rgb(19, 48, 44);
    pub const ACCENT_TEXT: Color32 = Color32::from_rgb(94, 234, 212);
    pub const OK: Color32 = Color32::from_rgb(111, 211, 160);
    pub const OK_BG: Color32 = Color32::from_rgb(22, 52, 38);
    pub const WARN: Color32 = Color32::from_rgb(240, 192, 104);
    pub const WARN_BG: Color32 = Color32::from_rgb(58, 45, 18);
    pub const DANGER: Color32 = Color32::from_rgb(255, 155, 146);
    pub const DANGER_BG: Color32 = Color32::from_rgb(61, 28, 26);
    pub const INFO: Color32 = Color32::from_rgb(138, 184, 240);
    pub const INFO_BG: Color32 = Color32::from_rgb(20, 38, 61);
    pub const FOCUS: Color32 = Color32::from_rgb(138, 180, 255);
    pub const SCRIM: Color32 = Color32::from_rgba_premultiplied(0, 0, 0, 153);
    pub const ON_TILE: Color32 = Color32::from_rgb(255, 255, 255);
    pub const QR_BG: Color32 = Color32::from_rgb(255, 255, 255);
}

/// Palette claire en contraste renforcé.
pub mod light_more {
    use super::Color32;

    pub const BG: Color32 = Color32::from_rgb(244, 246, 249);
    pub const SURFACE: Color32 = Color32::from_rgb(255, 255, 255);
    pub const SUNKEN: Color32 = Color32::from_rgb(238, 242, 246);
    pub const SEL: Color32 = Color32::from_rgb(226, 241, 238);
    pub const TEXT: Color32 = Color32::from_rgb(20, 32, 51);
    pub const TEXT_MUTED: Color32 = Color32::from_rgb(20, 32, 51);
    pub const BORDER: Color32 = Color32::from_rgb(123, 136, 153);
    pub const BORDER_STRONG: Color32 = Color32::from_rgb(74, 85, 102);
    pub const ACCENT: Color32 = Color32::from_rgb(20, 84, 74);
    pub const ACCENT_HOVER: Color32 = Color32::from_rgb(10, 85, 79);
    pub const ON_ACCENT: Color32 = Color32::from_rgb(255, 255, 255);
    pub const ACCENT_SOFT: Color32 = Color32::from_rgb(217, 240, 236);
    pub const ACCENT_TEXT: Color32 = Color32::from_rgb(10, 88, 81);
    pub const OK: Color32 = Color32::from_rgb(23, 106, 66);
    pub const OK_BG: Color32 = Color32::from_rgb(227, 244, 234);
    pub const WARN: Color32 = Color32::from_rgb(138, 88, 0);
    pub const WARN_BG: Color32 = Color32::from_rgb(251, 240, 216);
    pub const DANGER: Color32 = Color32::from_rgb(179, 38, 30);
    pub const DANGER_BG: Color32 = Color32::from_rgb(251, 230, 228);
    pub const INFO: Color32 = Color32::from_rgb(31, 95, 168);
    pub const INFO_BG: Color32 = Color32::from_rgb(228, 238, 250);
    pub const FOCUS: Color32 = Color32::from_rgb(11, 63, 168);
    pub const SCRIM: Color32 = Color32::from_rgba_premultiplied(9, 14, 23, 115);
    pub const ON_TILE: Color32 = Color32::from_rgb(255, 255, 255);
    pub const QR_BG: Color32 = Color32::from_rgb(255, 255, 255);
}

/// Palette sombre en contraste renforcé.
pub mod dark_more {
    use super::Color32;

    pub const BG: Color32 = Color32::from_rgb(11, 16, 22);
    pub const SURFACE: Color32 = Color32::from_rgb(18, 25, 34);
    pub const SUNKEN: Color32 = Color32::from_rgb(24, 33, 44);
    pub const SEL: Color32 = Color32::from_rgb(19, 48, 44);
    pub const TEXT: Color32 = Color32::from_rgb(230, 237, 243);
    pub const TEXT_MUTED: Color32 = Color32::from_rgb(229, 235, 242);
    pub const BORDER: Color32 = Color32::from_rgb(106, 124, 145);
    pub const BORDER_STRONG: Color32 = Color32::from_rgb(154, 169, 187);
    pub const ACCENT: Color32 = Color32::from_rgb(125, 211, 193);
    pub const ACCENT_HOVER: Color32 = Color32::from_rgb(94, 234, 212);
    pub const ON_ACCENT: Color32 = Color32::from_rgb(4, 32, 28);
    pub const ACCENT_SOFT: Color32 = Color32::from_rgb(19, 48, 44);
    pub const ACCENT_TEXT: Color32 = Color32::from_rgb(94, 234, 212);
    pub const OK: Color32 = Color32::from_rgb(111, 211, 160);
    pub const OK_BG: Color32 = Color32::from_rgb(22, 52, 38);
    pub const WARN: Color32 = Color32::from_rgb(240, 192, 104);
    pub const WARN_BG: Color32 = Color32::from_rgb(58, 45, 18);
    pub const DANGER: Color32 = Color32::from_rgb(255, 155, 146);
    pub const DANGER_BG: Color32 = Color32::from_rgb(61, 28, 26);
    pub const INFO: Color32 = Color32::from_rgb(138, 184, 240);
    pub const INFO_BG: Color32 = Color32::from_rgb(20, 38, 61);
    pub const FOCUS: Color32 = Color32::from_rgb(179, 205, 255);
    pub const SCRIM: Color32 = Color32::from_rgba_premultiplied(0, 0, 0, 153);
    pub const ON_TILE: Color32 = Color32::from_rgb(255, 255, 255);
    pub const QR_BG: Color32 = Color32::from_rgb(255, 255, 255);
}

/// Couleurs des pastilles d'initiale, dans l'ordre de colorFor().
pub const TILES: [Color32; 8] = [
    Color32::from_rgb(47, 95, 167),
    Color32::from_rgb(27, 107, 95),
    Color32::from_rgb(90, 106, 31),
    Color32::from_rgb(168, 69, 42),
    Color32::from_rgb(109, 74, 168),
    Color32::from_rgb(154, 58, 106),
    Color32::from_rgb(60, 90, 120),
    Color32::from_rgb(47, 122, 58),
];

// Espacements, rayons et tailles de texte, en points.
pub const SPACE_1: f32 = 4.0;
pub const SPACE_2: f32 = 8.0;
pub const SPACE_3: f32 = 12.0;
pub const SPACE_4: f32 = 16.0;
pub const SPACE_5: f32 = 24.0;
pub const SPACE_6: f32 = 32.0;
pub const SPACE_7: f32 = 48.0;
pub const RADIUS_SM: f32 = 8.0;
pub const RADIUS_MD: f32 = 12.0;
pub const RADIUS_LG: f32 = 16.0;
pub const RADIUS_XL: f32 = 24.0;
pub const RADIUS_FULL: f32 = 999.0;
pub const TEXT_XS: f32 = 13.0;
pub const TEXT_SM: f32 = 14.0;
pub const TEXT_MD: f32 = 16.0;
pub const TEXT_LG: f32 = 18.0;
pub const TEXT_XL: f32 = 22.0;
pub const TEXT_XXL: f32 = 28.0;
pub const TEXT_SECRET: f32 = 20.0;
pub const TEXT_CODE: f32 = 24.0;
pub const CONTROL_H: f32 = 44.0;
pub const ROW_H_COMFORTABLE: f32 = 64.0;
pub const ROW_H_COMPACT: f32 = 48.0;
