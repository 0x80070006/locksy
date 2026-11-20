//! Presse-papiers des secrets.
//!
//! Sous Windows, un secret copié est exclu de l'historique (Win+V) et de la
//! synchronisation cloud du presse-papiers : il n'existe qu'en un exemplaire,
//! que Locksy efface au délai prévu, au verrouillage et à la fermeture.
//! `exclude_from_monitoring` n'est pas ajouté : la documentation d'arboard
//! déconseille de le combiner avec les deux exclusions ci-dessus.

use zeroize::Zeroizing;

/// Place un secret dans le presse-papiers.
pub fn set_secret(text: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use arboard::SetExtWindows;
        clipboard.set().exclude_from_history().exclude_from_cloud().text(text).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        clipboard.set_text(text).map_err(|e| e.to_string())
    }
}

/// Vide le presse-papiers seulement s'il contient encore `expected` : on
/// n'efface jamais ce que l'utilisateur a copié depuis, ailleurs.
pub fn clear_if(expected: &str) {
    if expected.is_empty() {
        return;
    }
    let Ok(mut clipboard) = arboard::Clipboard::new() else { return };
    let Ok(current) = clipboard.get_text() else { return };
    let current = Zeroizing::new(current);
    if *current == expected {
        let _ = clipboard.clear();
    }
}
