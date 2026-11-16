//! Icône et informations de version de locksy.exe (ressource Windows).
fn main() {
    println!("cargo:rerun-if-changed=../../branding/locksy.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    if !cfg!(windows) {
        // Compilation croisée depuis Linux avec MinGW.
        res.set_windres_path("x86_64-w64-mingw32-windres");
        res.set_ar_path("x86_64-w64-mingw32-ar");
    }
    res.set_icon("../../branding/locksy.ico")
        .set("ProductName", "Locksy")
        .set("FileDescription", "Locksy - gestionnaire de mots de passe")
        .set("CompanyName", "Locksy")
        .set("LegalCopyright", "Licence MIT");
    res.compile().expect("ressource Windows (icône) : windres introuvable ?");
}
