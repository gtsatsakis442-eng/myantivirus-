//! Build script: embed a Windows icon + version metadata into `talos.exe`.
//! No-op on non-Windows builds (the resource compiler only exists on Windows).

fn main() {
    #[cfg(windows)]
    embed_windows_resources();
}

#[cfg(windows)]
fn embed_windows_resources() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let icon = format!("{manifest_dir}/../../assets/talos.ico");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let mut res = winresource::WindowsResource::new();
    res.set_icon(&icon)
        .set("ProductName", "Talos EPP")
        .set("FileDescription", "Talos EPP — endpoint protection (CLI)")
        .set("CompanyName", "Talos EPP")
        .set("LegalCopyright", "Talos EPP")
        .set("OriginalFilename", "talos.exe")
        .set("InternalName", "talos")
        .set("ProductVersion", &version)
        .set("FileVersion", &version);
    if let Err(e) = res.compile() {
        println!("cargo:warning=winresource (talos.exe): {e}");
    }
}
