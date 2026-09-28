// Windows-only link settings for the Network Monitor's packet capture.
//
// pnet links against Npcap's Packet.dll. Npcap is a separate driver install
// that most machines (including Microsoft Store certification test PCs) don't
// have, and a normal import makes Windows refuse to start the whole app with a
// "Packet.dll was not found" error dialog before any of our code runs.
//
// Delay-loading defers that DLL until the first packet-capture call, and
// packet_monitor::capture_backend_available() checks for it before that call
// ever happens, so the app starts everywhere and only Network Monitor needs
// Npcap.
fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:Packet.dll");
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
