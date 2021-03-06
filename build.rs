use std::env;

use std::ffi::{OsStr, OsString};
use std::os as os_imp;
use std::path::Path;

use cc::Build;

fn main() {
    println!("xxxxxxxxxxxxxxx");
    build_net_devices();
    build_pcap_wrapper();
    link_pcap();
}

fn is_dir(d: &OsStr) -> bool {
    let path = Path::new(d);

    path.is_dir()
}

fn link(lib: &str, static_flag_var: &str) {
    let link_static_lib = flag_from_var(static_flag_var);

    if link_static_lib.unwrap_or(false) {
        println!("cargo:rustc-link-lib=static={}", lib);
    } else {
        println!("cargo:rustc-link-lib={}", lib);
    }
}

fn emit_lib_path(path: &OsStr) {
    let path = path.to_str().expect("lib path is not UTF-8 encoded");

    println!("cargo:rustc-link-search=native={}", path);
}

fn flag_from_var(flag_var: &str) -> Option<bool> {
    env::var_os(flag_var).map(|v| &v.to_string_lossy() != "0")
}

// fn flag_from_str(flag_str: &str) -> Option<bool> {
//     let flag_dir = OsStr::new(flag_str);
//     env::var_os(flag_dir).map(|v| &v.to_string_lossy() != "0")
// }

fn dir_from_var(var: &str) -> Option<OsString> {
    if let Some(dir) = env::var_os(var) {
        if is_dir(&dir) {
            return Some(dir);
        }
    }

    None
}

fn dir_from_str(str: &str) -> Option<OsString> {
    let dir = OsStr::new(str);
    if let Some(dir) = env::var_os(dir) {
        if is_dir(&dir) {
            println!("Is dirrrrrrrrrrrrrrrrrrrr");
            return Some(dir);
        }
    }

    None
}

fn get_platform() -> &'static str {
    match "" {
        _ if cfg!(target_os = "linux") => "linux",
        _ if cfg!(target_os = "windows") => "windows",
        _ if cfg!(target_os = "macos") => "macos",
        _ => panic!("Unsupported OS"),
    }

    // "windows"
}

fn build_net_devices() {
    Build::new()
        .include("src")
        .include("src/net/raw/devices")
        .file("src/net/raw/devices/devices-common.c")
        .file(&format!("src/net/raw/devices/devices-{}.c", get_platform()))
        .compile("net_devices");
}

fn build_pcap_wrapper() {
    let mut wrapper_builder = Build::new();

    if cfg!(target_os = "windows") {
        // on Windows, we primarily try to find the lib using vcpkg
        let lib = vcpkg::Config::new()
            .cargo_metadata(false)
            .emit_includes(false)
            .copy_dlls(false)
            .find_package("winpcap");

        if let Ok(lib) = lib {
            for include in lib.include_paths {
                wrapper_builder.include(include);
            }
        } else if let Some(dir) = dir_from_str("C:/Program Files (x86)/WinPcap") {
            // if vcpkg cannot find the lib, we try the env. variable
            wrapper_builder.include(dir);
        }
    } else if let Some(dir) = dir_from_var("LIBPCAP_INCLUDE_DIR") {
        // on other platforms, we expect the lib will be in standard paths or the paths will be
        // defined using env. variables
        wrapper_builder.include(dir);
    }

    wrapper_builder
        .include("src")
        .include("src/net/raw/pcap")
        .file("src/net/raw/pcap/wrapper-common.c")
        .file(&format!("src/net/raw/pcap/wrapper-{}.c", get_platform()))
        .compile("pcap_wrapper");
}

fn link_pcap() {
    if cfg!(target_os = "windows") {
        // on Windows, we primarily try to find the lib using vcpkg
        let lib = vcpkg::Config::new()
            .cargo_metadata(true)
            .emit_includes(false)
            .copy_dlls(false)
            .find_package("winpcap");

        // if vcpkg cannot find the lib, we try the env. variables
        if lib.is_err() {
            if let Some(dir) = dir_from_str("C:/Program Files (x86)/WinPcap") {
                emit_lib_path(&dir);
            }

            link("winpcap", "WINPCAP_STATIC");
        }
    } else {
        // on other platforms, we expect the lib will be in standard paths or the paths will be
        // defined using env. variables
        if let Some(dir) = dir_from_var("LIBPCAP_LIB_DIR") {
            emit_lib_path(&dir);
        }

        link("pcap", "LIBPCAP_STATIC");
    }
}
