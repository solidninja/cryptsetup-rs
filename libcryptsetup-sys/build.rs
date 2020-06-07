extern crate pkg_config;

fn main() {
    let lib = pkg_config::Config::new()
        .statik(true)
        .atleast_version("2.1.0")
        .probe("libcryptsetup")
        .unwrap();

    // flags for supported versions of cryptsetup
    if lib.version.as_str().starts_with("2.3.") {
        println!("cargo:rustc-cfg=cryptsetup2_3");
        println!("cargo:rustc-cfg=cryptsetup2_2");
    }

    if lib.version.as_str().starts_with("2.2.") {
        println!("cargo:rustc-cfg=cryptsetup2_2");
    }
}
