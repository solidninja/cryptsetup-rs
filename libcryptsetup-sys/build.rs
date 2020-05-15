extern crate pkg_config;

fn main() {
    pkg_config::Config::new()
        .statik(true)
        .atleast_version("2.0.0")
        .probe("libcryptsetup")
        .unwrap();
}
