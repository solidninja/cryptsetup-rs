#![deny(warnings)]
#![allow(unused)]

extern crate cryptsetup_rs;
extern crate env_logger;
extern crate expectest;
extern crate log;
extern crate serde_json;
extern crate tempfile;
extern crate uuid;

use std::process::Command;

use expectest::prelude::*;
use tempfile::{Builder, TempDir};
use uuid::Uuid;

use cryptsetup_rs::device::{luks2_token_status, TokenHandlerResult};
use cryptsetup_rs::*;
use libcryptsetup_sys::crypt_device;

struct TestContext {
    dir: TempDir,
    name: String,
}

impl TestContext {
    fn new(name: String) -> TestContext {
        let _ = env_logger::builder().is_test(true).try_init();
        cryptsetup_rs::enable_debug(true);
        let dir = Builder::new().prefix(&name).tempdir().expect("Tempdir!");
        TestContext { name, dir }
    }

    fn new_crypt_device(&self) -> api::CryptDeviceFormatBuilder {
        let crypt_file = self.dir.path().join(format!("{}.image", self.name));
        let dd_status = Command::new("dd")
            .arg("if=/dev/zero")
            .arg(format!("of={}", crypt_file.display()))
            .arg("bs=1M")
            .arg("count=10")
            .status()
            .unwrap();
        if !dd_status.success() {
            panic!("Failed to create disk image at {}", crypt_file.display());
        }

        cryptsetup_rs::format(crypt_file).unwrap()
    }
}

#[test]
fn test_create_new_luks1_cryptdevice_no_errors() {
    let ctx = TestContext::new("new_luks1_cryptdevice".to_string());
    let uuid = Uuid::new_v4();

    let device_format = ctx
        .new_crypt_device()
        .rng_type(crypt_rng_type::CRYPT_RNG_URANDOM)
        .iteration_time(42);

    let mut dev = device_format
        .luks1("aes", "xts-plain", "sha256", 256, Some(&uuid))
        .expect("LUKS format should succeed");

    dev.dump();

    expect!(dev.uuid()).to(be_equal_to(uuid));
    expect!(dev.device_type()).to(be_equal_to(crypt_device_type::LUKS1));
    expect!(dev.cipher()).to(be_equal_to("aes"));
    expect!(dev.cipher_mode()).to(be_equal_to("xts-plain"));
    expect!(dev.volume_key_size()).to(be_equal_to(32));

    expect!(dev.add_keyslot(b"hello world", None, Some(3))).to(be_ok().value(3));
}

#[test]
fn test_create_new_luks2_cryptdevice_no_errors() {
    let ctx = TestContext::new("new_luks1_cryptdevice".to_string());

    let dev = ctx
        .new_crypt_device()
        .luks2("aes", "xts-plain", 256, None, None, None)
        .label("test")
        .argon2i("sha256", 200, 1, 1024, 1)
        .start()
        .expect("LUKS2 format should succeed");

    dev.dump();

    expect!(dev.device_type()).to(be_equal_to(crypt_device_type::LUKS2));

    // TODO: add more assertions
}

enum CustomTokenHandler {}

impl Luks2TokenHandler for CustomTokenHandler {
    fn name() -> &'static str {
        "my_custom"
    }

    fn open(cd: *mut crypt_device, _token_id: i32) -> (Vec<u8>, TokenHandlerResult) {
        (vec![0xca, 0xfe, 0xba, 0xbe], TokenHandlerResult::Success)
    }

    fn free(buf: Vec<u8>) {
        // noop
    }

    fn can_validate() -> bool {
        false
    }

    fn is_valid(cd: *mut crypt_device, json: String) -> Option<TokenHandlerResult> {
        None
    }

    fn dump(cd: *mut crypt_device, json: String) {
        println!("noop: dump called");
    }
}

impl Luks2TokenHandlerRaw for CustomTokenHandler {}

#[test]
fn test_create_new_luks2_cryptdevice_with_token() {
    let ctx = TestContext::new("new_luks1_cryptdevice".to_string());
    let handler = Luks2CryptDeviceHandle::register_new_token_handler::<CustomTokenHandler>().expect("handler register");

    let mut dev = ctx
        .new_crypt_device()
        .luks2("aes", "xts-plain", 256, None, None, None)
        .label("test")
        .argon2i("sha256", 200, 1, 1024, 1)
        .start()
        .expect("LUKS2 format should succeed");

    let keyslot: Keyslot = 1;
    dev.add_keyslot(&[0xca, 0xfe, 0xba, 0xbe], None, Some(keyslot))
        .expect("add to keyslot");

    let token = Luks2Token {
        type_: "my_custom".to_string(),
        keyslots: vec![],
        other: serde_json::Map::new(),
    };

    let token_id = dev.add_token(&token).expect("adding token");
    dev.assign_token_to_keyslot(token_id, Some(keyslot));

    let got_keyslot = dev.check_activation_with_token(token_id).expect("activate with token");

    dev.dump();

    expect!(dev.device_type()).to(be_equal_to(crypt_device_type::LUKS2));
    expect!(got_keyslot).to(be_equal_to(keyslot));

    let _deferred = (handler,);

    // TODO: add more assertions
}
