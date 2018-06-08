#![deny(warnings)]

extern crate blkid_rs;
extern crate errno;
extern crate libc;
extern crate libcryptsetup_sys as raw;
extern crate uuid;

#[macro_use]
extern crate log;

pub mod api;
pub mod device;

pub use api::{enable_debug, format, open};
pub use api::{CryptDevice, CryptDeviceType, Error, Keyslot, Luks1CryptDevice, Result};
pub use raw::{crypt_device_type, crypt_keyslot_info, crypt_rng_type};
