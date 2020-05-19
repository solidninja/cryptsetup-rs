//! Rust bindings to `libcryptsetup` - working with encrypted disks on Linux
//!
//! # Example
//!
//! See `api` module documentation for more.
//!
//! ```
//! use cryptsetup_rs::*;
//! # fn foo() -> Result<()> {
//! let device = open("/dev/loop0")?.luks1()?;
//! println!("Device UUID: {}", device.uuid());
//! println!("Device cipher: {}", device.cipher());
//! # Ok(())
//! # }
//! ```

#![deny(warnings)]
#[warn(unused_must_use)]
extern crate base64;
extern crate blkid_rs;
extern crate either;
extern crate errno;
extern crate libc;
extern crate libcryptsetup_sys as raw;
extern crate serde;
extern crate serde_json;
extern crate serde_repr;
extern crate serde_with;
extern crate uuid;

#[macro_use]
extern crate base64_serde;

#[macro_use]
extern crate log;

pub mod api;
pub mod device;
mod global;
mod luks1;
mod luks2;
mod luks2_meta;

#[allow(deprecated)]
pub use api::{enable_debug, format, luks1_uuid, luks_uuid, luks_version, open};
pub use api::{
    CryptDevice, CryptDeviceType, Error, Keyslot, Luks1CryptDevice, Luks1CryptDeviceHandle, Luks2CryptDevice,
    Luks2CryptDeviceHandle, Luks2Metadata, LuksCryptDevice, Result,
};
pub use raw::{crypt_device_type, crypt_keyslot_info, crypt_rng_type};
