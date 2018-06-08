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
