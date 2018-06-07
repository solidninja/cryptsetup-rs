#![deny(warnings)]

extern crate blkid_rs;
extern crate errno;
extern crate libc;
extern crate libcryptsetup_sys as raw;
extern crate uuid;

#[macro_use]
extern crate log;

pub mod device;

pub use blkid_rs::{BlockDevice, LuksHeader};
