#![allow(bad_style, deprecated, invalid_value)]
// allowing invalid_value due to https://github.com/gnzlbg/ctest/pull/93
#[deny(warnings)]
extern crate libc;
extern crate libcryptsetup_sys;

use libc::*;
use libcryptsetup_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
