[![pipeline status](https://gitlab.com/solidninja/cryptsetup-rs/badges/main/pipeline.svg)](https://gitlab.com/solidninja/cryptsetup-rs/commits/main)
[![crates.io Status](https://img.shields.io/crates/v/cryptsetup-rs.svg)](https://crates.io/crates/cryptsetup-rs)
[![docs.rs build](https://docs.rs/cryptsetup-rs/badge.svg)](https://docs.rs/crate/cryptsetup-rs/)

# cryptsetup-rs - Rust bindings to `libcryptsetup` on Linux

A safe binding to `libcryptsetup` that allows working with encrypted disks on Linux.

Requires `libcryptetup >= 2.1.0` to compile.

Features:
  * High-level API for LUKS open/format/other operations
  * LUKS2 support including tokens handlers

Documentation for the bindings can be found on [docs.rs](https://docs.rs/crate/cryptsetup-rs/).

The example [`luks_dump.rs`](examples/luks_dump.rs) shows how a command like `cryptsetup luksDump` can
be implemented.

## TODO

* High-level API for non-LUKS1 disks (truecrypt, verity, bitlocker)
* LUKS2 reencryption support

### Other libraries

The [libcryptsetup-rs](https://crates.io/crates/libcryptsetup-rs) library provides a more complete set of bindings with
a different (non-builder like) API.

## Contributing

`cryptsetup-rs` is the work of its contributors and is a free software project licensed under the
LGPLv3 or later.

If you would like to contribute, please follow the [C4](https://rfc.zeromq.org/spec:42/C4/) process.
