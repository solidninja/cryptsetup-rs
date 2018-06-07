#![deny(warnings)]
#[warn(unused_must_use)]

extern crate cryptsetup_rs;
extern crate env_logger;

use std::env;
use cryptsetup_rs::{CryptDevice, Result, Keyslot};
use cryptsetup_rs::device::crypt_keyslot_info;

fn _dump_slot(crypt_device: &CryptDevice, slot: Keyslot) -> Result<()> {
    let status = match crypt_device.keyslot_status(slot) {
        crypt_keyslot_info::CRYPT_SLOT_INVALID => "INVALID",
        crypt_keyslot_info::CRYPT_SLOT_INACTIVE => "DISABLED",
        crypt_keyslot_info::CRYPT_SLOT_ACTIVE | crypt_keyslot_info::CRYPT_SLOT_ACTIVE_LAST => "ENABLED",
    };

    println!("Key Slot {}: {}", slot, status);
    match status {
        "ENABLED" => /* TODO  add keyslot information */ (),
        _ => (),
    }
    Ok(())
}

fn dump(device_path: &str) -> Result<()> {
    // TODO: refactor API so each device type has only the methods it needs
    let (crypt_device, luks1_params) = CryptDevice::load_luks1(device_path)?;

    println!("LUKS header information for {}", device_path);
    println!();
    println!("{:<16}{}", "Version:", "1");
    println!("{:<16}{}", "Cipher name:", crypt_device.cipher().unwrap());
    println!("{:<16}{}", "Cipher mode:", crypt_device.cipher_mode().unwrap());
    println!("{:<16}{}", "Hash spec:", &luks1_params.hash_spec);
    println!("{:<16}{}", "Payload offset:", &luks1_params.payload_offset);
    println!("{:<16}{}", "MK bits:", &luks1_params.mk_bits);

    print!("{:<16}", "MK digest:");
    for b in luks1_params.mk_digest.iter() {
        print!("{:x} ", b);
    }
    println!();

    let salt_h1 = &luks1_params.mk_salt[0..16];
    let salt_h2 = &luks1_params.mk_salt[16..];
    print!("{:<16}", "MK salt:");
    for b in salt_h1.iter() {
        print!("{:x} ", b);
    }
    println!();
    print!("{:<16}", "");
    for b in salt_h2.iter() {
        print!("{:x} ", b);
    }
    println!();

    println!("{:<16}{}", "MK iterations:", &luks1_params.mk_iterations);
    println!("{:<16}{}", "UUID:", crypt_device.uuid().expect("LUKS1 UUID"));

    println!();

    for slot in 0..8 {
        _dump_slot(&crypt_device, slot)?;
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 1 {
        println!("Usage: luks_dump <device path>");
        ::std::process::exit(1);
    }
    let device_path = args[0].as_str();

    if let Err(e) = dump(device_path) {
        println!("Error: {:?}", e);
        ::std::process::exit(2);
    }
}