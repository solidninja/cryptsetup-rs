use std::fs::File;
use std::path::Path;

use uuid::Uuid;

use blkid_rs::{Luks1Header, LuksHeader};

use crate::api::CryptDeviceHandle;
use crate::api::{CryptDeviceType, Luks1CryptDevice, LuksCryptDevice};
use crate::device::{Error, Keyslot, Result};

/// Struct for storing LUKS1 parameters in memory
#[derive(Debug, PartialEq)]
pub struct Luks1Params {
    hash_spec: String,
    payload_offset: u32,
    mk_bits: u32,
    mk_digest: [u8; 20],
    mk_salt: [u8; 32],
    mk_iterations: u32,
}

impl Luks1Params {
    fn from(header: impl Luks1Header) -> Result<Luks1Params> {
        let hash_spec = header.hash_spec()?.to_owned();
        let payload_offset = header.payload_offset();
        let mk_bits = header.key_bytes() * 8;
        let mut mk_digest = [0u8; 20];
        mk_digest.copy_from_slice(header.mk_digest());
        let mut mk_salt = [0u8; 32];
        mk_salt.copy_from_slice(header.mk_digest_salt());
        let mk_iterations = header.mk_digest_iterations();
        Ok(Luks1Params {
            hash_spec,
            payload_offset,
            mk_bits,
            mk_digest,
            mk_salt,
            mk_iterations,
        })
    }

    pub(crate) fn from_path<P: AsRef<Path>>(path: P) -> Result<Luks1Params> {
        let device_file = File::open(path.as_ref())?;
        match LuksHeader::read(device_file)? {
            LuksHeader::Luks1(v1) => Luks1Params::from(v1),
            _ => Err(Error::InvalidLuksVersion),
        }
    }
}

impl LuksCryptDevice for CryptDeviceHandle<Luks1Params> {
    fn activate(&mut self, name: &str, key: &[u8]) -> Result<Keyslot> {
        crate::device::luks_activate(&mut self.cd, name, key)
    }

    fn deactivate(self, name: &str) -> Result<()> {
        crate::device::deactivate(self.cd, name)
    }

    fn destroy_keyslot(&mut self, slot: Keyslot) -> Result<()> {
        crate::device::luks_destroy_keyslot(&mut self.cd, slot)
    }

    fn keyslot_status(&self, keyslot: Keyslot) -> raw::crypt_keyslot_info {
        crate::device::keyslot_status(&self.cd, keyslot)
    }

    fn dump(&self) {
        crate::device::dump(&self.cd).expect("Dump should be fine for initialised device")
    }

    fn uuid(&self) -> Uuid {
        crate::device::uuid(&self.cd).expect("Initialised device should have UUID")
    }

    fn add_keyslot(
        &mut self,
        key: &[u8],
        maybe_prev_key: Option<&[u8]>,
        maybe_keyslot: Option<Keyslot>,
    ) -> Result<Keyslot> {
        crate::device::luks_add_keyslot(&mut self.cd, key, maybe_prev_key, maybe_keyslot)
    }

    fn update_keyslot(&mut self, key: &[u8], prev_key: &[u8], maybe_keyslot: Option<Keyslot>) -> Result<Keyslot> {
        crate::device::luks_update_keyslot(&mut self.cd, key, prev_key, maybe_keyslot)
    }
}

impl Luks1CryptDevice for CryptDeviceHandle<Luks1Params> {
    fn hash_spec(&self) -> &str {
        self.params.hash_spec.as_ref()
    }

    fn mk_bits(&self) -> u32 {
        self.params.mk_bits
    }

    fn mk_digest(&self) -> &[u8; 20] {
        &self.params.mk_digest
    }

    fn mk_iterations(&self) -> u32 {
        self.params.mk_iterations
    }

    fn mk_salt(&self) -> &[u8; 32] {
        &self.params.mk_salt
    }

    fn payload_offset(&self) -> u32 {
        self.params.payload_offset
    }
}

impl CryptDeviceType for CryptDeviceHandle<Luks1Params> {
    fn device_type(&self) -> raw::crypt_device_type {
        raw::crypt_device_type::LUKS1
    }
}
