use std::fs::File;
use std::path::Path;

use uuid::Uuid;

use blkid_rs::{Luks2Header, LuksHeader};

use crate::api::CryptDeviceHandle;
use crate::api::{CryptDeviceType, Luks2CryptDevice, LuksCryptDevice};
use crate::device::{Error, Keyslot, Result};

/// Struct for storing LUKS2 parameters in memory
#[derive(Debug, PartialEq)]
pub struct Luks2Params {
    label: Option<String>,
    subsystem: Option<String>,
    seqid: u64,
    header_size: u64,
    header_offset: u64,
    // TODO do we need to expose others?
}

impl Luks2Params {
    pub(crate) fn from(header: impl Luks2Header) -> Result<Luks2Params> {
        let label = header.label()?.map(|s| s.to_owned());
        let subsystem = header.subsystem()?.map(|s| s.to_owned());
        let seqid = header.seqid();
        let header_size = header.header_size();
        let header_offset = header.header_offset();
        Ok(Luks2Params {
            label,
            subsystem,
            seqid,
            header_size,
            header_offset,
        })
    }

    pub(crate) fn from_path<P: AsRef<Path>>(path: P) -> Result<Luks2Params> {
        let device_file = File::open(path.as_ref())?;
        match LuksHeader::read(device_file)? {
            LuksHeader::Luks2(v2) => Luks2Params::from(v2),
            _ => Err(Error::InvalidLuksVersion),
        }
    }
}

impl LuksCryptDevice for CryptDeviceHandle<Luks2Params> {
    fn activate(&mut self, name: &str, key: &[u8]) -> Result<u8> {
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
}

impl Luks2CryptDevice for CryptDeviceHandle<Luks2Params> {}

impl CryptDeviceType for CryptDeviceHandle<Luks2Params> {
    fn device_type(&self) -> raw::crypt_device_type {
        raw::crypt_device_type::LUKS2
    }
}
