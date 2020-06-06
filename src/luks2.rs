use std::convert::TryFrom;
use std::fs::File;
use std::path::Path;

use uuid::Uuid;

use blkid_rs::{Luks2Header, LuksHeader};

use crate::api::{crypt_token_info, CryptDeviceHandle};
use crate::api::{CryptDeviceType, Luks2CryptDevice, LuksCryptDevice};
use crate::device::{Error, Keyslot, Luks2TokenHandlerBox, Luks2TokenHandlerRaw, Luks2TokenId, Result};
use crate::luks2_meta::Luks2Token;

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

impl Luks2CryptDevice for CryptDeviceHandle<Luks2Params> {
    fn register_new_token_handler<Handler: Luks2TokenHandlerRaw>() -> Result<Luks2TokenHandlerBox<Handler>> {
        let b = Luks2TokenHandlerBox::new();
        Self::register_token_handler(&b)?;
        Ok(b)
    }

    fn register_token_handler<Handler: Luks2TokenHandlerRaw>(handler: &Luks2TokenHandlerBox<Handler>) -> Result<()> {
        crate::device::luks2_register_token_handler::<Handler>(handler)
    }

    fn token_status(&mut self, token_id: Luks2TokenId) -> (crypt_token_info, Option<String>) {
        crate::device::luks2_token_status(&mut self.cd, token_id)
    }

    fn get_token(&mut self, token_id: Luks2TokenId) -> Result<Luks2Token> {
        let json = crate::device::luks2_token_json(&mut self.cd, token_id)?;
        let token = Luks2Token::try_from(json.as_str()).map_err(|err| Error::InvalidJson(format!("{}", err)))?;
        Ok(token)
    }

    fn add_token_with_id(&mut self, token: &Luks2Token, token_id: Luks2TokenId) -> Result<()> {
        let js = String::try_from(token).map_err(|err| Error::InvalidJson(format!("{}", err)))?;
        crate::device::luks2_token_json_allocate(&mut self.cd, js.as_str(), Some(token_id))?;
        Ok(())
    }

    fn add_token(&mut self, token: &Luks2Token) -> Result<Luks2TokenId> {
        let js = String::try_from(token).map_err(|err| Error::InvalidJson(format!("{}", err)))?;
        crate::device::luks2_token_json_allocate(&mut self.cd, js.as_str(), None)
    }

    fn remove_token(&mut self, token_id: Luks2TokenId) -> Result<()> {
        crate::device::luks2_token_remove(&mut self.cd, token_id)
    }

    fn assign_token_to_keyslot(&mut self, token_id: Luks2TokenId, keyslot_opt: Option<Keyslot>) -> Result<()> {
        crate::device::luks2_token_assign_keyslot(&mut self.cd, token_id, keyslot_opt)
    }

    fn unassign_token_keyslot(&mut self, token_id: Luks2TokenId, keyslot_opt: Option<Keyslot>) -> Result<()> {
        crate::device::luks2_token_unassign_keyslot(&mut self.cd, token_id, keyslot_opt)
    }

    fn token_keyslot_is_assigned(&mut self, token_id: Luks2TokenId, keyslot: Keyslot) -> Result<bool> {
        crate::device::luks2_token_is_assigned(&mut self.cd, token_id, keyslot)
    }

    fn activate_with_token(&mut self, name: &str, token_id: Luks2TokenId) -> Result<Keyslot> {
        crate::device::luks2_activate_by_token(&mut self.cd, Some(name), Some(token_id))
    }

    fn check_activation_with_token(&mut self, token_id: Luks2TokenId) -> Result<Keyslot> {
        crate::device::luks2_activate_by_token(&mut self.cd, None, Some(token_id))
    }
}

impl CryptDeviceType for CryptDeviceHandle<Luks2Params> {
    fn device_type(&self) -> raw::crypt_device_type {
        raw::crypt_device_type::LUKS2
    }
}
