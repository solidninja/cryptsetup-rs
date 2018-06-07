use std::cmp::PartialEq;
use std::ffi;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::ptr;
use std::result;
use std::str;
use std::str::FromStr;

use blkid_rs;
use blkid_rs::LuksHeader;
use errno;
use libc;
use raw;
use uuid;

#[derive(Debug)]
pub enum Error {
    CryptsetupError(errno::Errno),
    IOError(::std::io::Error),
    BlkidError(blkid_rs::Error)
}

impl From<::std::io::Error> for Error {
    fn from(e: ::std::io::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<blkid_rs::Error> for Error {
    fn from(e: blkid_rs::Error) -> Self {
        Error::BlkidError(e)
    }
}

pub type Result<T> = result::Result<T, Error>;
pub type Keyslot = u8;

pub use raw::{crypt_device_type, crypt_rng_type, crypt_keyslot_info};

// TODO - each time .to_owned() is called, need to manually zero the memory afterwards

const ANY_KEYSLOT: libc::c_int = -1 as libc::c_int;

// FIXME: remove as you can just use CStr::to_str() ?
unsafe fn str_from_c_str<'a>(c_str: *const libc::c_char) -> Option<&'a str> {
    if c_str.is_null() {
        None
    } else {
        let c_str_bytes: &[u8] = ffi::CStr::from_ptr(c_str).to_bytes();
        Some(str::from_utf8(c_str_bytes).unwrap())
    }
}

macro_rules! crypt_error {
    ($res:expr) => {
        Err(Error::CryptsetupError(errno::Errno(-$res)))
    };
}

macro_rules! check_crypt_error {
    ($res:expr) => {
        if $res != 0 {
            crypt_error!($res)
        } else {
            Ok(())
        }
    };
}

#[allow(unused)]
#[no_mangle]
pub extern "C" fn cryptsetup_rs_log_callback(
    level: raw::crypt_log_level,
    message: *const libc::c_char,
    usrptr: *mut libc::c_void,
) {
    let msg = unsafe { str_from_c_str(message) }.unwrap();
    match level {
        raw::crypt_log_level::CRYPT_LOG_NORMAL => info!("{}", msg),
        raw::crypt_log_level::CRYPT_LOG_ERROR => error!("{}", msg),
        raw::crypt_log_level::CRYPT_LOG_VERBOSE => debug!("{}", msg),
        raw::crypt_log_level::CRYPT_LOG_DEBUG => debug!("{}", msg),
    }
}

// TODO - this could be a series of traits that represent the different aspects of the crypt device
// TODO - handle the state transitions of the crypt device

pub struct CryptDevice {
    pub path: PathBuf,
    cd: *mut raw::crypt_device,
}

// TODO: decide whether to load all of these at once or read every time

/// Parameters for LUKS1 devices
pub struct Luks1Params {
    pub hash_spec: String,
    pub payload_offset: u32,
    pub mk_bits: u32,
    pub mk_digest: [u8; 20],
    pub mk_salt: [u8; 32],
    pub mk_iterations: u32,
}

impl Luks1Params {
    pub fn from(header: impl LuksHeader) -> Result<Luks1Params> {
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
            mk_iterations
        })
    }
}

impl fmt::Debug for CryptDevice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CryptDevice(path={}, raw={:p})",
            self.path.display(),
            self.cd
        )
    }
}

impl CryptDevice {
    pub fn new<P: Into<PathBuf>>(p: P) -> Result<CryptDevice> {
        let path = p.into();
        let mut cd: *mut raw::crypt_device = ptr::null_mut();
        let c_path = ffi::CString::new(path.to_str().unwrap()).unwrap();

        let res =
            unsafe { raw::crypt_init(&mut cd as *mut *mut raw::crypt_device, c_path.as_ptr()) };

        if res != 0 {
            crypt_error!(res)
        } else {
            unsafe {
                raw::crypt_set_log_callback(cd, Some(cryptsetup_rs_log_callback), ptr::null_mut());
            }
            Ok(CryptDevice { path, cd })
        }
    }

    pub fn enable_debug(debug: bool) {
        if debug {
            unsafe { raw::crypt_set_debug_level(raw::crypt_debug_level::CRYPT_DEBUG_ALL) };
        } else {
            unsafe { raw::crypt_set_debug_level(raw::crypt_debug_level::CRYPT_DEBUG_NONE) };
        }
    }

    pub fn load(&self, requested_type: raw::crypt_device_type) -> Result<()> {
        let c_type = ffi::CString::new(requested_type.to_str()).unwrap();

        let res = unsafe { raw::crypt_load(self.cd, c_type.as_ptr(), ptr::null_mut()) };

        check_crypt_error!(res)
    }

    // NOTE: the additional param structs are only applicable to tcrypt and verity types,
    // also `lib/setup.c:crypt_load()` does not allow loading LUKS1 header information
    fn _load_struct<S>(&self, requested_type: raw::crypt_device_type, s: &mut S) -> Result<()> {
        let c_type = ffi::CString::new(requested_type.to_str()).unwrap();
        let c_struct_ref = s as *mut S;

        let res = unsafe { raw::crypt_load(self.cd, c_type.as_ptr(), c_struct_ref as *mut libc::c_void) };
        check_crypt_error!(res)
    }

    /// Loads a LUKS v1 device from the specified path
    pub fn load_luks1<P: AsRef<Path>>(p: P) -> Result<(CryptDevice, Luks1Params)> {
        let crypt_device = CryptDevice::new(p.as_ref())?;

        crypt_device.load(raw::crypt_device_type::LUKS1)?;
        let device_file = File::open(p)?;
        let luks_phdr = blkid_rs::BlockDevice::read_luks_header(device_file)?;

        let device_type = crypt_device.device_type();
        if let Some(raw::crypt_device_type::LUKS1) = device_type {
            let params = Luks1Params::from(luks_phdr)?;
            Ok((crypt_device, params))
        } else {
            error!("Unexpected device type: {:?}", device_type);
            crypt_error!(42)
        }
    }

    pub fn rng_type(&self) -> raw::crypt_rng_type {
        unsafe {
            let res = raw::crypt_get_rng_type(self.cd);
            mem::transmute(res)
        }
    }

    pub fn set_rng_type(&mut self, rng_type: raw::crypt_rng_type) {
        unsafe { raw::crypt_set_rng_type(self.cd, rng_type) }
    }

    pub fn device_type(&self) -> Option<raw::crypt_device_type> {
        let res = unsafe { str_from_c_str(raw::crypt_get_type(self.cd)) };
        res.map(|res_str| raw::crypt_device_type::from_str(res_str).unwrap())
    }

    pub fn keyslot_status(&self, slot: Keyslot) -> raw::crypt_keyslot_info {
        unsafe {
            raw::crypt_keyslot_status(self.cd, slot as libc::c_int)
        }
    }

    pub fn uuid(&self) -> Option<uuid::Uuid> {
        // TODO: the uuid is not available before load() has been called. We can use blkid-rs to get around the limitation
        let res = unsafe { str_from_c_str(raw::crypt_get_uuid(self.cd)) };
        res.and_then(|uuid_str| uuid::Uuid::parse_str(uuid_str).ok())
    }

    pub fn cipher(&self) -> Option<String> {
        let res = unsafe { str_from_c_str(raw::crypt_get_cipher(self.cd)) };
        res.map(|r| r.to_owned())
    }

    pub fn cipher_mode(&self) -> Option<String> {
        let res = unsafe { str_from_c_str(raw::crypt_get_cipher_mode(self.cd)) };
        res.map(|r| r.to_owned())
    }

    pub fn volume_key_size(&self) -> Option<usize> {
        let res = unsafe { raw::crypt_get_volume_key_size(self.cd) };
        // TODO - is this safe to do?
        Some(res as usize)
    }

    pub fn device_name(&self) -> String {
        let res = unsafe { str_from_c_str(raw::crypt_get_device_name(self.cd)) };
        res.unwrap().to_owned()
    }

    pub fn dump(&self) -> Result<()> {
        let res = unsafe { raw::crypt_dump(self.cd) };
        check_crypt_error!(res)
    }

    pub fn format_luks(
        &mut self,
        cipher: &str,
        cipher_mode: &str,
        hash: &str,
        mk_bits: usize,
        maybe_uuid: Option<&uuid::Uuid>,
    ) -> Result<()> {
        let c_cipher = ffi::CString::new(cipher).unwrap();
        let c_cipher_mode = ffi::CString::new(cipher_mode).unwrap();
        let c_hash = ffi::CString::new(hash).unwrap();
        let c_uuid =
            maybe_uuid.map(|uuid| ffi::CString::new(uuid.hyphenated().to_string()).unwrap());

        let mut luks_params = raw::crypt_params_luks1 {
            hash: c_hash.as_ptr(),
            data_alignment: 0,
            data_device: ptr::null(),
        };
        let c_luks_params: *mut raw::crypt_params_luks1 = &mut luks_params;
        let c_luks_type = ffi::CString::new(raw::crypt_device_type::LUKS1.to_str()).unwrap();
        let c_uuid_ptr = c_uuid.as_ref().map(|u| u.as_ptr()).unwrap_or(ptr::null());
        let res = unsafe {
            raw::crypt_format(
                self.cd,
                c_luks_type.as_ptr(),
                c_cipher.as_ptr(),
                c_cipher_mode.as_ptr(),
                c_uuid_ptr,
                ptr::null(),
                mk_bits / 8,
                c_luks_params as *mut libc::c_void,
            )
        };

        check_crypt_error!(res)
    }

    /// Set the iteration time for the `PBKDF2` function. Note that this does not affect the MK iterations.
    pub fn set_iteration_time(&mut self, iteration_time_ms: u64) {
        unsafe {
            raw::crypt_set_iteration_time(self.cd, iteration_time_ms);
        }
    }

    pub fn add_keyslot(
        &mut self,
        key: &[u8],
        maybe_prev_key: Option<&[u8]>,
        maybe_keyslot: Option<Keyslot>,
    ) -> Result<Keyslot> {
        let c_key_len = key.len() as libc::size_t;
        let c_key = unsafe { ffi::CString::from_vec_unchecked(key.to_owned()) };
        let c_keyslot = maybe_keyslot
            .map(|k| k as libc::c_int)
            .unwrap_or(ANY_KEYSLOT as libc::c_int);

        let res = if let Some(prev_key) = maybe_prev_key {
            let c_prev_key_len = prev_key.len() as libc::size_t;
            let c_prev_key = unsafe { ffi::CString::from_vec_unchecked(prev_key.to_owned()) };

            unsafe {
                raw::crypt_keyslot_add_by_passphrase(
                    self.cd,
                    c_keyslot,
                    c_prev_key.as_ptr(),
                    c_prev_key_len,
                    c_key.as_ptr(),
                    c_key_len,
                )
            }
        } else {
            unsafe {
                raw::crypt_keyslot_add_by_volume_key(
                    self.cd,
                    c_keyslot,
                    ptr::null(),
                    0 as libc::size_t,
                    c_key.as_ptr(),
                    c_key_len,
                )
            }
        };

        if res < 0 {
            crypt_error!(res)
        } else {
            Ok(res as Keyslot)
        }
    }

    pub fn activate(&mut self, name: &str, key: &[u8]) -> Result<Keyslot> {
        let c_name = ffi::CString::new(name).unwrap();
        let c_passphrase_len = key.len() as libc::size_t;

        let res = unsafe {
            let c_passphrase = ffi::CString::from_vec_unchecked(key.to_owned());
            raw::crypt_activate_by_passphrase(
                self.cd,
                c_name.as_ptr(),
                ANY_KEYSLOT,
                c_passphrase.as_ptr(),
                c_passphrase_len,
                0u32,
            )
        };

        if res < 0 {
            crypt_error!(res)
        } else {
            Ok(res as u8)
        }
    }
}

impl Drop for CryptDevice {
    fn drop(&mut self) {
        unsafe {
            raw::crypt_free(self.cd);
        }
        self.cd = ptr::null_mut();
    }
}

impl Hash for CryptDevice {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.path.hash(state)
    }
}

impl PartialEq for CryptDevice {
    fn eq(&self, other: &CryptDevice) -> bool {
        self.path == other.path
    }
}

impl Eq for CryptDevice {}
