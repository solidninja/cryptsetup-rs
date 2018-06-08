use std::ffi;
use std::mem;
use std::path::Path;
use std::ptr;
use std::result;
use std::str;

use blkid_rs;
use errno;
use libc;
use raw;
use uuid;

pub type RawDevice = *mut raw::crypt_device;

#[derive(Debug)]
pub enum Error {
    CryptsetupError(errno::Errno),
    IOError(::std::io::Error),
    BlkidError(blkid_rs::Error),
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

// TODO - each time .to_owned() is called, need to manually zero the memory afterwards

const ANY_KEYSLOT: libc::c_int = -1 as libc::c_int;

fn str_from_c_str<'a>(c_str: *const libc::c_char) -> Option<&'a str> {
    if c_str.is_null() {
        None
    } else {
        unsafe { Some(ffi::CStr::from_ptr(c_str).to_str().unwrap()) }
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
    let msg = str_from_c_str(message).unwrap();
    match level {
        raw::crypt_log_level::CRYPT_LOG_NORMAL => info!("{}", msg),
        raw::crypt_log_level::CRYPT_LOG_ERROR => error!("{}", msg),
        raw::crypt_log_level::CRYPT_LOG_VERBOSE => debug!("{}", msg),
        raw::crypt_log_level::CRYPT_LOG_DEBUG => debug!("{}", msg),
    }
}

/// Enable internal `libcryptsetup` debugging
pub fn enable_debug(debug: bool) {
    if debug {
        unsafe { raw::crypt_set_debug_level(raw::crypt_debug_level::CRYPT_DEBUG_ALL) };
    } else {
        unsafe { raw::crypt_set_debug_level(raw::crypt_debug_level::CRYPT_DEBUG_NONE) };
    }
}

pub fn init<P: AsRef<Path>>(path: P) -> Result<RawDevice> {
    let mut cd = ptr::null_mut();
    let c_path = ffi::CString::new(path.as_ref().to_str().unwrap()).unwrap();

    let res = unsafe { raw::crypt_init(&mut cd as *mut *mut raw::crypt_device, c_path.as_ptr()) };

    if res != 0 {
        crypt_error!(res)
    } else {
        unsafe {
            raw::crypt_set_log_callback(cd, Some(cryptsetup_rs_log_callback), ptr::null_mut());
        }
        Ok(cd)
    }
}

pub fn load(cd: &RawDevice, requested_type: raw::crypt_device_type) -> Result<()> {
    let c_type = ffi::CString::new(requested_type.to_str()).unwrap();

    let res = unsafe { raw::crypt_load(*cd, c_type.as_ptr(), ptr::null_mut()) };

    check_crypt_error!(res)
}

pub fn cipher<'a>(cd: &'a RawDevice) -> Option<&'a str> {
    let c_cipher = unsafe { raw::crypt_get_cipher(*cd) };
    str_from_c_str(c_cipher)
}

pub fn cipher_mode<'a>(cd: &'a RawDevice) -> Option<&'a str> {
    let c_cipher_mode = unsafe { raw::crypt_get_cipher_mode(*cd) };
    str_from_c_str(c_cipher_mode)
}

pub fn device_name<'a>(cd: &'a RawDevice) -> Option<&'a str> {
    let c_device_name = unsafe { raw::crypt_get_device_name(*cd) };
    str_from_c_str(c_device_name)
}

pub fn dump(cd: &RawDevice) -> Result<()> {
    let res = unsafe { raw::crypt_dump(*cd) };
    check_crypt_error!(res)
}

pub fn free(cd: &mut RawDevice) {
    unsafe { raw::crypt_free(*cd) }
}

pub fn luks_activate(cd: &mut RawDevice, name: &str, key: &[u8]) -> Result<Keyslot> {
    let c_name = ffi::CString::new(name).unwrap();
    let c_passphrase_len = key.len() as libc::size_t;

    let res = unsafe {
        let c_passphrase = ffi::CString::from_vec_unchecked(key.to_owned());
        raw::crypt_activate_by_passphrase(
            *cd,
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

pub fn luks_add_keyslot(
    cd: &mut RawDevice,
    key: &[u8], // FIXME investigate safer types for not leaking passwords in memory
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
                *cd,
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
                *cd,
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

pub fn luks_format(
    cd: &mut RawDevice,
    cipher: &str,
    cipher_mode: &str,
    hash: &str,
    mk_bits: usize,
    maybe_uuid: Option<&uuid::Uuid>,
) -> Result<()> {
    let c_cipher = ffi::CString::new(cipher).unwrap();
    let c_cipher_mode = ffi::CString::new(cipher_mode).unwrap();
    let c_hash = ffi::CString::new(hash).unwrap();
    let c_uuid = maybe_uuid.map(|uuid| ffi::CString::new(uuid.hyphenated().to_string()).unwrap());

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
            *cd,
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

pub fn rng_type(cd: &RawDevice) -> raw::crypt_rng_type {
    unsafe {
        let res = raw::crypt_get_rng_type(*cd);
        mem::transmute(res)
    }
}

pub fn set_iteration_time(cd: &mut RawDevice, iteration_time_ms: u64) {
    unsafe {
        raw::crypt_set_iteration_time(*cd, iteration_time_ms);
    }
}

pub fn set_rng_type(cd: &mut RawDevice, rng_type: raw::crypt_rng_type) {
    unsafe { raw::crypt_set_rng_type(*cd, rng_type) }
}

pub fn keyslot_status(cd: &RawDevice, slot: Keyslot) -> raw::crypt_keyslot_info {
    unsafe { raw::crypt_keyslot_status(*cd, slot as libc::c_int) }
}

pub fn volume_key_size(cd: &RawDevice) -> u8 {
    let res = unsafe { raw::crypt_get_volume_key_size(*cd) };
    res as u8
}

pub fn uuid<'a>(cd: &'a RawDevice) -> Option<uuid::Uuid> {
    let c_uuid_str = unsafe { raw::crypt_get_uuid(*cd) };
    str_from_c_str(c_uuid_str).and_then(|uuid_str| uuid::Uuid::parse_str(uuid_str).ok())
}
