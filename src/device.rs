//! Low-level cryptsetup binding that sits directly on top of the `libcryptsetup` C API
//!
//! Consider using the high-level binding in the `api` module instead

use std::boxed::Box;
use std::error;
use std::ffi;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::mem;
use std::path::Path;
use std::ptr;
use std::result;
use std::str;
use std::sync::Once;

use errno;
use libc;
use uuid::Uuid;

use crate::api::crypt_status_info;
use blkid_rs;
use raw;

/// Raw pointer to the underlying `crypt_device` opaque struct
pub type RawDevice = *mut raw::crypt_device;
pub type Luks2TokenId = i32;

static INIT_LOGGING: Once = Once::new();

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Error that originates from `libcryptsetup` (with numeric error code)
    CryptsetupError(errno::Errno),
    /// IO error
    IOError(::std::io::Error),
    /// Error from the blkid-rs library (while reading LUKS1 header)
    BlkidError(blkid_rs::Error),
    /// The operation tried was not valid for the LUKS version
    InvalidLuksVersion,
    /// Invalid JSON (with message)
    InvalidJson(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CryptsetupError(e) => write!(f, "Cryptsetup error: {}", e),
            Error::IOError(io) => write!(f, "Underlying IO error: {}", io),
            Error::BlkidError(e) => write!(f, "Blkid error: {}", e),
            Error::InvalidLuksVersion => write!(f, "Invalid or unexpected LUKS version"),
            Error::InvalidJson(msg) => write!(f, "Invalid JSON encountered: {}", msg),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            &Error::IOError(e) => Some(e),
            &Error::BlkidError(e) => Some(e),
            _ => None,
        }
    }
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

/// Log function callback used by `libcryptsetup`
#[allow(unused)]
#[no_mangle]
pub extern "C" fn cryptsetup_rs_log_callback(
    level: raw::crypt_log_level,
    message: *const libc::c_char,
    usrptr: *mut libc::c_void,
) {
    let msg = str_from_c_str(message).unwrap();
    match level {
        raw::crypt_log_level::CRYPT_LOG_NORMAL => info!(target: "cryptsetup", "{}", msg.trim_end()),
        raw::crypt_log_level::CRYPT_LOG_ERROR => error!(target: "cryptsetup", "{}", msg.trim_end()),
        raw::crypt_log_level::CRYPT_LOG_VERBOSE => debug!(target: "cryptsetup", "{}", msg.trim_end()),
        raw::crypt_log_level::CRYPT_LOG_DEBUG => debug!(target: "cryptsetup", "{}", msg.trim_end()),
        raw::crypt_log_level::CRYPT_LOG_DEBUG_JSON => debug!(target: "cryptsetup", "{}", msg.trim_end()), // TODO - really?
    }
}

fn init_logging() {
    INIT_LOGGING.call_once(|| unsafe {
        raw::crypt_set_log_callback(ptr::null_mut(), Some(cryptsetup_rs_log_callback), ptr::null_mut());
    });
}

/// Initialise crypt device and check if provided device exists
pub fn init<P: AsRef<Path>>(path: P) -> Result<RawDevice> {
    init_logging();
    let mut cd = ptr::null_mut();
    let c_path = ffi::CString::new(path.as_ref().to_str().unwrap()).unwrap();

    let res = unsafe { raw::crypt_init(&mut cd as *mut *mut raw::crypt_device, c_path.as_ptr()) };

    if res != 0 {
        crypt_error!(res)
    } else {
        Ok(cd)
    }
}

/// Initialise crypt device by header device and data device, and check if provided device exists
pub fn init_detached_header<P1: AsRef<Path>, P2: AsRef<Path>>(header_path: P1, device_path: P2) -> Result<RawDevice> {
    init_logging();
    let mut cd = ptr::null_mut();

    let c_header_path = ffi::CString::new(header_path.as_ref().to_str().unwrap()).unwrap();
    let c_device_path = ffi::CString::new(device_path.as_ref().to_str().unwrap()).unwrap();

    let res = unsafe {
        raw::crypt_init_data_device(
            &mut cd as *mut *mut raw::crypt_device,
            c_header_path.as_ptr(),
            c_device_path.as_ptr(),
        )
    };

    if res != 0 {
        crypt_error!(res)
    } else {
        Ok(cd)
    }
}

/// Initialise active crypt device by name (and error out if inactive)
pub fn init_by_name(name: &str) -> Result<RawDevice> {
    init_logging();
    let mut cd = ptr::null_mut();
    let c_name = ffi::CString::new(name).unwrap();

    let res = unsafe { raw::crypt_init_by_name(&mut cd as *mut *mut raw::crypt_device, c_name.as_ptr()) };

    if res != 0 {
        crypt_error!(res)
    } else {
        Ok(cd)
    }
}

/// Load crypt device parameters from the on-disk header
///
/// Note that typically you cannot query the crypt device for information before this function is
/// called.
pub fn load(cd: &RawDevice, requested_type: raw::crypt_device_type) -> Result<()> {
    let c_type = ffi::CString::new(requested_type.to_str()).unwrap();

    let res = unsafe { raw::crypt_load(*cd, c_type.as_ptr(), ptr::null_mut()) };

    check_crypt_error!(res)
}

/// Get the cipher used by this crypt device
pub fn cipher<'a>(cd: &'a RawDevice) -> Option<&'a str> {
    let c_cipher = unsafe { raw::crypt_get_cipher(*cd) };
    str_from_c_str(c_cipher)
}

/// Get the cipher mode used by this crypt device
pub fn cipher_mode<'a>(cd: &'a RawDevice) -> Option<&'a str> {
    let c_cipher_mode = unsafe { raw::crypt_get_cipher_mode(*cd) };
    str_from_c_str(c_cipher_mode)
}

/// Deactivate crypt device, removing active device-mapper mapping from kernel.
pub fn deactivate(cd: RawDevice, name: &str) -> Result<()> {
    let c_name = ffi::CString::new(name).expect("name to cstr");
    let res = unsafe { raw::crypt_deactivate(cd, c_name.as_ptr()) };
    check_crypt_error!(res)
}

/// Get the path to the device (as `libcryptsetup` sees it)
pub fn device_name<'a>(cd: &'a RawDevice) -> Option<&'a str> {
    let c_device_name = unsafe { raw::crypt_get_device_name(*cd) };
    str_from_c_str(c_device_name)
}

/// Dump text-formatted information about this device to the console
pub fn dump(cd: &RawDevice) -> Result<()> {
    let res = unsafe { raw::crypt_dump(*cd) };
    check_crypt_error!(res)
}

/// Releases crypt device context and memory
pub fn free(cd: &mut RawDevice) {
    unsafe { raw::crypt_free(*cd) }
}

/// Get status info about a device name
pub fn status(cd: &mut RawDevice, name: &str) -> crypt_status_info {
    let c_name = ffi::CString::new(name).unwrap();

    unsafe { raw::crypt_status(*cd, c_name.as_ptr()) }
}

/// Get status info about a device name (only)
pub fn status_only(name: &str) -> crypt_status_info {
    let c_name = ffi::CString::new(name).unwrap();

    unsafe { raw::crypt_status(ptr::null_mut(), c_name.as_ptr()) }
}

/// Activate device based on provided key ("passphrase")
pub fn luks_activate(cd: &mut RawDevice, name: &str, key: &[u8]) -> Result<Keyslot> {
    let c_name = ffi::CString::new(name).unwrap();
    let c_passphrase_len = key.len() as libc::size_t;
    // cast the passphrase to a pointer directly - it will not be NUL terminated but the passed length is used
    let c_passphrase = key as *const [u8] as *const libc::c_char;

    let res = unsafe {
        raw::crypt_activate_by_passphrase(*cd, c_name.as_ptr(), ANY_KEYSLOT, c_passphrase, c_passphrase_len, 0u32)
    };

    if res < 0 {
        crypt_error!(res)
    } else {
        Ok(res as u8)
    }
}

/// Add key slot using provided passphrase. If there is no previous passphrase, use the volume key
/// that is in-memory to add the new key slot.
pub fn luks_add_keyslot(
    cd: &mut RawDevice,
    key: &[u8],
    maybe_prev_key: Option<&[u8]>,
    maybe_keyslot: Option<Keyslot>,
) -> Result<Keyslot> {
    let c_key_len = key.len() as libc::size_t;
    let c_key = key as *const [u8] as *const libc::c_char;
    let c_keyslot = maybe_keyslot
        .map(|k| k as libc::c_int)
        .unwrap_or(ANY_KEYSLOT as libc::c_int);

    let res = if let Some(prev_key) = maybe_prev_key {
        let c_prev_key_len = prev_key.len() as libc::size_t;
        let c_prev_key = prev_key as *const [u8] as *const libc::c_char;

        unsafe { raw::crypt_keyslot_add_by_passphrase(*cd, c_keyslot, c_prev_key, c_prev_key_len, c_key, c_key_len) }
    } else {
        unsafe {
            raw::crypt_keyslot_add_by_volume_key(*cd, c_keyslot, ptr::null(), 0 as libc::size_t, c_key, c_key_len)
        }
    };

    if res < 0 {
        crypt_error!(res)
    } else {
        Ok(res as Keyslot)
    }
}

/// Add key slot using provided passphrase.
pub fn luks_update_keyslot(
    cd: &mut RawDevice,
    key: &[u8],
    prev_key: &[u8],
    maybe_keyslot: Option<Keyslot>,
) -> Result<Keyslot> {
    let c_key_len = key.len() as libc::size_t;
    let c_key = key as *const [u8] as *const libc::c_char;
    let c_keyslot = maybe_keyslot
        .map(|k| k as libc::c_int)
        .unwrap_or(ANY_KEYSLOT as libc::c_int);

    let c_prev_key_len = prev_key.len() as libc::size_t;
    let c_prev_key = prev_key as *const [u8] as *const libc::c_char;

    let res = unsafe {
        raw::crypt_keyslot_change_by_passphrase(*cd, c_keyslot, c_keyslot, c_prev_key, c_prev_key_len, c_key, c_key_len)
    };

    if res < 0 {
        crypt_error!(res)
    } else {
        Ok(res as Keyslot)
    }
}

/// Destroy (and disable) key slot
pub fn luks_destroy_keyslot(cd: &mut RawDevice, keyslot: Keyslot) -> Result<()> {
    let res = unsafe { raw::crypt_keyslot_destroy(*cd, keyslot as libc::c_int) };
    if res < 0 {
        crypt_error!(res)
    } else {
        Ok(())
    }
}

fn generic_format(
    cd: &mut RawDevice,
    cipher: &str,
    cipher_mode: &str,
    mk_bits: usize,
    maybe_uuid: Option<&uuid::Uuid>,
    type_: raw::crypt_device_type,
    c_params: *mut libc::c_void,
) -> Result<()> {
    let c_cipher = ffi::CString::new(cipher).unwrap();
    let c_cipher_mode = ffi::CString::new(cipher_mode).unwrap();
    let c_uuid = maybe_uuid.map(|uuid| ffi::CString::new(uuid.hyphenated().to_string()).unwrap());

    let c_luks_type = ffi::CString::new(type_.to_str()).unwrap();
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
            c_params,
        )
    };

    check_crypt_error!(res)
}

/// Format a new crypt device as LUKS1 but do not activate it
///
/// Note this does not add an active keyslot
pub fn luks1_format(
    cd: &mut RawDevice,
    cipher: &str,
    cipher_mode: &str,
    hash: &str,
    mk_bits: usize,
    maybe_uuid: Option<&uuid::Uuid>,
) -> Result<()> {
    let c_hash = ffi::CString::new(hash).unwrap();
    let mut luks_params = raw::crypt_params_luks1 {
        hash: c_hash.as_ptr(),
        data_alignment: 0,
        data_device: ptr::null(),
    };
    let c_luks_params: *mut raw::crypt_params_luks1 = &mut luks_params;
    generic_format(
        cd,
        cipher,
        cipher_mode,
        mk_bits,
        maybe_uuid,
        raw::crypt_device_type::LUKS1,
        c_luks_params as *mut libc::c_void,
    )
}

/// equivalent to `raw::crypt_pbkdf_type`
pub struct Luks2FormatPbkdf<'a> {
    pub type_: raw::crypt_pbkdf_algo_type,
    pub hash: &'a str,
    pub time_ms: u32,
    pub iterations: u32,
    pub max_memory_kb: u32,
    pub parallel_threads: u32,
    pub flags: u32,
}

/// equivalent to `raw::crypt_params_integrity` (with omitted params for constants)
pub struct Luks2FormatIntegrity<'a> {
    journal_size: u64,
    journal_watermark: u64,
    journal_commit_time: u64,
    interleave_sectors: u32,
    tag_size: u32,
    sector_size: u32,
    buffer_sectors: u32,
    journal_integrity_algorithm: &'a str,
    journal_encryption_algorithm: &'a str,
}

/// Format a new crypt device as LUKS2 but do not activate it
///
/// Note this does not add an active keyslot
pub fn luks2_format<'a>(
    cd: &mut RawDevice,
    cipher: &str,
    cipher_mode: &str,
    mk_bits: usize,
    data_alignment: usize,
    sector_size: u32,
    label: Option<&'a str>,
    subsystem: Option<&'a str>,
    data_device: Option<&Path>,
    maybe_uuid: Option<&uuid::Uuid>,
    pbkdf: Option<&'a Luks2FormatPbkdf>,
    integrity: Option<&'a Luks2FormatIntegrity>,
) -> Result<()> {
    let maybe_pbkdf = pbkdf.map(|p| {
        let c_type = ffi::CString::new(p.type_.to_str()).unwrap();
        let c_hash = ffi::CString::new(p.hash).unwrap();

        let res = raw::crypt_pbkdf_type {
            type_: c_type.as_ptr(),
            hash: c_hash.as_ptr(),
            time_ms: p.time_ms,
            iterations: p.iterations,
            max_memory_kb: p.max_memory_kb,
            parallel_threads: p.parallel_threads,
            flags: p.flags,
        };

        (res, (c_type, c_hash))
    });
    let maybe_integrity = integrity.map(|i| {
        let c_journal_integrity = ffi::CString::new(i.journal_integrity_algorithm).unwrap();
        let c_journal_crypt = ffi::CString::new(i.journal_encryption_algorithm).unwrap();

        let res = raw::crypt_params_integrity {
            journal_size: i.journal_size,
            journal_watermark: i.journal_watermark as libc::c_uint,
            journal_commit_time: i.journal_commit_time as libc::c_uint,
            interleave_sectors: i.interleave_sectors,
            tag_size: i.tag_size,
            sector_size: i.sector_size,
            buffer_sectors: i.buffer_sectors,
            integrity: ptr::null(), // always null
            integrity_key_size: 0,  // always 0
            journal_integrity: c_journal_integrity.as_ptr(),
            journal_integrity_key: ptr::null(), // only for crypt_load
            journal_integrity_key_size: 0,      // only for crypt_load
            journal_crypt: c_journal_crypt.as_ptr(),
            journal_crypt_key: ptr::null(), // only for crypt_load
            journal_crypt_key_size: 0,      // only for crypt_load
        };

        (res, (c_journal_integrity, c_journal_crypt))
    });

    let maybe_data_device = data_device
        .map(|p| p.to_str())
        .flatten()
        .map(|s| ffi::CString::new(s).unwrap());
    let maybe_label = label.map(|l| ffi::CString::new(l).unwrap());
    let maybe_subsystem = subsystem.map(|s| ffi::CString::new(s).unwrap());

    let mut luks2_params = raw::crypt_params_luks2 {
        pbkdf: maybe_pbkdf
            .as_ref()
            .map_or(ptr::null(), |(p, _)| p as *const raw::crypt_pbkdf_type),
        integrity: maybe_integrity.as_ref().map_or(ptr::null(), |(_, (i, _))| i.as_ptr()),
        integrity_params: maybe_integrity
            .as_ref()
            .map_or(ptr::null(), |(i, _)| i as *const raw::crypt_params_integrity),
        data_alignment,
        data_device: maybe_data_device.as_ref().map_or(ptr::null(), |d| d.as_ptr()),
        sector_size,
        label: maybe_label.as_ref().map_or(ptr::null(), |l| l.as_ptr()),
        subsystem: maybe_subsystem.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
    };
    let c_luks2_params: *mut raw::crypt_params_luks2 = &mut luks2_params;

    let res = generic_format(
        cd,
        cipher,
        cipher_mode,
        mk_bits,
        maybe_uuid,
        raw::crypt_device_type::LUKS2,
        c_luks2_params as *mut libc::c_void,
    );

    let _discard = (
        maybe_pbkdf,
        maybe_integrity,
        maybe_data_device,
        maybe_label,
        maybe_subsystem,
        luks2_params,
    );
    res
}

#[repr(i32)]
pub enum TokenHandlerResult {
    Success = 0,
    Failure = 1,
}

/// In-memory representation of handler (needed because cryptsetup doesn't copy the handler struct)
pub struct Luks2TokenHandlerBox<H>
where
    H: Luks2TokenHandler + Luks2TokenHandlerRaw,
{
    _c_name: ffi::CString,
    c_handler: Box<raw::crypt_token_handler>,
    _handler: PhantomData<H>,
}

impl<H: Luks2TokenHandler + Luks2TokenHandlerRaw> Luks2TokenHandlerBox<H> {
    pub fn new() -> Luks2TokenHandlerBox<H> {
        let c_name = ffi::CString::new(H::name()).expect("valid name");
        let c_handler = Box::new(raw::crypt_token_handler {
            name: c_name.as_ptr(),
            open: H::raw_open_func,
            buffer_free: Some(H::raw_free_func),
            validate: Some(H::raw_validate_func),
            dump: Some(H::raw_dump_func),
        });
        Luks2TokenHandlerBox {
            _c_name: c_name,
            c_handler,
            _handler: PhantomData,
        }
    }
}

/// Equivalence trait for `raw::crypt_token_handler`
///
/// The implementation makes use of traits to generate the raw C functions as a default trait implementation in
/// `Luks2TokenHandlerRaw`. There isn't really an alternative (safe) way to create the C functions because the
/// libcryptsetup interface does not offer user pointers as parameters on all of the callback functions (eliminating
/// the possibility of using boxed closures)
pub trait Luks2TokenHandler {
    /// Display name of token handler
    fn name() -> &'static str;

    /// Return the key (the vector returned will be disowned and passed to the free function later)
    fn open(cd: RawDevice, token_id: Luks2TokenId) -> (Vec<u8>, TokenHandlerResult);

    /// Free the key (by passing it the reconstructed) vector
    fn free(buf: Vec<u8>);

    /// Whether the handler can validate json
    fn can_validate() -> bool;

    /// Validate the token handler JSON representation
    fn is_valid(cd: RawDevice, json: String) -> Option<TokenHandlerResult>;

    /// Dump debug information about the token handler implementation
    fn dump(cd: RawDevice, json: String);
}

/// Companion trait to `Luks2TokenHandler` which contains the raw FFI implementation. Users should implement this trait
/// but not override the implementation.
pub trait Luks2TokenHandlerRaw: Luks2TokenHandler {
    extern "C" fn raw_open_func(
        cd: *mut raw::crypt_device,
        token: libc::c_int,
        buffer: *mut *mut libc::c_char,
        buffer_len: *mut libc::size_t,
        _usrptr: *mut libc::c_void,
    ) -> libc::c_int {
        let (mut buf, res) = Self::open(cd, token as Luks2TokenId);

        // capacity shrinking is approximate, but we only have a single pointer :/
        buf.shrink_to_fit();
        assert!(buf.capacity() == buf.len());

        let buf_ptr = buf.as_mut_ptr();
        let len = buf.len();
        mem::forget(buf);

        unsafe {
            *buffer = buf_ptr as *mut libc::c_char;
            *buffer_len = len as libc::size_t;
        }

        res as i32 as libc::c_int
    }

    extern "C" fn raw_free_func(buffer: *mut libc::c_void, buffer_len: libc::size_t) {
        let buf = unsafe { Vec::from_raw_parts(buffer as *mut libc::c_char as *mut u8, buffer_len, buffer_len) };
        Self::free(buf)
    }

    extern "C" fn raw_dump_func(cd: *mut raw::crypt_device, token_json: *const libc::c_char) {
        let json = str_from_c_str(token_json).map_or_else(|| String::new(), |s| s.to_string());
        Self::dump(cd, json)
    }

    extern "C" fn raw_validate_func(cd: *mut raw::crypt_device, token_json: *const libc::c_char) -> libc::c_int {
        let res = if Self::can_validate() {
            let json = str_from_c_str(token_json).map_or_else(|| String::new(), |s| s.to_string());
            Self::is_valid(cd, json).expect("validation result")
        } else {
            TokenHandlerResult::Success
        };

        res as i32 as libc::c_int
    }
}

/// Register a LUKS2 token handler
///
/// Note: the implementation relies on a struct with a box containing the actual handler C struct. The handler C struct
///     must not be deallocated while the handler is registered.
pub fn luks2_register_token_handler<H: Luks2TokenHandlerRaw>(handler_box: &Luks2TokenHandlerBox<H>) -> Result<()> {
    let res = unsafe { raw::crypt_token_register(handler_box.c_handler.as_ref()) };
    check_crypt_error!(res)
}

/// Get the status of LUKS2 token id (and if successful, the type name of the token)
pub fn luks2_token_status(cd: &mut RawDevice, token_id: Luks2TokenId) -> (raw::crypt_token_info, Option<String>) {
    let mut type_ptr: *const libc::c_char = ptr::null();
    let res =
        unsafe { raw::crypt_token_status(*cd, token_id as libc::c_int, &mut type_ptr as *mut *const libc::c_char) };

    let token_type = if !type_ptr.is_null() {
        str_from_c_str(type_ptr).map(|s| s.to_string())
    } else {
        None
    };

    (res, token_type)
}

/// Get the token's JSON value for a token id
pub fn luks2_token_json(cd: &mut RawDevice, token_id: Luks2TokenId) -> Result<String> {
    let mut json_ptr: *const libc::c_char = ptr::null();
    let res =
        unsafe { raw::crypt_token_json_get(*cd, token_id as libc::c_int, &mut json_ptr as *mut *const libc::c_char) };

    if res < 0 {
        crypt_error!(res)
    } else {
        let json = str_from_c_str(json_ptr)
            .map(|s| s.to_string())
            .expect("valid json string");
        Ok(json)
    }
}

/// Set the token's JSON value and allocate it to a token id (new token id will be allocated if no token id is passed)
///
/// Note: the JSON string passed in must have a "type" field with the token handler type and a list of "keyslots"
pub fn luks2_token_json_allocate(
    cd: &mut RawDevice,
    json: &str,
    token_id: Option<Luks2TokenId>,
) -> Result<Luks2TokenId> {
    let c_json = ffi::CString::new(json).unwrap();

    println!("BEFORE JSON ALLOCATE: {}", json);

    let res = unsafe { raw::crypt_token_json_set(*cd, token_id.unwrap_or(raw::CRYPT_ANY_TOKEN), c_json.as_ptr()) };
    let _deferred = (c_json,);

    if res < 0 {
        crypt_error!(res)
    } else {
        Ok(res as Luks2TokenId)
    }
}

/// Removes a token by its id
pub fn luks2_token_remove(cd: &mut RawDevice, token_id: Luks2TokenId) -> Result<()> {
    let res = unsafe { raw::crypt_token_json_set(*cd, token_id, ptr::null()) };

    check_crypt_error!(res)
}

/// Assigns a token id to a keyslot (or, if no keyslot is specified, all active keyslots)
pub fn luks2_token_assign_keyslot(cd: &mut RawDevice, token_id: Luks2TokenId, keyslot: Option<Keyslot>) -> Result<()> {
    let res = unsafe {
        raw::crypt_token_assign_keyslot(
            *cd,
            token_id,
            keyslot.map_or(raw::CRYPT_ANY_SLOT, |ks| ks as libc::c_int),
        )
    };

    check_crypt_error!(res)
}

/// Unassigns a token id from a keyslot (or, if no keyslot is specified, all active keyslots)
pub fn luks2_token_unassign_keyslot(
    cd: &mut RawDevice,
    token_id: Luks2TokenId,
    keyslot: Option<Keyslot>,
) -> Result<()> {
    let res = unsafe {
        raw::crypt_token_unassign_keyslot(
            *cd,
            token_id,
            keyslot.map_or(raw::CRYPT_ANY_SLOT, |ks| ks as libc::c_int),
        )
    };

    check_crypt_error!(res)
}

/// Get information about token assignment for a particular keyslot
pub fn luks2_token_is_assigned(cd: &mut RawDevice, token_id: Luks2TokenId, keyslot: Keyslot) -> Result<bool> {
    let res = unsafe { raw::crypt_token_is_assigned(*cd, token_id, keyslot as libc::c_int) };

    if res == 0 {
        Ok(true)
    } else if res == libc::ENOENT {
        Ok(false)
    } else {
        crypt_error!(res)
    }
}

/// Activate device, or when name is not provided, check the key can open the device
pub fn luks2_activate_by_token(
    cd: &mut RawDevice,
    name: Option<&str>,
    token_id: Option<Luks2TokenId>,
) -> Result<Keyslot> {
    let c_name_opt = name.and_then(|n| ffi::CString::new(n).ok());

    let res = unsafe {
        raw::crypt_activate_by_token(
            *cd,
            c_name_opt.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            token_id.unwrap_or(raw::CRYPT_ANY_TOKEN),
            ptr::null_mut(),
            0,
        )
    };

    let _deferred = (c_name_opt,);

    if res < 0 {
        crypt_error!(res)
    } else {
        Ok(res as Keyslot)
    }
}

pub fn luks2_set_pbkdf_type(cd: &mut RawDevice, pbkdf: &Luks2FormatPbkdf) -> Result<()> {
    let c_type = ffi::CString::new(pbkdf.type_.to_str()).unwrap();
    let c_hash = ffi::CString::new(pbkdf.hash).unwrap();

    let c_pbkdf_type = raw::crypt_pbkdf_type {
        type_: c_type.as_ptr(),
        hash: c_hash.as_ptr(),
        time_ms: pbkdf.time_ms,
        iterations: pbkdf.iterations,
        max_memory_kb: pbkdf.max_memory_kb,
        parallel_threads: pbkdf.parallel_threads,
        flags: pbkdf.flags,
    };

    let res = unsafe { raw::crypt_set_pbkdf_type(*cd, &c_pbkdf_type as *const raw::crypt_pbkdf_type) };

    let _discard = (c_type, c_hash, c_pbkdf_type);

    check_crypt_error!(res)
}

/// Get which RNG is used
pub fn rng_type(cd: &RawDevice) -> raw::crypt_rng_type {
    unsafe {
        let res = raw::crypt_get_rng_type(*cd);
        mem::transmute(res)
    }
}

/// Set the number of milliseconds for `PBKDF2` function iteration
#[deprecated]
pub fn set_iteration_time(cd: &mut RawDevice, iteration_time_ms: u64) {
    unsafe {
        #[allow(deprecated)]
        raw::crypt_set_iteration_time(*cd, iteration_time_ms);
    }
}

/// Set which RNG is used
pub fn set_rng_type(cd: &mut RawDevice, rng_type: raw::crypt_rng_type) {
    unsafe { raw::crypt_set_rng_type(*cd, rng_type) }
}

/// Get information about a keyslot
pub fn keyslot_status(cd: &RawDevice, slot: Keyslot) -> raw::crypt_keyslot_info {
    unsafe { raw::crypt_keyslot_status(*cd, slot as libc::c_int) }
}

/// Get size in bytes of the volume key
pub fn volume_key_size(cd: &RawDevice) -> u8 {
    let res = unsafe { raw::crypt_get_volume_key_size(*cd) };
    res as u8
}

/// Get device UUID
pub fn uuid(cd: &RawDevice) -> Option<Uuid> {
    let c_uuid_str = unsafe { raw::crypt_get_uuid(*cd) };
    str_from_c_str(c_uuid_str).and_then(|uuid_str| Uuid::parse_str(uuid_str).ok())
}
