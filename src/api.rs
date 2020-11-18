//! High-level API to work with `libcryptsetup` supported devices (disks)
//! The main focus is on LUKS1 and LUKS2 devices

use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::ptr;

use either::Either;
use either::Either::{Left, Right};
use uuid;

use blkid_rs::{LuksHeader, LuksVersionedHeader};
use raw;
pub use raw::{crypt_pbkdf_algo_type, crypt_token_info};

pub use crate::device::{
    Error, Keyslot, Luks2TokenHandler, Luks2TokenHandlerBox, Luks2TokenHandlerRaw, Luks2TokenId, Result,
};
use crate::device::{Luks2FormatPbkdf, RawDevice};
pub use crate::global::enable_debug;
use crate::luks1::Luks1Params;
use crate::luks2::Luks2Params;
pub use crate::luks2_meta::{Luks2Metadata, Luks2Token};

pub type Luks1CryptDeviceHandle = CryptDeviceHandle<Luks1Params>;
pub type Luks2CryptDeviceHandle = CryptDeviceHandle<Luks2Params>;

/// Builder to open a crypt device at the specified path
///
/// # Examples
///
/// ```
/// use cryptsetup_rs::*;
/// # fn foo() -> Result<()> {
/// let device = open("/dev/loop0")?.luks1()?;
/// # Ok(())
/// # }
/// ```
pub fn open<P: AsRef<Path>>(path: P) -> Result<CryptDeviceOpenBuilder> {
    let cd = crate::device::init(path.as_ref())?;
    Ok(CryptDeviceOpenBuilder {
        path: path.as_ref().to_owned(),
        cd,
    })
}

/// Builder to format a crypt device at the specified path
///
/// # Examples
///
/// ```
/// # extern crate uuid;
/// # extern crate cryptsetup_rs;
/// use cryptsetup_rs::*;
/// use uuid::Uuid;
///
/// # fn foo() -> Result<()> {
/// let uuid = Uuid::new_v4();
/// let device = format("/dev/loop0")?
///     .rng_type(crypt_rng_type::CRYPT_RNG_URANDOM)
///     .iteration_time(5000)
///     .luks1("aes", "xts-plain", "sha256", 256, Some(&uuid))?;
/// # Ok(())
/// # }
/// ```
///
/// For LUKS2:
///
/// ```
/// # extern crate cryptsetup_rs;
/// use cryptsetup_rs::*;
///
/// # fn foo() -> Result<()> {
/// let device = format("/dev/loop0")?
///     .luks2("aes", "xts-plain", 256, None, None, None)
///     .label("test")
///     .argon2i("sha256", 200, 1, 1024, 1)
///     .start();
/// # Ok(())
/// # }
/// ```
///
pub fn format<P: AsRef<Path>>(path: P) -> Result<CryptDeviceFormatBuilder> {
    let cd = crate::device::init(path.as_ref())?;
    Ok(CryptDeviceFormatBuilder {
        path: path.as_ref().to_owned(),
        cd,
    })
}

/// Read the LUKS version used by a LUKS container without opening the device
pub fn luks_version<P: AsRef<Path>>(path: P) -> Result<u16> {
    let device_file = File::open(path.as_ref())?;
    let header = LuksHeader::read(device_file)?;
    Ok(header.version())
}

/// Read the LUKS version used by a LUKS container without opening the device
pub fn luks_uuid<P: AsRef<Path>>(path: P) -> Result<uuid::Uuid> {
    let device_file = File::open(path.as_ref())?;
    let uuid = LuksHeader::read(device_file)?.uuid()?;
    Ok(uuid)
}

/// Read the UUID of a LUKS1 container without opening the device
///
/// Please use `luks_uuid()` instead
#[deprecated]
pub fn luks1_uuid<P: AsRef<Path>>(path: P) -> Result<uuid::Uuid> {
    luks_uuid(path)
}

/// Struct containing state for the `open()` builder
pub struct CryptDeviceOpenBuilder {
    path: PathBuf,
    cd: RawDevice,
}

impl CryptDeviceOpenBuilder {
    /// Loads an existing LUKS1 crypt device
    pub fn luks1(self: CryptDeviceOpenBuilder) -> Result<CryptDeviceHandle<Luks1Params>> {
        let _ = crate::device::load(&self.cd, raw::crypt_device_type::LUKS1);
        let params = Luks1Params::from_path(&self.path)?;
        Ok(CryptDeviceHandle {
            cd: self.cd,
            path: self.path,
            params,
        })
    }

    /// Loads an existing LUKS2 crypt device
    pub fn luks2(self: CryptDeviceOpenBuilder) -> Result<CryptDeviceHandle<Luks2Params>> {
        let _ = crate::device::load(&self.cd, raw::crypt_device_type::LUKS2);
        let params = Luks2Params::from_path(&self.path)?;
        Ok(CryptDeviceHandle {
            cd: self.cd,
            path: self.path,
            params,
        })
    }

    pub fn luks(
        self: CryptDeviceOpenBuilder,
    ) -> Result<Either<CryptDeviceHandle<Luks1Params>, CryptDeviceHandle<Luks2Params>>> {
        match luks_version(&self.path)? {
            1 => self.luks1().map(|d| Left(d)),
            2 => self.luks2().map(|d| Right(d)),
            _ => Err(Error::InvalidLuksVersion),
        }
    }
}

/// Struct containing state for the `format()` builder
pub struct CryptDeviceFormatBuilder {
    path: PathBuf,
    cd: RawDevice,
}

#[derive(Default)]
struct Luks2FormatBuilderParams<'a> {
    label: Option<&'a str>,
    subsystem: Option<&'a str>,
    data_device: Option<&'a Path>,
    pbkdf: Option<Luks2FormatPbkdf<'a>>,
}

pub struct CryptDeviceLuks2FormatBuilder<'a> {
    path: PathBuf,
    cd: RawDevice,
    // common params
    cipher: &'a str,
    cipher_mode: &'a str,
    mk_bits: usize,
    maybe_uuid: Option<&'a uuid::Uuid>,
    // luks2 specifics
    data_alignment: usize,
    sector_size: u32,
    other: Luks2FormatBuilderParams<'a>,
}

impl<'a> CryptDeviceLuks2FormatBuilder<'a> {
    /// Set device primary label
    pub fn label(mut self, label: &'a str) -> Self {
        self.other.label = Some(label);
        self
    }

    /// Set device secondary label, 'subsystem'
    pub fn subsystem(mut self, subsystem: &'a str) -> Self {
        self.other.subsystem = Some(subsystem);
        self
    }

    /// Set path to data device (this will result in a split header)
    pub fn data_device(mut self, p: &'a Path) -> Self {
        self.other.data_device = Some(p);
        self
    }

    /// Set PBKDF parameters for pbkdf2
    pub fn pbkdf2(mut self, hash: &'a str, time_ms: u32, iterations: u32) -> Self {
        self.other.pbkdf = Some(Luks2FormatPbkdf {
            type_: crypt_pbkdf_algo_type::pbkdf2,
            hash,
            time_ms,
            iterations,
            max_memory_kb: 0,
            parallel_threads: 0,
            flags: 0,
        });
        self
    }

    /// Set PBKDF parameters for argon2i
    pub fn argon2i(
        mut self,
        hash: &'a str,
        time_ms: u32,
        iterations: u32,
        max_memory_kb: u32,
        parallel_threads: u32,
    ) -> Self {
        self.other.pbkdf = Some(Luks2FormatPbkdf {
            type_: crypt_pbkdf_algo_type::argon2i,
            hash,
            time_ms,
            iterations,
            max_memory_kb,
            parallel_threads,
            flags: 0,
        });
        self
    }

    /// Set PBKDF parameters for argon2id
    pub fn argon2id(
        mut self,
        hash: &'a str,
        time_ms: u32,
        iterations: u32,
        max_memory_kb: u32,
        parallel_threads: u32,
    ) -> Self {
        self.other.pbkdf = Some(Luks2FormatPbkdf {
            type_: crypt_pbkdf_algo_type::argon2id,
            hash,
            time_ms,
            iterations,
            max_memory_kb,
            parallel_threads,
            flags: 0,
        });
        self
    }

    /// Format a new block device as a LUKS2 crypt device with specified parameters
    pub fn start(mut self) -> Result<CryptDeviceHandle<Luks2Params>> {
        let _ = crate::device::luks2_format(
            &mut self.cd,
            self.cipher,
            self.cipher_mode,
            self.mk_bits,
            self.data_alignment,
            self.sector_size,
            self.other.label,
            self.other.subsystem,
            self.other.data_device,
            self.maybe_uuid,
            self.other.pbkdf.as_ref(),
            None,
        )?;
        let params = Luks2Params::from_path(&self.path)?;
        Ok(CryptDeviceHandle {
            cd: self.cd,
            path: self.path,
            params,
        })
    }
}

impl CryptDeviceFormatBuilder {
    /// Set the iteration time for the `PBKDF2` function. Note that this does not affect the MK iterations.
    pub fn iteration_time(mut self, iteration_time_ms: u64) -> Self {
        #[allow(deprecated)]
        crate::device::set_iteration_time(&mut self.cd, iteration_time_ms);
        self
    }

    /// Set the random number generator to use
    pub fn rng_type(mut self, rng_type: raw::crypt_rng_type) -> Self {
        crate::device::set_rng_type(&mut self.cd, rng_type);
        self
    }

    /// Formats a new block device as a LUKS1 crypt device with the specified parameters
    pub fn luks1(
        mut self: CryptDeviceFormatBuilder,
        cipher: &str,
        cipher_mode: &str,
        hash: &str,
        mk_bits: usize,
        maybe_uuid: Option<&uuid::Uuid>,
    ) -> Result<CryptDeviceHandle<Luks1Params>> {
        let _ = crate::device::luks1_format(&mut self.cd, cipher, cipher_mode, hash, mk_bits, maybe_uuid)?;
        let params = Luks1Params::from_path(&self.path)?;
        Ok(CryptDeviceHandle {
            cd: self.cd,
            path: self.path,
            params,
        })
    }

    /// Set the format to LUKS2, and build further options
    pub fn luks2<'a>(
        self: CryptDeviceFormatBuilder,
        cipher: &'a str,
        cipher_mode: &'a str,
        mk_bits: usize,
        maybe_uuid: Option<&'a uuid::Uuid>,
        maybe_data_alignment: Option<u32>,
        maybe_sector_size: Option<u32>,
    ) -> CryptDeviceLuks2FormatBuilder<'a> {
        CryptDeviceLuks2FormatBuilder {
            path: self.path,
            cd: self.cd,
            cipher,
            cipher_mode,
            mk_bits,
            maybe_uuid,
            data_alignment: maybe_data_alignment.unwrap_or(0) as usize,
            sector_size: maybe_sector_size.unwrap_or(512),
            other: Default::default(),
        }
    }
}

/// Trait representing common operations on a crypt device
pub trait CryptDevice {
    /// Path the device was opened/created with
    fn path(&self) -> &Path;

    /// Name of cipher used
    fn cipher(&self) -> &str;

    /// Name of cipher mode used
    fn cipher_mode(&self) -> &str;

    /// Path to the underlying device (as reported by `libcryptsetup`)
    fn device_name(&self) -> &str;

    /// Random number generator used for operations on this crypt device
    fn rng_type(&self) -> raw::crypt_rng_type;

    /// Sets the random number generator to use
    fn set_rng_type(&mut self, rng_type: raw::crypt_rng_type);

    /// Sets the iteration time for the `PBKDF2` function. Note that this does not affect the MK iterations.
    fn set_iteration_time(&mut self, iteration_time_ms: u64);

    /// Volume key size (in bytes)
    fn volume_key_size(&self) -> u8;
}

/// Trait for querying the device type at runtime
pub trait CryptDeviceType {
    /// Type of the crypt device
    fn device_type(&self) -> raw::crypt_device_type;
}

// TODO: consider different state for activated device, this would require tracking status

pub trait LuksCryptDevice: CryptDevice + CryptDeviceType {
    /// Activate the crypt device, and give it the specified name
    fn activate(&mut self, name: &str, key: &[u8]) -> Result<Keyslot>;

    /// Deactivate the crypt device, remove the device-mapper mapping and key information from kernel
    fn deactivate(self, name: &str) -> Result<()>;

    /// Destroy (and disable) key slot
    fn destroy_keyslot(&mut self, slot: Keyslot) -> Result<()>;

    /// Get status of key slot
    fn keyslot_status(&self, keyslot: Keyslot) -> raw::crypt_keyslot_info;

    /// Dump text-formatted information about the current device to stdout
    fn dump(&self);

    /// UUID of the current device
    fn uuid(&self) -> uuid::Uuid;

    /// Add a new keyslot with the specified key
    fn add_keyslot(
        &mut self,
        key: &[u8],
        maybe_prev_key: Option<&[u8]>,
        maybe_keyslot: Option<Keyslot>,
    ) -> Result<Keyslot>;

    /// Replace an old key with a new one
    fn update_keyslot(&mut self, key: &[u8], prev_key: &[u8], maybe_keyslot: Option<Keyslot>) -> Result<Keyslot>;
}

/// Trait representing specific operations on a LUKS1 device
pub trait Luks1CryptDevice: LuksCryptDevice {
    /// Get the hash algorithm used
    fn hash_spec(&self) -> &str;

    /// Number of bits in the master key
    fn mk_bits(&self) -> u32;

    /// Master key header digest
    fn mk_digest(&self) -> &[u8; 20];

    /// Master key `PBKDF2` iterations
    fn mk_iterations(&self) -> u32;

    /// Master key salt
    fn mk_salt(&self) -> &[u8; 32];

    /// Get the offset of the payload
    fn payload_offset(&self) -> u32;
}

/// Trait representing specific operations on a LUKS2 device
pub trait Luks2CryptDevice: LuksCryptDevice {
    /// Register a LUKS2 token handler
    fn register_new_token_handler<Handler: Luks2TokenHandlerRaw>() -> Result<Luks2TokenHandlerBox<Handler>>;

    /// Register a LUKS2 token handler given a reference to it
    fn register_token_handler<Handler: Luks2TokenHandlerRaw>(handler: &Luks2TokenHandlerBox<Handler>) -> Result<()>;

    /// Get token status for a given token id
    fn token_status(&mut self, token_id: Luks2TokenId) -> (crypt_token_info, Option<String>);

    /// Get a token by id
    fn get_token(&mut self, token_id: Luks2TokenId) -> Result<Luks2Token>;

    /// Add a token with a specific id
    fn add_token_with_id(&mut self, token: &Luks2Token, token_id: Luks2TokenId) -> Result<()>;

    /// Add a token, returning the allocated token id
    fn add_token(&mut self, token: &Luks2Token) -> Result<Luks2TokenId>;

    /// Remove a token by id
    fn remove_token(&mut self, token_id: Luks2TokenId) -> Result<()>;

    /// Assign a token id to a keyslot (or all active keyslots if no keyslot is specified)
    fn assign_token_to_keyslot(&mut self, token_id: Luks2TokenId, keyslot_opt: Option<Keyslot>) -> Result<()>;

    /// Unassing a token from a keyslot (or all active keyslots if no keyslot is specified)
    fn unassign_token_keyslot(&mut self, token_id: Luks2TokenId, keyslot_opt: Option<Keyslot>) -> Result<()>;

    /// Check whether a token is assigned to a given keyslot
    fn token_keyslot_is_assigned(&mut self, token_id: Luks2TokenId, keyslot: Keyslot) -> Result<bool>;

    /// Activate the crypt device with the specified name and token
    fn activate_with_token(&mut self, name: &str, token_id: Luks2TokenId) -> Result<Keyslot>;

    /// Check activation of a device with a token
    fn check_activation_with_token(&mut self, token_id: Luks2TokenId) -> Result<Keyslot>;

    /// Set PBKDF parameters (used during next keyslot registration)
    fn set_pbkdf_params(
        &mut self,
        type_: crypt_pbkdf_algo_type,
        hash: &str,
        time_ms: u32,
        iterations: u32,
        max_memory_kb: u32,
        parallel_threads: u32,
    ) -> Result<()>;
}

/// An opaque handle on an initialized crypt device
#[derive(PartialEq)]
pub struct CryptDeviceHandle<P: fmt::Debug> {
    /// Pointer to the raw device
    pub(crate) cd: RawDevice,

    /// Path to the crypt device (useful for diagnostics)
    pub(crate) path: PathBuf,

    /// Additional parameters depending on type of crypt device opened
    pub(crate) params: P,
}

impl<P: fmt::Debug> fmt::Debug for CryptDeviceHandle<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CryptDeviceHandle(path={}, raw={:p}, params={:?})",
            self.path.display(),
            self.cd,
            self.params
        )
    }
}

impl<P: fmt::Debug> Drop for CryptDeviceHandle<P> {
    fn drop(&mut self) {
        crate::device::free(&mut self.cd);
        self.cd = ptr::null_mut();
    }
}

impl<P: fmt::Debug> CryptDevice for CryptDeviceHandle<P> {
    fn path(&self) -> &Path {
        self.path.as_ref()
    }

    fn cipher(&self) -> &str {
        crate::device::cipher(&self.cd).expect("Initialised device should have cipher")
    }

    fn cipher_mode(&self) -> &str {
        crate::device::cipher_mode(&self.cd).expect("Initialised device should have cipher mode")
    }

    fn device_name(&self) -> &str {
        crate::device::device_name(&self.cd).expect("Initialised device should have an underlying path")
    }

    fn rng_type(&self) -> raw::crypt_rng_type {
        crate::device::rng_type(&self.cd)
    }

    fn set_rng_type(&mut self, rng_type: raw::crypt_rng_type) {
        crate::device::set_rng_type(&mut self.cd, rng_type)
    }

    fn set_iteration_time(&mut self, iteration_time_ms: u64) {
        #[allow(deprecated)]
        crate::device::set_iteration_time(&mut self.cd, iteration_time_ms)
    }

    fn volume_key_size(&self) -> u8 {
        crate::device::volume_key_size(&self.cd)
    }
}
