//! High-level API to work with `libcryptsetup` supported devices (disks)
//! The main focus is on LUKS1 and LUKS2 devices

use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::ptr;

use blkid_rs::{Luks1Header, Luks2Header, LuksHeader, LuksVersionedHeader};

use crate::device::RawDevice;
pub use crate::device::{Error, Keyslot, Result};
pub use crate::global::enable_debug;
use either::Either;
use either::Either::{Left, Right};
use raw;
use uuid;
use uuid::Uuid;

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

fn load_luks1_params<P: AsRef<Path>>(path: P) -> Result<Luks1Params> {
    let device_file = File::open(path.as_ref())?;
    match LuksHeader::read(device_file)? {
        LuksHeader::Luks1(v1) => Luks1Params::from(v1),
        _ => Err(Error::InvalidLuksVersion),
    }
}

fn load_luks2_params<P: AsRef<Path>>(path: P) -> Result<Luks2Params> {
    let device_file = File::open(path.as_ref())?;
    match LuksHeader::read(device_file)? {
        LuksHeader::Luks2(v2) => Luks2Params::from(v2),
        _ => Err(Error::InvalidLuksVersion),
    }
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
        let params = load_luks1_params(&self.path)?;
        Ok(CryptDeviceHandle {
            cd: self.cd,
            path: self.path,
            params,
        })
    }

    /// Loads an existing LUKS2 crypt device
    pub fn luks2(self: CryptDeviceOpenBuilder) -> Result<CryptDeviceHandle<Luks2Params>> {
        let _ = crate::device::load(&self.cd, raw::crypt_device_type::LUKS2);
        let params = load_luks2_params(&self.path)?;
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

impl CryptDeviceFormatBuilder {
    /// Set the iteration time for the `PBKDF2` function. Note that this does not affect the MK iterations.
    pub fn iteration_time(mut self, iteration_time_ms: u64) -> Self {
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
        let params = load_luks1_params(&self.path)?;
        Ok(CryptDeviceHandle {
            cd: self.cd,
            path: self.path,
            params,
        })
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
}

/// Trait representing specific operations on a LUKS1 device
pub trait Luks1CryptDevice: LuksCryptDevice {
    /// Add a new keyslot with the specified key
    fn add_keyslot(
        &mut self,
        key: &[u8],
        maybe_prev_key: Option<&[u8]>,
        maybe_keyslot: Option<Keyslot>,
    ) -> Result<Keyslot>;

    /// Replace an old key with a new one
    fn update_keyslot(&mut self, key: &[u8], prev_key: &[u8], maybe_keyslot: Option<Keyslot>) -> Result<Keyslot>;

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
pub trait Luks2CryptDevice: LuksCryptDevice {}

/// An opaque handle on an initialized crypt device
#[derive(PartialEq)]
pub struct CryptDeviceHandle<P: fmt::Debug> {
    /// Pointer to the raw device
    cd: RawDevice,

    /// Path to the crypt device (useful for diagnostics)
    path: PathBuf,

    /// Additional parameters depending on type of crypt device opened
    params: P,
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
        crate::device::set_iteration_time(&mut self.cd, iteration_time_ms)
    }

    fn volume_key_size(&self) -> u8 {
        crate::device::volume_key_size(&self.cd)
    }
}

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
}

impl Luks1CryptDevice for CryptDeviceHandle<Luks1Params> {
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
    fn from(header: impl Luks2Header) -> Result<Luks2Params> {
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
