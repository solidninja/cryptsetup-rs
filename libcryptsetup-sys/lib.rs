#![deny(warnings)]
#![allow(non_camel_case_types)]
extern crate libc;

use libc::{c_char, c_double, c_int, c_uint, c_void, size_t};
use std::str::FromStr;

// custom enums (to model strings)

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_device_type {
    PLAIN,
    LUKS1,
    LUKS2,
    LOOPAES,
    VERITY,
    TCRYPT,
    INTEGRITY,
    BITLK,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_pbkdf_algo_type {
    pbkdf2,
    argon2i,
    argon2id,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum reencrypt_resilience_mode {
    none,
    checksum,
    journal,
    shift,
}

// end custom enums

pub enum crypt_device {}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_log_level {
    CRYPT_LOG_NORMAL = 0,
    CRYPT_LOG_ERROR = 1,
    CRYPT_LOG_VERBOSE = 2,
    CRYPT_LOG_DEBUG = -1,
    CRYPT_LOG_DEBUG_JSON = -2,
}

pub type crypt_log_cb = extern "C" fn(crypt_log_level, *const c_char, *mut c_void);
pub type crypt_confirm_cb = extern "C" fn(*const c_char, *mut c_void) -> c_int;
pub type crypt_benchmark_cb = extern "C" fn(u32, *mut c_void) -> c_int;
pub type crypt_write_op_cb = extern "C" fn(u64, u64, *mut c_void) -> c_int;

pub type crypt_token_open_func =
    extern "C" fn(*mut crypt_device, c_int, *mut *mut c_char, *mut size_t, *mut c_void) -> c_int;
pub type crypt_token_buffer_free_func = extern "C" fn(*mut c_void, size_t);
pub type crypt_token_validate_func = extern "C" fn(*mut crypt_device, *const c_char) -> c_int;
pub type crypt_token_dump_func = extern "C" fn(*mut crypt_device, *const c_char);

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_rng_type {
    CRYPT_RNG_URANDOM = 0,
    CRYPT_RNG_RANDOM = 1,
}

#[repr(C)]
pub struct crypt_pbkdf_type {
    pub type_: *const c_char,
    pub hash: *const c_char,
    pub time_ms: u32,
    pub iterations: u32,
    pub max_memory_kb: u32,
    pub parallel_threads: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_pbkdf_flag {
    CRYPT_PBKDF_ITER_TIME_SET = 1 << 0,
    CRYPT_PBKDF_NO_BENCHMARK = 1 << 1,
}

#[repr(C)]
pub struct crypt_params_plain {
    pub hash: *const c_char,
    pub offset: u64,
    pub skip: u64,
    pub size: u64,
    pub sector_size: u32,
}

#[repr(C)]
pub struct crypt_params_luks1 {
    pub hash: *const c_char,
    pub data_alignment: size_t,
    pub data_device: *const c_char,
}

#[repr(C)]
pub struct crypt_params_loopaes {
    pub hash: *const c_char,
    pub offset: u64,
    pub skip: u64,
}

#[repr(C)]
pub struct crypt_params_verity {
    pub hash_name: *const c_char,
    pub data_device: *const c_char,
    pub hash_device: *const c_char,
    pub fec_device: *const c_char,
    pub salt: *const c_char,
    pub salt_size: u32,
    pub hash_type: u32,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_size: u64,
    pub hash_area_offset: u64,
    pub fec_area_offset: u64,
    pub fec_roots: u32,
    pub flags: u32,
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_verity_flag {
    CRYPT_VERITY_NO_HEADER = 1 << 0,
    CRYPT_VERITY_CHECK_HASH = 1 << 1,
    CRYPT_VERITY_CREATE_HASH = 1 << 2,
    CRYPT_VERITY_ROOT_HASH_SIGNATURE = 1 << 3,
}

#[repr(C)]
pub struct crypt_params_tcrypt {
    pub passphrase: *const c_char,
    pub passphrase_size: size_t,
    pub keyfiles: *mut *const c_char,
    pub keyfiles_count: c_uint,
    pub hash_name: *const c_char,
    pub cipher: *const c_char,
    pub mode: *const c_char,
    pub key_size: size_t,
    pub flags: u32,
    pub veracrypt_pim: u32,
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_tcrypt_flag {
    CRYPT_TCRYPT_LEGACY_MODES = 1 << 0,
    CRYPT_TCRYPT_HIDDEN_HEADER = 1 << 1,
    CRYPT_TCRYPT_BACKUP_HEADER = 1 << 2,
    CRYPT_TCRYPT_SYSTEM_HEADER = 1 << 3,
    CRYPT_TCRYPT_VERA_MODES = 1 << 4,
}

#[repr(C)]
pub struct crypt_params_integrity {
    pub journal_size: u64,
    pub journal_watermark: c_uint,
    pub journal_commit_time: c_uint,
    pub interleave_sectors: u32,
    pub tag_size: u32,
    pub sector_size: u32,
    pub buffer_sectors: u32,
    pub integrity: *const c_char,
    pub integrity_key_size: u32,
    pub journal_integrity: *const c_char,
    pub journal_integrity_key: *const c_char,
    pub journal_integrity_key_size: u32,
    pub journal_crypt: *const c_char,
    pub journal_crypt_key: *const c_char,
    pub journal_crypt_key_size: u32,
}

#[repr(C)]
pub struct crypt_params_luks2 {
    pub pbkdf: *const crypt_pbkdf_type,
    pub integrity: *const c_char,
    pub integrity_params: *const crypt_params_integrity,
    pub data_alignment: size_t,
    pub data_device: *const c_char,
    pub sector_size: u32,
    pub label: *const c_char,
    pub subsystem: *const c_char,
}

pub const CRYPT_ANY_SLOT: c_int = -1;
pub const CRYPT_ANY_TOKEN: c_int = -1;

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_activation_flag {
    CRYPT_ACTIVATE_READONLY = 1 << 0,
    CRYPT_ACTIVATE_NO_UUID = 1 << 1,
    CRYPT_ACTIVATE_SHARED = 1 << 2,
    CRYPT_ACTIVATE_ALLOW_DISCARDS = 1 << 3,
    CRYPT_ACTIVATE_PRIVATE = 1 << 4,
    CRYPT_ACTIVATE_CORRUPTED = 1 << 5,
    CRYPT_ACTIVATE_SAME_CPU_CRYPT = 1 << 6,
    CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS = 1 << 7,
    CRYPT_ACTIVATE_IGNORE_CORRUPTION = 1 << 8,
    CRYPT_ACTIVATE_RESTART_ON_CORRUPTION = 1 << 9,
    CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS = 1 << 10,
    CRYPT_ACTIVATE_KEYRING_KEY = 1 << 11,
    CRYPT_ACTIVATE_NO_JOURNAL = 1 << 12,
    CRYPT_ACTIVATE_RECOVERY = 1 << 13,
    CRYPT_ACTIVATE_IGNORE_PERSISTENT = 1 << 14,
    CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE = 1 << 15,
    CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY = 1 << 16,
    CRYPT_ACTIVATE_RECALCULATE = 1 << 17,
    CRYPT_ACTIVATE_REFRESH = 1 << 18,
    CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF = 1 << 19,
    CRYPT_ACTIVATE_NO_JOURNAL_BITMAP = 1 << 20,
    CRYPT_ACTIVATE_SUSPENDED = 1 << 21,
}

#[repr(C)]
pub struct crypt_active_device {
    pub offset: u64,
    pub iv_offset: u64,
    pub size: u64,
    pub flags: u32,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_status_info {
    CRYPT_INVALID,
    CRYPT_INACTIVE,
    CRYPT_ACTIVE,
    CRYPT_BUSY,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_keyslot_info {
    CRYPT_SLOT_INVALID,
    CRYPT_SLOT_INACTIVE,
    CRYPT_SLOT_ACTIVE,
    CRYPT_SLOT_ACTIVE_LAST,
    CRYPT_SLOT_UNBOUND,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_debug_level {
    CRYPT_DEBUG_JSON = -2,
    CRYPT_DEBUG_ALL = -1,
    CRYPT_DEBUG_NONE = 0,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_keyslot_priority {
    CRYPT_SLOT_PRIORITY_INVALID = -1,
    CRYPT_SLOT_PRIORITY_IGNORE = 0,
    CRYPT_SLOT_PRIORITY_NORMAL = 1,
    CRYPT_SLOT_PRIORITY_PREFER = 2,
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_volume_key_flag {
    CRYPT_VOLUME_KEY_NO_SEGMENT = 1 << 0,
    CRYPT_VOLUME_KEY_SET = 1 << 1,
    CRYPT_VOLUME_KEY_DIGEST_REUSE = 1 << 2,
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_luks2_header_requirement_flag {
    CRYPT_REQUIREMENT_OFFLINE_REENCRYPT = 1 << 0,
    CRYPT_REQUIREMENT_ONLINE_REENCRYPT = 1 << 1,
    CRYPT_REQUIREMENT_UNKNOWN = 1 << 31,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_flags_type {
    CRYPT_FLAGS_ACTIVATION,
    CRYPT_FLAGS_REQUIREMENTS,
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_deactivate_flag {
    CRYPT_DEACTIVATE_DEFERRED = 1 << 0,
    CRYPT_DEACTIVATE_FORCE = 1 << 1,
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_keyfile_read_flag {
    CRYPT_KEYFILE_STOP_EOL = 1 << 0,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_wipe_pattern {
    CRYPT_WIPE_ZERO,
    CRYPT_WIPE_RANDOM,
    CRYPT_WIPE_ENCRYPTED_ZERO,
    CRYPT_WIPE_SPECIAL,
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_wipe_flag {
    CRYPT_WIPE_NO_DIRECT_IO = 1 << 0,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_token_info {
    CRYPT_TOKEN_INVALID,
    CRYPT_TOKEN_INACTIVE,
    CRYPT_TOKEN_INTERNAL,
    CRYPT_TOKEN_INTERNAL_UNKNOWN,
    CRYPT_TOKEN_EXTERNAL,
    CRYPT_TOKEN_EXTERNAL_UNKNOWN,
}

#[repr(C)]
pub struct crypt_token_handler {
    pub name: *const c_char,
    pub open: crypt_token_open_func,
    pub buffer_free: Option<crypt_token_buffer_free_func>,
    pub validate: Option<crypt_token_validate_func>,
    pub dump: Option<crypt_token_dump_func>,
}

#[repr(C)]
pub struct crypt_token_params_luks2_keyring {
    pub key_description: *const c_char,
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_reencrypt_flag {
    CRYPT_REENCRYPT_INITIALIZE_ONLY = 1 << 0,
    CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT = 1 << 1,
    CRYPT_REENCRYPT_RESUME_ONLY = 1 << 2,
    CRYPT_REENCRYPT_RECOVERY = 1 << 3,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_reencrypt_direction_info {
    CRYPT_REENCRYPT_FORWARD = 0,
    CRYPT_REENCRYPT_BACKWARD,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_reencrypt_mode_info {
    CRYPT_REENCRYPT_REENCRYPT = 0,
    CRYPT_REENCRYPT_ENCRYPT,
    CRYPT_REENCRYPT_DECRYPT,
}

#[repr(C)]
pub struct crypt_params_reencrypt {
    pub mode: crypt_reencrypt_mode_info,
    pub direction: crypt_reencrypt_direction_info,
    pub resilience: *const c_char,
    pub hash: *const c_char,
    pub data_shift: u64,
    pub max_hotzone_size: u64,
    pub device_size: u64,
    pub luks2: *const crypt_params_luks2,
    pub flags: u32,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_reencrypt_info {
    CRYPT_REENCRYPT_NONE = 0,
    CRYPT_REENCRYPT_CLEAN,
    CRYPT_REENCRYPT_CRASH,
    CRYPT_REENCRYPT_INVALID,
}

extern "C" {
    pub fn crypt_init(cd: *mut *mut crypt_device, device: *const c_char) -> c_int;
    pub fn crypt_init_data_device(
        cd: *mut *mut crypt_device,
        device: *const c_char,
        data_device: *const c_char,
    ) -> c_int;
    pub fn crypt_init_by_name_and_header(
        cd: *mut *mut crypt_device,
        name: *const c_char,
        header_device: *const c_char,
    ) -> c_int;
    pub fn crypt_init_by_name(cd: *mut *mut crypt_device, name: *const c_char) -> c_int;

    pub fn crypt_free(cd: *mut crypt_device);

    pub fn crypt_set_confirm_callback(cd: *mut crypt_device, confirm: crypt_confirm_cb, usrptr: *mut c_void);
    pub fn crypt_set_data_device(cd: *mut crypt_device, device: *const c_char) -> c_int;
    pub fn crypt_set_data_offset(cd: *mut crypt_device, data_offset: u64) -> c_int;
    pub fn crypt_set_log_callback(cd: *mut crypt_device, log: Option<crypt_log_cb>, usrptr: *mut c_void);

    pub fn crypt_log(cd: *mut crypt_device, level: crypt_log_level, msg: *const c_char);

    pub fn crypt_set_rng_type(cd: *mut crypt_device, rng_type: crypt_rng_type);
    pub fn crypt_get_rng_type(cd: *mut crypt_device) -> c_int;

    pub fn crypt_set_pbkdf_type(cd: *mut crypt_device, pbkdf: *const crypt_pbkdf_type) -> c_int;
    pub fn crypt_get_pbkdf_type_params(pbkdf_type: *const c_char) -> *const crypt_pbkdf_type;
    pub fn crypt_get_pbkdf_default(type_: *const c_char) -> *const crypt_pbkdf_type;
    pub fn crypt_get_pbkdf_type(cd: *mut crypt_device) -> *const crypt_pbkdf_type;

    #[deprecated]
    pub fn crypt_set_iteration_time(cd: *mut crypt_device, iteration_time_ms: u64);

    pub fn crypt_memory_lock(cd: *mut crypt_device, lock: c_int) -> c_int;

    pub fn crypt_metadata_locking(cd: *mut crypt_device, enable: c_int) -> c_int;
    pub fn crypt_set_metadata_size(cd: *mut crypt_device, metadata_size: u64, keyslots_size: u64) -> c_int;
    pub fn crypt_get_metadata_size(cd: *mut crypt_device, metadata_size: *mut u64, keyslots_size: *mut u64) -> c_int;

    pub fn crypt_get_type(cd: *mut crypt_device) -> *const c_char;
    pub fn crypt_get_default_type() -> *const c_char;

    pub fn crypt_format(
        cd: *mut crypt_device,
        crypt_type: *const c_char,
        cipher: *const c_char,
        cipher_mode: *const c_char,
        uuid: *const c_char,
        volume_key: *const c_char,
        volume_key_size: size_t,
        params: *mut c_void,
    ) -> c_int;

    pub fn crypt_set_compatibility(cd: *mut crypt_device, flags: u32);
    pub fn crypt_get_compatibility(cd: *mut crypt_device) -> u32;

    pub fn crypt_convert(cd: *mut crypt_device, type_: *const c_char, params: *mut c_void) -> c_int;

    pub fn crypt_set_uuid(cd: *mut crypt_device, uuid: *const c_char) -> c_int;
    pub fn crypt_set_label(cd: *mut crypt_device, label: *const c_char, subsystem: *const c_char) -> c_int;

    pub fn crypt_volume_key_keyring(cd: *mut crypt_device, enable: c_int) -> c_int;

    pub fn crypt_load(cd: *mut crypt_device, requested_type: *const c_char, params: *mut c_void) -> c_int;

    pub fn crypt_repair(cd: *mut crypt_device, requested_type: *const c_char, params: *mut c_void) -> c_int;

    pub fn crypt_resize(cd: *mut crypt_device, name: *const c_char, new_size: u64) -> c_int;

    pub fn crypt_suspend(cd: *mut crypt_device, name: *const c_char) -> c_int;

    pub fn crypt_resume_by_passphrase(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        passphrase: *const c_char,
        passphrase_size: size_t,
    ) -> c_int;
    pub fn crypt_resume_by_keyfile_device_offset(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        keyfile_offset: u64,
    ) -> c_int;
    pub fn crypt_resume_by_keyfile_offset(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        keyfile_offset: size_t,
    ) -> c_int;
    pub fn crypt_resume_by_keyfile(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
    ) -> c_int;
    pub fn crypt_resume_by_volume_key(
        cd: *mut crypt_device,
        name: *const c_char,
        volume_key: *const c_char,
        volume_key_size: size_t,
    ) -> c_int;

    pub fn crypt_keyslot_add_by_passphrase(
        cd: *mut crypt_device,
        keyslot: c_int,
        passphrase: *const c_char,
        passphrase_size: size_t,
        new_passphrase: *const c_char,
        new_passphrase_size: size_t,
    ) -> c_int;
    pub fn crypt_keyslot_change_by_passphrase(
        cd: *mut crypt_device,
        keyslot_old: c_int,
        keyslot_new: c_int,
        passphrase: *const c_char,
        passphrase_size: size_t,
        new_passphrase: *const c_char,
        new_passphrase_size: size_t,
    ) -> c_int;

    pub fn crypt_keyslot_add_by_keyfile_device_offset(
        cd: *mut crypt_device,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        keyfile_offset: u64,
        new_keyfile: *const c_char,
        new_keyfile_size: size_t,
        new_keyfile_offset: u64,
    ) -> c_int;
    pub fn crypt_keyslot_add_by_keyfile_offset(
        cd: *mut crypt_device,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        keyfile_offset: size_t,
        new_keyfile: *const c_char,
        new_keyfile_size: size_t,
        new_keyfile_offset: size_t,
    ) -> c_int;
    pub fn crypt_keyslot_add_by_keyfile(
        cd: *mut crypt_device,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        new_keyfile: *const c_char,
        new_keyfile_size: size_t,
    ) -> c_int;
    pub fn crypt_keyslot_add_by_volume_key(
        cd: *mut crypt_device,
        keyslot: c_int,
        volume_key: *const c_char,
        volume_key_size: size_t,
        passphrase: *const c_char,
        passphrase_size: size_t,
    ) -> c_int;
    pub fn crypt_keyslot_add_by_key(
        cd: *mut crypt_device,
        keyslot: c_int,
        volume_key: *const c_char,
        volume_key_size: size_t,
        passphrase: *const c_char,
        passphrase_size: size_t,
        flags: u32,
    ) -> c_int;

    pub fn crypt_keyslot_destroy(cd: *mut crypt_device, keyslot: c_int) -> c_int;

    pub fn crypt_get_active_device(cd: *mut crypt_device, name: *const c_char, cad: *mut crypt_active_device) -> c_int;
    pub fn crypt_get_active_integrity_failures(cd: *mut crypt_device, name: *const c_char) -> u64;

    pub fn crypt_persistent_flags_set(cd: *mut crypt_device, type_: crypt_flags_type, flags: u32) -> c_int;
    pub fn crypt_persistent_flags_get(cd: *mut crypt_device, type_: crypt_flags_type, flags: *mut u32) -> c_int;

    pub fn crypt_activate_by_passphrase(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        passphrase: *const c_char,
        passphrase_size: size_t,
        flags: u32,
    ) -> c_int;
    pub fn crypt_activate_by_keyfile_device_offset(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        keyfile_offset: u64,
        flags: u32,
    ) -> c_int;
    pub fn crypt_activate_by_keyfile_offset(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        keyfile_offset: size_t,
        flags: u32,
    ) -> c_int;
    pub fn crypt_activate_by_keyfile(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        flags: u32,
    ) -> c_int;
    pub fn crypt_activate_by_volume_key(
        cd: *mut crypt_device,
        name: *const c_char,
        volume_key: *const c_char,
        volume_key_size: size_t,
        flags: u32,
    ) -> c_int;
    pub fn crypt_activate_by_signed_key(
        cd: *mut crypt_device,
        name: *const c_char,
        volume_key: *const c_char,
        volume_key_size: size_t,
        signature: *const c_char,
        signature_size: size_t,
        flags: u32,
    ) -> c_int;
    pub fn crypt_activate_by_keyring(
        cd: *mut crypt_device,
        name: *const c_char,
        key_description: *const c_char,
        keyslot: c_int,
        flags: u32,
    ) -> c_int;

    pub fn crypt_deactivate_by_name(cd: *mut crypt_device, name: *const c_char, flags: u32) -> c_int;
    pub fn crypt_deactivate(cd: *mut crypt_device, name: *const c_char) -> c_int;

    pub fn crypt_volume_key_get(
        cd: *mut crypt_device,
        keyslot: c_int,
        volume_key: *mut c_char,
        volume_key_size: *mut size_t,
        passphrase: *const c_char,
        passphrase_size: size_t,
    ) -> c_int;

    pub fn crypt_volume_key_verify(cd: *mut crypt_device, volume_key: *const c_char, volume_key_size: size_t) -> c_int;

    pub fn crypt_status(cd: *mut crypt_device, name: *const c_char) -> crypt_status_info;

    pub fn crypt_dump(cd: *mut crypt_device) -> c_int;

    pub fn crypt_get_cipher(cd: *mut crypt_device) -> *const c_char;
    pub fn crypt_get_cipher_mode(cd: *mut crypt_device) -> *const c_char;
    pub fn crypt_get_uuid(cd: *mut crypt_device) -> *const c_char;
    pub fn crypt_get_device_name(cd: *mut crypt_device) -> *const c_char;
    pub fn crypt_get_metadata_device_name(cd: *mut crypt_device) -> *const c_char;
    pub fn crypt_get_data_offset(cd: *mut crypt_device) -> u64;
    pub fn crypt_get_iv_offset(cd: *mut crypt_device) -> u64;
    pub fn crypt_get_volume_key_size(cd: *mut crypt_device) -> c_int;
    pub fn crypt_get_sector_size(cd: *mut crypt_device) -> c_int;
    pub fn crypt_get_verity_info(cd: *mut crypt_device, vp: *mut crypt_params_verity) -> c_int;
    pub fn crypt_get_integrity_info(cd: *mut crypt_device, ip: *mut crypt_params_integrity) -> c_int;

    pub fn crypt_benchmark(
        cd: *mut crypt_device,
        cipher: *const c_char,
        cipher_mode: *const c_char,
        volume_key_size: size_t,
        iv_size: size_t,
        buffer_size: size_t,
        encryption_mbs: *mut c_double,
        decryption_mbs: *mut c_double,
    ) -> c_int;
    pub fn crypt_benchmark_pbkdf(
        cd: *mut crypt_device,
        pbkdf: *mut crypt_pbkdf_type,
        password: *const c_char,
        password_size: size_t,
        salt: *const c_char,
        salt_size: size_t,
        volume_key_size: size_t,
        progress: crypt_benchmark_cb,
        usrptr: *mut c_void,
    ) -> c_int;

    pub fn crypt_keyslot_status(cd: *mut crypt_device, keyslot: c_int) -> crypt_keyslot_info;

    pub fn crypt_keyslot_get_priority(cd: *mut crypt_device, keyslot: c_int) -> crypt_keyslot_priority;
    pub fn crypt_keyslot_set_priority(cd: *mut crypt_device, keyslot: c_int, priority: crypt_keyslot_priority)
        -> c_int;

    pub fn crypt_keyslot_max(crypt_device_type: *const c_char) -> c_int;

    pub fn crypt_keyslot_area(cd: *mut crypt_device, keyslot: c_int, offset: *mut u64, length: *mut u64) -> c_int;

    pub fn crypt_keyslot_get_key_size(cd: *mut crypt_device, keyslot: c_int) -> c_int;
    pub fn crypt_keyslot_get_encryption(cd: *mut crypt_device, keyslot: c_int, key_size: *mut size_t) -> *const c_char;

    pub fn crypt_keyslot_get_pbkdf(cd: *mut crypt_device, keyslot: c_int, pbkdf: *mut crypt_pbkdf_type) -> c_int;
    pub fn crypt_keyslot_set_encryption(cd: *mut crypt_device, cipher: *const c_char, key_size: size_t) -> c_int;

    pub fn crypt_get_dir() -> *const c_char;

    pub fn crypt_header_backup(
        cd: *mut crypt_device,
        requested_type: *const c_char,
        backup_file: *const c_char,
    ) -> c_int;
    pub fn crypt_header_restore(
        cd: *mut crypt_device,
        requested_type: *const c_char,
        backup_file: *const c_char,
    ) -> c_int;

    pub fn crypt_set_debug_level(level: crypt_debug_level);

    pub fn crypt_keyfile_device_read(
        cd: *mut crypt_device,
        keyfile: *const c_char,
        key: *mut *mut c_char,
        key_size_read: *mut size_t,
        keyfile_offset: u64,
        key_size: size_t,
        flags: u32,
    ) -> c_int;

    pub fn crypt_keyfile_read(
        cd: *mut crypt_device,
        keyfile: *const c_char,
        key: *mut *mut c_char,
        key_size_read: *mut size_t,
        keyfile_offset: size_t,
        key_size: size_t,
        flags: u32,
    ) -> c_int;

    pub fn crypt_wipe(
        cd: *mut crypt_device,
        dev_path: *const c_char,
        pattern: crypt_wipe_pattern,
        offset: u64,
        length: u64,
        wipe_block_size: size_t,
        flags: u32,
        progress: crypt_write_op_cb,
        usrptr: *mut c_void,
    ) -> c_int;

    pub fn crypt_token_json_get(cd: *mut crypt_device, token: c_int, json: *mut *const c_char) -> c_int;
    pub fn crypt_token_json_set(cd: *mut crypt_device, token: c_int, json: *const c_char) -> c_int;
    pub fn crypt_token_status(cd: *mut crypt_device, token: c_int, type_: *mut *const c_char) -> crypt_token_info;
    pub fn crypt_token_luks2_keyring_set(
        cd: *mut crypt_device,
        token: c_int,
        params: *const crypt_token_params_luks2_keyring,
    ) -> c_int;
    pub fn crypt_token_luks2_keyring_get(
        cd: *mut crypt_device,
        token: c_int,
        params: *mut crypt_token_params_luks2_keyring,
    ) -> c_int;
    pub fn crypt_token_assign_keyslot(cd: *mut crypt_device, token: c_int, keyslot: c_int) -> c_int;
    pub fn crypt_token_unassign_keyslot(cd: *mut crypt_device, token: c_int, keyslot: c_int) -> c_int;
    pub fn crypt_token_is_assigned(cd: *mut crypt_device, token: c_int, keyslot: c_int) -> c_int;
    pub fn crypt_token_register(handler: *const crypt_token_handler) -> c_int;
    pub fn crypt_activate_by_token(
        cd: *mut crypt_device,
        name: *const c_char,
        token: c_int,
        usrptr: *mut c_void,
        flags: u32,
    ) -> c_int;

    pub fn crypt_reencrypt_init_by_passphrase(
        cd: *mut crypt_device,
        name: *const c_char,
        passphrase: *const c_char,
        passphrase_size: size_t,
        keyslot_old: c_int,
        keyslot_new: c_int,
        cipher: *const c_char,
        cipher_mode: *const c_char,
        params: *const crypt_params_reencrypt,
    ) -> c_int;
    pub fn crypt_reencrypt_init_by_keyring(
        cd: *mut crypt_device,
        name: *const c_char,
        key_description: *const c_char,
        keyslot_old: c_int,
        keyslot_new: c_int,
        cipher: *const c_char,
        cipher_mode: *const c_char,
        params: *const crypt_params_reencrypt,
    ) -> c_int;
    pub fn crypt_reencrypt(cd: *mut crypt_device, progress: crypt_write_op_cb) -> c_int;
    pub fn crypt_reencrypt_status(cd: *mut crypt_device, params: *mut crypt_params_reencrypt) -> crypt_reencrypt_info;

    pub fn crypt_safe_alloc(size: size_t) -> *mut c_void;
    pub fn crypt_safe_free(data: *mut c_void);
    pub fn crypt_safe_realloc(data: *mut c_void, size: size_t) -> *mut c_void;
    pub fn crypt_safe_memzero(data: *mut c_void, size: size_t);
}

impl FromStr for crypt_device_type {
    type Err = ();

    fn from_str(s: &str) -> Result<crypt_device_type, ()> {
        match s {
            "PLAIN" => Ok(crypt_device_type::PLAIN),
            "LUKS1" => Ok(crypt_device_type::LUKS1),
            "LUKS2" => Ok(crypt_device_type::LUKS2),
            "LOOPAES" => Ok(crypt_device_type::LOOPAES),
            "VERITY" => Ok(crypt_device_type::VERITY),
            "TCRYPT" => Ok(crypt_device_type::TCRYPT),
            "INTEGRITY" => Ok(crypt_device_type::INTEGRITY),
            "BITLK" => Ok(crypt_device_type::BITLK),
            _ => Err(()),
        }
    }
}

impl crypt_device_type {
    pub fn to_str(&self) -> &'static str {
        match self {
            &crypt_device_type::PLAIN => "PLAIN",
            &crypt_device_type::LUKS1 => "LUKS1",
            &crypt_device_type::LUKS2 => "LUKS2",
            &crypt_device_type::LOOPAES => "LOOPAES",
            &crypt_device_type::VERITY => "VERITY",
            &crypt_device_type::TCRYPT => "TCRYPT",
            &crypt_device_type::INTEGRITY => "INTEGRITY",
            &crypt_device_type::BITLK => "BITLK",
        }
    }
}

impl FromStr for crypt_pbkdf_algo_type {
    type Err = ();

    fn from_str(s: &str) -> Result<crypt_pbkdf_algo_type, ()> {
        match s {
            "pbkdf2" => Ok(crypt_pbkdf_algo_type::pbkdf2),
            "argon2i" => Ok(crypt_pbkdf_algo_type::argon2i),
            "argon2id" => Ok(crypt_pbkdf_algo_type::argon2id),
            _ => Err(()),
        }
    }
}

impl crypt_pbkdf_algo_type {
    pub fn to_str(&self) -> &'static str {
        match self {
            &crypt_pbkdf_algo_type::pbkdf2 => "pbkdf2",
            &crypt_pbkdf_algo_type::argon2i => "argon2i",
            &crypt_pbkdf_algo_type::argon2id => "argon2id",
        }
    }
}

impl FromStr for reencrypt_resilience_mode {
    type Err = ();

    fn from_str(s: &str) -> Result<reencrypt_resilience_mode, ()> {
        match s {
            "none" => Ok(reencrypt_resilience_mode::none),
            "checksum" => Ok(reencrypt_resilience_mode::checksum),
            "journal" => Ok(reencrypt_resilience_mode::journal),
            "shift" => Ok(reencrypt_resilience_mode::shift),
            _ => Err(()),
        }
    }
}

impl reencrypt_resilience_mode {
    pub fn to_str(&self) -> &'static str {
        match self {
            &reencrypt_resilience_mode::none => "none",
            &reencrypt_resilience_mode::checksum => "checksum",
            &reencrypt_resilience_mode::journal => "journal",
            &reencrypt_resilience_mode::shift => "shift",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::str::FromStr;

    #[test]
    fn test_device_type_conversion() {
        assert_eq!(Ok(crypt_device_type::PLAIN), crypt_device_type::from_str("PLAIN"));
        assert_eq!(Ok(crypt_device_type::LUKS1), crypt_device_type::from_str("LUKS1"));
        assert_eq!(Ok(crypt_device_type::LUKS2), crypt_device_type::from_str("LUKS2"));
        assert_eq!(Ok(crypt_device_type::LOOPAES), crypt_device_type::from_str("LOOPAES"));
        assert_eq!(Ok(crypt_device_type::VERITY), crypt_device_type::from_str("VERITY"));
        assert_eq!(Ok(crypt_device_type::TCRYPT), crypt_device_type::from_str("TCRYPT"));
        assert_eq!(
            Ok(crypt_device_type::INTEGRITY),
            crypt_device_type::from_str("INTEGRITY")
        );
        assert_eq!(Ok(crypt_device_type::BITLK), crypt_device_type::from_str("BITLK"));
    }

    #[test]
    fn test_pbkdf_algo_type_conversion() {
        assert_eq!(
            Ok(crypt_pbkdf_algo_type::pbkdf2),
            crypt_pbkdf_algo_type::from_str("pbkdf2")
        );
        assert_eq!(
            Ok(crypt_pbkdf_algo_type::argon2i),
            crypt_pbkdf_algo_type::from_str("argon2i")
        );
        assert_eq!(
            Ok(crypt_pbkdf_algo_type::argon2id),
            crypt_pbkdf_algo_type::from_str("argon2id")
        );
    }

    #[test]
    fn test_reencrypt_resilience_mode_conversion() {
        assert_eq!(
            Ok(reencrypt_resilience_mode::none),
            reencrypt_resilience_mode::from_str("none")
        );
        assert_eq!(
            Ok(reencrypt_resilience_mode::checksum),
            reencrypt_resilience_mode::from_str("checksum")
        );
        assert_eq!(
            Ok(reencrypt_resilience_mode::journal),
            reencrypt_resilience_mode::from_str("journal")
        );
        assert_eq!(
            Ok(reencrypt_resilience_mode::shift),
            reencrypt_resilience_mode::from_str("shift")
        );
    }

    #[test]
    fn test_keyslot_max_gt_zero() {
        unsafe {
            let luks_type = CString::new("LUKS1").unwrap();
            assert!(crypt_keyslot_max(luks_type.as_ptr()) > 0);
        }
    }
}
