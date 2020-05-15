extern crate ctest;

const ENUM_NAME_ENDINGS: &'static [&'static str] = &[
    "_mode_info",
    "_direction_info",
    "_log_level",
    "_rng_type",
    "_status_info",
    "_reencrypt_info",
    "_token_info",
    "_flags_type",
    "_keyslot_info",
    "_keyslot_priority",
    "_debug_level",
];

// note: due to https://github.com/gnzlbg/ctest/pull/86, all the callback typedefs generate errors
//       also, we sometimes have enums but the C header has constants and that is and error
const SKIPPED_FUNCTIONS: &'static [&'static str] = &[
    // use callbacks
    "crypt_set_confirm_callback",
    "crypt_set_log_callback",
    "crypt_wipe",
    "crypt_reencrypt",
    // use constants
    "crypt_log",
    "crypt_set_rng_type",
    "crypt_benchmark_pbkdf",
    "crypt_set_debug_level",
];

fn main() {
    let mut cfg = ctest::TestGenerator::new();
    cfg.header("libcryptsetup.h")
        .field_name(|_s, field| {
            field.replace("type_", "type")
        })
        .type_name(|s, is_struct, _is_union| {
            if s == "crypt_token_handler" {
                // emit the typedef
                s.to_string()
            } else if is_struct && ENUM_NAME_ENDINGS.iter().find(|&&i,| s.ends_with(i)).is_none()  {
                format!("struct {}", s)
            } else {
                s.to_string()
            }

        })
        .skip_type(|t| t.ends_with("_cb"))
        .skip_fn(|f| SKIPPED_FUNCTIONS.contains(&f))
        .skip_roundtrip(|f| f.ends_with("_func")) // due to lack of MaybeUninit
    ;
    cfg.generate("../libcryptsetup-sys/lib.rs", "all.rs");
}
