/// Enable internal `libcryptsetup` debugging
pub fn enable_debug(debug: bool) {
    if debug {
        unsafe { raw::crypt_set_debug_level(raw::crypt_debug_level::CRYPT_DEBUG_ALL) };
    } else {
        unsafe { raw::crypt_set_debug_level(raw::crypt_debug_level::CRYPT_DEBUG_NONE) };
    }
}
