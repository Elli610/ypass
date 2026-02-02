//! Password generation using Argon2id

use crate::config::{APP_SALT, COMPAT_PASSWORD_LENGTH, PASSWORD_LENGTH};
use argon2::{Argon2, Params, Version};
use zeroize::Zeroizing;

/// Password character sets (default mode)
pub const LOWERCASE: &[u8; 26] = b"abcdefghijklmnopqrstuvwxyz";
pub const UPPERCASE: &[u8; 26] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &[u8; 10] = b"0123456789";
pub const SYMBOLS: &[u8; 26] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

/// Compat mode: only symbols universally accepted by websites
pub const COMPAT_SYMBOLS: &[u8; 10] = b"!@#$%*-_+=";

/// All characters combined for password generation (computed at compile time)
const ALL_CHARS_LEN: usize = LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len();
const ALL_CHARS_ARRAY: [u8; ALL_CHARS_LEN] = {
    let mut result = [0u8; ALL_CHARS_LEN];
    let mut i = 0;

    let mut j = 0;
    while j < LOWERCASE.len() {
        result[i] = LOWERCASE[j];
        i += 1;
        j += 1;
    }

    j = 0;
    while j < UPPERCASE.len() {
        result[i] = UPPERCASE[j];
        i += 1;
        j += 1;
    }

    j = 0;
    while j < DIGITS.len() {
        result[i] = DIGITS[j];
        i += 1;
        j += 1;
    }

    j = 0;
    while j < SYMBOLS.len() {
        result[i] = SYMBOLS[j];
        i += 1;
        j += 1;
    }

    result
};
pub const ALL_CHARS: &[u8] = &ALL_CHARS_ARRAY;

/// Compat characters combined (computed at compile time)
const COMPAT_CHARS_LEN: usize =
    LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + COMPAT_SYMBOLS.len();
const COMPAT_CHARS_ARRAY: [u8; COMPAT_CHARS_LEN] = {
    let mut result = [0u8; COMPAT_CHARS_LEN];
    let mut i = 0;

    let mut j = 0;
    while j < LOWERCASE.len() {
        result[i] = LOWERCASE[j];
        i += 1;
        j += 1;
    }

    j = 0;
    while j < UPPERCASE.len() {
        result[i] = UPPERCASE[j];
        i += 1;
        j += 1;
    }

    j = 0;
    while j < DIGITS.len() {
        result[i] = DIGITS[j];
        i += 1;
        j += 1;
    }

    j = 0;
    while j < COMPAT_SYMBOLS.len() {
        result[i] = COMPAT_SYMBOLS[j];
        i += 1;
        j += 1;
    }

    result
};
pub const COMPAT_CHARS: &[u8] = &COMPAT_CHARS_ARRAY;

/// Type for charset validation checks: (predicate, charset, byte_offset)
type CharsetCheck = (fn(&u8) -> bool, &'static [u8], usize);

/// Generate password using Argon2id
pub fn generate_password(
    yubikey_seed: &[u8],
    pin: &str,
    domain: &str,
    username: &str,
    version: u32,
    compat: bool,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    // Combine all inputs: yubikey_seed || pin || domain || username || version || app_salt
    let mut input = Zeroizing::new(Vec::new());
    input.extend_from_slice(yubikey_seed);
    input.extend_from_slice(pin.as_bytes());
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(username.as_bytes());
    input.extend_from_slice(&version.to_le_bytes());
    input.extend_from_slice(&APP_SALT);

    // Argon2id parameters (OWASP recommendations)
    let params = Params::new(
        65536, // m_cost: 64 MiB
        3,     // t_cost: 3 iterations
        4,     // p_cost: 4 parallel lanes
        Some(64),
    )?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    // Use domain + username + app_salt prefix as salt for Argon2
    let mut salt = Zeroizing::new(Vec::new());
    salt.extend_from_slice(domain.as_bytes());
    salt.extend_from_slice(username.as_bytes());
    salt.extend_from_slice(&APP_SALT[..16]);

    while salt.len() < 8 {
        salt.push(0x00);
    }

    let mut derived_key = Zeroizing::new(vec![0u8; 64]);
    argon2.hash_password_into(&input, &salt, &mut derived_key)?;

    let password = if compat {
        bytes_to_password_compat(&derived_key)?
    } else {
        bytes_to_password(&derived_key)?
    };

    Ok(password)
}

/// Convert derived bytes to a password string ensuring all character types are present
fn bytes_to_password(bytes: &[u8]) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let mut password = Zeroizing::new(String::with_capacity(PASSWORD_LENGTH));
    let all_chars_len = ALL_CHARS.len();

    for byte in bytes.iter().take(PASSWORD_LENGTH) {
        let idx = *byte as usize % all_chars_len;
        password.push(ALL_CHARS[idx] as char);
    }

    let mut password_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(password.as_bytes().to_vec());

    let checks: [CharsetCheck; 4] = [
        (|c| c.is_ascii_lowercase(), LOWERCASE, 32),
        (|c| c.is_ascii_uppercase(), UPPERCASE, 36),
        (|c| c.is_ascii_digit(), DIGITS, 40),
        (|c| SYMBOLS.contains(c), SYMBOLS, 44),
    ];

    for (check_fn, charset, byte_offset) in checks {
        if !password_bytes.iter().any(check_fn) {
            let pos = bytes[byte_offset] as usize % PASSWORD_LENGTH;
            let char_idx = bytes[byte_offset + 1] as usize % charset.len();
            password_bytes[pos] = charset[char_idx];
        }
    }

    let result = String::from_utf8(password_bytes.to_vec())?;
    Ok(Zeroizing::new(result))
}

/// Convert derived bytes to a compat password (20 chars, universally accepted charset)
fn bytes_to_password_compat(
    bytes: &[u8],
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let mut password = Zeroizing::new(String::with_capacity(COMPAT_PASSWORD_LENGTH));
    let compat_chars_len = COMPAT_CHARS.len();

    for byte in bytes.iter().take(COMPAT_PASSWORD_LENGTH) {
        let idx = *byte as usize % compat_chars_len;
        password.push(COMPAT_CHARS[idx] as char);
    }

    let mut password_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(password.as_bytes().to_vec());

    let checks: [CharsetCheck; 4] = [
        (|c| c.is_ascii_lowercase(), LOWERCASE, 32),
        (|c| c.is_ascii_uppercase(), UPPERCASE, 36),
        (|c| c.is_ascii_digit(), DIGITS, 40),
        (|c| COMPAT_SYMBOLS.contains(c), COMPAT_SYMBOLS, 44),
    ];

    for (check_fn, charset, byte_offset) in checks {
        if !password_bytes.iter().any(check_fn) {
            let pos = bytes[byte_offset] as usize % COMPAT_PASSWORD_LENGTH;
            let char_idx = bytes[byte_offset + 1] as usize % charset.len();
            password_bytes[pos] = charset[char_idx];
        }
    }

    let result = String::from_utf8(password_bytes.to_vec())?;
    Ok(Zeroizing::new(result))
}
