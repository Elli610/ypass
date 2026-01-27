//! PIN checksum functions for early verification

use crate::config::get_config_dir;
use argon2::{Argon2, Params, Version};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Get path to PIN checksum file
fn get_pin_check_path() -> PathBuf {
    get_config_dir().join("pin.check")
}

/// Compute 2-bit checksum of PIN using Argon2id
pub fn compute_pin_checksum(pin: &str) -> Result<u8, Box<dyn std::error::Error>> {
    let params = Params::new(65536, 3, 4, Some(32))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let salt = b"dpg_pin_check_v1";
    let mut hash = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(pin.as_bytes(), salt, &mut *hash)?;

    // Return first 2 bits (values 0-3)
    Ok(hash[0] & 0b11)
}

/// Load PIN checksum from file (returns None if file doesn't exist)
pub fn load_pin_checksum() -> Option<u8> {
    let path = get_pin_check_path();
    fs::read(&path).ok().and_then(|data| data.first().copied())
}

/// Save PIN checksum to file
pub fn save_pin_checksum(checksum: u8) -> Result<(), Box<dyn std::error::Error>> {
    let path = get_pin_check_path();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&path, [checksum])?;
    Ok(())
}

/// Delete PIN checksum file
pub fn delete_pin_checksum() -> Result<bool, Box<dyn std::error::Error>> {
    let path = get_pin_check_path();
    if path.exists() {
        fs::remove_file(&path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Verify PIN against stored checksum
/// Returns Ok(true) if matches or no checksum stored, Ok(false) if mismatch
pub fn verify_pin_checksum(pin: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match load_pin_checksum() {
        Some(stored) => {
            let computed = compute_pin_checksum(pin)?;
            Ok(computed == stored)
        }
        None => Ok(true), // No checksum stored, accept any PIN
    }
}
