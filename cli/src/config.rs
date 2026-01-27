//! Configuration constants and path utilities

use std::path::PathBuf;

/// Hardcoded application salt - adds additional entropy unique to this installation
/// IMPORTANT: Regenerate this for your own installation using:
///   head -c 32 /dev/urandom | xxd -i   (macOS/Linux)
///   or use any secure random generator
pub const APP_SALT: [u8; 32] = [
    0x7a, 0x3f, 0x8b, 0x2c, 0xe1, 0x94, 0x5d, 0x6f, 0xb8, 0x0a, 0x4e, 0x73, 0xc2, 0x1b, 0x9d, 0x85,
    0xf4, 0x67, 0x2e, 0xa9, 0x3c, 0x58, 0xd0, 0x16, 0x8f, 0xe5, 0x4b, 0x7d, 0x0c, 0xa2, 0x63, 0x91,
];

/// Fixed challenge for deriving state file encryption key
pub const STATE_KEY_CHALLENGE: &str = "__dpg_state_key__";

/// Password length in characters
pub const PASSWORD_LENGTH: usize = 32;

/// Seconds before clipboard is automatically cleared
pub const CLIPBOARD_CLEAR_SECONDS: u64 = 20;

/// YubiKey slot to use for challenge-response
pub const YUBIKEY_SLOT: &str = "1";

/// State file format version
/// v1: Original format (no version field, per-domain versions)
/// v2: Per-username versions, added format version field
pub const STATE_FORMAT_VERSION: u32 = 2;

/// Get the ypass config directory, respecting XDG_CONFIG_HOME on Linux/macOS
pub fn get_config_dir() -> PathBuf {
    // On Windows, use USERPROFILE
    if cfg!(target_os = "windows") {
        let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
        return PathBuf::from(home).join(".config").join("ypass");
    }

    // On Linux/macOS, respect XDG_CONFIG_HOME if set
    if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg_config.is_empty() {
            return PathBuf::from(xdg_config).join("ypass");
        }
    }

    // Fall back to ~/.config/ypass
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config").join("ypass")
}
