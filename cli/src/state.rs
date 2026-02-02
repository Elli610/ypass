//! State management for stored domains and usernames

use crate::config::{STATE_FORMAT_VERSION, get_config_dir};
use argon2::{Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// State stored in encrypted file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// Format version for compatibility detection
    #[serde(default = "default_state_version")]
    pub version: u32,
    pub domains: HashMap<String, DomainState>,
}

fn default_state_version() -> u32 {
    1 // Old state files without version field are v1
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: STATE_FORMAT_VERSION,
            domains: HashMap::new(),
        }
    }
}

/// Per-username configuration (version + compat mode)
#[derive(Debug, Clone, Serialize)]
pub struct UsernameConfig {
    pub version: u32,
    /// Compatible mode: 20-char password with universally accepted characters
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub compat: bool,
}

impl Default for UsernameConfig {
    fn default() -> Self {
        Self {
            version: 1,
            compat: false,
        }
    }
}

impl<'de> Deserialize<'de> for UsernameConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct UsernameConfigVisitor;

        impl<'de> de::Visitor<'de> for UsernameConfigVisitor {
            type Value = UsernameConfig;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a version number (u32) or a UsernameConfig object")
            }

            // Handle legacy format: plain u32 version number
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<UsernameConfig, E> {
                let version = u32::try_from(value).map_err(de::Error::custom)?;
                Ok(UsernameConfig {
                    version,
                    compat: false,
                })
            }

            // Handle new format: { "version": N, "compat": bool }
            fn visit_map<M: de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<UsernameConfig, M::Error> {
                let mut version = None;
                let mut compat = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => version = Some(map.next_value()?),
                        "compat" => compat = Some(map.next_value()?),
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }

                Ok(UsernameConfig {
                    version: version.unwrap_or(1),
                    compat: compat.unwrap_or(false),
                })
            }
        }

        deserializer.deserialize_any(UsernameConfigVisitor)
    }
}

/// Domain state: maps username -> config (version + compat mode)
/// Empty string "" key represents domain-only mode
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainState {
    pub usernames: HashMap<String, UsernameConfig>,
}

/// Get path to encrypted state file
pub fn get_state_path() -> PathBuf {
    get_config_dir().join("state.enc")
}

/// Derive encryption key for state file from YubiKey response
pub fn derive_state_key(
    yubikey_response: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Box<dyn std::error::Error>> {
    let params = Params::new(65536, 3, 4, Some(32))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let salt = b"dpg_state_key_derivation";
    let mut key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(yubikey_response, salt, &mut *key)?;

    Ok(key)
}

/// Load state from encrypted file
pub fn load_state(key: &[u8; 32]) -> Result<State, Box<dyn std::error::Error>> {
    let path = get_state_path();
    if !path.exists() {
        return Ok(State::default());
    }

    let encrypted = fs::read(&path)?;
    if encrypted.len() < 12 {
        return Err("Invalid state file".into());
    }

    // First 12 bytes are nonce
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| "Invalid key length")?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Failed to decrypt state file")?;

    let mut state: State = serde_json::from_slice(&plaintext)?;

    // Check version compatibility
    if state.version > STATE_FORMAT_VERSION {
        return Err(format!(
            "State file is from a newer version (v{}) than this CLI supports (v{}). \
             Please update the CLI.",
            state.version, STATE_FORMAT_VERSION
        )
        .into());
    }

    // Upgrade old state format to current version
    if state.version < STATE_FORMAT_VERSION {
        eprintln!(
            "Upgrading state file from v{} to v{}",
            state.version, STATE_FORMAT_VERSION
        );
        state.version = STATE_FORMAT_VERSION;
    }

    Ok(state)
}

/// Save state to encrypted file
pub fn save_state(state: &State, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let path = get_state_path();

    // Create directory if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Ensure we always save with current version
    let mut state_to_save = state.clone();
    state_to_save.version = STATE_FORMAT_VERSION;

    let plaintext = serde_json::to_vec(&state_to_save)?;

    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| format!("Failed to generate random nonce: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| "Invalid key length")?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|_| "Failed to encrypt state")?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    fs::write(&path, output)?;
    Ok(())
}

/// Get list of usernames for a domain (excludes domain-only entry)
pub fn get_usernames(state: &State, domain: &str) -> Vec<String> {
    state
        .domains
        .get(domain)
        .map(|d| {
            d.usernames
                .keys()
                .filter(|k| !k.is_empty()) // Exclude domain-only entry
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Get version number for a domain/username combination
pub fn get_version(state: &State, domain: &str, username: &str) -> u32 {
    state
        .domains
        .get(domain)
        .and_then(|d| d.usernames.get(username).map(|c| c.version))
        .unwrap_or(1)
}

/// Get compat mode for a domain/username combination
pub fn get_compat(state: &State, domain: &str, username: &str) -> bool {
    state
        .domains
        .get(domain)
        .and_then(|d| d.usernames.get(username).map(|c| c.compat))
        .unwrap_or(false)
}

/// Add a username to a domain (with default config)
pub fn add_username(state: &mut State, domain: &str, username: &str) {
    let entry = state.domains.entry(domain.to_string()).or_default();
    entry.usernames.entry(username.to_string()).or_default();
}

/// Set version number for a domain/username combination
pub fn set_version(state: &mut State, domain: &str, username: &str, version: u32) {
    let entry = state.domains.entry(domain.to_string()).or_default();
    let config = entry.usernames.entry(username.to_string()).or_default();
    config.version = version;
}

/// Set compat mode for a domain/username combination
pub fn set_compat(state: &mut State, domain: &str, username: &str, compat: bool) {
    let entry = state.domains.entry(domain.to_string()).or_default();
    let config = entry.usernames.entry(username.to_string()).or_default();
    config.compat = compat;
}

/// List all stored domains and usernames
pub fn list_all_entries(state: &State) {
    if state.domains.is_empty() {
        eprintln!("No domains stored.");
        return;
    }

    let mut domains: Vec<_> = state.domains.iter().collect();
    domains.sort_by_key(|(k, _)| *k);

    for (domain, entry) in domains {
        println!("{}", domain);
        if entry.usernames.is_empty() {
            println!("  (no entries)");
        } else {
            let mut users: Vec<_> = entry.usernames.iter().collect();
            users.sort_by_key(|(k, _)| *k);
            for (username, config) in users {
                let compat_tag = if config.compat { " [compat]" } else { "" };
                if username.is_empty() {
                    println!("  - (domain-only) (v{}){}", config.version, compat_tag);
                } else {
                    println!("  - {} (v{}){}", username, config.version, compat_tag);
                }
            }
        }
    }
}
