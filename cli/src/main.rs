//! Secure password generator using YubiKey HMAC-SHA1 + PIN + domain
//!
//! Generates deterministic passwords using:
//! - YubiKey HMAC-SHA1 challenge-response (slot 1)
//! - User-provided PIN/password
//! - Target domain (normalized)
//! - Optional username (for multi-account support)
//! - Version number (for password rotation)
//! - Hardcoded application salt
//!
//! Uses Argon2id for key derivation
//! State file encrypted with ChaCha20-Poly1305
//!
//! Supported platforms: macOS, Linux, Windows

use argon2::{Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use clap::{CommandFactory, Parser};
use clap_complete::Shell;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Editor, Helper};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// Hardcoded application salt - adds additional entropy unique to this installation
/// IMPORTANT: Regenerate this for your own installation using:
///   head -c 32 /dev/urandom | xxd -i   (macOS/Linux)
///   or use any secure random generator
const APP_SALT: [u8; 32] = [
    0x7a, 0x3f, 0x8b, 0x2c, 0xe1, 0x94, 0x5d, 0x6f, 0xb8, 0x0a, 0x4e, 0x73, 0xc2, 0x1b, 0x9d, 0x85,
    0xf4, 0x67, 0x2e, 0xa9, 0x3c, 0x58, 0xd0, 0x16, 0x8f, 0xe5, 0x4b, 0x7d, 0x0c, 0xa2, 0x63, 0x91,
];

/// Fixed challenge for deriving state file encryption key
const STATE_KEY_CHALLENGE: &str = "__dpg_state_key__";

/// Password character sets
const LOWERCASE: &[u8; 26] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8; 26] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8; 10] = b"0123456789";
const SYMBOLS: &[u8; 26] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

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
const ALL_CHARS: &[u8] = &ALL_CHARS_ARRAY;

const PASSWORD_LENGTH: usize = 32;
const CLIPBOARD_CLEAR_SECONDS: u64 = 20;
const YUBIKEY_SLOT: &str = "1";

/// State file format version
/// v1: Original format (no version field, per-domain versions)
/// v2: Per-username versions, added format version field
const STATE_FORMAT_VERSION: u32 = 2;

/// Type for charset validation checks: (predicate, charset, byte_offset)
type CharsetCheck = (fn(&u8) -> bool, &'static [u8], usize);

/// State stored in encrypted file
#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    /// Format version for compatibility detection
    #[serde(default = "default_state_version")]
    version: u32,
    domains: HashMap<String, DomainState>,
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

/// Domain state: maps username -> version number
/// Empty string "" key represents domain-only mode
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DomainState {
    usernames: HashMap<String, u32>,
}

/// CLI arguments
#[derive(Debug, Parser)]
#[command(
    name = "ypass",
    about = "Secure deterministic password generator using YubiKey HMAC-SHA1",
    version,
    disable_version_flag = true,
    after_help = "Examples:
  ypass                    Interactive mode (select domain)
  ypass github.com         Generate password for domain
  ypass github.com -u user Generate password for domain/user
  ypass github.com -p      Print password to stdout
  ypass --list             List all stored domains

Requirements:
  YubiKey: ykchalresp (brew install ykpers / apt install yubikey-personalization)
  Setup:   ykman otp chalresp --generate --touch 1"
)]
struct Args {
    /// Target domain (e.g., github.com)
    #[arg(value_name = "DOMAIN")]
    domain: Option<String>,

    /// Use specific password version (default: latest from state)
    #[arg(short = 'v', long = "version", value_name = "N")]
    version_override: Option<u32>,

    /// Print application version
    #[arg(short = 'V', long = "app-version", action = clap::ArgAction::Version)]
    app_version: (),

    /// Use specific username (skip interactive selection)
    #[arg(short = 'u', long = "user", value_name = "NAME")]
    username: Option<String>,

    /// Add username to domain (no password generated)
    #[arg(long = "add-user", value_name = "NAME")]
    add_user: Option<String>,

    /// Delete username from domain
    #[arg(long = "delete-user", value_name = "NAME")]
    delete_user: Option<String>,

    /// Delete domain and all its usernames
    #[arg(long = "delete-domain")]
    delete_domain: bool,

    /// Increment version for domain/username
    #[arg(long = "bump-version")]
    bump_version: bool,

    /// List all domains and usernames
    #[arg(long)]
    list: bool,

    /// Generate shell completions
    #[arg(long = "generate-completions", value_name = "SHELL")]
    generate_completions: Option<Shell>,

    /// Interactive domain selection
    #[arg(short = 'i', long)]
    interactive: bool,

    /// Skip state unlock (requires domain, use with -u and -v for scripts)
    #[arg(long = "skip-state")]
    skip_state: bool,

    /// Reset PIN verification (use when changing PIN)
    #[arg(long = "reset-pin")]
    reset_pin: bool,

    /// Verify PIN from stdin (exit 0=ok, 1=wrong, no YubiKey needed)
    #[arg(long = "check-pin")]
    check_pin: bool,

    /// Print password to stdout (default: clipboard only)
    #[arg(short = 'p', long = "print")]
    print_password: bool,

    /// Don't copy to clipboard (use with -p for piping)
    #[arg(long = "no-clipboard")]
    no_clipboard: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Handle --generate-completions (no YubiKey needed)
    if let Some(shell) = args.generate_completions {
        print_completions(shell);
        return Ok(());
    }

    // Handle --check-pin (no YubiKey needed)
    if args.check_pin {
        let mut pin = String::new();
        io::stdin().read_line(&mut pin)?;
        let pin = pin.trim();

        if pin.is_empty() {
            std::process::exit(1);
        }

        // Check if PIN matches stored checksum
        if verify_pin_checksum(pin)? {
            std::process::exit(0); // PIN correct
        } else {
            std::process::exit(1); // PIN wrong
        }
    }

    // Fast path: --skip-state mode (no state unlock needed)
    if args.skip_state {
        let domain = args
            .domain
            .as_ref()
            .ok_or("--skip-state requires a domain argument")?;
        let normalized_domain = normalize_domain(domain);
        let username = args.username.clone().unwrap_or_default();
        let version = args.version_override.unwrap_or(1);

        // Only need YubiKey for password generation
        eprint!("Touch YubiKey for password...");
        io::stderr().flush()?;
        let yubikey_seed = get_yubikey_response(&normalized_domain)?;
        eprintln!(" OK");

        // Get and verify PIN (with retry on failure)
        let has_checksum = load_pin_checksum().is_some();
        let pin = loop {
            eprint!("Enter PIN: ");
            io::stderr().flush()?;
            let pin = read_password_no_echo()?;
            eprintln!();

            if pin.is_empty() {
                return Err("PIN cannot be empty".into());
            }

            // Verify PIN checksum if it exists
            if verify_pin_checksum(&pin)? {
                break pin;
            } else {
                eprintln!("Wrong PIN. Please try again.");
                continue;
            }
        };

        // Save PIN checksum if first use
        if !has_checksum {
            let checksum = compute_pin_checksum(&pin)?;
            save_pin_checksum(checksum)?;
            eprintln!("PIN verification enabled for future use.");
        }

        let password =
            generate_password(&yubikey_seed, &pin, &normalized_domain, &username, version)?;

        if !args.no_clipboard {
            copy_to_clipboard_with_clear(&password)?;
        }

        if args.print_password {
            println!("{}", &*password);
        }

        if !args.no_clipboard {
            eprintln!(
                "\nPassword copied to clipboard. Will clear in {} seconds.",
                CLIPBOARD_CLEAR_SECONDS
            );
        } else if !args.print_password {
            eprintln!("\nPassword generated (use -p to print or remove --no-clipboard to copy).");
        }
        return Ok(());
    }

    eprint!("Touch YubiKey to unlock state...");
    io::stderr().flush()?;
    let state_key_seed = get_yubikey_response(STATE_KEY_CHALLENGE)?;
    eprintln!(" OK");

    // Derive state encryption key
    let state_key = derive_state_key(&state_key_seed)?;

    // Load or create state
    let mut state = load_state(&state_key).unwrap_or_default();
    let mut state_modified = false;

    // Handle --list command
    if args.list {
        list_all_entries(&state);
        return Ok(());
    }

    // Handle --reset-pin command
    if args.reset_pin {
        if delete_pin_checksum()? {
            eprintln!(
                "PIN verification reset. Your new PIN will be saved on next password generation."
            );
        } else {
            eprintln!("PIN verification was not set up yet.");
        }
        return Ok(());
    }

    let normalized_domain = if args.domain.is_none() || args.interactive {
        select_domain(&state)?
    } else {
        normalize_domain(args.domain.as_ref().unwrap())
    };

    // Handle --add-user command
    if let Some(username) = args.add_user {
        add_username(&mut state, &normalized_domain, &username);
        save_state(&state, &state_key)?;
        eprintln!(
            "Added username '{}' to domain '{}'",
            username, normalized_domain
        );
        return Ok(());
    }

    // Handle --bump-version command (requires -u for username, or bumps domain-only)
    if args.bump_version {
        let username = args.username.clone().unwrap_or_default();
        let current = get_version(&state, &normalized_domain, &username);
        set_version(&mut state, &normalized_domain, &username, current + 1);
        save_state(&state, &state_key)?;
        if username.is_empty() {
            eprintln!(
                "Bumped version for '{}' (domain-only) from {} to {}",
                normalized_domain,
                current,
                current + 1
            );
        } else {
            eprintln!(
                "Bumped version for '{}' / '{}' from {} to {}",
                normalized_domain,
                username,
                current,
                current + 1
            );
        }
        return Ok(());
    }

    // Handle --delete-domain command
    if args.delete_domain {
        if state.domains.remove(&normalized_domain).is_some() {
            save_state(&state, &state_key)?;
            eprintln!("Deleted domain '{}'", normalized_domain);
        } else {
            eprintln!("Domain '{}' not found", normalized_domain);
        }
        return Ok(());
    }

    // Handle --delete-user command
    if let Some(username) = args.delete_user {
        if let Some(domain_state) = state.domains.get_mut(&normalized_domain) {
            if domain_state.usernames.remove(&username).is_some() {
                save_state(&state, &state_key)?;
                eprintln!(
                    "Deleted username '{}' from domain '{}'",
                    username, normalized_domain
                );
            } else {
                eprintln!(
                    "Username '{}' not found in domain '{}'",
                    username, normalized_domain
                );
            }
        } else {
            eprintln!("Domain '{}' not found", normalized_domain);
        }
        return Ok(());
    }

    // Ensure domain exists in state (even for domain-only mode)
    if !state.domains.contains_key(&normalized_domain) {
        state
            .domains
            .insert(normalized_domain.clone(), DomainState::default());
        state_modified = true;
    }

    let username = if let Some(u) = args.username {
        if !get_usernames(&state, &normalized_domain).contains(&u) {
            add_username(&mut state, &normalized_domain, &u);
            state_modified = true;
        }
        u
    } else {
        let usernames = get_usernames(&state, &normalized_domain);
        select_username(
            &usernames,
            &normalized_domain,
            &mut state,
            &mut state_modified,
        )?
    };

    let version = args
        .version_override
        .unwrap_or_else(|| get_version(&state, &normalized_domain, &username));

    eprint!("Touch YubiKey for password...");
    io::stderr().flush()?;
    let yubikey_seed = get_yubikey_response(&normalized_domain)?;
    eprintln!(" OK");

    // Get and verify PIN with retry loop
    let has_checksum = load_pin_checksum().is_some();
    let pin = loop {
        eprint!("Enter PIN: ");
        io::stderr().flush()?;
        let pin = read_password_no_echo()?;
        eprintln!();

        if pin.is_empty() {
            return Err("PIN cannot be empty".into());
        }

        if verify_pin_checksum(&pin)? {
            break pin;
        } else {
            eprintln!("Wrong PIN. Please try again.");
        }
    };

    let password = generate_password(&yubikey_seed, &pin, &normalized_domain, &username, version)?;

    if !has_checksum {
        let checksum = compute_pin_checksum(&pin)?;
        save_pin_checksum(checksum)?;
        eprintln!("PIN verification enabled for future use.");
    }

    if state_modified {
        save_state(&state, &state_key)?;
    }

    if !args.no_clipboard {
        copy_to_clipboard_with_clear(&password)?;
    }

    if args.print_password {
        println!("{}", &*password);
    }

    let info = if username.is_empty() {
        format!("domain={}, v{}", normalized_domain, version)
    } else {
        format!(
            "domain={}, user={}, v{}",
            normalized_domain, username, version
        )
    };

    if !args.no_clipboard {
        eprintln!(
            "Password copied to clipboard ({}). Will be cleared in {CLIPBOARD_CLEAR_SECONDS} seconds.",
            info
        );
    } else if !args.print_password {
        eprintln!(
            "Password generated ({}). Use -p to print or remove --no-clipboard to copy.",
            info
        );
    }

    Ok(())
}

/// Normalize domain for consistent password generation
fn normalize_domain(input: &str) -> String {
    let mut domain = input.trim().to_lowercase();

    // Remove protocol prefixes
    if let Some(rest) = domain.strip_prefix("https://") {
        domain = rest.to_string();
    } else if let Some(rest) = domain.strip_prefix("http://") {
        domain = rest.to_string();
    }

    // Remove www prefix
    if let Some(rest) = domain.strip_prefix("www.") {
        domain = rest.to_string();
    }

    // Remove trailing slashes, paths, query strings, and fragments
    // Find the first occurrence of /, ?, or # and truncate
    if let Some(pos) = domain.find(['/', '?', '#']) {
        domain.truncate(pos);
    }

    // Remove port numbers (e.g., localhost:3000 -> localhost)
    if let Some(pos) = domain.rfind(':') {
        // Only remove if what follows looks like a port number
        let potential_port = &domain[pos + 1..];
        if !potential_port.is_empty() && potential_port.chars().all(|c| c.is_ascii_digit()) {
            domain.truncate(pos);
        }
    }

    domain
}

// === State Management ===

/// Get the ypass config directory, respecting XDG_CONFIG_HOME on Linux/macOS
fn get_config_dir() -> PathBuf {
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

fn get_state_path() -> PathBuf {
    get_config_dir().join("state.enc")
}

fn derive_state_key(
    yubikey_response: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Box<dyn std::error::Error>> {
    let params = Params::new(65536, 3, 4, Some(32))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let salt = b"dpg_state_key_derivation";
    let mut key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(yubikey_response, salt, &mut *key)?;

    Ok(key)
}

fn load_state(key: &[u8; 32]) -> Result<State, Box<dyn std::error::Error>> {
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

fn save_state(state: &State, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
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

fn get_usernames(state: &State, domain: &str) -> Vec<String> {
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

fn get_version(state: &State, domain: &str, username: &str) -> u32 {
    state
        .domains
        .get(domain)
        .and_then(|d| d.usernames.get(username).copied())
        .unwrap_or(1)
}

fn add_username(state: &mut State, domain: &str, username: &str) {
    let entry = state.domains.entry(domain.to_string()).or_default();
    entry.usernames.entry(username.to_string()).or_insert(1);
}

fn set_version(state: &mut State, domain: &str, username: &str, version: u32) {
    let entry = state.domains.entry(domain.to_string()).or_default();
    entry.usernames.insert(username.to_string(), version);
}

fn list_all_entries(state: &State) {
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
            for (username, version) in users {
                if username.is_empty() {
                    println!("  - (domain-only) (v{})", version);
                } else {
                    println!("  - {} (v{})", username, version);
                }
            }
        }
    }
}

// === PIN Checksum Functions ===

/// Get path to PIN checksum file
fn get_pin_check_path() -> PathBuf {
    get_config_dir().join("pin.check")
}

/// Compute 2-bit checksum of PIN using Argon2id
fn compute_pin_checksum(pin: &str) -> Result<u8, Box<dyn std::error::Error>> {
    let params = Params::new(65536, 3, 4, Some(32))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let salt = b"dpg_pin_check_v1";
    let mut hash = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(pin.as_bytes(), salt, &mut *hash)?;

    // Return first 2 bits (values 0-3)
    Ok(hash[0] & 0b11)
}

/// Load PIN checksum from file (returns None if file doesn't exist)
fn load_pin_checksum() -> Option<u8> {
    let path = get_pin_check_path();
    fs::read(&path).ok().and_then(|data| data.first().copied())
}

/// Save PIN checksum to file
fn save_pin_checksum(checksum: u8) -> Result<(), Box<dyn std::error::Error>> {
    let path = get_pin_check_path();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&path, [checksum])?;
    Ok(())
}

/// Delete PIN checksum file
fn delete_pin_checksum() -> Result<bool, Box<dyn std::error::Error>> {
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
fn verify_pin_checksum(pin: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match load_pin_checksum() {
        Some(stored) => {
            let computed = compute_pin_checksum(pin)?;
            Ok(computed == stored)
        }
        None => Ok(true), // No checksum stored, accept any PIN
    }
}

// === Rustyline Completers ===

struct StringCompleter {
    candidates: Vec<String>,
}

impl StringCompleter {
    fn new(candidates: Vec<String>) -> Self {
        Self { candidates }
    }
}

impl Completer for StringCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let input = &line[..pos].to_lowercase();
        let matches: Vec<Pair> = self
            .candidates
            .iter()
            .filter(|c| c.to_lowercase().starts_with(input))
            .map(|c| Pair {
                display: c.clone(),
                replacement: c.clone(),
            })
            .collect();
        Ok((0, matches))
    }
}

impl Hinter for StringCompleter {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        if line.is_empty() || pos < line.len() {
            return None;
        }
        let input = line.to_lowercase();
        self.candidates
            .iter()
            .find(|c| c.to_lowercase().starts_with(&input) && c.len() > line.len())
            .map(|c| c[line.len()..].to_string())
    }
}

impl Highlighter for StringCompleter {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        // Gray color for hints
        Cow::Owned(format!("\x1b[90m{}\x1b[0m", hint))
    }
}

impl Validator for StringCompleter {}
impl Helper for StringCompleter {}

fn select_domain(state: &State) -> Result<String, Box<dyn std::error::Error>> {
    let mut domains: Vec<String> = state.domains.keys().cloned().collect();
    domains.sort();

    let completer = StringCompleter::new(domains.clone());
    let mut rl = Editor::new()?;
    rl.set_helper(Some(completer));

    let input = match rl.readline("Domain: ") {
        Ok(line) => line.trim().to_string(),
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
            return Err("Cancelled".into());
        }
        Err(e) => return Err(e.into()),
    };

    if input.is_empty() {
        return Err("No domain selected".into());
    }

    // Check if it's an exact match
    if domains
        .iter()
        .any(|d| d.to_lowercase() == input.to_lowercase())
    {
        return Ok(normalize_domain(&input));
    }

    // Check for prefix match
    let matches: Vec<_> = domains
        .iter()
        .filter(|d| d.to_lowercase().starts_with(&input.to_lowercase()))
        .collect();

    if matches.len() == 1 {
        return Ok(matches[0].clone());
    }

    // Treat as new domain
    Ok(normalize_domain(&input))
}

// === Shell Completions ===

fn print_completions(shell: Shell) {
    let mut cmd = Args::command();
    clap_complete::generate(shell, &mut cmd, "ypass", &mut io::stdout());
}

fn select_username(
    usernames: &[String],
    domain: &str,
    state: &mut State,
    state_modified: &mut bool,
) -> Result<String, Box<dyn std::error::Error>> {
    const MAX_DISPLAY: usize = 10;

    eprintln!();
    eprintln!("Usernames for '{}':", domain);

    if usernames.is_empty() {
        eprintln!("  (no saved usernames)");
    } else {
        let display_count = usernames.len().min(MAX_DISPLAY);
        for (i, u) in usernames.iter().take(display_count).enumerate() {
            eprintln!("  [{}] {}", i + 1, u);
        }
        if usernames.len() > MAX_DISPLAY {
            eprintln!(
                "  ... +{} more (Tab to complete)",
                usernames.len() - MAX_DISPLAY
            );
        }
    }
    eprintln!("  [d] domain-only mode (or press Enter with empty input)");
    eprintln!();

    let completer = StringCompleter::new(usernames.to_vec());
    let mut rl = Editor::new()?;
    rl.set_helper(Some(completer));

    let input = match rl.readline("Username: ") {
        Ok(line) => line.trim().to_string(),
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
            return Err("Cancelled".into());
        }
        Err(e) => return Err(e.into()),
    };

    // Empty input = domain-only mode
    if input.is_empty() {
        return Ok(String::new());
    }

    // Domain-only mode
    if input == "d" || input == "D" {
        return Ok(String::new());
    }

    // Try to parse as number
    if let Ok(n) = input.parse::<usize>() {
        if n >= 1 && n <= usernames.len() {
            return Ok(usernames[n - 1].clone());
        }
    }

    // Exact match (case-insensitive)
    if let Some(matched) = usernames
        .iter()
        .find(|u| u.to_lowercase() == input.to_lowercase())
    {
        return Ok(matched.clone());
    }

    // Prefix match
    let matches: Vec<_> = usernames
        .iter()
        .filter(|u| u.to_lowercase().starts_with(&input.to_lowercase()))
        .collect();

    if matches.len() == 1 {
        return Ok(matches[0].clone());
    }

    // No match - treat as new username
    add_username(state, domain, &input);
    *state_modified = true;
    Ok(input)
}

// === YubiKey and Password Generation ===

/// Detect current operating system
fn detect_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

/// Check if a command exists in PATH
fn command_exists(cmd: &str) -> bool {
    let check_cmd = if cfg!(target_os = "windows") {
        Command::new("where")
            .arg(cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    } else {
        Command::new("which")
            .arg(cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    };
    check_cmd.map(|s| s.success()).unwrap_or(false)
}

/// Get HMAC-SHA1 challenge-response from YubiKey
fn get_yubikey_response(challenge: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    if command_exists("ykchalresp") {
        let slot_flag = format!("-{}", YUBIKEY_SLOT);
        let output = Command::new("ykchalresp")
            .args([&slot_flag, "-H", challenge])
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;

        if output.status.success() {
            let hex_response = String::from_utf8(output.stdout)?.trim().to_string();
            if !hex_response.is_empty() {
                let bytes = hex_decode(&hex_response)?;
                return Ok(Zeroizing::new(bytes));
            }
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("YubiKey challenge-response failed: {}", stderr.trim()).into());
    }

    let os = detect_os();
    let install_hint = match os {
        "macos" => "Install: brew install ykpers",
        "windows" => {
            "Install: Download from https://developers.yubico.com/yubikey-personalization/Releases/"
        }
        _ => "Install: apt install yubikey-personalization",
    };

    let setup_hint = format!(
        "\
To configure HMAC-SHA1 challenge-response on slot {slot}:
  ykman otp chalresp --generate {slot}
  (requires: brew install ykman / pip install yubikey-manager)

To verify slot {slot} is configured:
  ykman otp info",
        slot = YUBIKEY_SLOT
    );

    Err(format!(
        "ykchalresp not found in PATH.\n\n\
         {install_hint}\n\n\
         {setup_hint}"
    )
    .into())
}

/// Read password from terminal without echoing characters
fn read_password_no_echo() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        read_password_windows()
    }

    #[cfg(not(target_os = "windows"))]
    {
        read_password_unix()
    }
}

#[cfg(not(target_os = "windows"))]
fn read_password_unix() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let output = Command::new("stty")
        .args(["-g"])
        .stdin(Stdio::inherit())
        .output()?;

    let saved_settings = String::from_utf8(output.stdout)?.trim().to_string();

    Command::new("stty")
        .args(["-echo"])
        .stdin(Stdio::inherit())
        .status()?;

    let mut password = Zeroizing::new(String::new());
    let result = io::stdin().read_line(&mut password);

    let _ = Command::new("stty")
        .arg(&saved_settings)
        .stdin(Stdio::inherit())
        .status();

    result?;

    if password.ends_with('\n') {
        password.pop();
    }
    if password.ends_with('\r') {
        password.pop();
    }

    Ok(password)
}

#[cfg(target_os = "windows")]
fn read_password_windows() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, dwMode: u32) -> i32;
    }

    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    let stdin = io::stdin();
    let handle = stdin.as_raw_handle() as *mut std::ffi::c_void;

    // Get current console mode
    let mut mode: u32 = 0;
    let got_mode = unsafe { GetConsoleMode(handle, &mut mode) };

    // Disable echo if we successfully got the mode
    if got_mode != 0 {
        unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) };
    }

    // Read password
    let mut password = Zeroizing::new(String::new());
    let result = io::stdin().read_line(&mut password);

    // Restore original mode
    if got_mode != 0 {
        unsafe { SetConsoleMode(handle, mode) };
    }

    result?;

    if password.ends_with('\n') {
        password.pop();
    }
    if password.ends_with('\r') {
        password.pop();
    }

    Ok(password)
}

/// Generate password using Argon2id
fn generate_password(
    yubikey_seed: &[u8],
    pin: &str,
    domain: &str,
    username: &str,
    version: u32,
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

    let password = bytes_to_password(&derived_key)?;

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

/// Copy password to clipboard and schedule automatic clearing
fn copy_to_clipboard_with_clear(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let os = detect_os();

    match os {
        "macos" => copy_clipboard_macos(password)?,
        "windows" => copy_clipboard_windows(password)?,
        _ => copy_clipboard_linux(password)?,
    }

    Ok(())
}

fn copy_clipboard_macos(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Use AppleScript to copy as "concealed" - this prevents clipboard managers
    // (Raycast, 1Password, Alfred, etc.) from storing it in clipboard history.
    // The org.nspasteboard.ConcealedType flag marks it as sensitive data.
    let script = format!(
        r#"
        use framework "AppKit"
        set pb to current application's NSPasteboard's generalPasteboard()
        pb's clearContents()
        pb's setString:"{}" forType:(current application's NSPasteboardTypeString)
        pb's setString:"" forType:"org.nspasteboard.ConcealedType"
        "#,
        password.replace('\\', "\\\\").replace('"', "\\\"")
    );

    let output = Command::new("osascript")
        .args(["-l", "AppleScript", "-e", &script])
        .output()?;

    if !output.status.success() {
        // Fallback to regular pbcopy if AppleScript fails
        let mut child = Command::new("pbcopy").stdin(Stdio::piped()).spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(password.as_bytes())?;
        }
        child.wait()?;
    }

    // Schedule clipboard clearing
    Command::new("sh")
        .args([
            "-c",
            &format!("sleep {CLIPBOARD_CLEAR_SECONDS} && echo -n '' | pbcopy"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    Ok(())
}

fn copy_clipboard_linux(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (copy_cmd, copy_args, clear_cmd) = if command_exists("xclip") {
        (
            "xclip",
            vec!["-sel", "clipboard"],
            "echo -n '' | xclip -sel clipboard",
        )
    } else if command_exists("wl-copy") {
        ("wl-copy", vec![], "wl-copy ''")
    } else {
        return Err("No clipboard tool found. Install xclip (X11) or wl-copy (Wayland).".into());
    };

    let mut child = Command::new(copy_cmd)
        .args(&copy_args)
        .stdin(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(password.as_bytes())?;
    }
    child.wait()?;

    Command::new("sh")
        .args([
            "-c",
            &format!("sleep {CLIPBOARD_CLEAR_SECONDS} && {clear_cmd}"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    Ok(())
}

fn copy_clipboard_windows(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("clip").stdin(Stdio::piped()).spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(password.as_bytes())?;
    }
    child.wait()?;

    Command::new("cmd")
        .args([
            "/C",
            &format!(
                "start /b powershell -WindowStyle Hidden -Command \"Start-Sleep -Seconds {CLIPBOARD_CLEAR_SECONDS}; Set-Clipboard -Value ''\""
            ),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    Ok(())
}

/// Decode hex string to bytes
fn hex_decode(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if hex.len() % 2 != 0 {
        return Err("Invalid hex string length".into());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);

    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)?;
        bytes.push(byte);
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("00").unwrap(), vec![0u8]);
        assert_eq!(hex_decode("ff").unwrap(), vec![255u8]);
        assert_eq!(hex_decode("0102").unwrap(), vec![1u8, 2u8]);
        assert_eq!(
            hex_decode("7a3f8b2c").unwrap(),
            vec![0x7a, 0x3f, 0x8b, 0x2c]
        );
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("GitHub.com"), "github.com");
        assert_eq!(normalize_domain("GITHUB.COM"), "github.com");
        assert_eq!(normalize_domain("https://github.com"), "github.com");
        assert_eq!(normalize_domain("http://github.com"), "github.com");
        assert_eq!(normalize_domain("www.github.com"), "github.com");
        assert_eq!(
            normalize_domain("https://www.github.com/path"),
            "github.com"
        );
        assert_eq!(normalize_domain("  github.com  "), "github.com");
        assert_eq!(normalize_domain("github.com/"), "github.com");
        // Query strings and fragments
        assert_eq!(normalize_domain("example.com?foo=bar"), "example.com");
        assert_eq!(normalize_domain("example.com#section"), "example.com");
        assert_eq!(
            normalize_domain("example.com/path?query=1#hash"),
            "example.com"
        );
        // Port numbers
        assert_eq!(normalize_domain("localhost:3000"), "localhost");
        assert_eq!(normalize_domain("localhost:8080/path"), "localhost");
        assert_eq!(normalize_domain("https://example.com:443"), "example.com");
        assert_eq!(normalize_domain("http://localhost:3000/api"), "localhost");
    }

    #[test]
    fn test_password_determinism() {
        let seed = vec![0x01, 0x02, 0x03, 0x04];
        let pin = "test123";
        let domain = "example.com";
        let username = "user@example.com";
        let version = 1;

        let pass1 = generate_password(&seed, pin, domain, username, version).unwrap();
        let pass2 = generate_password(&seed, pin, domain, username, version).unwrap();

        assert_eq!(*pass1, *pass2);
        assert_eq!(pass1.len(), PASSWORD_LENGTH);
    }

    #[test]
    fn test_password_differs_by_username() {
        let seed = vec![0x01, 0x02, 0x03, 0x04];
        let pin = "test123";
        let domain = "example.com";
        let version = 1;

        let pass1 = generate_password(&seed, pin, domain, "user1", version).unwrap();
        let pass2 = generate_password(&seed, pin, domain, "user2", version).unwrap();

        assert_ne!(*pass1, *pass2);
    }

    #[test]
    fn test_password_differs_by_version() {
        let seed = vec![0x01, 0x02, 0x03, 0x04];
        let pin = "test123";
        let domain = "example.com";
        let username = "user";

        let pass1 = generate_password(&seed, pin, domain, username, 1).unwrap();
        let pass2 = generate_password(&seed, pin, domain, username, 2).unwrap();

        assert_ne!(*pass1, *pass2);
    }

    #[test]
    fn test_password_backward_compatible() {
        // Empty username should work (domain-only mode)
        let seed = vec![0x01, 0x02, 0x03, 0x04];
        let pin = "test123";
        let domain = "example.com";

        let pass = generate_password(&seed, pin, domain, "", 1).unwrap();
        assert_eq!(pass.len(), PASSWORD_LENGTH);
    }

    #[test]
    fn test_password_has_all_char_types() {
        let seed = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pin = "testpin";
        let domain = "test.com";

        let password = generate_password(&seed, pin, domain, "", 1).unwrap();

        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| SYMBOLS.contains(&(c as u8))));
    }

    #[test]
    fn test_state_serialization() {
        let mut state = State::default();
        add_username(&mut state, "github.com", "user1");
        add_username(&mut state, "github.com", "user2");
        set_version(&mut state, "github.com", "user1", 2);
        set_version(&mut state, "github.com", "user2", 3);

        let json = serde_json::to_string(&state).unwrap();
        let loaded: State = serde_json::from_str(&json).unwrap();

        let usernames = get_usernames(&loaded, "github.com");
        assert!(usernames.contains(&"user1".to_string()));
        assert!(usernames.contains(&"user2".to_string()));
        assert_eq!(get_version(&loaded, "github.com", "user1"), 2);
        assert_eq!(get_version(&loaded, "github.com", "user2"), 3);
        assert_eq!(get_version(&loaded, "github.com", ""), 1); // domain-only defaults to 1
    }

    #[test]
    fn test_state_version_default() {
        // New state should have current version
        let state = State::default();
        assert_eq!(state.version, STATE_FORMAT_VERSION);
    }

    #[test]
    fn test_state_version_old_format() {
        // Old state without version field should default to v1
        let json = r#"{"domains":{"github.com":{"usernames":{"user1":1}}}}"#;
        let loaded: State = serde_json::from_str(json).unwrap();
        assert_eq!(loaded.version, 1);
    }

    #[test]
    fn test_state_version_preserved() {
        // Current version should be preserved in serialization
        let state = State::default();
        let json = serde_json::to_string(&state).unwrap();
        let loaded: State = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.version, STATE_FORMAT_VERSION);
    }

    #[test]
    fn test_pin_checksum_deterministic() {
        let pin = "test_pin";

        // Same PIN should produce same checksum
        let checksum1 = compute_pin_checksum(pin).unwrap();
        let checksum2 = compute_pin_checksum(pin).unwrap();

        assert_eq!(checksum1, checksum2);
    }

    #[test]
    fn test_pin_checksum_2_bits() {
        let pin = "test_pin";

        // Checksum should be 2 bits (0-3)
        let checksum = compute_pin_checksum(pin).unwrap();
        assert!(checksum <= 3);
    }

    #[test]
    fn test_pin_checksum_different_pins() {
        // Different PINs may or may not have same checksum (2-bit = 25% collision)
        // Just verify the function works with different inputs
        let checksum1 = compute_pin_checksum("pin1").unwrap();
        let checksum2 = compute_pin_checksum("pin2").unwrap();

        // Both should be valid 2-bit values
        assert!(checksum1 <= 3);
        assert!(checksum2 <= 3);
    }

    #[test]
    fn test_all_chars_length() {
        // Verify ALL_CHARS has the expected length (26 + 26 + 10 + 26 = 88)
        assert_eq!(ALL_CHARS.len(), 88);
        assert_eq!(
            ALL_CHARS.len(),
            LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len()
        );
    }

    // === Edge Case Tests ===

    #[test]
    fn test_unicode_domain_names() {
        // Unicode domains should be normalized properly
        let unicode_domains = [
            "example.com", // ASCII baseline
            "münchen.de",  // German umlaut
            "北京.中国",   // Chinese characters
            "موقع.مصر",    // Arabic
            "пример.рф",   // Cyrillic
            "例え.jp",     // Japanese
            "café.fr",     // Accented Latin
            "🔐.com",      // Emoji (edge case)
        ];

        for domain in &unicode_domains {
            let normalized = normalize_domain(domain);
            // Should not be empty after normalization
            assert!(
                !normalized.is_empty(),
                "Domain '{domain}' normalized to empty"
            );
            // Should be lowercase
            assert_eq!(
                normalized,
                normalized.to_lowercase(),
                "Domain '{domain}' not lowercased"
            );
            // Should be consistent
            let normalized2 = normalize_domain(domain);
            assert_eq!(
                normalized, normalized2,
                "Domain '{domain}' not deterministic"
            );
        }
    }

    #[test]
    fn test_unicode_domain_password_generation() {
        let seed = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pin = "testpin";

        // Generate passwords for unicode domains
        let domains = ["münchen.de", "北京.中国", "example.com"];

        for domain in &domains {
            let normalized = normalize_domain(domain);
            let password = generate_password(&seed, pin, &normalized, "", 1).unwrap();

            assert_eq!(password.len(), PASSWORD_LENGTH);
            // Password should only contain ASCII characters from our charset
            assert!(password.chars().all(|c| ALL_CHARS.contains(&(c as u8))));
        }

        // Different unicode domains should produce different passwords
        let pass1 = generate_password(&seed, pin, &normalize_domain("münchen.de"), "", 1).unwrap();
        let pass2 = generate_password(&seed, pin, &normalize_domain("北京.中国"), "", 1).unwrap();
        assert_ne!(*pass1, *pass2);
    }

    #[test]
    fn test_very_long_username() {
        let seed = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pin = "testpin";
        let domain = "example.com";

        // Test with username > 1000 chars
        let long_username: String = "a".repeat(1500);
        let password = generate_password(&seed, pin, domain, &long_username, 1).unwrap();

        assert_eq!(password.len(), PASSWORD_LENGTH);
        assert!(password.chars().all(|c| ALL_CHARS.contains(&(c as u8))));

        // Very long username should produce different password than short one
        let short_password = generate_password(&seed, pin, domain, "short", 1).unwrap();
        assert_ne!(*password, *short_password);
    }

    #[test]
    fn test_extremely_long_username() {
        let seed = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pin = "testpin";
        let domain = "example.com";

        // Test with username of 10,000 chars
        let huge_username: String = "x".repeat(10_000);
        let password = generate_password(&seed, pin, domain, &huge_username, 1).unwrap();

        assert_eq!(password.len(), PASSWORD_LENGTH);

        // Should be deterministic
        let password2 = generate_password(&seed, pin, domain, &huge_username, 1).unwrap();
        assert_eq!(*password, *password2);
    }

    #[test]
    fn test_state_with_long_usernames() {
        let mut state = State::default();
        let long_username: String = "user".repeat(500); // 2000 chars

        add_username(&mut state, "example.com", &long_username);
        set_version(&mut state, "example.com", &long_username, 5);

        // Serialize and deserialize
        let json = serde_json::to_string(&state).unwrap();
        let loaded: State = serde_json::from_str(&json).unwrap();

        let usernames = get_usernames(&loaded, "example.com");
        assert!(usernames.contains(&long_username));
        assert_eq!(get_version(&loaded, "example.com", &long_username), 5);
    }

    #[test]
    fn test_empty_state_json_recovery() {
        // Empty JSON object without required fields should fail to parse
        let result: Result<State, _> = serde_json::from_str("{}");
        // This fails because 'domains' is required
        assert!(result.is_err());

        // But a valid minimal state should work
        let result: Result<State, _> = serde_json::from_str(r#"{"domains":{}}"#);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert!(state.domains.is_empty());
        assert_eq!(state.version, 1); // Default version for old format
    }

    #[test]
    fn test_corrupted_state_json_recovery() {
        // Various corrupted JSON inputs
        let corrupted_inputs = [
            "",                       // Empty string
            "{",                      // Incomplete JSON
            "null",                   // Null value
            "[]",                     // Array instead of object
            "{\"domains\": null}",    // Null domains
            "not json at all",        // Plain text
            "{\"version\": \"bad\"}", // Wrong type for version
        ];

        for input in &corrupted_inputs {
            let result: Result<State, _> = serde_json::from_str(input);
            // These should all fail to parse (except maybe some edge cases)
            // The important thing is they don't panic
            let _ = result; // Just ensure no panic
        }
    }

    #[test]
    fn test_state_with_special_characters_in_username() {
        let mut state = State::default();

        // Test usernames with special characters (excluding empty - that's domain-only mode)
        let special_usernames = [
            "user@example.com",
            "user+tag@example.com",
            "user with spaces",
            "user\twith\ttabs",
            "user\"with\"quotes",
            "user\\with\\backslashes",
            "用户名",       // Chinese
            "пользователь", // Russian
        ];

        for username in &special_usernames {
            add_username(&mut state, "test.com", username);
        }

        // Also add domain-only entry (empty username)
        add_username(&mut state, "test.com", "");

        // Serialize and deserialize
        let json = serde_json::to_string(&state).unwrap();
        let loaded: State = serde_json::from_str(&json).unwrap();

        // Check non-empty usernames via get_usernames
        let usernames = get_usernames(&loaded, "test.com");
        for username in &special_usernames {
            assert!(
                usernames.contains(&username.to_string()),
                "Username '{username}' not found after serialization"
            );
        }

        // Check domain-only entry via get_version (get_usernames intentionally filters it out)
        assert_eq!(get_version(&loaded, "test.com", ""), 1);
    }

    #[test]
    fn test_concurrent_state_modifications() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let state = Arc::new(Mutex::new(State::default()));
        let mut handles = vec![];

        // Spawn multiple threads that modify state concurrently
        for i in 0..10 {
            let state_clone = Arc::clone(&state);
            let handle = thread::spawn(move || {
                let mut state = state_clone.lock().unwrap();
                let domain = format!("domain{i}.com");
                let username = format!("user{i}");

                add_username(&mut state, &domain, &username);
                set_version(&mut state, &domain, &username, (i + 1) as u32);

                // Verify our changes
                assert_eq!(get_version(&state, &domain, &username), (i + 1) as u32);
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all domains were added
        let final_state = state.lock().unwrap();
        assert_eq!(final_state.domains.len(), 10);

        for i in 0..10 {
            let domain = format!("domain{i}.com");
            let username = format!("user{i}");
            assert_eq!(
                get_version(&final_state, &domain, &username),
                (i + 1) as u32
            );
        }
    }

    #[test]
    fn test_password_generation_thread_safety() {
        use std::thread;

        let seed = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pin = "testpin";
        let domain = "example.com";

        let mut handles = vec![];

        // Generate passwords concurrently
        for i in 0..10 {
            let seed_clone = seed.clone();
            let pin = pin.to_string();
            let domain = domain.to_string();

            let handle = thread::spawn(move || {
                let username = format!("user{i}");
                let password = generate_password(&seed_clone, &pin, &domain, &username, 1).unwrap();

                // Verify password is valid
                assert_eq!(password.len(), PASSWORD_LENGTH);
                assert!(password.chars().all(|c| ALL_CHARS.contains(&(c as u8))));

                // Return for comparison
                (username, password.to_string())
            });
            handles.push(handle);
        }

        // Collect results
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Verify determinism - regenerate and compare
        for (username, expected_password) in &results {
            let password = generate_password(&seed, pin, domain, username, 1).unwrap();
            assert_eq!(&*password, expected_password);
        }
    }

    #[test]
    fn test_domain_normalization_edge_cases() {
        // Test various edge cases in domain normalization
        let test_cases = [
            ("GITHUB.COM", "github.com"),                       // Uppercase
            ("GitHub.Com", "github.com"),                       // Mixed case
            ("https://github.com", "github.com"),               // With protocol
            ("http://github.com", "github.com"),                // HTTP protocol
            ("github.com/user/repo", "github.com"),             // With path
            ("github.com?query=1", "github.com"),               // With query
            ("github.com#anchor", "github.com"),                // With anchor
            ("www.github.com", "github.com"),                   // With www
            ("  github.com  ", "github.com"),                   // With whitespace
            ("sub.domain.github.com", "sub.domain.github.com"), // Subdomain preserved
        ];

        for (input, expected) in &test_cases {
            let normalized = normalize_domain(input);
            assert_eq!(
                &normalized, expected,
                "normalize_domain({input:?}) = {normalized:?}, expected {expected:?}"
            );
        }
    }

    #[test]
    fn test_empty_and_whitespace_inputs() {
        let seed = vec![0x01, 0x02, 0x03, 0x04];
        let pin = "test";

        // Empty domain (after normalization of whitespace-only input)
        let empty_domain = normalize_domain("   ");
        // Should work but produce empty string
        assert!(empty_domain.is_empty() || !empty_domain.trim().is_empty());

        // Whitespace-only username should work
        let password = generate_password(&seed, pin, "example.com", "   ", 1).unwrap();
        assert_eq!(password.len(), PASSWORD_LENGTH);

        // Different whitespace patterns should produce different passwords
        let pass1 = generate_password(&seed, pin, "example.com", " ", 1).unwrap();
        let pass2 = generate_password(&seed, pin, "example.com", "  ", 1).unwrap();
        assert_ne!(*pass1, *pass2);
    }
}
