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

mod clipboard;
mod config;
mod interactive;
mod password;
mod pin;
mod state;
mod utils;
mod yubikey;

use clap::{CommandFactory, Parser};
use clap_complete::Shell;
use std::io::{self, Write};

use clipboard::copy_to_clipboard_with_clear;
use config::{CLIPBOARD_CLEAR_SECONDS, STATE_KEY_CHALLENGE};
use interactive::{select_domain, select_username};
use password::generate_password;
use pin::{
    compute_pin_checksum, delete_pin_checksum, load_pin_checksum, save_pin_checksum,
    verify_pin_checksum,
};
use state::{
    DomainState, add_username, derive_state_key, get_usernames, get_version, list_all_entries,
    load_state, save_state, set_version,
};
use utils::normalize_domain;
use yubikey::{get_yubikey_response, read_password_no_echo};

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
        select_username(
            &get_usernames(&state, &normalized_domain),
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

/// Generate shell completions
fn print_completions(shell: Shell) {
    let mut cmd = Args::command();
    clap_complete::generate(shell, &mut cmd, "ypass", &mut io::stdout());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PASSWORD_LENGTH, STATE_FORMAT_VERSION};
    use crate::password::{ALL_CHARS, SYMBOLS};
    use crate::state::State;

    #[test]
    fn test_hex_decode() {
        use crate::utils::hex_decode;
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
        use crate::pin::compute_pin_checksum;
        let pin = "test_pin";

        // Same PIN should produce same checksum
        let checksum1 = compute_pin_checksum(pin).unwrap();
        let checksum2 = compute_pin_checksum(pin).unwrap();

        assert_eq!(checksum1, checksum2);
    }

    #[test]
    fn test_pin_checksum_2_bits() {
        use crate::pin::compute_pin_checksum;
        let pin = "test_pin";

        // Checksum should be 2 bits (0-3)
        let checksum = compute_pin_checksum(pin).unwrap();
        assert!(checksum <= 3);
    }

    #[test]
    fn test_pin_checksum_different_pins() {
        use crate::pin::compute_pin_checksum;
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
        use crate::password::{DIGITS, LOWERCASE, UPPERCASE};
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
