//! Secure password generator using YubiKey HMAC-SHA1 + PIN + domain
//!
//! Generates deterministic passwords using:
//! - YubiKey HMAC-SHA1 challenge-response (slot 1)
//! - User-provided PIN/password
//! - Target domain
//! - Hardcoded application salt
//!
//! Uses Argon2id for key derivation
//!
//! Supported platforms: macOS, Linux, Windows

use argon2::{Argon2, Params, Version};
use std::io::{self, Write};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// Hardcoded application salt - adds additional entropy unique to this installation
/// IMPORTANT: Regenerate this for your own installation using:
///   head -c 32 /dev/urandom | xxd -i   (macOS/Linux)
///   or use any secure random generator
const APP_SALT: [u8; 32] = [
    0x7a, 0x3f, 0x8b, 0x2c, 0xe1, 0x94, 0x5d, 0x6f,
    0xb8, 0x0a, 0x4e, 0x73, 0xc2, 0x1b, 0x9d, 0x85,
    0xf4, 0x67, 0x2e, 0xa9, 0x3c, 0x58, 0xd0, 0x16,
    0x8f, 0xe5, 0x4b, 0x7d, 0x0c, 0xa2, 0x63, 0x91,
];

/// Password character sets
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

/// All characters combined for password generation
const ALL_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";

const PASSWORD_LENGTH: usize = 32;
const CLIPBOARD_CLEAR_SECONDS: u64 = 20;
const YUBIKEY_SLOT: &str = "1";

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <domain>", args[0]);
        eprintln!("Example: {} github.com", args[0]);
        eprintln!();
        eprintln!("Requirements:");
        eprintln!("  YubiKey: ykchalresp (brew install ykpers / apt install yubikey-personalization)");
        eprintln!("  Setup:   ykman otp chalresp --generate 1  (brew install ykman to configure)");
        eprintln!("  Clipboard:");
        eprintln!("    macOS:   pbcopy (built-in)");
        eprintln!("    Linux:   xclip (apt install xclip) or wl-copy (Wayland)");
        eprintln!("    Windows: clip.exe (built-in)");
        std::process::exit(1);
    }

    let domain = &args[1];

    // Step 1: Get YubiKey HMAC-SHA1 response
    eprint!("Touch your YubiKey...");
    io::stderr().flush()?;

    let yubikey_seed = get_yubikey_response(domain)?;
    eprintln!(" OK");

    // Step 2: Get PIN from user (no echo)
    eprint!("Enter PIN: ");
    io::stderr().flush()?;

    let pin = read_password_no_echo()?;
    eprintln!();

    if pin.is_empty() {
        return Err("PIN cannot be empty".into());
    }

    // Step 3: Generate password using Argon2id
    let password = generate_password(&yubikey_seed, &pin, domain)?;

    // Step 4: Copy to clipboard and schedule clear
    copy_to_clipboard_with_clear(&password)?;

    // Step 5: Display password (for terminal use)
    println!("{}", &*password);

    eprintln!("Password copied to clipboard. Will be cleared in {CLIPBOARD_CLEAR_SECONDS} seconds.");

    Ok(())
}

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
/// Uses ykchalresp from ykpers package (the correct tool for challenge-response)
fn get_yubikey_response(challenge: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    // ykchalresp is the tool for HMAC-SHA1 challenge-response
    // -1 or -2: slot number
    // -H: output as hex
    if command_exists("ykchalresp") {
        let slot_flag = format!("-{}", YUBIKEY_SLOT);
        let output = Command::new("ykchalresp")
            .args([&slot_flag, "-H", challenge])
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;

        if output.status.success() {
            let hex_response = String::from_utf8(output.stdout)?
                .trim()
                .to_string();
            if !hex_response.is_empty() {
                let bytes = hex_decode(&hex_response)?;
                return Ok(Zeroizing::new(bytes));
            }
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("YubiKey challenge-response failed: {}", stderr.trim()).into());
    }

    // Tool not found - provide helpful diagnostics
    let os = detect_os();
    let install_hint = match os {
        "macos" => "Install: brew install ykpers",
        "windows" => "Install: Download from https://developers.yubico.com/yubikey-personalization/Releases/",
        _ => "Install: apt install yubikey-personalization",
    };

    let setup_hint = format!("\
To configure HMAC-SHA1 challenge-response on slot {slot}:
  ykman otp chalresp --generate {slot}
  (requires: brew install ykman / pip install yubikey-manager)

To verify slot {slot} is configured:
  ykman otp info", slot = YUBIKEY_SLOT);

    Err(format!(
        "ykchalresp not found in PATH.\n\n\
         {install_hint}\n\n\
         {setup_hint}"
    ).into())
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
    // Save current terminal settings
    let output = Command::new("stty")
        .args(["-g"])
        .stdin(Stdio::inherit())
        .output()?;

    let saved_settings = String::from_utf8(output.stdout)?.trim().to_string();

    // Disable echo
    Command::new("stty")
        .args(["-echo"])
        .stdin(Stdio::inherit())
        .status()?;

    // Read the password
    let mut password = Zeroizing::new(String::new());
    let result = io::stdin().read_line(&mut password);

    // Always restore terminal settings, even on error
    let _ = Command::new("stty")
        .arg(&saved_settings)
        .stdin(Stdio::inherit())
        .status();

    result?;

    // Remove trailing newline
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

    // On Windows, we use a simple character-by-character read
    // In production, consider using the windows-sys crate for proper console mode handling
    let mut password = Zeroizing::new(String::new());

    // Fallback: read line normally (echo will show, but works)
    // For proper no-echo on Windows, would need winapi/windows-sys crate
    io::stdin().read_line(&mut password)?;

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
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    // Combine all inputs: yubikey_seed || pin || domain || app_salt
    let mut input = Zeroizing::new(Vec::new());
    input.extend_from_slice(yubikey_seed);
    input.extend_from_slice(pin.as_bytes());
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(&APP_SALT);

    // Argon2id parameters (OWASP recommendations)
    // - Memory: 64 MiB (65536 KiB)
    // - Iterations: 3
    // - Parallelism: 4
    let params = Params::new(
        65536,   // m_cost: 64 MiB
        3,       // t_cost: 3 iterations
        4,       // p_cost: 4 parallel lanes
        Some(64) // output length: 64 bytes
    )?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    // Use domain + app_salt prefix as salt for Argon2
    let mut salt = Zeroizing::new(Vec::new());
    salt.extend_from_slice(domain.as_bytes());
    salt.extend_from_slice(&APP_SALT[..16]);

    // Ensure salt is at least 8 bytes (Argon2 requirement)
    while salt.len() < 8 {
        salt.push(0x00);
    }

    let mut derived_key = Zeroizing::new(vec![0u8; 64]);
    argon2.hash_password_into(&input, &salt, &mut derived_key)?;

    // Convert derived bytes to password string
    let password = bytes_to_password(&derived_key)?;

    Ok(password)
}

/// Convert derived bytes to a password string ensuring all character types are present
fn bytes_to_password(bytes: &[u8]) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let mut password = Zeroizing::new(String::with_capacity(PASSWORD_LENGTH));
    let all_chars_len = ALL_CHARS.len();

    // Generate password characters
    for i in 0..PASSWORD_LENGTH {
        let idx = bytes[i] as usize % all_chars_len;
        password.push(ALL_CHARS[idx] as char);
    }

    // Ensure at least one character from each category
    let mut password_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(password.as_bytes().to_vec());

    let checks: [(fn(&u8) -> bool, &[u8], usize); 4] = [
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
    // Copy using pbcopy
    let mut child = Command::new("pbcopy")
        .stdin(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(password.as_bytes())?;
    }
    child.wait()?;

    // Schedule clear using background process
    Command::new("sh")
        .args([
            "-c",
            &format!(
                "sleep {CLIPBOARD_CLEAR_SECONDS} && echo -n '' | pbcopy"
            ),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    Ok(())
}

fn copy_clipboard_linux(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Try xclip first, then wl-copy for Wayland
    let (copy_cmd, copy_args, clear_cmd) = if command_exists("xclip") {
        ("xclip", vec!["-sel", "clipboard"], "echo -n '' | xclip -sel clipboard")
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

    // Schedule clear
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
    // Copy using clip.exe
    let mut child = Command::new("clip")
        .stdin(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(password.as_bytes())?;
    }
    child.wait()?;

    // Schedule clear using PowerShell in background
    // Note: This creates a visible PowerShell window briefly
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
    fn test_password_determinism() {
        let seed = vec![0x01, 0x02, 0x03, 0x04];
        let pin = "test123";
        let domain = "example.com";

        let pass1 = generate_password(&seed, pin, domain).unwrap();
        let pass2 = generate_password(&seed, pin, domain).unwrap();

        assert_eq!(*pass1, *pass2);
        assert_eq!(pass1.len(), PASSWORD_LENGTH);
    }

    #[test]
    fn test_password_has_all_char_types() {
        let seed = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pin = "testpin";
        let domain = "test.com";

        let password = generate_password(&seed, pin, domain).unwrap();

        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| SYMBOLS.contains(&(c as u8))));
    }
}
