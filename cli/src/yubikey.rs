//! YubiKey interaction and terminal input

use crate::config::YUBIKEY_SLOT;
use crate::utils::hex_decode;
use std::io;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// Detect current operating system
pub fn detect_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

/// Check if a command exists in PATH
pub fn command_exists(cmd: &str) -> bool {
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
pub fn get_yubikey_response(
    challenge: &str,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
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
pub fn read_password_no_echo() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
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
