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
            let mut stdout = Zeroizing::new(output.stdout);
            let mut hex_response = Zeroizing::new(String::from_utf8(std::mem::take(&mut *stdout))?);
            let trimmed = hex_response.trim().to_string();
            zeroize::Zeroize::zeroize(&mut *hex_response);
            let hex_response = Zeroizing::new(trimmed);
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
mod termios_guard {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Global storage for original termios so the signal handler can restore it.
    /// Safe because: only accessed from main thread (set/clear) and signal handler
    /// (read), and libc::termios is a plain C struct with no pointers.
    static ECHO_DISABLED: AtomicBool = AtomicBool::new(false);
    static mut SAVED_TERMIOS: std::mem::MaybeUninit<libc::termios> =
        std::mem::MaybeUninit::uninit();
    static mut PREV_SIGINT: libc::sighandler_t = libc::SIG_DFL;
    static mut PREV_SIGTERM: libc::sighandler_t = libc::SIG_DFL;

    /// RAII guard that restores terminal echo on drop and cleans up signal handlers.
    pub struct EchoGuard {
        fd: i32,
    }

    impl EchoGuard {
        pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let fd = libc::STDIN_FILENO;

            // Save current terminal settings
            let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
            if unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) } != 0 {
                return Err("Failed to get terminal attributes".into());
            }
            let original = unsafe { termios.assume_init() };

            // Store globally for signal handler access
            unsafe { SAVED_TERMIOS = std::mem::MaybeUninit::new(original) };

            // Install signal handlers before disabling echo
            unsafe {
                PREV_SIGINT = libc::signal(
                    libc::SIGINT,
                    restore_and_reraise as *const () as libc::sighandler_t,
                );
                PREV_SIGTERM = libc::signal(
                    libc::SIGTERM,
                    restore_and_reraise as *const () as libc::sighandler_t,
                );
            }

            // Disable echo
            let mut noecho = original;
            noecho.c_lflag &= !libc::ECHO;
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &noecho) } != 0 {
                // Restore signal handlers on failure
                unsafe {
                    libc::signal(libc::SIGINT, PREV_SIGINT);
                    libc::signal(libc::SIGTERM, PREV_SIGTERM);
                }
                return Err("Failed to disable terminal echo".into());
            }

            ECHO_DISABLED.store(true, Ordering::SeqCst);
            Ok(EchoGuard { fd })
        }
    }

    impl Drop for EchoGuard {
        fn drop(&mut self) {
            if ECHO_DISABLED.swap(false, Ordering::SeqCst) {
                let original = unsafe { SAVED_TERMIOS.assume_init() };
                unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &original) };
            }
            // Restore previous signal handlers
            unsafe {
                libc::signal(libc::SIGINT, PREV_SIGINT);
                libc::signal(libc::SIGTERM, PREV_SIGTERM);
            }
        }
    }

    /// Signal handler: restore terminal, then re-raise with default handler.
    extern "C" fn restore_and_reraise(sig: libc::c_int) {
        if ECHO_DISABLED.swap(false, Ordering::SeqCst) {
            let original = unsafe { SAVED_TERMIOS.assume_init() };
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &original) };
        }
        // Re-raise with default handler so the process exits with correct status
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn read_password_unix() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let _guard = termios_guard::EchoGuard::new()?;

    let mut password = Zeroizing::new(String::new());
    io::stdin().read_line(&mut password)?;

    // Guard restores echo on drop (including early returns and signals)
    drop(_guard);

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
