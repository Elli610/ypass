//! Platform-specific clipboard operations

use crate::config::CLIPBOARD_CLEAR_SECONDS;
use crate::yubikey::{command_exists, detect_os};
use std::io::Write;
use std::process::{Command, Stdio};

/// Copy password to clipboard and schedule automatic clearing
pub fn copy_to_clipboard_with_clear(password: &str) -> Result<(), Box<dyn std::error::Error>> {
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
