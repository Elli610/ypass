# Password Generator

A secure, deterministic password generator using YubiKey HMAC-SHA1 challenge-response.

## How It Works

Generates passwords by combining:
- YubiKey HMAC-SHA1 secret (hardware)
- Your PIN (memorized)
- Domain name (site-specific)
- Hardcoded application salt (in binary)

Same inputs always produce the same password. No password storage needed.

## Requirements

| Platform | YubiKey Tool | Clipboard |Tested ?|
|----------|--------------|-----------|--------|
| macOS    | `brew install ykpers` | pbcopy (built-in) | yes |
| Linux    | `apt install yubikey-personalization` | xclip or wl-copy | No |
| Windows  | [Download ykpers](https://developers.yubico.com/yubikey-personalization/Releases/) | clip.exe (built-in) | No |

For YubiKey configuration, also install ykman:
- macOS: `brew install ykman`
- Linux/Windows: `pip install yubikey-manager`

## YubiKey Setup

### 1. Configure HMAC-SHA1 on Slot 1

```bash
ykman otp chalresp --generate --touch 1

# With your own salt
ykman otp chalresp --touch 1
```


### 2. Backup Your Secret

**CRITICAL: Save the hex key immediately.** You cannot extract it later.

The secret is the hex string shown:
```
1baaf06deb405c5e3a2cd4978f0b0c5431a470a6
```

Store this in a secure vault (1Password, Bitwarden, etc.) or write it down and store physically.

### 3. Verify Setup

```bash
ykman otp info
```

Should show:
```
Slot 1: programmed
```

## Build

```bash
cargo build --release
```

Binary will be at `target/release/password-generator`.

## Install

Install the CLI to your local bin directory:

```bash
# macOS / Linux
cp target/release/password-generator ~/.local/bin/
# or system-wide
sudo cp target/release/password-generator /usr/local/bin/

# Windows (PowerShell as Admin)
copy target\release\password-generator.exe C:\Windows\System32\
```

Ensure `~/.local/bin` is in your PATH:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"
```

## Usage

```bash
password-generator github.com
```

1. Touch your YubiKey when prompted
2. Enter your PIN
3. Password is displayed and copied to clipboard
4. Clipboard auto-clears after 20 seconds

## Restore From Backup

If you lose your YubiKey, program a new one with the saved secret:

```bash
ykman otp chalresp --touch 1 YOUR_HEX_SECRET_HERE
```

Example:
```bash
ykman otp chalresp --touch 1 1baaf06deb405c5e3a2cd4978f0b0c5431a470a6
```

This will generate identical passwords as your original YubiKey.

## Security Notes

- `--touch` flag requires physical touch for each operation (recommended)
- PIN is never stored or displayed
- Clipboard clears automatically after 20 seconds
- Application salt in `src/main.rs` adds extra entropy (consider changing it for your build)

## Customization

Edit `src/main.rs` constants:

```rust
const PASSWORD_LENGTH: usize = 32;      // Password length
const CLIPBOARD_CLEAR_SECONDS: u64 = 20; // Clipboard timeout
const YUBIKEY_SLOT: &str = "1";          // YubiKey slot (1 or 2)
```

To generate your own application salt:
```bash
head -c 32 /dev/urandom | xxd -i
```

Replace `APP_SALT` array in `src/main.rs` with the output.
