# Password Generator

A secure, deterministic password generator using YubiKey HMAC-SHA1 challenge-response.

## How It Works

Generates passwords by combining:
- YubiKey HMAC-SHA1 secret (hardware)
- Your PIN (memorized)
- Domain name (normalized, site-specific)
- Username (optional, for multi-account support)
- Version number (for password rotation)
- Hardcoded application salt (in binary)

Same inputs always produce the same password. No password storage needed.

## Features

- **Domain normalization**: `GitHub.com`, `https://www.github.com/path` all normalize to `github.com`
- **Multi-account support**: Different passwords for different usernames on the same domain
- **Password rotation**: Bump version to generate new passwords without changing PIN
- **Encrypted state file**: Usernames and versions stored in `~/.config/dpg/state.enc`, encrypted with YubiKey

## Requirements

| Platform | YubiKey Tool | Clipboard | Tested? |
|----------|--------------|-----------|---------|
| macOS    | `brew install ykpers` | pbcopy (built-in) | Yes |
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

### Basic Usage

```bash
password-generator github.com
```

1. Touch YubiKey to unlock state file
2. Touch YubiKey again for password generation
3. Enter your PIN
4. Password is displayed and copied to clipboard
5. Clipboard auto-clears after 20 seconds

### Command Line Options

```
password-generator <domain> [options]

Options:
  -v, --version <n>     Use specific version (default: from state or 1)
  -u, --user <name>     Use specific username (skip interactive selection)
  --add-user <name>     Add username to domain (no password generated)
  --bump-version        Increment version for domain
  --list                List all domains and usernames
  -h, --help            Show help
```

### Multi-Account Support

For sites where you have multiple accounts (e.g., Gmail):

```bash
# Add usernames to a domain
password-generator gmail.com --add-user personal@gmail.com
password-generator gmail.com --add-user work@gmail.com

# Generate password - shows interactive selection
password-generator gmail.com
# Output:
# Usernames for 'gmail.com':
#   [1] personal@gmail.com
#   [2] work@gmail.com
#   [n] Add new username
#   [d] Use domain-only (no username)
# Select [1]:

# Or specify username directly
password-generator gmail.com -u personal@gmail.com
```

### Password Rotation

When a site is breached and you need a new password:

```bash
# Bump version (changes from v1 to v2)
password-generator github.com --bump-version

# Or use a specific version
password-generator github.com -v 3
```

> Note: latest version is use by default

### List All Entries

```bash
password-generator --list
# Output:
# github.com (v2)
#   - myuser
# gmail.com (v1)
#   - personal@gmail.com
#   - work@gmail.com
```

### Domain Normalization

All these produce the same password:

```bash
password-generator github.com
password-generator GitHub.com
password-generator https://github.com
password-generator https://www.github.com/settings
password-generator www.github.com
```

## State File

Usernames and versions are stored encrypted at `~/.config/dpg/state.enc`.

- Encrypted with ChaCha20-Poly1305
- Key derived from YubiKey HMAC response (requires YubiKey to decrypt)
- Contains only domain names, usernames, and version numbers
- No passwords or secrets are stored

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

**Note**: You also need to backup your state file (`~/.config/dpg/state.enc`) to preserve username and version information. Without it, you'll need to remember which usernames and versions you used.

## Security Notes

- `--touch` flag requires physical touch for each operation (recommended)
- PIN is never stored or displayed
- Clipboard clears automatically after 20 seconds
- Application salt in `src/main.rs` adds extra entropy (consider changing it for your build)
- State file is encrypted and requires YubiKey to decrypt
- Two YubiKey touches required per password generation (one for state, one for password)

## Customization

Edit `src/main.rs` constants:

```rust
const PASSWORD_LENGTH: usize = 32;       // Password length
const CLIPBOARD_CLEAR_SECONDS: u64 = 20; // Clipboard timeout
const YUBIKEY_SLOT: &str = "1";          // YubiKey slot (1 or 2)
```

To generate your own application salt:
```bash
head -c 32 /dev/urandom | xxd -i
```

Replace `APP_SALT` array in `src/main.rs` with the output.

## Backward Compatibility

If you were using an earlier version without username/version support:
- Domain-only mode still works (just don't add usernames)
- Version defaults to 1
- Existing passwords remain unchanged when using empty username and version 1
