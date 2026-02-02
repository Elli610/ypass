# Password Generator

A secure, password manager using YubiKey HMAC-SHA1 challenge-response.

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
- **Compat mode**: 20-char passwords with universally accepted characters for sites with strict password rules
- **PIN verification**: Detects typos before generating wrong passwords (no YubiKey required)
- **Encrypted state file**: Usernames and versions stored in `~/.config/ypass/state.enc`, encrypted with YubiKey
- **Interactive mode**: Run without arguments to search and select from stored domains
- **Shell completions**: Tab completion for bash, zsh, and fish

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

# With your own salt (up to 20 bytes, hex)
ykman otp chalresp --touch 1
```

### 2. Backup Your Secret

**CRITICAL: Save the hex key immediately.** You cannot extract it later.

The secret is the hex string shown:
(20 bytes, 40 hex chars)
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

Binary will be at `target/release/ypass`.

## Install

Install the CLI to your local bin directory:

```bash
# macOS / Linux
cp target/release/ypass ~/.local/bin/
# or system-wide
sudo cp target/release/ypass /usr/local/bin/

# Windows (PowerShell as Admin)
copy target\release\ypass.exe C:\Windows\System32\
```

Ensure `~/.local/bin` is in your PATH:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"
```

## Usage

### Basic Usage

```bash
ypass github.com
```

1. Touch YubiKey to unlock state file
2. Touch YubiKey again for password generation
3. Enter your PIN
4. Password is copied to clipboard (use `-p` to also print to stdout)
5. Clipboard auto-clears after 20 seconds

### Command Line Options

```
ypass [domain] [options]

Options:
  -v, --version <n>       Use specific version (default: latest from state)
  -u, --user <name>       Use specific username (skip interactive selection)
  -i, --interactive       Interactive domain selection
  -p, --print             Print password to stdout (default: clipboard only)
  --no-clipboard          Don't copy to clipboard (use with -p for piping)
  --add-user <name>       Add username to domain (no password generated)
  --delete-user <name>    Delete username from domain
  --delete-domain         Delete domain and all its usernames
  --bump-version          Increment version (use with -u for specific username)
  --list                  List all domains and usernames
  --compat                Generate compat password (20 chars, safe charset) and save preference
  --set-compat            Mark a domain/username as compat (no password generated)
  --unset-compat          Remove compat flag from a domain/username
  --skip-state            Skip state unlock, use with -u and -v (for scripts/integrations)
  --reset-pin             Reset PIN verification (use when changing PIN)
  --check-pin             Verify PIN from stdin (exit 0=ok, 1=wrong, no YubiKey needed)
  --generate-completions <shell>
                          Generate shell completions (bash, zsh, fish)
  -h, --help              Show help
```

### Interactive Mode

Run without arguments to enter interactive mode:

```bash
ypass
# Output:
# Domain: <tab completion available>
#
# Type a domain name (Tab to complete from stored domains)
# -> New domains are added automatically
```

You can:
- Type part of a domain name and press Tab to autocomplete
- Enter any new domain name directly (it will be added to state)

### Multi-Account Support

For sites where you have multiple accounts (e.g., Gmail):

```bash
# Add usernames to a domain
ypass gmail.com --add-user personal@gmail.com
ypass gmail.com --add-user work@gmail.com

# Generate password - shows interactive selection
ypass gmail.com
# Output:
# Usernames for 'gmail.com':
#   [1] personal@gmail.com
#   [2] work@gmail.com
#   [d] domain-only mode (or press Enter with empty input)
#
# Username: <tab completion available>

# Or specify username directly
ypass gmail.com -u personal@gmail.com
```

### Password Rotation

When a site is breached and you need a new password:

```bash
# Bump version for a specific username
ypass github.com --bump-version -u myuser

# Bump version for domain-only mode
ypass github.com --bump-version

# Or use a specific version
ypass github.com -u myuser -v 3
```

> Note: Versions are tracked per-username. Latest version is used by default.

### Compat Mode

Some websites reject passwords that contain certain special characters or are too long. Compat mode generates a 20-character password using only universally accepted characters:

- Lowercase: `a-z`
- Uppercase: `A-Z`
- Digits: `0-9`
- Symbols: `!@#$%*-_+=`

The compat preference is saved per domain/username entry in the state file. Once set, future password generations for that entry will automatically use compat mode.

```bash
# Generate a compat password (and persist the preference)
ypass github.com --compat -u myuser

# Mark an existing entry as compat (no password generated)
ypass github.com --set-compat -u myuser

# Remove compat flag (revert to full 32-char password)
ypass github.com --unset-compat -u myuser

# One-shot compat without persisting (with --skip-state)
ypass github.com --compat --skip-state -u myuser -v 1
```

Compat entries are marked in the `--list` output:

```bash
ypass --list
# github.com
#   - myuser (v1) [compat]
#   - other (v2)
```

> Note: Compat mode uses the same derivation process (Argon2id) as normal mode but maps the output bytes to a smaller, 72-character alphabet and truncates to 20 characters. The password is deterministic -- same inputs always produce the same compat password.

### Deleting Entries

Remove usernames or entire domains from the state file:

```bash
# Delete a specific username from a domain
ypass github.com --delete-user olduser

# Delete an entire domain and all its usernames
ypass github.com --delete-domain
```

Both commands require YubiKey touch to unlock the state file.

### List All Entries

```bash
ypass --list
# Output:
# github.com
#   - myuser (v2)
# gmail.com
#   - personal@gmail.com (v1)
#   - work@gmail.com (v3)
```

### Domain Normalization

All these produce the same password:

```bash
ypass github.com
ypass GitHub.com
ypass https://github.com
ypass https://www.github.com/settings
ypass www.github.com
```

### PIN Verification

On first use, a 4-bit checksum of your PIN is saved to `~/.config/ypass/pin.check`. On subsequent uses, the CLI checks your PIN before generating the password:

- **Correct PIN**: Proceeds to generate password
- **Wrong PIN**: Prompts to try again (~94% of typos caught)

This prevents most wrong passwords due to typos.

```bash
# Verify PIN without generating password (for scripts/integrations)
echo "mypin" | ypass --check-pin
# Exit code: 0 = correct, 1 = wrong

# If you need to change your PIN
ypass --reset-pin
# Then generate a password with your new PIN - it will be saved automatically
```

**Security**: The 4-bit checksum is a minimal information leak:
- Only 16 possible values (0-15)
- 6.25% of all PINs match any given checksum
- Attacker learns almost nothing useful
- No YubiKey needed to verify (works with `--skip-state`)

### Output Options

By default, the password is only copied to clipboard (not printed to stdout) for security:

```bash
# Default: clipboard only
ypass github.com

# Print to stdout (and clipboard)
ypass github.com -p

# Print to stdout only (no clipboard) - useful for piping
ypass github.com --no-clipboard -p

# Pipe to another program
ypass github.com --no-clipboard -p | some-other-tool
```

## State File

Usernames and versions are stored encrypted at `~/.config/ypass/state.enc`.

- Encrypted with ChaCha20-Poly1305
- Key derived from YubiKey HMAC response (requires YubiKey to decrypt)
- Contains only domain names, usernames, and version numbers
- No passwords or secrets are stored

### Format Versions

| Version | Description |
|---------|-------------|
| v1 | Original format, per-domain versions |
| v2 | Per-username versions, format version field |
| v3 | Per-username compat flag |

The CLI automatically upgrades old state files on first use. If you try to use a state file from a newer CLI version, you'll be prompted to update.

## Restore From Backup

If you lose your YubiKey, program a new one with the saved secret:

```bash
ykman otp chalresp --touch 1 YOUR_HEX_40_CHARS_SECRET_HERE
```

This will generate identical passwords as your original YubiKey.

**Note**: You also need to backup your state file (`~/.config/ypass/state.enc`) to preserve username and version information. Without it, you'll need to remember which usernames and versions you used.

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
const PASSWORD_LENGTH: usize = 32;              // Full password length
const COMPAT_PASSWORD_LENGTH: usize = 20;       // Compat password length
const CLIPBOARD_CLEAR_SECONDS: u64 = 20;        // Clipboard timeout
const YUBIKEY_SLOT: &str = "1";                 // YubiKey slot (1 or 2)
```

To generate your own application salt:
```bash
head -c 32 /dev/urandom | xxd -i
```

Replace `APP_SALT` array in `src/main.rs` with the output.

## Shell Completions

Enable Tab completion for domains and options.

### Bash

```bash
# Add to ~/.bashrc
ypass --generate-completions bash >> ~/.bashrc
source ~/.bashrc
```

### Zsh

```bash
# Add to ~/.zshrc
ypass --generate-completions zsh >> ~/.zshrc
source ~/.zshrc
```

### Fish

```bash
ypass --generate-completions fish > ~/.config/fish/completions/ypass.fish
```
