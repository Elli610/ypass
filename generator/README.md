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
- **PIN verification**: Detects typos before generating wrong passwords (requires YubiKey)
- **Encrypted state file**: Usernames and versions stored in `~/.config/dpg/state.enc`, encrypted with YubiKey
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
password-generator [domain] [options]

Options:
  -v, --version <n>       Use specific version (default: latest from state)
  -u, --user <name>       Use specific username (skip interactive selection)
  -i, --interactive       Interactive domain selection
  --add-user <name>       Add username to domain (no password generated)
  --delete-user <name>    Delete username from domain
  --delete-domain         Delete domain and all its usernames
  --bump-version          Increment version (use with -u for specific username)
  --list                  List all domains and usernames
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
password-generator
# Output:
# Stored domains:
#   [1] github.com (2 users)
#   [2] gmail.com (3 users)
#   [3] twitter.com
#   [n] Enter new domain
#
# Select or search: git
# -> Matches "github.com", proceeds to username selection
```

You can:
- Enter a number to select a domain
- Type part of a domain name to search (substring match)
- Enter `n` to add a new domain

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
# Bump version for a specific username
password-generator github.com --bump-version -u myuser

# Bump version for domain-only mode
password-generator github.com --bump-version

# Or use a specific version
password-generator github.com -u myuser -v 3
```

> Note: Versions are tracked per-username. Latest version is used by default.

### Deleting Entries

Remove usernames or entire domains from the state file:

```bash
# Delete a specific username from a domain
password-generator github.com --delete-user olduser

# Delete an entire domain and all its usernames
password-generator github.com --delete-domain
```

Both commands require YubiKey touch to unlock the state file.

### List All Entries

```bash
password-generator --list
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
password-generator github.com
password-generator GitHub.com
password-generator https://github.com
password-generator https://www.github.com/settings
password-generator www.github.com
```

### PIN Verification

On first use, a 2-bit checksum of your PIN is saved to `~/.config/dpg/pin.check`. On subsequent uses, the CLI checks your PIN before generating the password:

- **Correct PIN**: Proceeds to generate password
- **Wrong PIN**: Prompts to try again (75% of typos caught)

This prevents most wrong passwords due to typos.

```bash
# Verify PIN without generating password (for scripts/integrations)
echo "mypin" | password-generator --check-pin
# Exit code: 0 = correct, 1 = wrong

# If you need to change your PIN
password-generator --reset-pin
# Then generate a password with your new PIN - it will be saved automatically
```

**Security**: The 2-bit checksum is a minimal information leak:
- Only 4 possible values (0-3)
- 25% of all PINs match any given checksum
- Attacker learns almost nothing useful
- No YubiKey needed to verify (works with `--skip-state`)

## State File

Usernames and versions are stored encrypted at `~/.config/dpg/state.enc`.

- Encrypted with ChaCha20-Poly1305
- Key derived from YubiKey HMAC response (requires YubiKey to decrypt)
- Contains only domain names, usernames, and version numbers
- No passwords or secrets are stored

### Format Versions

| Version | Description |
|---------|-------------|
| v1 | Original format, per-domain versions |
| v2 | Per-username versions, format version field |

The CLI automatically upgrades old state files on first use. If you try to use a state file from a newer CLI version, you'll be prompted to update.

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

## Shell Completions

Enable Tab completion for domains and options.

### Bash

```bash
# Add to ~/.bashrc
password-generator --generate-completions bash >> ~/.bashrc
source ~/.bashrc
```

### Zsh

```bash
# Add to ~/.zshrc
password-generator --generate-completions zsh >> ~/.zshrc
source ~/.zshrc
```

### Fish

```bash
password-generator --generate-completions fish > ~/.config/fish/completions/password-generator.fish
```

### How It Works

- A plaintext cache of domain names is stored at `~/.config/dpg/domains.cache`
- The cache is updated every time you use the tool (after YubiKey unlock)
- Tab completion reads from this cache (no YubiKey needed for completion)
- Usernames are NOT cached (they remain encrypted)

## Backward Compatibility

If you were using an earlier version without username/version support:
- Domain-only mode still works (just don't add usernames)
- Version defaults to 1
- Existing passwords remain unchanged when using empty username and version 1
