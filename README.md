```
__   ______
\ \ / /  _ \ __ _ ___ ___
 \ V /| |_) / _` / __/ __|
  | | |  __/ (_| \__ \__ \
  |_| |_|   \__,_|___/___/
```

# Password Manager using Yubikey as storage

A secure password manager that combines YubiKey hardware security with a memorized pin. Same inputs always produce the same password - no software password storage needed.

## How It Works

```
YubiKey HMAC-SHA1 (hardware) ─┐
                              │
Memorized PIN ────────────────┼──► Argon2id ──► 32-char password
                              │
Domain + Username + Version ──┘
```

Your passwords are derived from:
- **YubiKey secret** - Hardware-bound, requires physical touch
- **PIN** - Memorized, never stored
- **Domain** - Normalized (github.com, GitHub.com, https://github.com/path all become `github`) (subdomains are preserved, except `www.`)
- **Username** - Optional, for multiple accounts per site
- **Version** - For password rotation when needed

## Components

### [cli/](./cli/) - CLI Tool

Rust command-line application for generating passwords.

```bash
ypass github              # Generate password for domain
ypass github -u user      # With specific username
ypass github --compat     # Generate compat password (20 chars, safe charset)
ypass --list              # List all stored domains
```

Features:
- Interactive mode with Tab completion
- Encrypted state file for usernames/versions
- Compat mode for sites with strict password rules (20 chars, universally accepted characters)
- ~94% PIN typo detection (no YubiKey needed) (4-bit checksum)
- Auto-clearing clipboard (20 seconds)
- Cross-platform (macOS, Linux _(not tested yet)_, Windows _(not tested yet)_)

### [raycast-app/](./raycast-app/) - Raycast Extension

macOS Raycast extension for quick password generation.

Features:
- Quick access from Raycast
- Domain/username selection UI
- YubiKey touch prompts
- Clipboard integration
- Cmd+G to generate/toggle compat password, Cmd+T to toggle compat mode

## Quick Start

### 1. Configure YubiKey

```bash
# Install tools
brew install ykpers ykman

# Configure HMAC-SHA1 on slot 1 (save the secret!)
ykman otp chalresp --generate --touch 1
```

### 2. Install CLI

```bash
cd cli
cargo build --release
cp target/release/ypass ~/.local/bin/
```

### 3. Generate Password

```bash
ypass github.com
# 1. Touch YubiKey (unlock state)
# 2. Touch YubiKey (generate password)
# 3. Enter PIN
# 4. Password copied to clipboard
```

## Security Model

| Component | Protection |
|-----------|------------|
| YubiKey secret | Hardware-bound, non-extractable |
| PIN | Memorized, never stored |
| State file | Encrypted with YubiKey-derived key |
| Clipboard | Auto-clears after 20 seconds |
| Generated passwords | 32 chars, all character types (or 20 chars in compat mode) |

Two-factor by design: **something you have** (YubiKey) + **something you know** (PIN).

## Requirements

- YubiKey with HMAC-SHA1 configured on slot 1
- `ykchalresp` command (`brew install ykpers`)
- Rust toolchain (for building)

## Recovery

If you lose your YubiKey, program a new one with your backed-up secret:

```bash
ykman otp chalresp --touch 1 YOUR_SAVED_HEX_SECRET
```

Your passwords will be identical to the original YubiKey.

## License

MIT
