# totp-vault

TOTP/2FA code vault for open-bot. Import accounts straight from Google Authenticator's export QR, generate codes on demand in chat or from a live dashboard, keep secrets encrypted at rest.

## Features

- **Google Authenticator import**: screenshot the app's "Transfer accounts → Export accounts" QR and import it — `otpauth-migration://` protobuf decoded natively (no dependencies), batch QRs supported. Plain `otpauth://` URIs and raw base32 secrets work too.
- **On-demand codes**: `ob-plugin-totp-vault-totp code <issuer|label|id>` prints the current code with its remaining validity (TOTP) or the next counter code (HOTP).
- **Dashboard tab**: live codes with countdown rings, one-click copy, QR/URI/manual import, rename, delete, secret reveal. Light and dark themes.
- **@totp composer mentions**: accounts appear in the chat composer so code requests resolve to the right account.
- **Encrypted at rest**: AES-256-GCM store; the master key lives in the plugin's `master_key` secret setting (auto-generated on first use), never in the manifest or the code.
- **Verified crypto**: built-in `selftest` checks the implementation against the RFC 6238 test vectors (SHA-1/256/512).

## Install

```sh
ob-plugin install totp-vault
```

Setup installs `zbar-tools` (QR decoding). First run of the CLI auto-creates the master key — see the installed guide: `ob-plugin guide totp-vault`.

## Usage

```sh
ob-plugin-totp-vault-totp list
ob-plugin-totp-vault-totp import --image ~/qr.png     # Google Authenticator export screenshot
ob-plugin-totp-vault-totp code github                  # 493 210 (valid 18s)
ob-plugin-totp-vault-totp show github                  # reveal secret (sensitive)
ob-plugin-totp-vault-totp remove <id> --yes
```

In chat, just ask for "my GitHub code" — the agent handles the rest.

## Security model

- Secrets are stored only in an encrypted blob; the key is in the open-bot vault and never printed.
- Codes are computed on demand (CLI) or per poll (dashboard); nothing is logged.
- The dashboard reveal endpoint exists for legitimate re-enrollment; treat revealed secrets like passwords.

## Development

```sh
cd ~/plugins-create/totp-vault
bun scripts/sync-manifest.ts   # re-assemble open-bot.plugin.json from tool/ + src/
ob-plugin validate .
ob-plugin install --path .
```

MIT — Justin Hallé / M2Tech Solutions.
