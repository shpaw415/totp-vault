# totp-vault — TOTP/2FA vault

TOTP/HOTP code vault for this desktop. Codes are generated on demand; secrets are encrypted at rest with a master key stored in the plugin's `master_key` secret setting. Import from Google Authenticator uses the app's own export QR format (otpauth-migration).

## Language

Always answer in the user's language. Never default to one language.

## First use / setup

- The master key (`master_key` secret setting) is generated and saved automatically the first time the CLI runs. If a dashboard action reports "not configured", run the CLI once:
  `ob-plugin-totp-vault-totp list`

## Importing from Google Authenticator (the usual flow)

1. Ask the user to open Google Authenticator on their phone → Transfer accounts → Export accounts → select the accounts → a QR code appears.
2. Ask them to send you a screenshot of that QR (multiple QR codes in one image are handled).
3. Save the image under /home/agent/workspace and run:
   `ob-plugin-totp-vault-totp import --image <path>`
4. Report what was added by name — never print secrets. If the export showed several QR screens (batches), repeat per screenshot.
5. Also accepted:
   - `totp import --uri <otpauth://…>` (any authenticator app export)
   - `totp import --secret <base32> --label <name> [--issuer <name>] [--digits 6|8] [--alg SHA1|SHA256|SHA512] [--type totp|hotp] [--counter <n>]`

## Daily use

- Current code: `ob-plugin-totp-vault-totp code <query>` (matches by id, issuer or label, case-insensitive). Print the code and its remaining validity — codes expire, so mention how many seconds are left; re-run if it expired mid-sentence.
- List accounts: `totp list` (add `--json` for machine output).
- Reveal a secret ONLY on explicit request: `totp show <query>` (prints the otpauth:// URI and the base32 secret).
- Rename: `totp rename <id> <new label>`. Remove: `totp remove <id> --yes`.
- Sanity check: `totp selftest` (RFC 6238 vectors + codec roundtrips).

## Security rules

- Never print or log secrets (`show` output, JSON with secrets) unless the user explicitly asks for that account's secret.
- Codes are sensitive too: generate and print one only when the user asks for it.
- When the user asks "my code for X" in a language, answer in that language with the code and its validity.

## Dashboard

- The **TOTP Vault** tab in the Dashboards drawer shows live codes with countdown rings, one-click copy, QR/URI/manual import, rename, delete and secret reveal. Light and dark themes are both supported.
- The chat composer's **@totp** menu lists accounts; when a message references one, generate its code with `totp code <label>` and answer directly.
