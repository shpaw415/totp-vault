# totp-vault — configuration guide

## What this plugin needs

1. **zbar-tools** — installed automatically by the plugin setup (skipped when `zbarimg` is already present; otherwise `apt-get update` then `apt-get install -y zbar-tools`, idempotent). It decodes QR screenshots (`zbarimg`).
2. **One secret setting: `master_key`** — a 32-byte hex key used to encrypt the account store (AES-256-GCM) at `/home/agent/.open-bot/pages-data/totp-vault/accounts.enc`.

## Ask → fill → verify

You normally ask nothing and fill nothing:

1. Run `ob-plugin-totp-vault-totp list` once — it generates the master key, stores it in the plugin's `master_key` secret setting, and prints `no accounts yet`.
2. Verify: dashboard → Plugins tab → totp-vault → Settings → `master_key` shows as saved (hidden input).
3. Prove it works:
   - `ob-plugin-totp-vault-totp selftest` → `all N checks passed`
   - Import a test account or ask for a code: `ob-plugin-totp-vault-totp code <label>`

## Recovery: accounts unreadable after an update (master key lost/changed)

Symptom: the dashboard shows a decrypt error, or the CLI says "the account store exists but can't be decrypted".

1. Preferred: restore the previous key in Plugins → totp-vault → Settings → `master_key` — the store comes back intact.
2. If the key is unrecoverable: `ob-plugin-totp-vault-totp reset --yes` wipes the encrypted store, then import the accounts again (they are still in Google Authenticator — re-export the QR).

The plugin REFUSES to write over an unreadable store (imports fail with 409, the CLI refuses to mint a new key) — a reset is always deliberate.

## If the user insists on providing their own master key

Dashboard → Plugins → totp-vault → Settings → `master_key` = 64 hex characters (32 bytes).

**Warning**: changing the key after accounts exist makes the store undecryptable. Reveal each secret (`totp show <id>`), change the key, then re-import the accounts.
