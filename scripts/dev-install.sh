#!/usr/bin/env bash
# dev install loop for totp-vault — sync manifest, strip skills (open-bot install
# bug e59b151b: skill read-back never converges), install locally, re-sync source.
set -e
cd ~/plugins-create/totp-vault
bun scripts/sync-manifest.ts
jq 'del(.skills)' open-bot.plugin.json > /tmp/opencode/totp-vault-noskill.json
mv /tmp/opencode/totp-vault-noskill.json open-bot.plugin.json
ob-plugin install --path ~/plugins-create/totp-vault | tail -6
bun scripts/sync-manifest.ts
echo "dev install done (skill kept in OpenViking, managed manually)"
