// Assembles open-bot.plugin.json from source files (tool/, src/skill.md).
// Run: bun scripts/sync-manifest.ts
const tool = await Bun.file(new URL("../tool/totp.ts", import.meta.url)).text();
const skillBody = await Bun.file(new URL("../src/skill.md", import.meta.url)).text();

const manifest = {
  $schema: "/home/agent/.config/opencode/skills/plugin/open-bot.plugin.schema.json",
  id: "totp-vault",
  name: "TOTP Vault",
  version: "0.2.4",
  description:
    "TOTP/2FA vault: import accounts from Google Authenticator's export QR (otpauth-migration decoded natively, batch QRs supported), generate codes on demand in chat, live codes with countdown in a dashboard tab. Secrets are AES-256-GCM encrypted at rest; the master key lives in the plugin vault. @totp composer mentions resolve code requests to the right account.",
  author: "shpaw415",
  repo: "shpaw415/totp-vault",
  category: "security",
  tags: ["totp", "2fa", "otp", "authenticator", "security", "vault"],
  permissions: {
    desktopTools: true,
  },
  configs: [
    {
      key: "master_key",
      label: "TOTP master key (64 hex chars — leave empty to auto-generate on first use)",
      type: "secret",
      def: "",
    },
  ],
  setup: {
    // Idempotent: skip when zbarimg is present; otherwise refresh apt lists
    // first (a fresh desktop has no package index, so a bare install fails
    // with "Unable to locate package zbar-tools").
    commands: [
      "sudo sh -c 'command -v zbarimg >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y zbar-tools; }'",
    ],
  },
  tools: [
    {
      name: "totp",
      content: tool,
    },
  ],
  files: [
    { name: "lib.ts", source: "src/lib.ts" },
    { name: "server.ts", source: "src/server/server.ts", exec: true },
    { name: "index.html", source: "src/server/index.html", exec: false },
    { name: "app.ts", source: "src/server/app.ts", exec: false },
    { name: "styles.css", source: "src/server/styles.css", exec: false },
  ],
  dashboard: {
    pages: { entry: "server.ts", ui: "src/server/index.html" },
    tabs: [{ id: "totp", title: "TOTP Vault", kind: "app", icon: "🔐" }],
    mentions: [{ section: "totp", label: "TOTP", path: "/mentions" }],
  },
  skills: [
    {
      name: "totp-vault",
      description:
        "Load when the user asks for a 2FA/TOTP/authenticator code, wants to import or export accounts from Google Authenticator (QR transfer), or manages their TOTP vault. Always answer in the user's language.",
      body: skillBody,
    },
  ],
};

await Bun.write(new URL("../open-bot.plugin.json", import.meta.url), JSON.stringify(manifest, null, 2) + "\n");
console.log("manifest synced:", manifest.id, manifest.version, `tool ${(tool.length / 1024).toFixed(1)}k`);
