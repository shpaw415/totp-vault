// WCAG contrast audit for both themes of the TOTP Vault page.
// Extracts CSS variables from the :root (light) and html[data-theme="dark"] blocks
// in src/server/server.ts and checks key foreground/background pairs (min 4.5:1).
// Run: bun scripts/contrast-check.ts
const src = await Bun.file(new URL("../src/server/server.ts", import.meta.url)).text();

function vars(block: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of block.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-fA-F]{3,8})/g)) out[m[1]] = m[2];
  return out;
}

const lightMatch = src.match(/:root\s*\{([\s\S]*?)\n  \}/);
const darkMatch = src.match(/html\[data-theme=["']dark["']\]\s*\{([\s\S]*?)\n  \}/);
if (!lightMatch || !darkMatch) {
  console.error("could not locate :root / dark blocks — check the selectors");
  process.exit(1);
}
const light = vars(lightMatch[1]);
const dark = vars(darkMatch[1]);

const lum = (hex: string): number => {
  let h = hex.slice(1);
  if (h.length === 3) h = h.split("").map((c) => c + c).join("");
  const [r, g, b] = [0, 2, 4].map((i) => {
    const c = parseInt(h.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (fg: string, bg: string): number => {
  const [l1, l2] = [lum(fg), lum(bg)].sort((a, b) => b - a);
  return (l1 + 0.05) / (l2 + 0.05);
};

// pairs: [label, fg var, bg var]
const pairs: [string, string, string][] = [
  ["text on bg", "text", "bg"],
  ["text on card", "text", "card"],
  ["muted on card", "muted", "card"],
  ["muted on bg", "muted", "bg"],
  ["accent on card", "accent", "card"],
  ["primary btn text on accent", "accent-contrast", "accent"],
  ["danger on card", "danger", "card"],
];

let failures = 0;
for (const [theme, v] of [["light", light], ["dark", dark]] as const) {
  console.log(`\n${theme} theme:`);
  for (const [label, fg, bg] of pairs) {
    const f = v[fg];
    const b = v[bg];
    if (!f || !b) {
      console.log(`  ?? ${label}: missing var (${fg}=${f}, ${bg}=${b})`);
      failures++;
      continue;
    }
    const r = ratio(f, b);
    const ok = r >= 4.5;
    if (!ok) failures++;
    console.log(`  ${ok ? "OK " : "FAIL"} ${label}: ${r.toFixed(2)}:1 (${f} on ${b})`);
  }
}
console.log(failures ? `\n${failures} check(s) failed` : "\nall contrast checks passed (min 4.5:1)");
process.exit(failures ? 1 : 0);
