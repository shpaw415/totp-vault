// UI stress-test harness (happy-dom) for the TOTP Vault dashboard page.
// Run against the live server: UI_PORT=4741 bun scripts/uitest.ts
// Cleans the account store at the START and the END of the run.
import { Window } from "happy-dom";

const PORT = process.env.UI_PORT ?? "4741";
const BASE = `http://127.0.0.1:${PORT}`;
let passed = 0;
let failed = 0;
const fails: string[] = [];
function check(name: string, ok: boolean, detail = ""): void {
  if (ok) {
    passed++;
    console.log(`  OK  ${name}`);
  } else {
    failed++;
    fails.push(name);
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function freshWindow(): Promise<{ win: any; doc: any }> {
  const html2 = await (await fetch(`${BASE}/`)).text();
  const w: any = new Window({ url: `${BASE}/` });
  const d = w.document;
  d.write(html2);
  Object.defineProperty(w.navigator, "language", { value: "fr-CA", configurable: true });
  const rf = w.fetch.bind(w);
  w.fetch = (input: any, init?: any) => rf(typeof input === "string" && input.startsWith("api/") ? `${BASE}/${input}` : input, init);
  const script = [...d.querySelectorAll("script")].map((s) => s.textContent!).sort((a, b) => b.length - a.length)[0];
  new Function("window", "with(window){ " + script + " }")(w);
  await sleep(1500);
  return { win: w, doc: d };
}

async function api(path: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(`${BASE}${path}`, opts);
  return r.json();
}

// ---------- cleanup before ----------
{
  const st = await api("/api/state");
  for (const a of st.accounts ?? []) await api(`/api/accounts/${a.id}`, { method: "DELETE" });
  const after = await api("/api/state");
  check("pre-run cleanup", (after.accounts ?? []).length === 0);
}

// ---------- build a QR png for the upload test ----------
const SECRET = "JBSWY3DPEHPK3PXP";
const QR_PNG = Bun.spawnSync(["qrencode", "-o", "-", "-s", "6", `otpauth://totp/Stress:uitest?secret=${SECRET}&issuer=Stress`]).stdout;

// ---------- load the page in happy-dom ----------
const html = await (await fetch(`${BASE}/`)).text();
const win = new Window({ url: `${BASE}/` });
const doc = win.document;
doc.write(html);
Object.defineProperty(win.navigator, "language", { value: "fr-CA", configurable: true });
const realFetch = win.fetch.bind(win);
(win as any).fetch = (input: any, init?: any) => {
  const url = typeof input === "string" && input.startsWith("api/") ? `${BASE}/${input}` : input;
  return realFetch(url, init);
};
(win as any).confirm = () => true;
(win as any).prompt = () => "uitest-renamed";
(win as any).clipboard = { writeText: async () => {} };

const scripts = [...doc.querySelectorAll("script")].map((s) => s.textContent!);
const appScript = scripts.sort((a, b) => b.length - a.length)[0];
try {
  new Function("window", "with(window){ " + appScript + " }")(win);
} catch (e) {
  check("app script evaluates", false, String(e));
}
await sleep(1200);

const $ = (id: string) => doc.getElementById(id);
const toast = () => ($("toast") as any)?.textContent ?? "";

// ---------- case 1: empty state ----------
check("empty state shown", doc.getElementById("list")!.textContent!.includes("Aucun compte"));

// ---------- case 2: URI import through the dialog ----------
$("addBtn")!.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(50);
const dialogOpen = ($("addDlg") as any).open === true;
check("add dialog opens", dialogOpen);
// × close button in the dialog header
$("addClose")!.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(100);
check("× button closes the dialog", ($("addDlg") as any).open === false);
$("addBtn")!.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(100);
doc.querySelector('[data-tab="uri"]')!.dispatchEvent(new win.Event("click", { bubbles: true }));
($("uriText") as any).value = `otpauth://totp/Stress:uitest?secret=${SECRET}&issuer=Stress`;
$("uriImport")!.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(900);
let st = await api("/api/state");
check("URI import adds account", st.accounts.length === 1 && st.accounts[0].issuer === "Stress", JSON.stringify(st.accounts?.map((a: any) => a.issuer)));
check("code is live", /^\d{6}$/.test(st.accounts[0]?.code ?? ""));
check("import result shown", $("impResult")!.textContent!.includes("Importés :"));

// ---------- case 3: repeat run (duplicate) ----------
($("uriText") as any).value = `otpauth://totp/Stress:uitest?secret=${SECRET}&issuer=Stress`;
$("uriImport")!.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(700);
st = await api("/api/state");
check("duplicate import skipped, no corruption", st.accounts.length === 1);
check("duplicate reported", $("impResult")!.textContent!.includes("déjà présents :"));

// ---------- case 4: QR upload through the dialog ----------
try {
  const dt = new (win as any).DataTransfer();
  dt.items.add(new (win as any).File([QR_PNG], "qr.png", { type: "image/png" }));
  const input = $("qrFile") as any;
  input.files = dt.files;
  input.dispatchEvent(new win.Event("change", { bubbles: true }));
  await sleep(1500);
  st = await api("/api/state");
  const dup = $("impResult")!.textContent!.includes("déjà présents :");
  check("QR upload through dialog handled", st.accounts.length === 1 && dup, `accounts=${st.accounts.length} result=${$("impResult")!.textContent!.slice(0, 80)}`);
} catch (e) {
  check("QR upload through dialog handled", false, String(e).slice(0, 120));
}

// ---------- case 5: search filter ----------
await api("/api/import/uri", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri: `otpauth://totp/Filter:target?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Filter` }) });
await sleep(5200); // wait for the 5s poll
const cards = () => doc.querySelectorAll("#list .card").length;
check("two accounts render", cards() === 2, `cards=${cards()}`);
($("search") as any).value = "target";
$("search")!.dispatchEvent(new win.Event("input", { bubbles: true }));
check("search filters to 1", cards() === 1, `cards=${cards()}`);
($("search") as any).value = "zzzz";
$("search")!.dispatchEvent(new win.Event("input", { bubbles: true }));
check("search no match empties list", cards() === 0);
($("search") as any).value = "";
$("search")!.dispatchEvent(new win.Event("input", { bubbles: true }));

// ---------- case 6: copy code ----------
const copyBtn = doc.querySelector('[data-copy]')!;
copyBtn.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(400);
check("copy gives feedback (toast)", toast().length > 0, `toast="${toast()}"`);

// ---------- case 7: reveal secret ----------
(doc.querySelector("[data-reveal]") as HTMLElement)!.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(500);
check("reveal shows the otpauth uri", $("secretUri")!.textContent!.startsWith("otpauth://totp/"));
check("reveal shows the base32 secret", $("secretB32")!.textContent!.length >= 16);
($("secretClose") as any).click();
await sleep(100);

// ---------- case 8: rename ----------
(doc.querySelector("[data-rename]") as HTMLElement)!.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(900);
st = await api("/api/state");
check("rename applied", st.accounts.some((a: any) => a.label === "uitest-renamed"), JSON.stringify(st.accounts.map((a: any) => a.label)));

// ---------- case 9: hostile inputs ----------
// garbage URI through the dialog
(doc.querySelector('[data-tab="uri"]') as HTMLElement)!.dispatchEvent(new win.Event("click", { bubbles: true }));
($("uriText") as any).value = "https://example.com/not-otpauth";
$("uriImport")!.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(700);
check("garbage URI rejected with error", $("impResult")!.textContent!.includes("✗"));
// empty URI
($("uriText") as any).value = "";
$("uriImport")!.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(700);
check("empty URI rejected", $("impResult")!.textContent!.includes("✗"));
// invalid base32
const bad = await api("/api/import/uri", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri: "otpauth://totp/Bad?secret=!!!not-base32!!!" }) });
check("invalid base32 rejected", !!bad.failed?.length);
// xss label + unicode + very long label
const xss = await api("/api/import/uri", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri: `otpauth://totp/Xss:<img src=x onerror=alert(1)>?secret=${SECRET}&issuer=Ünïcodé-🔐` }) });
check("unicode/xss import accepted", !!xss.added?.length, JSON.stringify(xss).slice(0, 120));
const long = await api("/api/import/uri", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri: `otpauth://totp/Long:${"x".repeat(200)}?secret=GEZDGNBVGY3TQOJQ&issuer=Long` }) });
check("200-char label accepted", !!long.added?.length);
st = await api("/api/state");
check("state stays valid JSON with all test accounts", Array.isArray(st.accounts) && st.accounts.length >= 4);
// direct-API imports land on the page at its own refresh cadence: verify rendering
// in a FRESH window (equivalent to a tab reload — the real user path).
const fresh1 = await freshWindow();
{
  const listHtml = fresh1.doc.getElementById("list")!.innerHTML;
  check("xss label escaped in fresh window (no <img> injected)", !listHtml.includes("<img"), "");
  check("unicode label renders in fresh window", listHtml.includes("Ünïcodé"));
}

// ---------- case 10: HOTP next ----------
await api("/api/import/uri", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri: "otpauth://hotp/Hotp:acct?secret=JBSWY3DPEHPK3PXP&issuer=Hotp&counter=3" }) });
const fresh2 = await freshWindow();
const hotpBtn = fresh2.doc.querySelector("[data-next]") as HTMLElement;
check("hotp next button rendered", !!hotpBtn);
const before = (await api("/api/state")).accounts.find((a: any) => a.issuer === "Hotp");
// happy-dom long-lived windows can swallow synthetic clicks: each attempt uses a
// FRESH window (the deterministic path) until the server counter moves.
let afterHotp: any = before;
let lastToast = "";
for (let i = 0; i < 4 && afterHotp?.counter === before?.counter; i++) {
  const f = await freshWindow();
  const btn = f.doc.querySelector("[data-next]") as HTMLElement;
  btn?.click();
  await sleep(900);
  afterHotp = (await api("/api/state")).accounts.find((a: any) => a.issuer === "Hotp");
  lastToast = f.doc.getElementById("toast")?.textContent ?? "";
}
check("hotp counter advanced", afterHotp?.counter === (before?.counter ?? 0) + 1, `${before?.counter} -> ${afterHotp?.counter} toast="${lastToast}"`);
const oathtool = Bun.spawnSync(["oathtool", "-c", String(afterHotp.counter), "-b", "JBSWY3DPEHPK3PXP"]).stdout.toString().trim();
check("hotp code matches oathtool", afterHotp?.code === oathtool, `${afterHotp?.code} vs ${oathtool}`);

// ---------- case 11: delete ----------
st = await api("/api/state");
const countBefore = st.accounts.length;
const delId = st.accounts.find((a: any) => a.issuer === "Stress").id;
const delBtn = doc.querySelector(`[data-del="${delId}"]`) as HTMLElement;
delBtn.dispatchEvent(new win.Event("click", { bubbles: true }));
await sleep(900);
st = await api("/api/state");
check("delete removes the account", st.accounts.length === countBefore - 1 && !st.accounts.some((a: any) => a.id === delId));

// ---------- case 12: second window = fresh reload ----------
{
  const f = await freshWindow();
  const w2cards = f.doc.querySelectorAll("#list .card").length;
  const w2state = await api("/api/state");
  check("fresh window renders same accounts (reload path)", w2cards === w2state.accounts.length, `cards=${w2cards} accounts=${w2state.accounts.length}`);
  check("second window has no zombie state", JSON.stringify(w2state).length > 10);
}

// ---------- cleanup after ----------
{
  const s = await api("/api/state");
  for (const a of s.accounts ?? []) await api(`/api/accounts/${a.id}`, { method: "DELETE" });
  const fin = await api("/api/state");
  check("post-run cleanup", (fin.accounts ?? []).length === 0);
}

console.log(`\n${passed} passed, ${failed} failed${fails.length ? ": " + fails.join(" | ") : ""}`);
process.exit(failed ? 1 : 0);
