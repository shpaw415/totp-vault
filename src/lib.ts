// totp-vault — core library (no external deps, runs on Bun)
// TOTP/HOTP (RFC 4226 / RFC 6238), otpauth:// URI parsing,
// Google Authenticator otpauth-migration:// protobuf decoding,
// AES-256-GCM encrypted account store, master-key handling via the open-bot vault.
import { createHmac, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync, rmSync, existsSync } from "node:fs";

export const PLUGIN_ID = "totp-vault";

export type OtpType = "totp" | "hotp";
export type OtpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface OtpAccount {
  id: string;
  label: string;
  issuer: string;
  secretB32: string;
  algorithm: OtpAlgorithm;
  digits: number; // 6 | 8
  period: number; // seconds, default 30
  type: OtpType;
  counter: number; // HOTP only
  createdAt: string;
}

export interface ParsedOtp {
  label: string;
  issuer: string;
  secretB32: string;
  algorithm: OtpAlgorithm;
  digits: number;
  period: number;
  type: OtpType;
  counter: number;
}

export interface Store {
  version: 1;
  updatedAt: string;
  accounts: OtpAccount[];
}

// ---------- base32 (RFC 4648) ----------

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(input: string): Buffer {
  const clean = input.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();
  if (!clean.length || /[^A-Z2-7]/.test(clean)) throw new Error("invalid base32 secret");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// ---------- HOTP / TOTP ----------

function hmacName(alg: OtpAlgorithm): string {
  return alg === "SHA256" ? "sha256" : alg === "SHA512" ? "sha512" : "sha1";
}

export function hotpCode(
  secret: Buffer,
  alg: OtpAlgorithm,
  counter: number,
  digits: number,
): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac(hmacName(alg), secret).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin =
    ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

export interface CodeResult {
  code: string;
  expiresAt: number | null; // epoch ms (TOTP only)
  counter: number; // TOTP: time counter; HOTP: counter used
}

export function accountCode(acc: OtpAccount, nowMs = Date.now()): CodeResult {
  const secret = base32Decode(acc.secretB32);
  if (acc.type === "hotp") {
    return { code: hotpCode(secret, acc.algorithm, acc.counter, acc.digits), expiresAt: null, counter: acc.counter };
  }
  const timeCounter = Math.floor(nowMs / 1000 / acc.period);
  return {
    code: hotpCode(secret, acc.algorithm, timeCounter, acc.digits),
    expiresAt: (timeCounter + 1) * acc.period * 1000,
    counter: timeCounter,
  };
}

export function newId(): string {
  return randomBytes(4).toString("hex");
}

export function accountToUri(acc: OtpAccount): string {
  const label = acc.issuer ? `${acc.issuer}:${acc.label}` : acc.label;
  const q = new URLSearchParams();
  q.set("secret", acc.secretB32);
  if (acc.issuer) q.set("issuer", acc.issuer);
  q.set("algorithm", acc.algorithm);
  q.set("digits", String(acc.digits));
  if (acc.type === "totp") q.set("period", String(acc.period));
  else q.set("counter", String(acc.counter));
  return `otpauth://${acc.type}/${encodeURIComponent(label)}?${q.toString()}`;
}

// ---------- otpauth:// URI parsing ----------

function splitIssuerLabel(rawLabel: string, paramIssuer: string | null): { label: string; issuer: string } {
  let label = rawLabel.trim();
  let issuer = (paramIssuer ?? "").trim();
  const idx = label.indexOf(":");
  if (idx > 0) {
    const maybeIssuer = label.slice(0, idx).trim();
    const rest = label.slice(idx + 1).trim();
    if (rest) {
      if (!issuer) issuer = maybeIssuer;
      label = rest;
    }
  }
  return { label, issuer };
}

export function parseOtpauthUri(uriRaw: string): ParsedOtp {
  const uri = uriRaw.trim().replace(/\s+/g, "");
  const m = /^otpauth:\/\/(totp|hotp)\/([^?]*)\?(.*)$/i.exec(uri);
  if (!m) throw new Error("not an otpauth:// URI");
  const type = (m[1].toLowerCase() as OtpType);
  const rawLabel = decodeURIComponent(m[2]);
  const params = new URLSearchParams(m[3]);
  const secretB32 = (params.get("secret") ?? "").replace(/\s/g, "");
  if (!secretB32) throw new Error("otpauth URI has no secret");
  base32Decode(secretB32); // validates
  const { label, issuer } = splitIssuerLabel(rawLabel, params.get("issuer"));
  const algRaw = (params.get("algorithm") ?? "SHA1").toUpperCase();
  const algorithm: OtpAlgorithm =
    algRaw === "SHA256" ? "SHA256" : algRaw === "SHA512" ? "SHA512" : "SHA1";
  const digits = Number(params.get("digits") ?? 6) === 8 ? 8 : 6;
  const period = Math.max(1, Number(params.get("period") ?? 30) || 30);
  const counter = Number(params.get("counter") ?? 0) || 0;
  if (!label) throw new Error("otpauth URI has no account label");
  return { label, issuer, secretB32: base32Encode(base32Decode(secretB32)), algorithm, digits, period, type, counter };
}

// ---------- Google Authenticator migration protobuf ----------

type FieldVisitor = (
  fieldNo: number,
  wireType: number,
  payload: { varint?: bigint; bytes?: Uint8Array },
) => void;

function readVarint(buf: Uint8Array, pos: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  while (pos < buf.length) {
    const b = buf[pos++];
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [result, pos];
    shift += 7n;
    if (shift > 63n) throw new Error("protobuf varint too long");
  }
  throw new Error("protobuf varint truncated");
}

function walkFields(buf: Uint8Array, visit: FieldVisitor): void {
  let pos = 0;
  while (pos < buf.length) {
    const [key, pos1] = readVarint(buf, pos);
    const fieldNo = Number(key >> 3n);
    const wireType = Number(key & 7n);
    pos = pos1;
    if (fieldNo === 0) throw new Error("protobuf invalid field number");
    if (wireType === 0) {
      const [v, pos2] = readVarint(buf, pos);
      pos = pos2;
      visit(fieldNo, wireType, { varint: v });
    } else if (wireType === 1) {
      if (pos + 8 > buf.length) throw new Error("protobuf truncated (i64)");
      visit(fieldNo, wireType, { bytes: buf.slice(pos, pos + 8) });
      pos += 8;
    } else if (wireType === 2) {
      const [len, pos2] = readVarint(buf, pos);
      const n = Number(len);
      pos = pos2;
      if (pos + n > buf.length) throw new Error("protobuf truncated (bytes)");
      visit(fieldNo, wireType, { bytes: buf.slice(pos, pos + n) });
      pos += n;
    } else if (wireType === 5) {
      if (pos + 4 > buf.length) throw new Error("protobuf truncated (i32)");
      visit(fieldNo, wireType, { bytes: buf.slice(pos, pos + 4) });
      pos += 4;
    } else {
      throw new Error(`protobuf unsupported wire type ${wireType}`);
    }
  }
}

const MIG_ALGS: Record<number, OtpAlgorithm | null> = { 0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: null };

export interface MigrationResult {
  accounts: ParsedOtp[];
  failed: { name: string; reason: string }[];
  version: number | null;
  batchSize: number | null;
  batchIndex: number | null;
}

export function decodeMigrationUri(uriRaw: string): MigrationResult {
  const uri = uriRaw.trim().replace(/\s+/g, "");
  if (!/^otpauth-migration:\/\/[a-z]+\/?\?/i.test(uri)) throw new Error("not an otpauth-migration:// URI");
  const qIdx = uri.indexOf("?");
  const params = new URLSearchParams(uri.slice(qIdx + 1));
  const data = params.get("data");
  if (!data) throw new Error("migration URI has no data parameter");
  const payload = Buffer.from(data, "base64");
  const result: MigrationResult = { accounts: [], failed: [], version: null, batchSize: null, batchIndex: null };
  walkFields(payload, (fieldNo, wireType, val) => {
    if (fieldNo === 1 && wireType === 2 && val.bytes) {
      const p: Partial<ParsedOtp> & { _algRaw?: number; _typeRaw?: number; _secret?: Uint8Array } = {};
      walkFields(val.bytes, (f, w, v) => {
        if (w === 0 && v.varint !== undefined) {
          const n = Number(v.varint);
          if (f === 4) p._algRaw = n;
          else if (f === 5) p.digits = n === 2 ? 8 : 6;
          else if (f === 6) p._typeRaw = n;
          else if (f === 7) p.counter = n;
        } else if (w === 2 && v.bytes) {
          const s = Buffer.from(v.bytes).toString("utf8");
          if (f === 1) p._secret = v.bytes;
          else if (f === 2) p.label = s;
          else if (f === 3) p.issuer = s;
        }
      });
      const name = p.label || "(unnamed)";
      if (!p._secret || p._secret.length === 0) {
        result.failed.push({ name, reason: "no secret in entry" });
        return;
      }
      const alg = MIG_ALGS[p._algRaw ?? 0];
      if (alg === null || alg === undefined) {
        result.failed.push({ name, reason: "unsupported algorithm" });
        return;
      }
      const split = splitIssuerLabel(p.label || "", p.issuer || null);
      result.accounts.push({
        label: split.label || name,
        issuer: split.issuer,
        secretB32: base32Encode(Buffer.from(p._secret)),
        algorithm: alg,
        digits: p.digits ?? 6,
        period: 30,
        type: p._typeRaw === 1 ? "hotp" : "totp",
        counter: p.counter ?? 0,
      });
    } else if (wireType === 0 && val.varint !== undefined) {
      const n = Number(val.varint);
      if (fieldNo === 2) result.version = n;
      else if (fieldNo === 3) result.batchSize = n;
      else if (fieldNo === 4) result.batchIndex = n;
    }
  });
  if (!result.accounts.length && !result.failed.length) throw new Error("migration payload has no accounts");
  return result;
}

// ---------- encrypted store ----------

export function dataDir(): string {
  return process.env.TOTP_VAULT_DATA_DIR ?? "/home/agent/.open-bot/pages-data/totp-vault";
}

function storePath(): string {
  return `${dataDir()}/accounts.enc`;
}

const STORE_MAGIC = "TVLT1";

export function storeExists(): boolean {
  try {
    return existsSync(storePath()) && readFileSync(storePath()).length > 5;
  } catch {
    return false;
  }
}

export function readMasterKey(configPathOverride?: string): string | null {
  const path = configPathOverride ?? `/home/agent/.config/open-bot/plugin-${PLUGIN_ID}.json`;
  try {
    const cfg = JSON.parse(readFileSync(path, "utf8"));
    const v = cfg?.settings?.master_key;
    if (typeof v === "string" && /^[0-9a-f]{64}$/i.test(v)) return v.toLowerCase();
    return null;
  } catch {
    return null;
  }
}

export function emptyStore(): Store {
  return { version: 1, updatedAt: new Date().toISOString(), accounts: [] };
}

export function loadStore(masterKeyHex: string): Store {
  if (!existsSync(storePath())) return emptyStore();
  const raw = readFileSync(storePath());
  if (!raw.length) return emptyStore();
  if (raw.slice(0, 5).toString() !== STORE_MAGIC) throw new Error("account store is corrupted (bad header)");
  const iv = raw.slice(5, 17);
  const tag = raw.slice(17, 33);
  const ct = raw.slice(33);
  const key = Buffer.from(masterKeyHex, "hex");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  const store = JSON.parse(pt.toString("utf8")) as Store;
  if (store.version !== 1 || !Array.isArray(store.accounts)) throw new Error("account store has an unknown format");
  return store;
}

export function saveStore(store: Store, masterKeyHex: string): void {
  const key = Buffer.from(masterKeyHex, "hex");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const pt = Buffer.from(JSON.stringify(store), "utf8");
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const out = Buffer.concat([Buffer.from(STORE_MAGIC), iv, cipher.getAuthTag(), ct]);
  mkdirSync(dataDir(), { recursive: true });
  writeFileSync(storePath() + ".tmp", out);
  renameSync(storePath() + ".tmp", storePath());
}

export function resetStore(): void {
  try {
    rmSync(storePath(), { force: true });
  } catch {
    // best effort — the file may already be gone
  }
}

// ---------- master key provisioning (tool-side) ----------

export async function ensureMasterKey(): Promise<string> {
  const existing = readMasterKey();
  if (existing) return existing;
  // Never mint a new key over an existing encrypted store: the old accounts
  // would become permanently unreadable. Recovery is explicit.
  if (storeExists())
    throw new Error(
      "an encrypted account store already exists but its master key is missing or changed — " +
      "restore the key in Plugins → TOTP Vault → Settings → master_key, " +
      "or wipe the store deliberately with: ob-plugin-totp-vault-totp reset --yes",
    );
  const hex = randomBytes(32).toString("hex");
  const proc = Bun.spawn(["ob-plugin", "settings", PLUGIN_ID, `master_key=${hex}`], {
    stdout: "ignore",
    stderr: "pipe",
  });
  const err = await new Response(proc.stderr).text();
  const code = await proc.exited;
  if (code !== 0) throw new Error(`could not save the master key to the plugin settings: ${err.trim() || `exit ${code}`}`);
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const k = readMasterKey();
    if (k) return k;
    await Bun.sleep(1000);
  }
  throw new Error("master key saved to the plugin settings but not synced to the config yet — retry in a few seconds");
}

// ---------- import / merge ----------

export interface ImportSummary {
  added: { issuer: string; label: string; id: string }[];
  duplicates: { issuer: string; label: string }[];
  failed: { name: string; reason: string }[];
}

function sameAccount(a: OtpAccount, p: ParsedOtp): boolean {
  // Same secret + same issuer = same credential, even if the label was renamed locally.
  return a.secretB32 === p.secretB32 && a.issuer.toLowerCase() === p.issuer.toLowerCase();
}

export function mergeAccounts(store: Store, parsed: ParsedOtp[], failed: { name: string; reason: string }[] = []): ImportSummary {
  const summary: ImportSummary = { added: [], duplicates: [], failed: [...failed] };
  for (const p of parsed) {
    if (store.accounts.some((a) => sameAccount(a, p))) {
      summary.duplicates.push({ issuer: p.issuer, label: p.label });
      continue;
    }
    const acc: OtpAccount = {
      id: newId(),
      label: p.label,
      issuer: p.issuer,
      secretB32: p.secretB32,
      algorithm: p.algorithm,
      digits: p.digits,
      period: p.period,
      type: p.type,
      counter: p.counter,
      createdAt: new Date().toISOString(),
    };
    store.accounts.push(acc);
    summary.added.push({ issuer: acc.issuer, label: acc.label, id: acc.id });
  }
  return summary;
}

// ---------- QR decoding via zbarimg ----------

export async function decodeQrImage(imagePath: string): Promise<string[]> {
  const proc = Bun.spawn(["zbarimg", "--raw", "--quiet", imagePath], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const out = await new Response(proc.stdout).text();
  const err = await new Response(proc.stderr).text();
  const code = await proc.exited;
  if (code === 4 || (!out.trim() && code !== 0)) {
    if (/zbarimg.*not found|No such file/i.test(err) && !Bun.which("zbarimg"))
      throw new Error("zbarimg is not installed — reinstall the plugin (ob-plugin install --path or Plugins tab → Re-install) so its setup can install zbar-tools");
    throw new Error("no QR code found in the image");
  }
  if (code !== 0) throw new Error(`QR decoding failed: ${err.trim() || `exit ${code}`}`);
  return out
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => /^otpauth(-migration)?:\/\//i.test(l));
}

// ---------- RFC 6238 self-test ----------

export function selftest(): { name: string; ok: boolean; detail?: string }[] {
  const results: { name: string; ok: boolean; detail?: string }[] = [];
  const check = (name: string, got: unknown, want: unknown) =>
    results.push({ name, ok: Object.is(got, want) || String(got) === String(want), detail: `got ${got}, want ${want}` });

  // RFC 6238 appendix B test vectors
  const s20 = Buffer.from("12345678901234567890");
  const s32 = Buffer.from("12345678901234567890123456789012");
  const s64 = Buffer.from("1234567890123456789012345678901234567890123456789012345678901234");
  const vectors: [Buffer, OtpAlgorithm, number, string][] = [
    [s20, "SHA1", 59, "94287082"],
    [s20, "SHA1", 1111111109, "07081804"],
    [s20, "SHA1", 1111111111, "14050471"],
    [s20, "SHA1", 1234567890, "89005924"],
    [s20, "SHA1", 2000000000, "69279037"],
    [s20, "SHA1", 20000000000, "65353130"],
    [s32, "SHA256", 59, "46119246"],
    [s32, "SHA256", 1111111109, "68084774"],
    [s32, "SHA256", 1111111111, "67062674"],
    [s32, "SHA256", 1234567890, "91819424"],
    [s32, "SHA256", 2000000000, "90698825"],
    [s32, "SHA256", 20000000000, "77737706"],
    [s64, "SHA512", 59, "90693936"],
    [s64, "SHA512", 1111111109, "25091201"],
    [s64, "SHA512", 1111111111, "99943326"],
    [s64, "SHA512", 1234567890, "93441116"],
    [s64, "SHA512", 2000000000, "38618901"],
    [s64, "SHA512", 20000000000, "47863826"],
  ];
  for (const [secret, alg, t, want] of vectors)
    check(`rfc6238 ${alg} T=${t}`, hotpCode(secret, alg, Math.floor(t / 30), 8), want);

  // base32 roundtrip
  const rnd = randomBytes(37);
  check("base32 roundtrip", base32Decode(base32Encode(rnd)).equals(rnd), true);

  // otpauth URI roundtrip
  const uri =
    "otpauth://totp/GitHub:user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
  const parsedUri = parseOtpauthUri(uri);
  check("otpauth label", parsedUri.label, "user@example.com");
  check("otpauth issuer", parsedUri.issuer, "GitHub");
  check("otpauth secret", parsedUri.secretB32, "JBSWY3DPEHPK3PXP");

  // migration protobuf decode (hand-built payload: 2 accounts)
  const secret1 = randomBytes(20);
  const secret2 = randomBytes(20);
  const enc = (s: string) => Buffer.from(s, "utf8");
  const otpParam = (secret: Buffer, name: string, issuer: string, alg: number, digits: number, type: number) => {
    const parts: Buffer[] = [];
    parts.push(Buffer.from([0x0a, secret.length]), secret);
    const n = enc(name);
    parts.push(Buffer.from([0x12, n.length]), n);
    const i = enc(issuer);
    parts.push(Buffer.from([0x1a, i.length]), i);
    parts.push(Buffer.from([0x20, alg]), Buffer.from([0x28, digits]), Buffer.from([0x30, type]));
    return Buffer.concat(parts);
  };
  const inner1 = otpParam(secret1, "user@example.com", "GitHub", 1, 1, 2);
  const inner2 = otpParam(secret2, "acct2", "AWS", 2, 2, 2);
  const varint = (n: number): Buffer => {
    const out: number[] = [];
    while (n > 0x7f) {
      out.push((n & 0x7f) | 0x80);
      n >>>= 7;
    }
    out.push(n);
    return Buffer.from(out);
  };
  const wrap = (msg: Buffer) => Buffer.concat([Buffer.from([0x0a]), varint(msg.length), msg]);
  const dataB64 = Buffer.concat([wrap(inner1), wrap(inner2)]).toString("base64");
  const mig = decodeMigrationUri(`otpauth-migration://offline?data=${encodeURIComponent(dataB64)}`);
  check("migration count", mig.accounts.length, 2);
  check("migration secret1", mig.accounts[0]?.secretB32, base32Encode(secret1));
  check("migration alg2", mig.accounts[1]?.algorithm, "SHA256");
  check("migration digits2", mig.accounts[1]?.digits, 8);
  check("migration issuer2", mig.accounts[1]?.issuer, "AWS");
  check("migration type1", mig.accounts[0]?.type, "totp");

  // accountToUri roundtrip
  const acc: OtpAccount = {
    id: "x",
    label: "user@example.com",
    issuer: "GitHub",
    secretB32: base32Encode(secret1),
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    type: "totp",
    counter: 0,
    createdAt: new Date().toISOString(),
  };
  const re = parseOtpauthUri(accountToUri(acc));
  check("uri roundtrip secret", re.secretB32, acc.secretB32);
  check("uri roundtrip issuer", re.issuer, "GitHub");
  check("uri roundtrip label", re.label, acc.label);

  // encryption roundtrip (temp dir)
  const tmp = `/tmp/opencode/totp-selftest-${Date.now()}`;
  process.env.TOTP_VAULT_DATA_DIR = tmp;
  const keyHex = randomBytes(32).toString("hex");
  const st = emptyStore();
  st.accounts.push(acc);
  saveStore(st, keyHex);
  const loaded = loadStore(keyHex);
  check("store roundtrip", loaded.accounts[0]?.secretB32, acc.secretB32);
  let tampered = false;
  try {
    loadStore(randomBytes(32).toString("hex"));
  } catch {
    tampered = true;
  }
  check("store wrong key rejected", tampered, true);
  rmSync(tmp, { recursive: true, force: true });

  return results;
}
