#!/usr/bin/env bun
// ob-plugin-totp-vault-totp — TOTP/2FA vault CLI for the totp-vault plugin
import {
  accountCode,
  accountToUri,
  base32Decode,
  base32Encode,
  decodeMigrationUri,
  decodeQrImage,
  emptyStore,
  ensureMasterKey,
  loadStore,
  mergeAccounts,
  parseOtpauthUri,
  resolveMasterKey,
  resetStore,
  saveStore,
  selftest,
  storeExists,
  type ImportSummary,
  type OtpAccount,
  type OtpAlgorithm,
  type OtpType,
  type ParsedOtp,
  type Store,
} from "/usr/local/bin/ob-plugin-totp-vault-lib.ts";

const USAGE = `ob-plugin-totp-vault-totp — TOTP/2FA vault

Usage:
  totp list [--json]
  totp code <query> [--json]     current code (TOTP) / next code (HOTP, increments)
  totp import --image <path>     import QR image (Google Authenticator export or otpauth://)
  totp import --uri <uri>        import from otpauth:// or otpauth-migration:// URI
  totp import --secret <b32> --label <name> [--issuer <name>] [--digits 6|8]
                [--period <sec>] [--alg SHA1|SHA256|SHA512] [--type totp|hotp] [--counter <n>]
  totp show <query>              reveal the secret + otpauth:// URI (sensitive!)
  totp rename <id> <new label>
  totp remove <id> --yes
  totp reset --yes              WIPE the encrypted store (recovery when the master key is lost)
  totp selftest                  RFC 6238 vectors + codec roundtrips

<query> matches an account by id, issuer or label (case-insensitive substring).
Secrets are stored encrypted at rest; the master key lives in the plugin vault.`;

function die(msg: string, code = 1): never {
  console.error(`error: ${msg}`);
  process.exit(code);
}

function loadOrDie(key: string): Store {
  try {
    return loadStore(key);
  } catch (e) {
    die("the account store exists but can't be decrypted (" + (e instanceof Error ? e.message : String(e)) + ") — restore the master key in Plugins → TOTP Vault → Settings → master_key, or wipe the store deliberately with: totp reset --yes");
  }
}

function keyOrDie(): string {
  const key = resolveMasterKey();
  if (key) return key;
  if (storeExists())
    die("the account store is encrypted but its master key is missing or changed — restore it in Plugins → TOTP Vault → Settings → master_key, or wipe the store deliberately with: totp reset --yes");
  die("no master key yet — run 'totp list' once to set up the vault");
}

function findAccount(store: Store, query: string): OtpAccount | undefined {
  const q = query.trim().toLowerCase();
  return (
    store.accounts.find((a) => a.id === q) ??
    store.accounts.find((a) => a.issuer.toLowerCase() === q) ??
    store.accounts.find((a) => a.label.toLowerCase() === q) ??
    store.accounts.find((a) => `${a.issuer}:${a.label}`.toLowerCase() === q) ??
    store.accounts.find((a) => a.issuer.toLowerCase().includes(q)) ??
    store.accounts.find((a) => a.label.toLowerCase().includes(q))
  );
}

async function importParsed(store: Store, parsed: ParsedOtp[], failed: { name: string; reason: string }[], asJson: boolean): Promise<ImportSummary> {
  const summary = mergeAccounts(store, parsed, failed);
  if (summary.added.length) saveStore(store, await ensureMasterKey());
  if (asJson) {
    console.log(JSON.stringify(summary, null, 2));
  } else {
    for (const a of summary.added) console.log(`added: ${a.issuer ? a.issuer + " / " : ""}${a.label} (id ${a.id})`);
    for (const d of summary.duplicates) console.log(`duplicate skipped: ${d.issuer ? d.issuer + " / " : ""}${d.label}`);
    for (const f of summary.failed) console.log(`failed: ${f.name} — ${f.reason}`);
    if (!summary.added.length && !summary.duplicates.length && !summary.failed.length) console.log("nothing to import");
  }
  return summary;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const asJson = args.includes("--json");
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    console.log(USAGE);
    process.exit(cmd ? 0 : 2);
  }

  if (cmd === "selftest") {
    const results = selftest();
    const failed = results.filter((r) => !r.ok);
    for (const r of failed) console.error(`FAIL ${r.name}: ${r.detail}`);
    console.log(asJson ? JSON.stringify({ passed: results.length - failed.length, failed: failed.length }) : failed.length ? `${failed.length}/${results.length} checks FAILED` : `all ${results.length} checks passed`);
    process.exit(failed.length ? 1 : 0);
  }

  if (cmd === "list") {
    await ensureMasterKey();
    const key = resolveMasterKey();
    const store = key ? loadOrDie(key) : emptyStore();
    if (asJson) {
      console.log(JSON.stringify({ accounts: store.accounts.map(({ secretB32: _s, ...rest }) => rest) }, null, 2));
    } else if (!store.accounts.length) {
      console.log("no accounts yet — import with: totp import --image <qr.png>");
    } else {
      for (const a of store.accounts)
        console.log(`${a.id}  ${a.issuer ? a.issuer + " — " : ""}${a.label}  [${a.type} ${a.algorithm} ${a.digits}d ${a.period}s]`);
    }
    return;
  }

  if (cmd === "code") {
    const query = args[1];
    if (!query) die("usage: totp code <query>");
    const key = keyOrDie();
    const store = loadOrDie(key);
    const acc = findAccount(store, query);
    if (!acc) die(`no account matches "${query}"`, 2);
    const { code, expiresAt, counter } = accountCode(acc);
    if (acc.type === "hotp") {
      acc.counter += 1;
      saveStore(store, key);
    }
    const remain = expiresAt ? Math.max(0, Math.round((expiresAt - Date.now()) / 1000)) : null;
    if (asJson) console.log(JSON.stringify({ id: acc.id, issuer: acc.issuer, label: acc.label, code, remainingSeconds: remain, counter }, null, 2));
    else console.log(remain === null ? `${code} (counter ${counter})` : `${code} (valid ${remain}s)`);
    return;
  }

  if (cmd === "import") {
    const imageIdx = args.indexOf("--image");
    const uriIdx = args.indexOf("--uri");
    const secretIdx = args.indexOf("--secret");
    const parsed: ParsedOtp[] = [];
    const failed: { name: string; reason: string }[] = [];
    if (imageIdx > 0) {
      const imagePath = args[imageIdx + 1];
      if (!imagePath) die("usage: totp import --image <path>");
      let uris: string[];
      try {
        uris = await decodeQrImage(imagePath);
      } catch (e) {
        die(e instanceof Error ? e.message : String(e));
      }
      for (const uri of uris) {
        try {
          if (/^otpauth-migration:\/\//i.test(uri)) {
            const res = decodeMigrationUri(uri);
            parsed.push(...res.accounts);
            failed.push(...res.failed);
          } else parsed.push(parseOtpauthUri(uri));
        } catch (e) {
          failed.push({ name: uri.slice(0, 60), reason: e instanceof Error ? e.message : String(e) });
        }
      }
      if (!uris.length) die("no otpauth QR code found in the image");
    } else if (uriIdx > 0) {
      const uri = args[uriIdx + 1];
      if (!uri) die("usage: totp import --uri <uri>");
      try {
        if (/^otpauth-migration:\/\//i.test(uri)) {
          const res = decodeMigrationUri(uri);
          parsed.push(...res.accounts);
          failed.push(...res.failed);
        } else parsed.push(parseOtpauthUri(uri));
      } catch (e) {
        die(e instanceof Error ? e.message : String(e));
      }
    } else if (secretIdx > 0) {
      const get = (flag: string): string | undefined => {
        const i = args.indexOf(flag);
        return i > 0 ? args[i + 1] : undefined;
      };
      const secret = args[secretIdx + 1];
      const label = get("--label");
      if (!secret || !label) die("usage: totp import --secret <b32> --label <name> [...]");
      try {
        base32Decode(secret);
      } catch {
        die("invalid base32 secret");
      }
      const algRaw = (get("--alg") ?? "SHA1").toUpperCase();
      const algorithm: OtpAlgorithm = algRaw === "SHA256" ? "SHA256" : algRaw === "SHA512" ? "SHA512" : "SHA1";
      const type: OtpType = (get("--type") ?? "totp").toLowerCase() === "hotp" ? "hotp" : "totp";
      parsed.push({
        label,
        issuer: get("--issuer") ?? "",
        secretB32: base32Encode(base32Decode(secret)),
        algorithm,
        digits: Number(get("--digits") ?? 6) === 8 ? 8 : 6,
        period: Math.max(1, Number(get("--period") ?? 30) || 30),
        type,
        counter: Number(get("--counter") ?? 0) || 0,
      });
    } else {
      die("usage: totp import --image <path> | --uri <uri> | --secret <b32> --label <name>");
    }
    const key = resolveMasterKey();
    const store = key ? loadOrDie(key) : emptyStore();
    await importParsed(store, parsed, failed, asJson);
    return;
  }

  if (cmd === "show") {
    const query = args[1];
    if (!query) die("usage: totp show <query>");
    const key = keyOrDie();
    const store = loadOrDie(key);
    const acc = findAccount(store, query);
    if (!acc) die(`no account matches "${query}"`, 2);
    if (asJson) console.log(JSON.stringify({ ...acc, uri: accountToUri(acc) }, null, 2));
    else console.log(`${accountToUri(acc)}\nsecret: ${acc.secretB32}`);
    return;
  }

  if (cmd === "rename") {
    const [query, newLabel] = [args[1], args[2]];
    if (!query || !newLabel) die("usage: totp rename <id> <new label>");
    const key = keyOrDie();
    const store = loadOrDie(key);
    const acc = findAccount(store, query);
    if (!acc) die(`no account matches "${query}"`, 2);
    acc.label = newLabel;
    saveStore(store, key);
    console.log(asJson ? JSON.stringify({ id: acc.id, label: acc.label }) : `renamed to "${newLabel}"`);
    return;
  }

  if (cmd === "remove") {
    const query = args[1];
    if (!query || !args.includes("--yes")) die("usage: totp remove <id> --yes");
    const key = keyOrDie();
    const store = loadOrDie(key);
    const acc = findAccount(store, query);
    if (!acc) die(`no account matches "${query}"`, 2);
    store.accounts = store.accounts.filter((a) => a.id !== acc.id);
    saveStore(store, key);
    console.log(asJson ? JSON.stringify({ removed: acc.id }) : `removed ${acc.issuer ? acc.issuer + " / " : ""}${acc.label}`);
    return;
  }

  if (cmd === "reset") {
    if (!args.includes("--yes")) die("usage: totp reset --yes  (WIPEs the encrypted account store — recovery path when the master key is lost)");
    resetStore();
    console.log(asJson ? JSON.stringify({ reset: true }) : "encrypted account store wiped — import your accounts again");
    return;
  }

  die(`unknown command "${cmd}" — run without args for usage`, 2);
}

main().catch((e) => die(e instanceof Error ? e.message : String(e)));
