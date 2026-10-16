// totp-vault — dashboard page server (Bun)
import {
  accountCode,
  accountToUri,
  PLUGIN_ID,
  decodeMigrationUri,
  decodeQrImage,
  emptyStore,
  loadStore,
  mergeAccounts,
  parseOtpauthUri,
  resolveMasterKey,
  saveStore,
  type OtpAccount,
  type Store,
} from "/usr/local/bin/ob-plugin-totp-vault-lib.ts";

const PORT = Number(process.env.OPEN_BOT_PAGE_PORT ?? 4740);
const TOKEN = process.env.OPEN_BOT_PAGE_TOKEN ?? "";

function authorized(
  req: Request,
  server?: { requestIP(req: Request): { address: string } | null } | null,
): boolean {
  if (!TOKEN) return true;
  const h = req.headers.get("x-open-bot-page-token");
  if (h === TOKEN) return true;
  // The open-bot preview iframe can't know the token — it identifies itself
  // with the fixed "dev-preview" value, tolerated from loopback peers only so
  // non-loopback callers still need the real shared secret (review fix v0.2.1).
  // A missing header is likewise only tolerated for loopback peers (local
  // browser click-testing on 127.0.0.1) — never for other interfaces. Fail
  // closed when the peer address is unavailable. The captured Bun.serve
  // instance is passed by the caller: with html-import routes Bun's second
  // fetch argument can be undefined. IPv4-mapped loopback (::ffff:127.0.0.1)
  // counts too.
  if (h === "dev-preview") {
    const lo = server?.requestIP?.(req)?.address ?? "";
    return /^(::ffff:)?127\.0\.0\.1$|^::1$/.test(lo);
  }
  const ip = server?.requestIP?.(req)?.address ?? "";
  return /^(::ffff:)?127\.0\.0\.1$|^::1$/.test(ip);
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

function fail(e: unknown, status = 400): Response {
  return json({ error: e instanceof Error ? e.message : String(e) }, status);
}

// ---- store helpers ----

interface ViewState {
  configured: boolean;
  error: string | null;
  store: Store;
  // The master key that actually decrypted the store (settings copy, healed
  // from the local mirror when an update reset the settings). Saves must use
  // this exact key — not a fresh settings read.
  key: string | null;
}

function viewState(): ViewState {
  const key = resolveMasterKey();
  if (!key) return { configured: false, error: null, store: emptyStore(), key: null };
  try {
    return { configured: true, error: null, store: loadStore(key), key };
  } catch (e) {
    return { configured: true, error: e instanceof Error ? e.message : String(e), store: emptyStore(), key };
  }
}

// Writes are FORBIDDEN while the store exists but can't be decrypted: saving an
// empty/new store would silently destroy every account encrypted with the old key.
function writableOr409(vs: ViewState): Response | null {
  if (vs.error)
    return fail(
      "the account store exists but can't be decrypted (" +
        vs.error +
        ") — refusing to overwrite it. Restore the master key in Plugins → TOTP Vault → Settings, or wipe the store deliberately with: ob-plugin-totp-vault-totp reset --yes",
      409,
    );
  return null;
}

function accountPublic(a: OtpAccount, now: number) {
  const { code, expiresAt, counter } = accountCode(a, now);
  return {
    id: a.id,
    issuer: a.issuer,
    label: a.label,
    type: a.type,
    algorithm: a.algorithm,
    digits: a.digits,
    period: a.period,
    counter,
    code,
    expiresAt,
  };
}

function findById(store: Store, id: string): OtpAccount | undefined {
  return store.accounts.find((a) => a.id === id);
}

async function readBodyJson(req: Request): Promise<Record<string, unknown>> {
  try {
    return (await req.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

// ---- server ----

// The UI is bundled by the control plane at install (from dashboard.pages.ui)
// and handed over via OPEN_BOT_PAGE_UI as ONE self-contained HTML. Local
// checkouts / previews build the same thing here (app.ts bundled for the
// browser, CSS and JS inlined) so every response carries cache-control:
// no-cache — a cached stale UI on a phone kept serving dead buttons after
// every fix. v0.2.9: inline EVERYTHING into the document. Serving separate
// chunk-*.css/js files (v0.2.7) broke the dashboard proxy path: the phone got
// the HTML but the chunks 404'd — unstyled, dead page. Relative fetch("api/…")
// is the only sub-path guarantee the proxy makes.
// Note: with our own build the UI is frozen at server start (bun --hot no
// longer hot-reloads the UI; restart the page server after UI edits). If the
// build ever fails we fall back to the Bun.serve html-import special case
// (also self-contained, its own headers, always works).
const HTML_HEADERS = { "content-type": "text/html; charset=utf-8", "cache-control": "no-cache" };
async function checkoutUiRoutes(): Promise<Record<string, unknown> | null> {
  try {
    const [jsBuild, html, css] = await Promise.all([
      Bun.build({ entrypoints: [new URL("./app.ts", import.meta.url).pathname], target: "browser" }),
      Bun.file(new URL("./index.html", import.meta.url).pathname).text(),
      Bun.file(new URL("./styles.css", import.meta.url).pathname).text(),
    ]);
    const js = (await jsBuild.outputs[0].text()).replace(/<\/script/gi, "<\\/script");
    const inlined = html
      .replace(/<link rel="stylesheet" href="\.?\/?styles\.css">/, () => `<style>\n${css}\n</style>`)
      .replace(/<script src="\.?\/?app\.ts"><\/script>/, () => `<script type="module">\n${js}\n</script>`);
    if (inlined === html) return null; // markers not found — fall back to html-import
    return { "/": (): Response => new Response(inlined, { headers: HTML_HEADERS }) };
  } catch {
    return null;
  }
}
const routes: Record<string, unknown> = process.env.OPEN_BOT_PAGE_UI
  ? {
      "/": (): Response =>
        new Response(Bun.file(process.env.OPEN_BOT_PAGE_UI as string), { headers: HTML_HEADERS }),
    }
  : (await checkoutUiRoutes()) ?? {
      "/": await import("./index.html").then((m) => m.default),
    };

const pageServer = Bun.serve({
  port: PORT,
  routes: routes as never,
  async fetch(req): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/healthz") return new Response("ok");

    if (!authorized(req, pageServer)) return json({ error: "unauthorized" }, 403);

    if (req.method === "GET" && path === "/api/state") {
      const vs = viewState();
      const now = Date.now();
      return json({
        configured: vs.configured,
        error: vs.error,
        now,
        accounts: vs.store.accounts.map((a) => accountPublic(a, now)),
      });
    }

    if (req.method === "POST" && path === "/api/import/uri") {
      try {
        const body = await readBodyJson(req);
        const uri = String(body.uri ?? "");
        if (!uri) return fail("missing uri");
        const vs = viewState();
        if (!vs.configured) return fail("not configured: no master key yet — run 'ob-plugin-totp-vault-totp list' once in a chat", 409);
        const blocked = writableOr409(vs);
        if (blocked) return blocked;
        const parsed = [];
        const failed: { name: string; reason: string }[] = [];
        if (/^otpauth-migration:\/\//i.test(uri.trim())) {
          const res = decodeMigrationUri(uri.trim());
          parsed.push(...res.accounts);
          failed.push(...res.failed);
        } else {
          try {
            parsed.push(parseOtpauthUri(uri));
          } catch (e) {
            failed.push({ name: "input", reason: e instanceof Error ? e.message : String(e) });
          }
        }
        const summary = mergeAccounts(vs.store, parsed, failed);
        if (summary.added.length) saveStore(vs.store, vs.key!);
        return json(summary);
      } catch (e) {
        return fail(e);
      }
    }

    if (req.method === "POST" && path === "/api/import/qr") {
      try {
        const buf = Buffer.from(await req.arrayBuffer());
        if (!buf.length) return fail("empty image body");
        const dir = `${process.env.TOTP_VAULT_DATA_DIR ?? "/home/agent/.open-bot/pages-data/totp-vault"}/tmp`;
        await Bun.$`mkdir -p ${dir}`.quiet();
        const tmp = `${dir}/qr-${Date.now()}.png`;
        await Bun.write(tmp, buf);
        try {
          const uris = await decodeQrImage(tmp);
          const vs = viewState();
          if (!vs.configured) return fail("not configured: no master key yet — run 'ob-plugin-totp-vault-totp list' once in a chat", 409);
          const blocked = writableOr409(vs);
          if (blocked) return blocked;
          const parsed = [];
          const failed: { name: string; reason: string }[] = [];
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
          const summary = mergeAccounts(vs.store, parsed, failed);
          if (summary.added.length) saveStore(vs.store, vs.key!);
          if (!summary.added.length && !summary.duplicates.length && !summary.failed.length)
            return fail("no otpauth QR code found in the image");
          return json(summary);
        } finally {
          await Bun.$`rm -f ${tmp}`.quiet();
        }
      } catch (e) {
        return fail(e);
      }
    }

    const m = /^\/api\/accounts\/([0-9a-f]+)(\/[a-z]+)?$/.exec(path);
    if (m) {
      const vs = viewState();
      if (!vs.configured) return fail("not configured", 409);
      const blocked = writableOr409(vs);
      if (blocked) return blocked;
      const acc = findById(vs.store, m[1]);
      if (!acc) return fail("account not found", 404);
      const action = m[2] ?? "";
      try {
        if (req.method === "GET" && action === "/secret")
          return json({ id: acc.id, issuer: acc.issuer, label: acc.label, secretB32: acc.secretB32, uri: accountToUri(acc) });
        if (req.method === "DELETE" && !action) {
          vs.store.accounts = vs.store.accounts.filter((a) => a.id !== acc.id);
          saveStore(vs.store, vs.key!);
          return json({ removed: acc.id });
        }
        if (req.method === "POST" && action === "/rename") {
          const body = await readBodyJson(req);
          const label = String(body.label ?? "").trim();
          if (!label) return fail("missing label");
          acc.label = label;
          saveStore(vs.store, vs.key!);
          return json({ id: acc.id, label });
        }
        if (req.method === "POST" && action === "/next") {
          if (acc.type !== "hotp") return fail("not an HOTP account");
          acc.counter += 1;
          saveStore(vs.store, vs.key!);
          return json(accountPublic(acc, Date.now()));
        }
        return fail("not found", 404);
      } catch (e) {
        return fail(e);
      }
    }

    if (req.method === "GET" && path === "/mentions") {
      const vs = viewState();
      return json({
        items: vs.store.accounts.map((a) => ({
          name: a.issuer ? `${a.issuer} / ${a.label}` : a.label,
          description: `2FA account (${a.type.toUpperCase()})`,
          aliases: [a.label, a.issuer].filter((s) => s && s.length > 1).slice(0, 5),
          hint: "TOTP/2FA account — generate its current code with: ob-plugin-totp-vault-totp code <query>",
        })),
      });
    }

    return json({ error: "not found" }, 404);
  },
});

