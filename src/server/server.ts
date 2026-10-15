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
  readMasterKey,
  saveStore,
  type OtpAccount,
  type Store,
} from "/usr/local/bin/ob-plugin-totp-vault-lib.ts";

const PORT = Number(process.env.OPEN_BOT_PAGE_PORT ?? 4740);
const TOKEN = process.env.OPEN_BOT_PAGE_TOKEN ?? "";

function authorized(req: Request): boolean {
  if (!TOKEN) return true;
  const h = req.headers.get("x-open-bot-page-token");
  return !h || h === TOKEN;
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
}

function viewState(): ViewState {
  const key = readMasterKey();
  if (!key) return { configured: false, error: null, store: emptyStore() };
  try {
    return { configured: true, error: null, store: loadStore(key) };
  } catch (e) {
    return { configured: true, error: e instanceof Error ? e.message : String(e), store: emptyStore() };
  }
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

Bun.serve({
  port: PORT,
  async fetch(req): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/healthz") return new Response("ok");

    if (!authorized(req)) return json({ error: "unauthorized" }, 403);

    if (req.method === "GET" && path === "/") return new Response(pageHtml(), { headers: { "content-type": "text/html; charset=utf-8" } });

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
        if (summary.added.length) saveStore(vs.store, readMasterKey()!);
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
          if (summary.added.length) saveStore(vs.store, readMasterKey()!);
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
      const acc = findById(vs.store, m[1]);
      if (!acc) return fail("account not found", 404);
      const action = m[2] ?? "";
      try {
        if (req.method === "GET" && action === "/secret")
          return json({ id: acc.id, issuer: acc.issuer, label: acc.label, secretB32: acc.secretB32, uri: accountToUri(acc) });
        if (req.method === "DELETE" && !action) {
          vs.store.accounts = vs.store.accounts.filter((a) => a.id !== acc.id);
          saveStore(vs.store, readMasterKey()!);
          return json({ removed: acc.id });
        }
        if (req.method === "POST" && action === "/rename") {
          const body = await readBodyJson(req);
          const label = String(body.label ?? "").trim();
          if (!label) return fail("missing label");
          acc.label = label;
          saveStore(vs.store, readMasterKey()!);
          return json({ id: acc.id, label });
        }
        if (req.method === "POST" && action === "/next") {
          if (acc.type !== "hotp") return fail("not an HOTP account");
          acc.counter += 1;
          saveStore(vs.store, readMasterKey()!);
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

// ---- UI ----

function pageHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TOTP Vault</title>
<script>
  // Theme: light is the default (Justin's rule), dark via browser preference,
  // overridable with ?theme=light|dark — the open-bot dashboard toggle drives this
  // parameter on the proxied page. Set before CSS so there is no flash.
  (function () {
    var apply = function () {
      var q = null;
      try { q = new URLSearchParams(location.search).get("theme"); } catch (e) {}
      var dark = q === "dark" || (q !== "light" && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
      if (dark) document.documentElement.setAttribute("data-theme", "dark");
      else document.documentElement.removeAttribute("data-theme");
    };
    apply();
    try {
      var mq = window.matchMedia("(prefers-color-scheme: dark)");
      if (mq.addEventListener) mq.addEventListener("change", function () { if (!new URLSearchParams(location.search).get("theme")) apply(); });
    } catch (e) {}
  })();
</script>
<style>
  :root {
    --bg: #f6f7f9; --card: #ffffff; --border: #d9dde3; --text: #1a1f27; --muted: #5b6472;
    --accent: #2456c8; --accent-soft: #e8eefb; --danger: #b3261e; --danger-soft: #fbe9e7; --accent-contrast: #ffffff;
    --ok: #1a7f37; --ring: #d9dde3; --ring-fg: #2456c8; --input-bg: #ffffff; --shadow: 0 1px 3px rgba(15,20,30,.08);
  }
  html[data-theme="dark"] {
    --bg: #12161c; --card: #1a2029; --border: #2c3440; --text: #e8ecf1; --muted: #98a2b0;
    --accent: #7ea4f0; --accent-soft: #21304d; --danger: #f28b82; --danger-soft: #3a2220; --accent-contrast: #10141b;
    --ok: #6dd58c; --ring: #2c3440; --ring-fg: #7ea4f0; --input-bg: #12161c; --shadow: 0 1px 4px rgba(0,0,0,.4);
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
  .wrap { max-width: 780px; margin: 0 auto; padding: 20px 16px 60px; }
  header { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
  header h1 { font-size: 20px; margin: 0; flex: 1; }
  .btn { border: 1px solid var(--border); background: var(--card); color: var(--text); border-radius: 8px; padding: 7px 14px; font-size: 14px; cursor: pointer; }
  .btn:hover { border-color: var(--accent); }
  .btn.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-contrast); }
  .btn.danger { color: var(--danger); border-color: var(--danger); }
  .btn.small { padding: 4px 9px; font-size: 13px; }
  .iconbtn { border: 1px solid transparent; background: none; color: var(--muted); cursor: pointer; font-size: 15px; border-radius: 6px; padding: 4px 7px; }
  .iconbtn:hover { color: var(--accent); background: var(--accent-soft); }
  .iconbtn.del:hover { color: var(--danger); background: var(--danger-soft); }
  .notice { background: var(--accent-soft); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; margin-bottom: 16px; font-size: 14px; }
  .notice.error { background: var(--danger-soft); }
  .search { width: 100%; padding: 9px 12px; border: 1px solid var(--border); border-radius: 8px; background: var(--input-bg); color: var(--text); font-size: 14px; margin-bottom: 14px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow); padding: 14px 16px; display: flex; align-items: center; gap: 14px; margin-bottom: 10px; }
  .ringwrap { position: relative; width: 46px; height: 46px; flex: none; }
  .ringwrap svg { width: 46px; height: 46px; transform: rotate(-90deg); }
  .ringwrap .secs { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 11px; color: var(--muted); }
  .code { font: 700 26px/1 ui-monospace, "SF Mono", Menlo, monospace; letter-spacing: 2px; min-width: 140px; cursor: pointer; }
  .code.hotp { cursor: default; }
  .who { flex: 1; min-width: 0; }
  .who .issuer { font-weight: 600; }
  .who .label { color: var(--muted); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .who .meta { color: var(--muted); font-size: 11px; margin-top: 2px; }
  .empty { text-align: center; padding: 46px 18px; color: var(--muted); }
  .empty .big { font-size: 40px; margin-bottom: 10px; }
  dialog { border: 1px solid var(--border); border-radius: 14px; background: var(--card); color: var(--text); padding: 20px; width: min(520px, 92vw); }
  dialog::backdrop { background: rgba(8,10,14,.55); }
  dialog h2 { margin: 0; font-size: 17px; }
  .dlg-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 14px; }
  .dlg-close { border: none; background: none; color: var(--muted); font-size: 24px; line-height: 1; cursor: pointer; padding: 2px 9px; border-radius: 8px; }
  .dlg-close:hover { color: var(--accent); background: var(--accent-soft); }
  .tabs { display: flex; gap: 6px; margin-bottom: 14px; }
  .tabs .btn.on { background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }
  label.f { display: block; margin: 10px 0 4px; font-size: 13px; color: var(--muted); }
  input.f, textarea.f, select.f { width: 100%; padding: 8px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--input-bg); color: var(--text); font-size: 14px; }
  select.f option { background: var(--card); color: var(--text); }
  textarea.f { min-height: 74px; font-family: ui-monospace, monospace; }
  .row { display: flex; gap: 10px; } .row > * { flex: 1; }
  .drop { border: 2px dashed var(--border); border-radius: 10px; padding: 26px; text-align: center; color: var(--muted); cursor: pointer; }
  .drop:hover { border-color: var(--accent); color: var(--accent); }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
  .imp-result { margin-top: 12px; font-size: 13px; }
  .imp-result .ok { color: var(--ok); } .imp-result .dup { color: var(--muted); } .imp-result .err { color: var(--danger); }
  .secret-box { font-family: ui-monospace, monospace; background: var(--input-bg); border: 1px solid var(--border); border-radius: 8px; padding: 10px; word-break: break-all; font-size: 13px; margin: 6px 0 12px; }
  #toast { position: fixed; bottom: 22px; left: 50%; transform: translateX(-50%); background: var(--text); color: var(--bg); padding: 9px 18px; border-radius: 20px; font-size: 14px; opacity: 0; transition: opacity .25s; pointer-events: none; z-index: 9; }
  #toast.show { opacity: 1; }
  .hint { color: var(--muted); font-size: 12px; margin-top: 10px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>🔐 <span data-i18n="title">TOTP Vault</span></h1>
    <button class="btn primary" id="addBtn" data-i18n="add">+ Add</button>
  </header>
  <div id="notice"></div>
  <input class="search" id="search" type="search" data-i18n-ph="search" placeholder="Filter…">
  <div id="list"></div>
  <div class="hint" id="updatedAt"></div>
</div>

<dialog id="addDlg">
  <div class="dlg-head"><h2 data-i18n="addTitle">Add an account</h2><button class="dlg-close" id="addClose" title="Esc">×</button></div>
  <div class="tabs">
    <button class="btn small on" data-tab="qr" data-i18n="tabQr">QR image</button>
    <button class="btn small" data-tab="uri" data-i18n="tabUri">URI</button>
    <button class="btn small" data-tab="manual" data-i18n="tabManual">Manual</button>
  </div>
  <div id="tab-qr">
    <div class="drop" id="drop">📷 <span data-i18n="dropText">Click or drop a screenshot of the QR code</span></div>
    <input type="file" id="qrFile" accept="image/*" hidden>
    <div class="hint" data-i18n="qrHint">Google Authenticator → Transfer accounts → Export accounts → select accounts → screenshot the QR (batch QRs welcome).</div>
  </div>
  <div id="tab-uri" hidden>
    <label class="f" data-i18n="uriLabel">otpauth:// or otpauth-migration:// URI</label>
    <textarea class="f" id="uriText" placeholder="otpauth://totp/…"></textarea>
    <div class="actions"><button class="btn" id="uriCancel" data-i18n="cancel">Cancel</button><button class="btn primary" id="uriImport" data-i18n="import">Import</button></div>
  </div>
  <div id="tab-manual" hidden>
    <div class="row">
      <div><label class="f" data-i18n="fSecret">Secret (base32)</label><input class="f" id="mSecret" placeholder="JBSWY3DPEHPK3PXP"></div>
      <div><label class="f" data-i18n="fLabel">Account</label><input class="f" id="mLabel"></div>
    </div>
    <div class="row">
      <div><label class="f" data-i18n="fIssuer">Issuer (optional)</label><input class="f" id="mIssuer"></div>
      <div><label class="f" data-i18n="fDigits">Digits</label><select class="f" id="mDigits"><option>6</option><option>8</option></select></div>
    </div>
    <div class="row">
      <div><label class="f" data-i18n="fAlg">Algorithm</label><select class="f" id="mAlg"><option>SHA1</option><option>SHA256</option><option>SHA512</option></select></div>
      <div><label class="f" data-i18n="fType">Type</label><select class="f" id="mType"><option value="totp">TOTP</option><option value="hotp">HOTP</option></select></div>
    </div>
    <div class="actions"><button class="btn" id="mCancel" data-i18n="cancel">Cancel</button><button class="btn primary" id="mImport" data-i18n="import">Import</button></div>
  </div>
  <div class="imp-result" id="impResult"></div>
</dialog>

<dialog id="secretDlg">
  <h2 data-i18n="secretTitle">Account secret</h2>
  <p data-i18n="secretWarn" style="color:var(--muted);font-size:13px">Keep this secret safe — anyone with it can generate your codes.</p>
  <div class="secret-box" id="secretUri"></div>
  <div class="secret-box" id="secretB32"></div>
  <div class="actions">
    <button class="btn" id="secretCopy" data-i18n="copySecret">Copy secret</button>
    <button class="btn primary" id="secretClose" data-i18n="close">Close</button>
  </div>
</dialog>

<div id="toast"></div>

<script>
(() => {
  const LANG = (navigator.language || "en").toLowerCase().startsWith("fr") ? "fr" : "en";
  const I18N = {
    en: {
      title: "TOTP Vault", add: "+ Add", search: "Filter by issuer or account…",
      addTitle: "Add an account", tabQr: "QR image", tabUri: "URI", tabManual: "Manual",
      dropText: "Click or drop a screenshot of the QR code",
      qrHint: "Google Authenticator → Transfer accounts → Export accounts → select accounts → screenshot the QR (batch QRs welcome).",
      uriLabel: "otpauth:// or otpauth-migration:// URI", import: "Import", cancel: "Cancel",
      fSecret: "Secret (base32)", fLabel: "Account", fIssuer: "Issuer (optional)", fDigits: "Digits", fAlg: "Algorithm", fType: "Type",
      secretTitle: "Account secret", secretWarn: "Keep this secret safe — anyone with it can generate your codes.",
      copySecret: "Copy secret", close: "Close", copied: "Copied!",
      notConfigured: "Not set up yet: in a chat, just ask for one of your codes (or run 'totp list') — the master key is created automatically.",
      decryptError: "Could not decrypt the account store (the master key changed?). Import your accounts again.",
      empty: "No account yet", emptyHint: "Export from Google Authenticator and import the QR here.",
      confirmDelete: "Delete this account?", renamePrompt: "New account label:",
      imported: "Imported:", duplicates: "already present:", failed: "Failed:", nothing: "Nothing imported",
      next: "Next code", reveal: "Show secret", del: "Delete", copy: "Copy code",
    },
    fr: {
      title: "Coffre TOTP", add: "+ Ajouter", search: "Filtrer par service ou compte…",
      addTitle: "Ajouter un compte", tabQr: "Image QR", tabUri: "URI", tabManual: "Manuel",
      dropText: "Clique ou dépose une capture du code QR",
      qrHint: "Google Authenticator → Transférer les comptes → Exporter les comptes → sélectionne les comptes → capture le QR (QR multiples bienvenus).",
      uriLabel: "URI otpauth:// ou otpauth-migration://", import: "Importer", cancel: "Annuler",
      fSecret: "Secret (base32)", fLabel: "Compte", fIssuer: "Service (optionnel)", fDigits: "Chiffres", fAlg: "Algorithme", fType: "Type",
      secretTitle: "Secret du compte", secretWarn: "Garde ce secret précieusement — quiconque le possède peut générer tes codes.",
      copySecret: "Copier le secret", close: "Fermer", copied: "Copié !",
      notConfigured: "Pas encore configuré : dans une conversation, demande simplement un de tes codes (ou lance 'totp list') — la clé maîtresse est créée automatiquement.",
      decryptError: "Impossible de déchiffrer le coffre (clé maîtresse changée ?). Réimporte tes comptes.",
      empty: "Aucun compte pour l'instant", emptyHint: "Exporte depuis Google Authenticator et importe le QR ici.",
      confirmDelete: "Supprimer ce compte ?", renamePrompt: "Nouveau libellé du compte :",
      imported: "Importés :", duplicates: "déjà présents :", failed: "Échecs :", nothing: "Rien à importer",
      next: "Code suivant", reveal: "Voir le secret", del: "Supprimer", copy: "Copier le code",
    },
  };
  const t = (k) => I18N[LANG][k] ?? I18N.en[k] ?? k;
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  document.documentElement.lang = LANG;
  document.querySelectorAll("[data-i18n]").forEach((el) => (el.textContent = t(el.dataset.i18n)));
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => (el.placeholder = t(el.dataset.i18nPh)));

  // Theme is handled by the head script: ?theme=light|dark (dashboard toggle)
  // or browser preference. No in-page override.

  const $ = (id) => document.getElementById(id);
  const list = $("list"), notice = $("notice"), search = $("search");
  let accounts = [];
  let timer = null;

  function toast(msg) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(el._t);
    el._t = setTimeout(() => el.classList.remove("show"), 1600);
  }
  const fmt = (code, digits) => digits === 8 ? code.slice(0,4) + " " + code.slice(4) : code.slice(0,3) + " " + code.slice(3);

  async function api(path, opts) {
    const r = await fetch(path, opts);
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || r.status);
    return d;
  }

  async function refresh() {
    try {
      const d = await api("api/state");
      accounts = d.accounts || [];
      if (!d.configured) notice.innerHTML = '<div class="notice">' + esc(t("notConfigured")) + "</div>";
      else if (d.error) notice.innerHTML = '<div class="notice error">' + esc(t("decryptError")) + "</div>";
      else notice.innerHTML = "";
      render();
      const next = accounts.filter(a => a.expiresAt).map(a => a.expiresAt - d.now).sort((a,b) => a-b)[0];
      clearTimeout(timer);
      if (next !== undefined) timer = setTimeout(refresh, Math.max(250, next + 250));
    } catch (e) {
      notice.innerHTML = '<div class="notice error">' + esc(String(e.message || e)) + "</div>";
    }
  }

  function ring(secs, period) {
    const r = 19, c = 2 * Math.PI * r;
    const frac = Math.max(0, Math.min(1, secs / period));
    return '<svg viewBox="0 0 46 46"><circle cx="23" cy="23" r="' + r + '" fill="none" stroke="var(--ring)" stroke-width="4"/>' +
      '<circle cx="23" cy="23" r="' + r + '" fill="none" stroke="var(--ring-fg)" stroke-width="4" stroke-linecap="round" ' +
      'stroke-dasharray="' + c + '" stroke-dashoffset="' + (c * (1 - frac)) + '"/></svg>';
  }

  function render() {
    const q = search.value.trim().toLowerCase();
    const shown = accounts.filter(a => !q || (a.issuer + " " + a.label).toLowerCase().includes(q));
    if (!accounts.length) {
      list.innerHTML = '<div class="empty"><div class="big">🔐</div><div><b>' + esc(t("empty")) + "</b></div><div>" + esc(t("emptyHint")) + "</div></div>";
      return;
    }
    list.innerHTML = "";
    for (const a of shown) {
      const card = document.createElement("div");
      card.className = "card";
      const secs = a.expiresAt ? Math.max(0, Math.ceil((a.expiresAt - Date.now()) / 1000)) : 0;
      card.innerHTML =
        '<div class="ringwrap">' + ring(secs, a.period) + '<div class="secs">' + (a.expiresAt ? secs + "s" : "·") + "</div></div>" +
        '<div class="code' + (a.type === "hotp" ? " hotp" : "") + '" data-copy="' + a.id + '">' + esc(fmt(a.code, a.digits)) + "</div>" +
        '<div class="who"><div class="issuer">' + esc(a.issuer || "—") + "</div>" +
        '<div class="label">' + esc(a.label) + "</div>" +
        '<div class="meta">' + esc(a.type.toUpperCase() + " · " + a.algorithm + " · " + a.digits + "d") + "</div></div>" +
        (a.type === "hotp" ? '<button class="iconbtn" data-next="' + a.id + '" title="' + esc(t("next")) + '">⏭</button>' : "") +
        '<button class="iconbtn" data-copy="' + a.id + '" title="' + esc(t("copy")) + '">📋</button>' +
        '<button class="iconbtn" data-rename="' + a.id + '" title="✎">✎</button>' +
        '<button class="iconbtn" data-reveal="' + a.id + '" title="' + esc(t("reveal")) + '">👁</button>' +
        '<button class="iconbtn del" data-del="' + a.id + '" title="' + esc(t("del")) + '">🗑</button>';
      list.appendChild(card);
    }
  }
  setInterval(render, 500);
  search.addEventListener("input", render);

  list.addEventListener("click", async (ev) => {
    const el = ev.target.closest("[data-copy],[data-del],[data-rename],[data-reveal],[data-next]");
    if (!el) return;
    const id = el.dataset.copy || el.dataset.del || el.dataset.rename || el.dataset.reveal || el.dataset.next;
    const acc = accounts.find(a => a.id === id);
    if (!acc) return;
    if (el.dataset.copy) {
      try { await navigator.clipboard.writeText(acc.code); toast(t("copied")); }
      catch { toast(acc.code); }
    } else if (el.dataset.del) {
      if (confirm(t("confirmDelete") + "\\n" + (acc.issuer ? acc.issuer + " / " : "") + acc.label)) {
        try { await api("api/accounts/" + id, { method: "DELETE" }); refresh(); } catch (e) { toast(e.message); }
      }
    } else if (el.dataset.rename) {
      const v = prompt(t("renamePrompt"), acc.label);
      if (v && v.trim()) {
        try { await api("api/accounts/" + id + "/rename", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ label: v.trim() }) }); refresh(); } catch (e) { toast(e.message); }
      }
    } else if (el.dataset.reveal) {
      try {
        const d = await api("api/accounts/" + id + "/secret");
        $("secretUri").textContent = d.uri;
        $("secretB32").textContent = d.secretB32;
        $("secretCopy").onclick = async () => { try { await navigator.clipboard.writeText(d.secretB32); toast(t("copied")); } catch {} };
        $("secretDlg").showModal();
      } catch (e) { toast(e.message); }
    } else if (el.dataset.next) {
      try { await api("api/accounts/" + id + "/next", { method: "POST" }); refresh(); } catch (e) { toast(e.message); }
    }
  });

  // ---- add dialog ----
  const addDlg = $("addDlg"), impResult = $("impResult");
  $("addBtn").onclick = () => { impResult.innerHTML = ""; addDlg.showModal(); };
  $("addClose").setAttribute("aria-label", LANG === "fr" ? "Fermer" : "Close");
  $("addClose").onclick = () => addDlg.close();
  document.querySelectorAll("[data-tab]").forEach((b) => {
    b.onclick = () => {
      document.querySelectorAll("[data-tab]").forEach((x) => x.classList.toggle("on", x === b));
      for (const tab of ["qr", "uri", "manual"]) $("tab-" + tab).hidden = tab !== b.dataset.tab;
    };
  });

  function showResult(s) {
    const parts = [];
    if (s.added?.length) parts.push('<div class="ok">✓ ' + esc(t("imported")) + " " + s.added.map(x => esc((x.issuer ? x.issuer + " / " : "") + x.label)).join(", ") + "</div>");
    if (s.duplicates?.length) parts.push('<div class="dup">= ' + esc(t("duplicates")) + " " + s.duplicates.map(x => esc((x.issuer ? x.issuer + " / " : "") + x.label)).join(", ") + "</div>");
    if (s.failed?.length) parts.push('<div class="err">✗ ' + esc(t("failed")) + " " + s.failed.map(x => esc(x.name + " — " + x.reason)).join("; ") + "</div>");
    impResult.innerHTML = parts.join("") || '<div class="dup">' + esc(t("nothing")) + "</div>";
    if (s.added?.length) refresh();
  }

  const drop = $("drop"), qrFile = $("qrFile");
  drop.onclick = () => qrFile.click();
  drop.ondragover = (e) => { e.preventDefault(); };
  drop.ondrop = (e) => { e.preventDefault(); if (e.dataTransfer.files[0]) sendQr(e.dataTransfer.files[0]); };
  qrFile.onchange = () => { if (qrFile.files[0]) sendQr(qrFile.files[0]); };
  async function sendQr(file) {
    drop.textContent = "⏳ …";
    try {
      const s = await api("api/import/qr", { method: "POST", body: await file.arrayBuffer() });
      showResult(s);
    } catch (e) {
      impResult.innerHTML = '<div class="err">✗ ' + esc(e.message) + "</div>";
    }
    drop.innerHTML = '📷 <span data-i18n="dropText"></span>';
    drop.querySelector("[data-i18n]").textContent = t("dropText");
  }

  $("uriCancel").onclick = () => addDlg.close();
  $("uriImport").onclick = async () => {
    try { showResult(await api("api/import/uri", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri: $("uriText").value.trim() }) })); }
    catch (e) { impResult.innerHTML = '<div class="err">✗ ' + esc(e.message) + "</div>"; }
  };

  $("mCancel").onclick = () => addDlg.close();
  $("mImport").onclick = async () => {
    const secret = $("mSecret").value.replace(/\\s+/g, "").toUpperCase();
    const label = $("mLabel").value.trim();
    if (!secret || !label) { impResult.innerHTML = '<div class="err">✗ secret + label required</div>'; return; }
    const q = new URLSearchParams({ secret });
    if ($("mIssuer").value.trim()) q.set("issuer", $("mIssuer").value.trim());
    q.set("algorithm", $("mAlg").value);
    q.set("digits", $("mDigits").value);
    const type = $("mType").value;
    const uri = "otpauth://" + type + "/" + encodeURIComponent(label) + "?" + q.toString();
    try { showResult(await api("api/import/uri", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri }) })); }
    catch (e) { impResult.innerHTML = '<div class="err">✗ ' + esc(e.message) + "</div>"; }
  };

  $("secretClose").onclick = () => $("secretDlg").close();

  refresh();
})();
</script>
</body>
</html>`;
}
