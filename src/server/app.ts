// TOTP Vault — dashboard page app (bundled by the control plane from index.html).
// Logic moved verbatim from the former inline script in server.ts: same ids,
// same i18n hooks (data-i18n / data-i18n-ph), same fetch paths (relative only).
(() => {
  const LANG = (navigator.language || "en").toLowerCase().startsWith("fr") ? "fr" : "en";
  const I18N: Record<string, Record<string, string>> = {
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
  const t = (k: string): string => I18N[LANG][k] ?? I18N.en[k] ?? k;
  const esc = (s: unknown): string => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
  document.documentElement.lang = LANG;
  document.querySelectorAll<HTMLElement>("[data-i18n]").forEach((el) => (el.textContent = t(el.dataset.i18n!)));
  document.querySelectorAll<HTMLInputElement>("[data-i18n-ph]").forEach((el) => (el.placeholder = t(el.dataset.i18nPh!)));

  // Theme is handled by the head script: ?theme=light|dark (dashboard toggle)
  // or browser preference. No in-page override.

  type Account = {
    id: string; issuer: string; label: string; type: string; algorithm: string;
    digits: number; period: number; counter: number; code: string; expiresAt: number | null;
  };
  const $ = (id: string): HTMLElement => document.getElementById(id)!;
  const list = $("list"), notice = $("notice"), search = $("search") as HTMLInputElement;
  let accounts: Account[] = [];
  let timer: ReturnType<typeof setTimeout> | null = null;

  function toast(msg: string): void {
    const el = $("toast");
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout((el as HTMLElement & { _t?: ReturnType<typeof setTimeout> })._t);
    (el as HTMLElement & { _t?: ReturnType<typeof setTimeout> })._t = setTimeout(() => el.classList.remove("show"), 1600);
  }
  const fmt = (code: string, digits: number): string => digits === 8 ? code.slice(0,4) + " " + code.slice(4) : code.slice(0,3) + " " + code.slice(3);

  async function api(path: string, opts?: RequestInit): Promise<any> {
    const r = await fetch(path, opts);
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || r.status);
    return d;
  }

  async function refresh(): Promise<void> {
    try {
      const d = await api("api/state");
      accounts = d.accounts || [];
      if (!d.configured) notice.innerHTML = '<div class="notice">' + esc(t("notConfigured")) + "</div>";
      else if (d.error) notice.innerHTML = '<div class="notice error">' + esc(t("decryptError")) + "</div>";
      else notice.innerHTML = "";
      render();
    } catch (e) {
      notice.innerHTML = '<div class="notice error">' + esc(String((e as Error).message || e)) + "</div>";
    } finally {
      // self-healing poll: a transient failure must never kill the loop
      if (timer) clearTimeout(timer);
      const next = accounts.filter(a => a.expiresAt).map(a => a.expiresAt! - Date.now()).sort((a, b) => a - b)[0];
      timer = setTimeout(refresh, Math.max(1000, Math.min(5000, (next ?? 5000) + 250)));
    }
  }

  function ring(secs: number, period: number): string {
    const r = 19, c = 2 * Math.PI * r;
    const frac = Math.max(0, Math.min(1, secs / period));
    return '<svg viewBox="0 0 46 46"><circle cx="23" cy="23" r="' + r + '" fill="none" stroke="var(--ring)" stroke-width="4"/>' +
      '<circle cx="23" cy="23" r="' + r + '" fill="none" stroke="var(--ring-fg)" stroke-width="4" stroke-linecap="round" ' +
      'stroke-dasharray="' + c + '" stroke-dashoffset="' + (c * (1 - frac)) + '"/></svg>';
  }

  function render(): void {
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
    const el = (ev.target as HTMLElement).closest("[data-copy],[data-del],[data-rename],[data-reveal],[data-next]") as HTMLElement | null;
    if (!el) return;
    const id = el.dataset.copy || el.dataset.del || el.dataset.rename || el.dataset.reveal || el.dataset.next;
    const acc = accounts.find(a => a.id === id);
    if (!acc) return;
    if (el.dataset.copy) {
      try { await navigator.clipboard.writeText(acc.code); toast(t("copied")); }
      catch { toast(acc.code); }
    } else if (el.dataset.del) {
      if (confirm(t("confirmDelete") + "\n" + (acc.issuer ? acc.issuer + " / " : "") + acc.label)) {
        try { await api("api/accounts/" + id, { method: "DELETE" }); refresh(); } catch (e) { toast((e as Error).message); }
      }
    } else if (el.dataset.rename) {
      const v = prompt(t("renamePrompt"), acc.label);
      if (v && v.trim()) {
        try { await api("api/accounts/" + id + "/rename", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ label: v.trim() }) }); refresh(); } catch (e) { toast((e as Error).message); }
      }
    } else if (el.dataset.reveal) {
      try {
        const d = await api("api/accounts/" + id + "/secret");
        $("secretUri").textContent = d.uri;
        $("secretB32").textContent = d.secretB32;
        $("secretCopy").onclick = async () => { try { await navigator.clipboard.writeText(d.secretB32); toast(t("copied")); } catch {} };
        ($("secretDlg") as HTMLDialogElement).showModal();
      } catch (e) { toast((e as Error).message); }
    } else if (el.dataset.next) {
      try { await api("api/accounts/" + id + "/next", { method: "POST" }); refresh(); } catch (e) { toast((e as Error).message); }
    }
  });

  // ---- add dialog ----
  const addDlg = $("addDlg") as HTMLDialogElement, impResult = $("impResult");
  $("addBtn").onclick = () => { impResult.innerHTML = ""; addDlg.showModal(); };
  $("addClose").setAttribute("aria-label", LANG === "fr" ? "Fermer" : "Close");
  $("addClose").onclick = () => addDlg.close();
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((b) => {
    b.onclick = () => {
      document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((x) => x.classList.toggle("on", x === b));
      for (const tab of ["qr", "uri", "manual"]) ($("tab-" + tab) as HTMLElement).hidden = tab !== b.dataset.tab;
    };
  });

  function showResult(s: { added?: { issuer: string; label: string }[]; duplicates?: { issuer: string; label: string }[]; failed?: { name: string; reason: string }[] }): void {
    const parts: string[] = [];
    if (s.added?.length) parts.push('<div class="ok">✓ ' + esc(t("imported")) + " " + s.added.map(x => esc((x.issuer ? x.issuer + " / " : "") + x.label)).join(", ") + "</div>");
    if (s.duplicates?.length) parts.push('<div class="dup">= ' + esc(t("duplicates")) + " " + s.duplicates.map(x => esc((x.issuer ? x.issuer + " / " : "") + x.label)).join(", ") + "</div>");
    if (s.failed?.length) parts.push('<div class="err">✗ ' + esc(t("failed")) + " " + s.failed.map(x => esc(x.name + " — " + x.reason)).join("; ") + "</div>");
    impResult.innerHTML = parts.join("") || '<div class="dup">' + esc(t("nothing")) + "</div>";
    if (s.added?.length) refresh();
  }

  const drop = $("drop"), qrFile = $("qrFile") as HTMLInputElement;
  drop.onclick = () => qrFile.click();
  drop.ondragover = (e) => { e.preventDefault(); };
  drop.ondrop = (e) => { e.preventDefault(); if ((e as DragEvent).dataTransfer!.files[0]) sendQr((e as DragEvent).dataTransfer!.files[0]); };
  qrFile.onchange = () => { if (qrFile.files![0]) sendQr(qrFile.files![0]); };
  async function sendQr(file: File): Promise<void> {
    drop.textContent = "⏳ …";
    try {
      const s = await api("api/import/qr", { method: "POST", body: await file.arrayBuffer() });
      showResult(s);
    } catch (e) {
      impResult.innerHTML = '<div class="err">✗ ' + esc((e as Error).message) + "</div>";
    }
    drop.innerHTML = '📷 <span data-i18n="dropText"></span>';
    drop.querySelector("[data-i18n]")!.textContent = t("dropText");
  }

  $("uriCancel").onclick = () => addDlg.close();
  $("uriImport").onclick = async () => {
    try { showResult(await api("api/import/uri", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri: ($("uriText") as HTMLTextAreaElement).value.trim() }) })); }
    catch (e) { impResult.innerHTML = '<div class="err">✗ ' + esc((e as Error).message) + "</div>"; }
  };

  $("mCancel").onclick = () => addDlg.close();
  $("mImport").onclick = async () => {
    const secret = ($("mSecret") as HTMLInputElement).value.replace(/\s+/g, "").toUpperCase();
    const label = ($("mLabel") as HTMLInputElement).value.trim();
    if (!secret || !label) { impResult.innerHTML = '<div class="err">✗ secret + label required</div>'; return; }
    const q = new URLSearchParams({ secret });
    if (($("mIssuer") as HTMLInputElement).value.trim()) q.set("issuer", ($("mIssuer") as HTMLInputElement).value.trim());
    q.set("algorithm", ($("mAlg") as HTMLSelectElement).value);
    q.set("digits", ($("mDigits") as HTMLSelectElement).value);
    const type = ($("mType") as HTMLSelectElement).value;
    const uri = "otpauth://" + type + "/" + encodeURIComponent(label) + "?" + q.toString();
    try { showResult(await api("api/import/uri", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri }) })); }
    catch (e) { impResult.innerHTML = '<div class="err">✗ ' + esc((e as Error).message) + "</div>"; }
  };

  $("secretClose").onclick = () => ($("secretDlg") as HTMLDialogElement).close();

  refresh();
})();
