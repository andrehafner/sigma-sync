/* Sigma Sync - frontend. Vanilla JS, no build step. */
'use strict';

(() => {
  // ------------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------------
  const S = {
    me: null,
    csrf: '',
    config: {},
    txs: [],
    wallets: [],
    versions: null,
    filter: 'queue',
    search: '',
    detail: null,
    signin: null,
    pollTimer: null,
    qrTimers: new Set(),
    view: 0, // counts the routes drawn, so a late answer can tell it is stale
    listSeq: 0, // counts the list fetches, so an older answer can tell a newer one has started
    runWallet: null, // the context of a connected wallet that passed the B1 and Q7 checks, or null (Q4)
    selection: new Set(), // ids of the rows picked for a run (Q4). It lives here so a redraw keeps it (Q9).
    selGroup: '', // the group key of those rows: a selection holds one group
    selNotes: [], // plain texts that say why the selection is not what the signer asked for
    acks: new Map(), // id -> the reading of the flagged item that the signer ticked. A different reading drops the tick (Q5).
    readings: new Map(), // id -> the reading the review screen shows now
  };

  const MINOTAUR_RELEASES = 'https://github.com/minotaur-ergo/minotaur-wallet/releases';
  const MINOTAUR_API = 'https://api.github.com/repos/minotaur-ergo/minotaur-wallet/releases?per_page=100';
  // Used when GitHub cannot be reached. Newest first.
  const FALLBACK_VERSIONS = ['v4.3.0', 'v4.2.1', 'v4.2.0', 'v4.1.0', 'v4.0.0', 'v3.4.0', 'v3.3.0', 'v3.2.0',
    'v3.1.0', 'v3.0.1', 'v3.0.0', 'v2.5.0', 'v2.4.0', 'v2.3.0', 'v2.2.0', 'v2.1.0', 'v2.0.2'];
  const QR_DENSITY = [1600, 900, 450]; // characters per QR page: dense, medium, light
  const ADDRESS_KEY = 'sigmasync.address';

  // ------------------------------------------------------------------------
  // Utilities
  // ------------------------------------------------------------------------
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const app = () => $('#app');

  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function store(key, value) {
    try {
      if (value === undefined) return localStorage.getItem(key);
      localStorage.setItem(key, value);
    } catch (e) { /* storage unavailable: convenience only */ }
    return null;
  }

  // Server timestamps are UTC "YYYY-MM-DD HH:MM:SS[.ffffff]".
  function parseTs(ts) { return ts ? new Date(ts.slice(0, 19).replace(' ', 'T') + 'Z') : null; }

  function ago(ts) {
    const d = parseTs(ts);
    if (!d) return '';
    const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
    if (s < 60) return 'just now';
    const units = [[86400 * 365, 'y'], [86400 * 30, 'mo'], [86400, 'd'], [3600, 'h'], [60, 'm']];
    for (const [sec, label] of units) if (s >= sec) return `${Math.floor(s / sec)}${label} ago`;
    return '';
  }

  function fullDate(ts) {
    const d = parseTs(ts);
    return d ? d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '';
  }

  function timeTag(ts) {
    return `<time datetime="${esc(parseTs(ts)?.toISOString() || '')}" title="${esc(fullDate(ts))}">${esc(ago(ts))}</time>`;
  }

  function minutesText(m) {
    if (m < 60) return `${m} min`;
    const h = Math.floor(m / 60);
    return h < 48 ? `${h} h ${m % 60} min` : `${Math.floor(h / 24)} days`;
  }

  // nanoERG string -> "1,234.5678 ERG" without floating point.
  function erg(nano) {
    if (nano === undefined || nano === null || nano === '') return '';
    const s = String(nano).padStart(10, '0');
    const whole = s.slice(0, -9).replace(/^0+(?=\d)/, '');
    const frac = s.slice(-9).replace(/0+$/, '');
    return `${Number(whole).toLocaleString()}${frac ? '.' + frac : ''} ERG`;
  }

  const shortAddr = (a) => (a && a.length > 16 ? `${a.slice(0, 7)}…${a.slice(-5)}` : a || '');
  const shortId = (id) => (id ? `${id.slice(0, 8)}…${id.slice(-6)}` : '');

  async function copyText(text, label = 'Copied') {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${label} to clipboard`, 'success');
    } catch (e) {
      toast('Copy failed - select the text and copy it manually', 'error');
    }
  }

  function download(filename, text) {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function toast(message, type = '') {
    const el = document.createElement('div');
    el.className = `toast${type ? ' toast-' + type : ''}`;
    el.textContent = message;
    $('#toasts').appendChild(el);
    setTimeout(() => el.remove(), type === 'error' ? 7000 : 3500);
  }

  // Removes characters clipboards and chat apps add that never belong in a payload.
  // Mirrors ErgoKit::sanitize_payload on the server, which has the final say.
  function cleanPayload(text) {
    return String(text || '')
      .replace(/[​-‍⁠﻿­]/g, '')
      .replace(/[“-‟″]/g, '"')
      .replace(/[‘-‛′]/g, "'")
      .replace(/ /g, ' ')
      .replace(/[\r\n\t]+/g, '')
      .trim();
  }

  // ------------------------------------------------------------------------
  // API
  // ------------------------------------------------------------------------
  async function api(action, params = {}) {
    const form = new FormData();
    form.append('action', action);
    if (S.csrf) form.append('csrf', S.csrf);
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null) form.append(k, v);
    });
    let data;
    try {
      const res = await fetch('api.pl', { method: 'POST', body: form, credentials: 'same-origin' });
      data = await res.json();
    } catch (e) {
      throw new Error('Could not reach the server. Check your connection and try again.');
    }
    if (!data.success) {
      if (data.signed_out && S.me) {
        S.me = null;
        S.csrf = '';
        renderSignIn();
      }
      const err = new Error(data.error || 'Unknown error');
      err.data = data;
      throw err;
    }
    return data;
  }

  // ------------------------------------------------------------------------
  // Dialogs
  // ------------------------------------------------------------------------
  function dialog({ title, body = '', confirm = 'OK', cancel = 'Cancel', danger = false, input = null }) {
    const dlg = $('#dialog');
    const form = $('#dialog-form');
    form.innerHTML = `
      <h2>${esc(title)}</h2>
      <div class="muted">${body}</div>
      ${input ? `<div class="field"><label for="dialog-input">${esc(input.label)}</label>
        <input type="text" id="dialog-input" maxlength="${input.max || 255}" autocomplete="off"></div>` : ''}
      <div class="dialog-actions">
        ${cancel ? `<button class="btn" value="cancel">${esc(cancel)}</button>` : ''}
        <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" value="ok">${esc(confirm)}</button>
      </div>`;
    return new Promise((resolve) => {
      const done = () => {
        dlg.removeEventListener('close', done);
        if (dlg.returnValue !== 'ok') return resolve(null);
        resolve(input ? ($('#dialog-input').value || '').trim() : true);
      };
      dlg.addEventListener('close', done);
      dlg.returnValue = '';
      dlg.showModal();
      (input ? $('#dialog-input') : form.querySelector('[value=ok]')).focus();
    });
  }

  // ------------------------------------------------------------------------
  // QR codes - compatible with Minotaur's paged format:
  //   {"<TYPE>": "<chunk>", "p": page, "n": pages, "a": animated}
  // ------------------------------------------------------------------------
  function qrSvg(text) {
    const qr = window.qrcode(0, 'L');
    qr.addData(text, 'Byte');
    qr.make();
    const n = qr.getModuleCount();
    const m = 4;
    let path = '';
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) if (qr.isDark(r, c)) path += `M${c + m} ${r + m}h1v1h-1z`;
    }
    const size = n + m * 2;
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="QR code">
      <rect width="${size}" height="${size}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
  }

  // Mounts a paged QR viewer into `el`. `envelope` is the full {"TYPE":"..."} text.
  function mountQr(el, envelope) {
    let type;
    let inner;
    try {
      const obj = JSON.parse(envelope);
      type = Object.keys(obj).find((k) => !['p', 'n', 'a'].includes(k));
      inner = typeof obj[type] === 'string' ? obj[type] : JSON.stringify(obj[type]);
    } catch (e) {
      el.innerHTML = '<p class="faint small">QR code is not available for this payload.</p>';
      return;
    }
    let density = inner.length > QR_DENSITY[0] ? 1 : 0;
    let page = 0;
    let timer = null;

    const pagesFor = () => Math.max(1, Math.ceil(inner.length / QR_DENSITY[density]));
    const stop = () => { if (timer) { clearInterval(timer); S.qrTimers.delete(timer); timer = null; } };

    function draw() {
      const pages = pagesFor();
      page = Math.min(page, pages - 1);
      const size = Math.ceil(inner.length / pages);
      const value = JSON.stringify({ [type]: inner.slice(page * size, (page + 1) * size), p: page + 1, n: pages, a: timer ? 1 : 0 });
      let svg;
      try { svg = qrSvg(value); } catch (e) { svg = '<p class="small">Too large for one page - choose a lighter density.</p>'; }
      el.innerHTML = `
        <div class="qr">
          ${svg}
          <div class="qr-controls">
            ${pages > 1 ? `
              <button type="button" class="btn btn-sm" data-qr="prev" ${timer ? 'disabled' : ''} aria-label="Previous page">‹</button>
              <span>Page ${page + 1} of ${pages}</span>
              <button type="button" class="btn btn-sm" data-qr="next" ${timer ? 'disabled' : ''} aria-label="Next page">›</button>
              <button type="button" class="btn btn-sm" data-qr="play">${timer ? 'Pause' : 'Auto-play'}</button>` : '<span>Single page</span>'}
            <button type="button" class="btn btn-sm" data-qr="density" title="Change how much data each QR page holds">
              ${['Dense', 'Medium', 'Light'][density]}</button>
          </div>
        </div>`;
    }

    el.onclick = (ev) => {
      const btn = ev.target.closest('[data-qr]');
      if (!btn) return;
      const pages = pagesFor();
      switch (btn.dataset.qr) {
        case 'prev': page = (page - 1 + pages) % pages; break;
        case 'next': page = (page + 1) % pages; break;
        case 'play':
          if (timer) stop();
          else {
            timer = setInterval(() => { page = (page + 1) % pagesFor(); draw(); }, 800);
            S.qrTimers.add(timer);
          }
          break;
        case 'density': stop(); density = (density + 1) % QR_DENSITY.length; page = 0; break;
        default: break;
      }
      draw();
    };
    draw();
  }

  function stopQrTimers() {
    S.qrTimers.forEach((t) => clearInterval(t));
    S.qrTimers.clear();
  }

  // Camera scanner. Resolves with the assembled payload text, or null if closed.
  function loadJsQr() {
    if (window.jsQR) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'vendor/jsQR-1.4.0.js';
      s.onload = resolve;
      s.onerror = () => reject(new Error('Could not load the QR scanner.'));
      document.head.appendChild(s);
    });
  }

  async function scanQr() {
    if (!navigator.mediaDevices?.getUserMedia) {
      toast('This browser cannot use the camera here. Copy and paste the text instead.', 'error');
      return null;
    }
    const dlg = $('#dialog');
    const form = $('#dialog-form');
    form.innerHTML = `
      <h2>Scan QR code</h2>
      <div class="scanner"><video playsinline muted></video></div>
      <div class="scanner-status" id="scan-status">Starting camera…</div>
      <div class="dialog-actions"><button class="btn" value="cancel">Close</button></div>`;
    dlg.returnValue = '';
    dlg.showModal();
    const video = $('video', form);
    const status = $('#scan-status');
    let stream;
    let active = true;
    const chunks = [];
    let type = null;

    const finish = (result) => {
      active = false;
      stream?.getTracks().forEach((t) => t.stop());
      if (dlg.open) dlg.close(result ? 'ok' : 'cancel');
      return result;
    };

    return new Promise(async (resolve) => {
      dlg.addEventListener('close', () => { if (active) resolve(finish(null)); }, { once: true });
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        video.srcObject = stream;
        await video.play();
      } catch (e) {
        status.textContent = 'Camera not available or permission denied.';
        return;
      }
      let detector = null;
      if ('BarcodeDetector' in window) {
        try { detector = new window.BarcodeDetector({ formats: ['qr_code'] }); } catch (e) { detector = null; }
      }
      if (!detector) {
        try { await loadJsQr(); } catch (e) { status.textContent = e.message; return; }
      }
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      status.textContent = 'Point the camera at the QR code.';

      const handle = (raw) => {
        let obj;
        try { obj = JSON.parse(raw); } catch (e) { resolve(finish(raw)); return; }
        const t = Object.keys(obj).find((k) => !['p', 'n', 'a'].includes(k));
        if (!obj.n || obj.n === 1) { resolve(finish(JSON.stringify({ [t]: obj[t] }))); return; }
        if (type && t !== type) return;
        type = t;
        chunks.length = obj.n;
        chunks[obj.p - 1] = obj[t];
        const have = chunks.filter((c) => c !== undefined).length;
        status.textContent = `Scanned ${have} of ${obj.n} pages…`;
        if (have === obj.n) resolve(finish(JSON.stringify({ [type]: chunks.join('') })));
      };

      const tick = async () => {
        if (!active) return;
        if (video.readyState >= 2) {
          try {
            if (detector) {
              const codes = await detector.detect(video);
              if (codes[0]) handle(codes[0].rawValue);
            } else {
              canvas.width = video.videoWidth;
              canvas.height = video.videoHeight;
              ctx.drawImage(video, 0, 0);
              const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
              const code = window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
              if (code) handle(code.data);
            }
          } catch (e) { /* keep scanning */ }
        }
        if (active) requestAnimationFrame(tick);
      };
      tick();
    });
  }

  // ------------------------------------------------------------------------
  // Minotaur versions (live from GitHub, cached; fallback list if offline)
  // ------------------------------------------------------------------------
  async function loadVersions() {
    if (S.versions) return S.versions;
    try {
      const cached = JSON.parse(store('sigmasync.versions') || 'null');
      if (cached && Date.now() - cached.at < 6 * 3600 * 1000) return (S.versions = cached.list);
    } catch (e) { /* ignore */ }
    try {
      const res = await fetch(MINOTAUR_API, { headers: { Accept: 'application/vnd.github+json' } });
      if (!res.ok) throw new Error(String(res.status));
      const rel = await res.json();
      const list = rel.filter((r) => !r.draft).map((r) => ({
        tag: r.tag_name, pre: !!r.prerelease, date: (r.published_at || '').slice(0, 10), url: r.html_url,
      }));
      if (!list.length) throw new Error('empty');
      store('sigmasync.versions', JSON.stringify({ at: Date.now(), list }));
      S.versions = list;
    } catch (e) {
      S.versions = FALLBACK_VERSIONS.map((tag) => ({ tag, pre: false, date: '', url: `${MINOTAUR_RELEASES}/tag/${tag}` }));
      S.versions.offline = true;
    }
    return S.versions;
  }

  const releaseUrl = (tag) => `${MINOTAUR_RELEASES}/tag/${encodeURIComponent(tag)}`;

  const versionLabel = (v) => `Minotaur ${v}`;

  // ------------------------------------------------------------------------
  // Wallet challenges (sign-in and linking an extra address)
  // ------------------------------------------------------------------------

  // Renders "sign this request in Minotaur, paste the result" into `el`.
  // `ch` = { address, challenge, request, expires }. onDone receives the API result.
  function mountChallenge(el, ch, { submitLabel, onDone, onRestart, error = '' }) {
    el.innerHTML = `
      <div class="stack">
        <div class="row"><strong>Wallet</strong><code class="faint">${esc(shortAddr(ch.address))}</code>
          <span class="spacer"></span><button type="button" class="btn btn-ghost btn-sm" data-ch="restart">Change</button></div>
        <div>
          <p class="step-label"><span class="step-num">1</span> Sign this request in Minotaur</p>
          <ol class="howto small">
            <li>In Minotaur, tap the <strong>QR scanner</strong>. Scan the code below, or choose paste after copying the request.</li>
            <li>Check it is the wallet for this address, then <strong>Sign</strong>. Air-gapped wallets work the same way.</li>
            <li>Copy (or show) the signed result Minotaur produces.</li>
          </ol>
          <p class="small faint">Minotaur did not ask for your password? Then it is showing an old result -
          fully close and reopen Minotaur and scan again.</p>
          <div data-ch="qr"></div>
          <div class="row mt-8">
            <button type="button" class="btn btn-sm" data-ch="copy">Copy request</button>
            <span class="faint small" data-ch="expiry"></span>
          </div>
          <div class="notice notice-info small mt-12">This only proves you control the wallet - it is not a payment.
          The request spends a made-up box that does not exist on the blockchain, so the signed result can never be
          broadcast and no funds can move.</div>
        </div>
        <form class="stack" novalidate data-ch="form">
          <p class="step-label"><span class="step-num">2</span> Paste the signed result</p>
          <textarea class="payload" required autocomplete="off" autocapitalize="off" autocorrect="off"
            spellcheck="false" placeholder='{"CSTX":"…"}' aria-label="Signed result"></textarea>
          <div data-ch="error">${error ? `<div class="notice notice-error">${esc(error)}</div>` : ''}</div>
          <div class="row">
            <button type="button" class="btn" data-ch="scan">Scan QR</button>
            <span class="spacer"></span>
            <button class="btn btn-primary" type="submit">${esc(submitLabel)}</button>
          </div>
        </form>
      </div>`;
    const part = (name) => $(`[data-ch=${name}]`, el);
    const input = $('textarea', el);
    mountQr(part('qr'), ch.request);
    part('restart').onclick = onRestart;
    part('copy').onclick = () => copyText(ch.request, 'Request copied');
    part('scan').onclick = async () => { const text = await scanQr(); if (text) input.value = text; };

    const expiry = part('expiry');
    const tick = () => {
      if (!document.body.contains(expiry)) return;
      const left = Math.round((ch.expires - Date.now()) / 60000);
      expiry.textContent = left > 0 ? `Expires in ${left} min` : 'Expired - start again';
      if (left > 0) setTimeout(tick, 15000);
    };
    tick();

    part('form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const response = cleanPayload(input.value);
      if (!response) return;
      const btn = $('button[type=submit]', ev.target);
      btn.disabled = true;
      try {
        onDone(await api('auth_finish', { challenge: ch.challenge, response }));
      } catch (e) {
        btn.disabled = false;
        part('error').innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`;
      }
    });
  }

  async function startChallenge(address, purpose) {
    const r = await api('auth_start', { address, purpose });
    return { address, challenge: r.challenge, request: r.request, expires: Date.now() + r.expires_minutes * 60000 };
  }

  // ------------------------------------------------------------------------
  // Nautilus: sign in or link an address with the browser wallet (SPEC L1 to L3, L6, L8)
  // ------------------------------------------------------------------------
  // Everything the wallet returns is untrusted data (I4). Its addresses are shown after a shape
  // check and escaping. No other text of the wallet reaches the page: a refusal shows a fixed message.
  const NAUTILUS_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{40,60}$/;
  const NAUTILUS_MESSAGE = {
    connect: 'Nautilus did not connect. Unlock Nautilus, approve the connection in its window and try again.',
    sign: 'Nautilus did not sign the request. Approve it in the Nautilus window and try again.',
  };

  function nautilusConnector() {
    const wallet = window.ergoConnector?.nautilus;
    return typeof wallet?.connect === 'function' ? wallet : null;
  }

  // Connects and reads both address lists, used and unused. Resolves null when the wallet says no.
  async function connectNautilus(wallet) {
    if (!(await wallet.connect({ createErgoObject: false }))) return null;
    const ctx = await wallet.getContext();
    const lists = await Promise.all([ctx.get_used_addresses(), ctx.get_unused_addresses()]);
    const choices = [];
    lists.forEach((list, i) => {
      if (!Array.isArray(list)) return;
      list.forEach((address) => {
        if (typeof address === 'string' && NAUTILUS_ADDRESS.test(address) && !choices.some((c) => c.address === address)) {
          choices.push({ address, used: i === 0 });
        }
      });
    });
    return { ctx, choices };
  }

  // Runs the Nautilus steps inside `el`: connect, choose an address, ask for a challenge, call auth,
  // send the text and the proof. `purpose` is 'login' or 'link'. onDone gets the auth_finish reply.
  // The flow stops quietly when the page has drawn another view over `el`.
  function mountNautilus(el, { purpose, label, hint, onDone }) {
    el.innerHTML = '<p class="or-divider" aria-hidden="true">or</p><div class="stack" data-nautilus="body"></div>';
    const body = $('[data-nautilus=body]', el);
    const show = (html, focus = true) => {
      body.innerHTML = html;
      if (focus) $('[data-focus]', body)?.focus();
    };
    const retry = '<button type="button" class="btn btn-block" data-nautilus="retry" data-focus>Try again</button>';
    const onRetry = () => { $('[data-nautilus=retry]', body).onclick = start; };

    const idle = (focus) => {
      show(`<button type="button" class="btn btn-block" data-nautilus="start" data-focus>${esc(label)}</button>
        <p class="hint">${esc(hint)}</p>`, focus);
      $('[data-nautilus=start]', body).onclick = start;
    };
    const wait = (text) => show(`<p class="wallet-status" role="status" tabindex="-1" data-nautilus="status" data-focus>${esc(text)}</p>`);
    const fail = (message) => {
      show(`<div class="notice notice-error" data-nautilus="error">${esc(message)}</div>${retry}`);
      onRetry();
    };
    const empty = () => {
      show(`<div class="notice notice-info" data-nautilus="empty">Nautilus offered no address. Add one in Nautilus, then try again.</div>${retry}`);
      onRetry();
    };
    const choose = (ctx, choices) => {
      const mine = new Set(purpose === 'link' ? S.me?.addresses : []);
      const first = choices.findIndex((c) => !mine.has(c.address));
      show(`<p class="step-label">Choose the address to use</p>
        <ul class="addr-choice">${choices.map((c, i) => `
          <li><button type="button" class="btn addr-option" data-nautilus-choice="${i}"${mine.has(c.address) ? ' disabled' : ''}${i === first ? ' data-focus' : ''}>
            <code>${esc(c.address)}</code><span class="tag">${mine.has(c.address) ? 'Linked' : c.used ? 'Used' : 'Not used yet'}</span></button></li>`).join('')}
        </ul>
        <p class="hint">An address that only signs for a multi-sig wallet can be listed as not used yet.</p>
        <button type="button" class="btn btn-ghost btn-sm" data-nautilus="cancel">Cancel</button>`);
      $$('[data-nautilus-choice]', body).forEach((btn) => {
        btn.onclick = () => sign(ctx, choices[Number(btn.dataset.nautilusChoice)].address);
      });
      $('[data-nautilus=cancel]', body).onclick = () => idle(true);
    };

    async function start() {
      wait('Connecting to Nautilus. Approve the connection in its window if it asks.');
      let found = null;
      try {
        const wallet = nautilusConnector();
        found = wallet && await connectNautilus(wallet);
      } catch (e) { /* the wallet refused: one fixed message below */ }
      if (!el.isConnected) return;
      if (!found) fail(NAUTILUS_MESSAGE.connect);
      else if (!found.choices.length) empty();
      else choose(found.ctx, found.choices);
    }

    async function sign(ctx, address) {
      wait('Waiting for Nautilus. Approve the request in its window.');
      let challenge;
      try {
        challenge = (await api('auth_start', { address, purpose, method: 'nautilus' })).challenge;
      } catch (e) {
        if (el.isConnected) fail(e.message);
        return;
      }
      if (!el.isConnected) return;
      let signed = null;
      try { signed = await ctx.auth(address, challenge); } catch (e) { /* the wallet refused: one fixed message below */ }
      if (!el.isConnected) return;
      if (typeof signed?.signedMessage !== 'string' || typeof signed.proof !== 'string') { fail(NAUTILUS_MESSAGE.sign); return; }
      let reply;
      try {
        reply = await api('auth_finish', { challenge, signed_message: signed.signedMessage, proof: signed.proof });
      } catch (e) {
        if (el.isConnected) fail(e.message);
        return;
      }
      if (!el.isConnected) return;
      try {
        await onDone(reply);
      } catch (e) {
        if (el.isConnected) fail(e.message);
      }
    }

    idle(false);
  }

  // The wallet's script can arrive after app.js, so the slot is filled when the connector is there
  // at draw time and again when the wallet's event fires (L1). A filled slot is never redrawn.
  let nautilusSlot = null;
  function offerNautilus(el, options) {
    const fill = () => {
      if (!el.firstChild && S.config.nautilus === 1 && nautilusConnector()) mountNautilus(el, options);
    };
    nautilusSlot = { el, fill };
    fill();
  }
  window.addEventListener('ergo-wallet:injected', () => {
    if (nautilusSlot?.el.isConnected) nautilusSlot.fill();
    if ($('#tx-filter')) checkRunWallet(viewGuard());
  });

  // ------------------------------------------------------------------------
  // Sign-in
  // ------------------------------------------------------------------------
  function renderSignIn(step = 'address', error = '') {
    stopPolling();
    stopQrTimers();
    $('#user-chip').hidden = true;
    resetRun();
    const si = S.signin || {};
    app().innerHTML = `
      <section class="signin">
        <div class="signin-hero">
          <img src="favicon.svg" alt="">
          <h1>Sign in to Sigma Sync</h1>
          <p class="muted">Coordinate multi-sig commitments and signatures with your fellow signers.
          Sign in with the Minotaur wallet you sign multi-sig transactions with - no password, no sign-up.
          You will see the transactions of every multi-sig wallet that wallet is a signer of.</p>
        </div>
        <ol class="steps" aria-hidden="true">
          <li class="done"></li><li class="${step === 'sign' ? 'done' : ''}"></li>
        </ol>
        <div class="panel" id="signin-panel"></div>
      </section>`;
    const panel = $('#signin-panel');

    if (step === 'sign') {
      mountChallenge(panel, si, {
        submitLabel: 'Sign in',
        error,
        onRestart: () => renderSignIn('address'),
        onDone: (r) => { S.signin = null; startSession(r); },
      });
      return;
    }

    panel.innerHTML = `
      <form id="address-form" class="stack" novalidate>
        <div class="field">
          <label for="address">Your signing wallet address</label>
          <input type="text" id="address" name="address" required autocomplete="off" autocapitalize="off"
            autocorrect="off" spellcheck="false" placeholder="9…" value="${esc(si.address || store(ADDRESS_KEY) || '')}">
          <p class="hint">The first address of the Minotaur wallet you sign multi-sig transactions with -
          not the multi-sig wallet itself. You can link more addresses later.</p>
        </div>
        ${error ? `<div class="notice notice-error">${esc(error)}</div>` : ''}
        <button class="btn btn-primary btn-block" type="submit">Continue</button>
      </form>
      <div data-nautilus-slot></div>`;
    offerNautilus($('[data-nautilus-slot]', panel), {
      purpose: 'login',
      label: 'Sign in with Nautilus',
      hint: 'Nautilus asks you to connect, then to sign a one-time request. It is not a payment.',
      onDone: (r) => startSession(r),
    });
    $('#address').focus();
    $('#address-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const address = $('#address').value.replace(/\s+/g, '');
      if (!address) return;
      $('button[type=submit]', panel).disabled = true;
      try {
        S.signin = await startChallenge(address, 'login');
        store(ADDRESS_KEY, address);
        renderSignIn('sign');
      } catch (e) {
        renderSignIn('address', e.message);
      }
    });
  }

  function setMe(member) {
    S.me = member;
    $('#user-name').textContent = member.display_name;
    const first = member.addresses?.[0] || '';
    $('#user-address').textContent = shortAddr(first);
    $('#user-address').title = (member.addresses || []).join('\n');
    $('#user-chip').hidden = false;
  }

  function startSession(r) {
    S.csrf = r.csrf;
    S.config = r.config || {};
    setMe(r.member);
    // New accounts pick a name first so co-signers can recognise them.
    if (!r.member.name_chosen && location.hash !== '#account') location.hash = 'account';
    else route();
  }

  // ------------------------------------------------------------------------
  // Routing & shell
  // ------------------------------------------------------------------------
  function route() {
    S.view += 1;
    if (!S.me) return renderSignIn();
    stopPolling();
    stopQrTimers();
    const hash = location.hash.replace(/^#/, '');
    const m = hash.match(/^tx\/(\d+)$/);
    if (m) return renderDetail(Number(m[1]));
    if (hash === 'start') return renderStart();
    if (hash === 'batch') return renderBatch();
    if (hash === 'review') return renderReview();
    if (hash === 'wallets') return renderWallets();
    const w = hash.match(/^wallet\/(\d+)$/);
    if (w) return renderWallet(w[1]);
    if (hash === 'account') return renderAccount();
    if (hash === 'admin' && S.me.is_admin) return renderAdmin();
    return renderList();
  }

  function updateTabCount() {
    const tab = $('.tab[data-nav=sign]');
    if (!tab) return;
    const n = S.txs.filter((t) => t.me.awaiting).length;
    $('.count', tab)?.remove();
    if (n) tab.insertAdjacentHTML('beforeend', `<span class="count" aria-label="${n} waiting">${n}</span>`);
  }

  function shell(active) {
    const awaiting = S.txs.filter((t) => t.me.awaiting).length;
    const tabs = [
      ['sign', 'Sign Transactions', awaiting],
      ['start', 'Start Transaction'],
      ['batch', 'Start Batch'],
      ['wallets', 'Wallets'],
      ['account', 'Account'],
      ...(S.me.is_admin ? [['admin', 'Admin']] : []),
    ];
    app().innerHTML = `
      <nav class="tabs" role="tablist">
        ${tabs.map(([id, label, count]) => `
          <button class="tab" role="tab" data-nav="${id}" aria-selected="${id === active}">
            ${esc(label)}${count ? `<span class="count" aria-label="${count} waiting">${count}</span>` : ''}
          </button>`).join('')}
      </nav>
      <div id="view"></div>`;
    return $('#view');
  }

  function stopPolling() {
    if (S.pollTimer) clearTimeout(S.pollTimer);
    S.pollTimer = null;
  }

  // The next tick is armed only while the route that asked for the poll is on screen. An answer that
  // arrives after a route change must not draw into the new route or start a poll of the old one (Q8).
  function poll(fn, ms) {
    stopPolling();
    const seq = S.view;
    S.pollTimer = setTimeout(async () => {
      if (document.visibilityState === 'visible') {
        try { await fn(); } catch (e) { /* next tick */ }
      }
      if (seq === S.view) poll(fn, ms);
    }, ms);
  }

  // ------------------------------------------------------------------------
  // Transaction list
  // ------------------------------------------------------------------------
  const STATUS_LABEL = {
    commit: 'Commitment round', sign: 'Signing round', complete: 'Ready to broadcast',
    broadcast: 'Broadcast', cancelled: 'Cancelled',
  };
  const isOpen = (t) => t.status === 'commit' || t.status === 'sign';

  // False when a newer fetch has started: its answer is the one to keep, so this one is dropped.
  // The selection is reconciled with every answer that is kept, whether or not a view draws it.
  async function fetchList() {
    const seq = ++S.listSeq;
    const r = await api('list_transactions');
    if (seq !== S.listSeq) return false;
    S.txs = r.transactions;
    S.wallets = r.wallet_names || [];
    reconcileSelection();
    return true;
  }

  async function renderList() {
    const live = viewGuard();
    const view = shell('sign');
    view.innerHTML = '<div class="loading">Loading transactions…</div>';
    let fresh;
    try { fresh = await fetchList(); } catch (e) { if (live()) view.innerHTML = loadError(e.message); return; }
    if (!fresh || !live()) return;
    if (location.hash.replace(/^#/, '') !== '' && location.hash !== '#sign') return;
    drawList();
    poll(async () => { if (await fetchList() && live()) drawList(true); }, 30000);
    checkRunWallet(live);
  }

  function progressBars(t) {
    const req = t.signers_required;
    const bar = (n, cls) => {
      const pct = Math.min(100, Math.round((n / req) * 100));
      return `<div class="bar ${cls} ${n >= req ? 'full' : ''}"><span data-pct="${pct}"></span></div>`;
    };
    return `
      <div class="progress">
        <div class="progress-row"><span>Commitments</span>${bar(t.commits, 'commit')}<strong>${t.commits}/${req}</strong></div>
        <div class="progress-row"><span>Signatures</span>${bar(t.signatures, 'sign')}<strong>${t.signatures}/${req}</strong></div>
      </div>`;
  }

  // Bar widths are set through the CSSOM (allowed by the CSP, unlike style attributes).
  function paintBars(root) {
    $$('[data-pct]', root).forEach((el) => { el.style.width = `${el.dataset.pct}%`; });
  }

  function statusPill(status) {
    return `<span class="pill pill-${esc(status)}">${esc(STATUS_LABEL[status] || status)}</span>`;
  }

  function myStatusText(t) {
    if (t.me.awaiting) return t.status === 'commit' ? 'Needs your commitment' : 'Needs your signature';
    if (t.me.signed) return 'You signed';
    if (t.me.committed) return 'You committed';
    return '';
  }

  // The groups of the queue, in the order of SPEC Q1. A row is in the first group whose test it meets.
  // The test reads `status` and `me.can_act` alone, so every signer's page agrees with the server's turn rules.
  const QUEUE_GROUPS = [
    ['commit', 'Needs your commitment', (t) => t.status === 'commit' && t.me.can_act],
    ['sign', 'Needs your signature', (t) => t.status === 'sign' && t.me.can_act],
    ['waiting', 'Waiting for others', (t) => isOpen(t) && !t.me.can_act],
    ['ready', 'Ready to broadcast', (t) => t.status === 'complete'],
  ];
  // Closed rows stay behind the filter: only the Closed and All filters let any through.
  const CLOSED_GROUP = ['closed', 'Closed', (t) => t.status === 'broadcast' || t.status === 'cancelled'];

  function drawList(keepFocus = false) {
    const view = $('#view');
    if (!view) return;
    const refocus = keepFocus ? focusSelector() : '';
    const counts = {
      awaiting: S.txs.filter((t) => t.me.awaiting).length,
      active: S.txs.filter(isOpen).length,
      complete: S.txs.filter((t) => t.status === 'complete').length,
      done: S.txs.filter((t) => t.status === 'broadcast' && (Date.now() - parseTs(t.closed_at)) < 30 * 86400000).length,
    };
    const filters = {
      queue: (t) => isOpen(t) || t.status === 'complete',
      awaiting: (t) => t.me.awaiting,
      active: isOpen,
      complete: (t) => t.status === 'complete',
      closed: CLOSED_GROUP[2],
      all: () => true,
    };
    const q = S.search.toLowerCase();
    const list = S.txs.filter(filters[S.filter] || filters.queue).filter((t) => !q
      || [t.title, t.wallet?.name, t.created_by, t.ergo_tx_id, `#${t.id}`].some((v) => (v || '').toLowerCase().includes(q)));
    const groups = [...QUEUE_GROUPS, CLOSED_GROUP]
      .map(([key, title, test]) => [key, title, list.filter(test)])
      .filter(([, , rows]) => rows.length);

    const stat = (key, value, label, attention) => `
      <button type="button" class="stat ${attention && value ? 'attention' : ''}" data-filter="${key}" aria-pressed="${S.filter === key}">
        <div class="stat-value">${value}</div><div class="stat-label">${label}</div>
      </button>`;

    const searchValue = $('#tx-search')?.value ?? S.search;
    view.innerHTML = `
      <div class="stats">
        ${stat('awaiting', counts.awaiting, 'Waiting on you', true)}
        ${stat('active', counts.active, 'In progress')}
        ${stat('complete', counts.complete, 'Ready to broadcast')}
        ${stat('closed', counts.done, 'Broadcast (30 days)')}
      </div>
      <div class="toolbar">
        <input type="search" id="tx-search" placeholder="Search title, wallet, creator, TX ID…" value="${esc(searchValue)}" aria-label="Search transactions">
        <span class="spacer"></span>
        <select id="tx-filter" aria-label="Filter">
          ${[['queue', 'Queue'], ['active', 'In progress'], ['awaiting', 'Waiting on you'], ['complete', 'Ready to broadcast'], ['closed', 'Closed'], ['all', 'All']]
            .map(([v, l]) => `<option value="${v}" ${S.filter === v ? 'selected' : ''}>${l}</option>`).join('')}
        </select>
        <a class="btn btn-primary" href="#start">Start transaction</a>
      </div>
      ${selectionBarHtml()}
      ${groups.length ? groups.map(([key, title, rows]) => `
        <section class="group" data-group="${key}" aria-labelledby="group-${key}">
          ${S.runWallet && rows.some(selectable) ? `<div class="group-head">${groupHeading(key, title, rows.length)}
            <button type="button" class="btn btn-sm" data-select-all="${key}" aria-label="Select all in ${esc(title)}">Select all</button></div>`
            : groupHeading(key, title, rows.length)}
          <div class="cards">${rows.map((t) => (S.runWallet ? pickRow(t) : card(t, true, false))).join('')}</div>
        </section>`).join('') : `
        <div class="empty" data-queue="empty">${S.txs.length ? 'Nothing matches this filter.' : 'No transactions for your wallets yet. They appear here when someone starts one for a multi-sig wallet one of your addresses signs for.'}</div>`}`;

    paintBars(view);
    updateTabCount();
    // The focus returns without a scroll: a list refresh must not move the page (Q9).
    if (keepFocus && refocus) $(refocus)?.focus({ preventScroll: true });
    $('#tx-search').addEventListener('input', (ev) => { S.search = ev.target.value; drawList(true); placeCaret(); });
    $('#tx-filter').addEventListener('change', (ev) => { S.filter = ev.target.value; drawList(); });
  }

  function placeCaret() {
    const el = $('#tx-search');
    if (!el) return;
    el.focus();
    el.setSelectionRange(el.value.length, el.value.length);
  }

  const groupHeading = (key, title, count) => `
    <h2 class="group-title" id="group-${key}"><span data-group-title>${title}</span> <span class="group-count" data-group-count>${count}</span></h2>`;

  // `showTurn` is false inside a group: the heading already says what the signer owes.
  // `why` is the reason a row cannot be picked for a run. It stands in for the two lines that say the same.
  function card(t, showWallet = true, showTurn = true, why = '') {
    const mine = myStatusText(t);
    return `
      <a class="card ${t.me.awaiting ? 'attention' : ''}" href="#tx/${t.id}">
        ${showTurn && t.me.awaiting ? `<span class="your-turn">${esc(mine)}</span>` : ''}
        <div class="card-head">
          <div class="grow">
            <div class="card-title">${esc(t.title)}</div>
            <div class="card-sub">#${t.id}${showWallet ? ` · ${t.wallet ? esc(walletName(t.wallet)) : 'No wallet'}` : ''} · ${esc(versionLabel(t.minotaur_version))}</div>
          </div>
          ${statusPill(t.status)}
        </div>
        ${isOpen(t) || t.status === 'complete' ? progressBars(t) : ''}
        ${t.lock ? `<div><span class="pill pill-lock">Locked by ${esc(t.lock.mine ? 'you' : t.lock.name)} · ${timeTag(t.lock.since)}</span></div>` : ''}
        ${why ? `<div class="why" data-why>${esc(why)}</div>` : ''}
        <div class="card-foot">
          <span>By ${esc(t.created_by)} · ${timeTag(t.created_at)}</span>
          <span>Updated ${timeTag(t.updated_at)}</span>
          ${t.comments ? `<span>${t.comments} comment${t.comments > 1 ? 's' : ''}</span>` : ''}
          ${!t.me.awaiting && mine && !why ? `<span class="tick">${esc(mine)}</span>` : ''}
          ${!why && t.status === 'sign' && !t.me.committed ? '<span class="muted">Commitments are closed, so you cannot sign</span>' : ''}
        </div>
      </a>`;
  }

  // ------------------------------------------------------------------------
  // Pick rows for a run (SPEC Q4, Q9, B1, B2)
  // ------------------------------------------------------------------------
  const RUN_MAX = 20; // B2: one wallet call holds at most 20 items
  const GROUPS = [...QUEUE_GROUPS, CLOSED_GROUP];
  const groupOf = (t) => GROUPS.find(([, , test]) => test(t))?.[0];
  const groupLabel = (key) => GROUPS.find(([k]) => k === key)?.[1] || '';
  // The server's turn rule (`me.can_act`) and the lock decide, as section 2 of queue-patterns.md has it.
  const selectable = (t) => !!t.me.can_act && !(t.lock && !t.lock.mine);

  // Why a row cannot be picked, as plain text, or '' when it can.
  function whyNot(t) {
    if (selectable(t)) return '';
    if (t.me.can_act) return `${t.lock.name || 'A co-signer'} holds the lock, taken ${ago(t.lock.since)}.`;
    if (t.status === 'commit') return t.me.committed ? 'You committed. Waiting for others.' : 'None of your keys has an open commitment slot.';
    if (t.status === 'sign') return t.me.signed ? 'You signed.' : 'Commitments are closed, so you cannot sign.';
    return t.status === 'complete' ? 'Nothing left to sign.' : 'This transaction is closed.';
  }

  function clearSelection() {
    S.selection.clear();
    S.acks.clear();
    S.selGroup = '';
  }

  function resetRun() {
    S.runWallet = null;
    S.selNotes = [];
    clearSelection();
  }

  // Run actions need a wallet that passes three checks (SPEC B1, Q7). The origin already allows it: the page
  // opens no connect window of its own. Its context has `multisig` as an own property, with version 1: the
  // context is frozen but its prototype is not, so a plain read could find a `multisig` any script added there.
  // One of its addresses belongs to the signed-in account. Any failure of the wallet reads as "no".
  async function findRunWallet() {
    const wallet = nautilusConnector();
    if (!wallet) return null;
    try {
      if (!(await wallet.isAuthorized()) || !(await wallet.connect({ createErgoObject: false }))) return null;
      const ctx = await wallet.getContext();
      if (!Object.hasOwn(ctx, 'multisig') || ctx.multisig?.version !== 1) return null;
      const lists = await Promise.all([ctx.get_used_addresses(), ctx.get_unused_addresses()]);
      const mine = S.me?.addresses || [];
      return lists.flat().some((a) => mine.includes(a)) ? ctx : null;
    } catch (e) {
      return null;
    }
  }

  // Draws the list again only when the answer changes whether run actions show.
  async function checkRunWallet(live) {
    const ctx = await findRunWallet();
    if (!live()) return;
    const changed = !!ctx !== !!S.runWallet;
    S.runWallet = ctx;
    if (changed) drawList(true);
  }

  // A selector that finds the focused control of the list again after the list is drawn anew (Q9).
  function focusSelector() {
    const el = document.activeElement;
    if (!el || !$('#view')?.contains(el)) return '';
    for (const attr of ['id', 'data-select', 'data-select-all', 'data-clear-selection', 'data-filter', 'href']) {
      const value = el.getAttribute(attr);
      if (value) return attr === 'id' ? `#${CSS.escape(value)}` : `[${attr}="${CSS.escape(value)}"]`;
    }
    return '';
  }

  // Drops the rows that a list answer made unselectable, and says why. Runs when a list answer is kept.
  function reconcileSelection() {
    for (const id of [...S.selection]) {
      const t = S.txs.find((x) => x.id === id);
      const why = !t ? 'It is no longer in your queue.' : whyNot(t) || (groupOf(t) === S.selGroup ? '' : 'It moved to another group.');
      if (!why) continue;
      S.selection.delete(id);
      S.acks.delete(id);
      S.selNotes.push(`#${id}${t ? ` ${t.title}` : ''} left your selection. ${why}`);
    }
    if (!S.selection.size) S.selGroup = '';
  }

  function pick(id, on) {
    const t = S.txs.find((x) => x.id === id);
    S.selNotes = [];
    if (!t || whyNot(t)) return drawList(true);
    if (!on) {
      S.selection.delete(id);
      S.acks.delete(id);
    } else {
      const group = groupOf(t);
      if (S.selection.size && S.selGroup !== group) {
        clearSelection();
        S.selNotes.push(`Started a new selection in ${groupLabel(group)}. A run covers one group.`);
      }
      if (S.selection.size >= RUN_MAX) {
        S.selNotes.push(`A run holds at most ${RUN_MAX} transactions. Clear one before you add #${id}.`);
      } else {
        S.selection.add(id);
        S.selGroup = group;
      }
    }
    if (!S.selection.size) S.selGroup = '';
    drawList(true);
  }

  // "Select all" takes the selectable rows the list shows for the group, up to the cap.
  function pickAll(group) {
    const ids = $$(`[data-group="${group}"] [data-select]`).map((el) => Number(el.dataset.select));
    clearSelection();
    S.selNotes = [];
    S.selection = new Set(ids.slice(0, RUN_MAX));
    S.selGroup = ids.length ? group : '';
    if (ids.length > RUN_MAX) S.selNotes.push(`Selected the first ${RUN_MAX} of ${ids.length}. A run holds at most ${RUN_MAX} transactions.`);
    drawList(true);
  }

  const selNotesHtml = (attr) =>
    S.selNotes.length ? `<ul class="select-notes" ${attr}>${S.selNotes.map((m) => `<li>${esc(m)}</li>`).join('')}</ul>` : '';

  function selectionBarHtml() {
    const n = S.selection.size;
    if (!n && !S.selNotes.length) return '';
    return `
      <section class="selection-bar" data-selection aria-label="Selection">
        ${n && S.runWallet ? `<strong data-select-count>${n} selected</strong> <span class="muted">in ${esc(groupLabel(S.selGroup))}</span>
          <span class="spacer"></span>
          <a class="btn btn-primary btn-sm" href="#review">Review</a>
          <button type="button" class="btn btn-sm" data-clear-selection="1">Clear</button>` : ''}
        ${n && !S.runWallet ? `<p class="muted" data-wallet-away>Your wallet is not available, so run actions are hidden. Your selection of ${n} stays.</p>` : ''}
        ${selNotesHtml('data-select-note')}
      </section>`;
  }

  // The checkbox sits outside the card: a control inside a link is not valid markup.
  function pickRow(t) {
    const why = whyNot(t);
    const on = S.selection.has(t.id);
    return `
      <div class="card-row ${on ? 'selected' : ''}">
        <span class="pick">${why ? '' : `<input type="checkbox" data-select="${t.id}" ${on ? 'checked' : ''} aria-label="Select #${t.id} ${esc(t.title)}">`}</span>
        ${card(t, true, false, why)}
      </div>`;
  }

  // ------------------------------------------------------------------------
  // Review before a run (SPEC Q5)
  // ------------------------------------------------------------------------
  // The review reads the newest list first, so an id that the list no longer holds never gets an item. A fetch
  // started here also makes an older list answer that is still on its way drop itself (listSeq).
  async function renderReview() {
    const live = viewGuard();
    const view = shell('sign');
    const back = '<a class="back" href="#">← Back to the queue</a>';
    if (S.selection.size) {
      view.innerHTML = '<div class="loading">Loading the review…</div>';
      try { await fetchList(); } catch (e) { if (live()) view.innerHTML = back + loadError(e.message); return; }
      if (!live()) return;
    }
    const ids = [...S.selection];
    if (!ids.length) {
      view.innerHTML = `${back}
        <div class="empty" data-review-empty>Nothing is selected. Pick transactions in the queue to review them.</div>
        ${selNotesHtml('data-review-note')}`;
      return;
    }
    const items = await Promise.all(ids.map(async (id) => {
      try { return { id, t: (await api('get_transaction', { id })).transaction }; } catch (e) { return { id, error: e.message }; }
    }));
    if (live()) drawReview(items);
  }

  function drawReview(items) {
    const view = $('#view');
    if (!view) return;
    // A tick holds for the reading the signer saw. Boxes can change with the Ergo transaction id the same, so compare all of the decoded view.
    S.readings = new Map(items.filter((i) => i.t).map((i) => [i.id, JSON.stringify([i.t.review, i.t.ergo_tx_id])]));
    for (const [id, seen] of S.acks) if (S.readings.has(id) && S.readings.get(id) !== seen) S.acks.delete(id);
    view.innerHTML = `
      <a class="back" href="#">← Back to the queue</a>
      <h1>Review ${items.length} transaction${items.length === 1 ? '' : 's'}</h1>
      <p class="muted">${esc(groupLabel(S.selGroup))}. Decoded by Sigma Sync from each request. Your wallet shows its own review of every item.
        Your selection stays in the queue.</p>
      ${selNotesHtml('data-review-note')}
      <div class="stack" data-review-list>${items.map(reviewItemHtml).join('')}</div>
      <div class="row mt-16">
        <a class="btn" href="#">Back to the queue</a>
        ${items.some((i) => i.error) ? '<button type="button" class="btn" data-retry>Try again</button>' : ''}
      </div>`;
    fillTokenNames(view);
  }

  // What makes an item need its own tick (Q5): the server's doubts about its reading, and a payment to a contract.
  function reviewFlags(t) {
    const r = t.review;
    if (!r) return [['No decoded view', 'Sigma Sync has no decoded view of this transaction.']];
    const flags = [];
    if (r.inputs_unverified) flags.push(['unverified', 'Inputs unverified', 'The input boxes of this request do not match the inputs it spends, so no amount is cross-checked.']);
    if (r.outputs_partial) flags.push(['partial', 'Outputs partial', 'Sigma Sync could not read every output.']);
    if (r.outputs_uncertain) flags.push(['uncertain', 'Outputs uncertain', 'Some outputs pay to contracts Sigma Sync cannot read fully, or could not be cross-checked against the inputs.']);
    else if ((r.outputs || []).some((o) => o.is_contract)) flags.push(['contract', 'Pays to a smart contract', 'Check the contract in your wallet.']);
    return flags;
  }

  function reviewSendHtml(o) {
    return `
      <div class="send" data-review-send>
        <div class="send-amount">${esc(erg(o.value))}</div>
        ${(o.tokens || []).map((tk) => `<div class="token-line">${tokenHtml(tk.id, tk.amount)}</div>`).join('')}
        <div class="small muted mt-8">to ${o.to_input_address ? '<span class="tag">same address it spends from</span>'
          : o.is_multisig ? '<span class="tag">multi-sig address</span>'
          : o.is_contract ? '<span class="tag">smart contract</span>' : ''}</div>
        <div class="mono anywhere" data-review-to>${esc(o.address)}</div>
      </div>`;
  }

  function reviewItemHtml({ id, t, error }) {
    if (error) {
      return `<section class="panel" data-review-item="${id}"><div class="notice notice-error">Could not load #${id}: ${esc(error)}</div></section>`;
    }
    const outputs = t.review?.outputs || [];
    const sends = outputs.filter((o) => !o.is_fee && !o.is_change);
    const fee = outputs.filter((o) => o.is_fee).reduce((n, o) => n + BigInt(o.value), 0n).toString();
    const flags = reviewFlags(t);
    const gone = whyNot(t);
    return `
      <section class="panel" data-review-item="${id}" aria-labelledby="review-${id}">
        <div class="card-head">
          <div class="grow">
            <h2 id="review-${id}"><a class="row-link" href="#tx/${id}">${esc(t.title)}</a></h2>
            <div class="meta">
              <span>#${id}</span>
              <span data-review-wallet>${t.wallet ? esc(walletName(t.wallet)) : 'No wallet'}</span>
              <span data-review-m>${esc(t.signers_required)} of ${esc(t.signers_total)} signatures</span>
            </div>
          </div>
          ${statusPill(t.status)}
        </div>
        ${gone ? `<div class="notice notice-error small mt-12" data-review-gone>It cannot be run now. ${esc(gone)}</div>` : ''}
        <h3 class="mt-16">Pays</h3>
        ${!outputs.length ? '<p class="small muted">Sigma Sync could not read the outputs.</p>'
          : sends.length ? sends.map(reviewSendHtml).join('') : '<p class="small muted">Nothing leaves the wallet except the fee.</p>'}
        <dl class="kv mt-12"><dt>Network fee</dt><dd data-review-fee>${outputs.length ? esc(erg(fee)) : 'Unknown'}</dd></dl>
        ${t.ergo_tx_id ? `<p class="small mt-12">Ergo transaction ID <code class="anywhere" data-review-txid>${esc(t.ergo_tx_id)}</code></p>` : ''}
        ${flags.length ? `
          <div class="notice notice-warning mt-12" data-review-flags>
            <ul class="flags">${flags.map(([key, label, text]) => `<li data-flag="${esc(key)}"><strong>${esc(label)}.</strong> ${esc(text)}</li>`).join('')}</ul>
            <label class="check mt-8"><input type="checkbox" data-ack="${id}" ${S.acks.has(id) ? 'checked' : ''}>
              I have read ${flags.length > 1 ? 'these warnings' : 'this warning'} for #${id}.</label>
          </div>` : ''}
      </section>`;
  }

  // ------------------------------------------------------------------------
  // Start transaction
  // ------------------------------------------------------------------------
  async function renderStart() {
    const view = shell('start');
    view.innerHTML = `
      <div class="detail">
        <form class="panel" id="start-form" novalidate>
          <div class="panel-title"><h2>Start a multi-sig transaction</h2></div>
          <p class="muted small">Create the transaction in your Minotaur multi-sig wallet, press <strong>Commit</strong>,
          then copy the request and paste it below. Your fellow signers will see it under <em>Sign Transactions</em>.</p>
          <div class="field">
            <label for="f-title">Transaction name</label>
            <input type="text" id="f-title" maxlength="120" required placeholder="e.g. October hosting & meetup expenses">
          </div>
          <div class="field-row">
            <div>
              <label for="f-wallet">Multi-sig wallet <span class="faint">(optional)</span></label>
              <input type="text" id="f-wallet" maxlength="80" list="wallet-names" placeholder="e.g. Sigmanauts Treasury 2.0">
              <datalist id="wallet-names">${S.wallets.map((w) => `<option value="${esc(w)}">`).join('')}</datalist>
            </div>
            <div>
              <label for="f-version">Minotaur version</label>
              <select id="f-version" required><option value="">Loading releases…</option></select>
              <p class="hint" id="version-hint"></p>
            </div>
            <div>
              <label for="f-required">Signatures required</label>
              <input type="number" id="f-required" min="1" max="50" required placeholder="M of N">
              <p class="hint" id="required-hint">Filled in from the request when detected.</p>
            </div>
          </div>
          <div class="field">
            <label for="f-desc">What is this transaction for?</label>
            <textarea id="f-desc" maxlength="10000" rows="5" placeholder="Who is being paid, for what, amounts, links to the vote or invoice…"></textarea>
          </div>
          <div class="field">
            <label for="f-payload">Multi-sig request from Minotaur (usually with your commitment)</label>
            <textarea class="payload" id="f-payload" required autocomplete="off" autocapitalize="off" autocorrect="off"
              spellcheck="false" placeholder='{"MSR":"{\\"tx\\":\\"…"}'></textarea>
            <div class="row mt-8"><button type="button" class="btn btn-sm" id="f-scan">Scan QR</button>
              <span class="hint">Pasted exactly as-is. Line breaks and invisible characters are removed automatically.</span></div>
          </div>
          <div id="f-analysis" class="field" hidden></div>
          <div class="field">
            <label for="f-comment">Note to signers <span class="faint">(optional)</span></label>
            <textarea id="f-comment" maxlength="4000" rows="2"></textarea>
          </div>
          <div id="f-error"></div>
          <div class="row mt-16"><span class="spacer"></span>
            <button class="btn btn-primary" type="submit">Start transaction</button></div>
        </form>
        <aside class="panel detail-side">
          <h3>How the rounds work</h3>
          <ol class="howto small">
            <li><strong>Commitment round</strong> - each signer locks the transaction, copies the latest request into Minotaur,
            commits, and pastes the new request back. Needs M commitments.</li>
            <li><strong>Signing round</strong> - the same signers take turns again, this time pressing Sign.</li>
            <li><strong>Broadcast</strong> - the final signer's output is the complete transaction; anyone can publish it from Minotaur.</li>
          </ol>
          <p class="small muted">Sigma Sync checks every paste: it must be the same transaction, keep every earlier
          commitment, and add yours. Only one signer works at a time (the lock), so nobody's work is overwritten.</p>
        </aside>
      </div>`;

    fillVersions($('#f-version'), $('#version-hint'));    // fills in when GitHub answers

    let timer;
    $('#f-payload').addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => analyzeInto($('#f-payload').value, $('#f-analysis'), null, (a) => {
        if (a.valid && a.required) {
          $('#f-required').value = a.required;
          $('#required-hint').textContent = `This wallet needs ${a.required} of ${a.signers} signatures.`;
        }
      }), 350);
    });
    $('#f-scan').onclick = async () => {
      const text = await scanQr();
      if (text) { $('#f-payload').value = text; $('#f-payload').dispatchEvent(new Event('input')); }
    };

    $('#start-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const btn = $('button[type=submit]', ev.target);
      btn.disabled = true;
      $('#f-error').innerHTML = '';
      try {
        const r = await api('create_transaction', {
          title: $('#f-title').value,
          wallet_name: $('#f-wallet').value,
          minotaur_version: $('#f-version').value,
          signers_required: $('#f-required').value,
          description: $('#f-desc').value,
          payload: cleanPayload($('#f-payload').value),
          comment: $('#f-comment').value,
        });
        toast('Transaction started - your signers can see it now', 'success');
        S.txs = [];
        location.hash = `#tx/${r.id}`;
      } catch (e) {
        btn.disabled = false;
        $('#f-error').innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`;
      }
    });
  }

  // Fills a <select> with Minotaur releases; returns false if the view is gone.
  async function fillVersions(sel, hintEl) {
    const versions = await loadVersions();
    if (!sel || !document.body.contains(sel)) return false;
    const stable = versions.filter((v) => !v.pre);
    const pre = versions.filter((v) => v.pre);
    const opt = (v, i) => `<option value="${esc(v.tag)}" ${i === 0 && !v.pre ? 'selected' : ''}>${esc(v.tag)}${i === 0 && !v.pre ? ' (latest)' : ''}${v.date ? ` - ${esc(v.date)}` : ''}</option>`;
    sel.innerHTML = `
      <optgroup label="Releases">${stable.map(opt).join('')}</optgroup>
      ${pre.length ? `<optgroup label="Pre-releases">${pre.map((v) => opt(v, 1)).join('')}</optgroup>` : ''}`;
    const hint = () => {
      const v = sel.value;
      hintEl.innerHTML = v
        ? `Every signer should use this version. <a href="${esc(releaseUrl(v))}" target="_blank" rel="noopener">Release notes</a>`
        : '';
      if (versions.offline) hintEl.insertAdjacentHTML('beforeend', ' (GitHub unreachable - showing known versions)');
    };
    sel.addEventListener('change', hint);
    hint();
    return true;
  }

  // ------------------------------------------------------------------------
  // Start batch: many requests at once
  // ------------------------------------------------------------------------
  async function renderBatch() {
    const view = shell('batch');
    view.innerHTML = `
      <div class="detail">
        <form class="panel" id="batch-form" novalidate>
          <div class="panel-title"><h2>Start a batch of transactions</h2></div>
          <p class="muted small">Paste or upload many requests at once - one JSON request after another, or a JSON array.
          Cold signing requests (<code>{"CSR":…}</code>, nobody committed yet) and multi-sig requests (<code>{"MSR":…}</code>,
          with or without commitments already in it) both work. Each becomes its own transaction, named after the batch.</p>
          <div class="field-row">
            <div>
              <label for="b-name">Batch name</label>
              <input type="text" id="b-name" maxlength="100" required placeholder="e.g. Rosen TX Cleanup">
              <p class="hint" id="b-name-hint">Transactions are named "Batch name 1", "Batch name 2", …</p>
            </div>
            <div>
              <label for="b-wallet">Multi-sig wallet <span class="faint">(optional)</span></label>
              <input type="text" id="b-wallet" maxlength="80" list="b-wallet-names" placeholder="e.g. Rosen Guard">
              <datalist id="b-wallet-names">${S.wallets.map((w) => `<option value="${esc(w)}">`).join('')}</datalist>
            </div>
            <div>
              <label for="b-version">Minotaur version</label>
              <select id="b-version" required><option value="">Loading releases…</option></select>
              <p class="hint" id="b-version-hint"></p>
            </div>
          </div>
          <div class="field">
            <label for="b-desc">What are these transactions for? <span class="faint">(shown on every one)</span></label>
            <textarea id="b-desc" maxlength="10000" rows="4"></textarea>
          </div>
          <div class="field">
            <label for="b-items">Requests</label>
            <textarea class="payload" id="b-items" required autocomplete="off" autocapitalize="off" autocorrect="off"
              spellcheck="false" placeholder='{"CSR":"…"}&#10;{"CSR":"…"}&#10;…'></textarea>
            <div class="row mt-8">
              <label class="btn btn-sm" for="b-file">Upload file(s)</label>
              <input type="file" id="b-file" accept=".json,.txt,application/json,text/plain" multiple hidden>
              <span class="hint" id="b-file-hint">.json or .txt - their contents are added to the box above.</span>
            </div>
          </div>
          <div class="field">
            <label for="b-comment">Note to signers <span class="faint">(optional, added to every transaction)</span></label>
            <textarea id="b-comment" maxlength="4000" rows="2"></textarea>
          </div>
          <div id="b-error"></div>
          <div class="row mt-16"><span class="spacer"></span>
            <button class="btn btn-primary" type="submit">Check batch</button></div>
        </form>
        <aside class="panel detail-side">
          <h3>How batches work</h3>
          <ol class="howto small">
            <li><strong>Check</strong> reads every request, shows what each one sends, and flags problems (duplicates,
            transactions already tracked, wallets you do not sign for) before anything is created.</li>
            <li><strong>Start</strong> creates one transaction per valid request. They appear under Sign Transactions
            for every signer of the wallet.</li>
            <li>Signers take them one at a time as usual; after each submit, <strong>Next in batch</strong> jumps
            to the next one waiting for them.</li>
          </ol>
          <p class="small muted">For a CSR, the first committer opens it with Minotaur's <strong>home-screen</strong>
          scanner (or paste there): Minotaur files it under the multi-sig wallet, where they press Commit.</p>
        </aside>
      </div>
      <section class="panel mt-16" id="b-preview" hidden></section>`;

    fillVersions($('#b-version'), $('#b-version-hint'));    // fills in when GitHub answers

    $('#b-name').addEventListener('input', () => {
      const n = $('#b-name').value.trim() || 'Batch name';
      $('#b-name-hint').textContent = `Transactions are named "${n} 1", "${n} 2", …`;
    });

    $('#b-file').addEventListener('change', async (ev) => {
      const files = Array.from(ev.target.files || []);
      if (!files.length) return;
      const texts = await Promise.all(files.map((f) => f.text()));
      const box = $('#b-items');
      box.value = [box.value.trim(), ...texts.map((t) => t.trim())].filter(Boolean).join('\n');
      $('#b-file-hint').textContent = `Added ${files.length} file${files.length === 1 ? '' : 's'}.`;
      ev.target.value = '';
    });

    const params = () => ({
      name: $('#b-name').value, wallet_name: $('#b-wallet').value, minotaur_version: $('#b-version').value,
      description: $('#b-desc').value, comment: $('#b-comment').value, items: $('#b-items').value,
    });

    $('#batch-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const btn = $('button[type=submit]', ev.target);
      btn.disabled = true;
      btn.textContent = 'Checking…';
      $('#b-error').innerHTML = '';
      try {
        const r = await api('batch_preview', params());
        drawBatchPreview(r, params);
      } catch (e) {
        $('#b-error').innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`;
      } finally {
        btn.disabled = false;
        btn.textContent = 'Check batch';
      }
    });
  }

  function drawBatchPreview(r, params) {
    const box = $('#b-preview');
    const name = $('#b-name').value.trim() || 'Batch';
    const bad = r.items.length - r.ok;
    box.hidden = false;
    box.innerHTML = `
      <div class="panel-title"><h2>Check result</h2>
        <span class="faint small">${r.ok} of ${r.items.length} ready${bad ? ` · ${bad} with problems` : ''}</span></div>
      <div class="table-wrap"><table class="list">
        <thead><tr><th>#</th><th>Will be named</th><th>Request</th><th>Sends</th><th>Ergo TX</th><th>Status</th></tr></thead>
        <tbody>${r.items.map((it) => {
          const nm = it.ok ? `${name} ${it.seq}` : '';
          const sends = it.sends
            ? (it.decoded ? `${esc(erg(it.sends.value))}${it.sends.tokens ? ` + ${it.sends.tokens} token type${it.sends.tokens === 1 ? '' : 's'}` : ''}
                <div class="small faint">${it.sends.outputs} output${it.sends.outputs === 1 ? '' : 's'}${it.sends.to.length
                  ? ` · to ${it.sends.to.slice(0, 2).map((a) => `<code>${esc(shortAddr(a))}</code>`).join(', ')}${it.sends.to.length > 2 ? '…' : ''}` : ''}</div>`
              : '<span class="faint">could not decode</span>')
            : '';
          return `<tr class="${it.ok ? '' : 'inactive'}">
            <td>${it.index}</td>
            <td>${esc(nm)}</td>
            <td>${it.format ? `${esc(it.format)}${it.required ? ` · ${it.required}-of-${it.signers}` : ''}${it.format === 'MSR' ? ` · ${it.committed} committed` : ''}` : ''}</td>
            <td>${sends}</td>
            <td>${it.tx_id ? `<code title="${esc(it.tx_id)}">${esc(shortId(it.tx_id))}</code>` : ''}</td>
            <td>${it.ok ? `<span class="tick">✓ Ready</span>${it.after ? `<div class="small muted">after entr${it.after.length === 1 ? 'y' : 'ies'}
              ${it.after.join(', ')} - spends ${it.after.length === 1 ? 'its' : 'their'} output</div>` : ''}`
              : `<span class="small error-text">${esc(it.error)}</span>${it.tracked ? ` <a href="#tx/${it.tracked}">open</a>` : ''}`}</td>
          </tr>`;
        }).join('')}</tbody>
      </table></div>
      ${r.ok ? `<div class="row mt-16">
          <span class="small muted">${bad ? `${bad} entr${bad === 1 ? 'y' : 'ies'} with problems will be skipped.` : 'Everything checks out.'}</span>
          <span class="spacer"></span>
          <button type="button" class="btn btn-primary" id="b-create">Start ${r.ok} transaction${r.ok === 1 ? '' : 's'}</button>
        </div>` : '<p class="small muted mt-12">Nothing to start - fix the problems above and check again.</p>'}`;
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });

    const create = $('#b-create');
    if (!create) return;
    create.addEventListener('click', async () => {
      if (!$('#b-name').value.trim()) { toast('Give the batch a name', 'error'); $('#b-name').focus(); return; }
      if (bad && !(await dialog({
        title: `Start ${r.ok} of ${r.items.length}?`,
        body: `${bad} entr${bad === 1 ? 'y has' : 'ies have'} problems and will be skipped.`,
        confirm: `Start ${r.ok}`,
      }))) return;
      create.disabled = true;
      create.textContent = 'Starting…';
      try {
        const res = await api('create_batch', { ...params(), skip_invalid: bad ? 1 : 0 });
        toast(`Started ${res.created.length} transactions`, 'success');
        S.txs = [];
        S.search = $('#b-name').value.trim();
        S.filter = 'active';
        location.hash = '';
      } catch (e) {
        create.disabled = false;
        create.textContent = `Start ${r.ok} transaction${r.ok === 1 ? '' : 's'}`;
        toast(e.message, 'error');
      }
    });
  }

  // Calls the server-side analyzer and renders what it found.
  async function analyzeInto(text, el, txId, onResult) {
    const payload = cleanPayload(text);
    if (!payload) { el.hidden = true; return null; }
    let a;
    try {
      a = (await api('analyze', { payload, id: txId || undefined })).analysis;
    } catch (e) {
      el.hidden = false;
      el.innerHTML = `<div class="analysis bad">${esc(e.message)}</div>`;
      return null;
    }
    el.hidden = false;
    const items = [];
    if (!txId && a.valid && a.format === 'MSR' && a.is_signer !== undefined) {
      if (!a.is_signer) a.problem = 'None of your addresses is a signer of this multi-sig wallet. Link the address you sign with on the Account tab.';
    }
    const bad = !a.valid || !!a.problem;
    if (a.format === 'MSR') {
      items.push(`Minotaur multi-sig request${a.required ? ` · ${a.required}-of-${a.signers} wallet` : ''}`);
      items.push(`${a.committed} commitment${a.committed === 1 ? '' : 's'}, ${a.signed} signature${a.signed === 1 ? '' : 's'}`);
      if (a.compare) {
        const c = a.compare;
        if (c.new_commits) items.push(`<strong>+${c.new_commits} new commitment</strong>`);
        if (c.new_signatures) items.push(`<strong>+${c.new_signatures} new signature</strong>`);
        items.push('Keeps every earlier commitment and signature');
      }
    } else if (a.format === 'CSR') {
      items.push(`Unsigned cold signing request${a.required ? ` · ${a.required}-of-${a.signers} wallet` : ''} · no commitments yet`);
    } else if (a.format === 'CSTX') {
      items.push('<strong>Fully signed transaction</strong> - ready to broadcast');
    }
    if (a.tx_id) items.push(`Ergo TX ID <code>${esc(shortId(a.tx_id))}</code>${txId && !a.problem ? ' · matches this transaction' : ''}`);
    if (a.outputs?.length) {
      const sends = a.outputs.filter((o) => !o.is_fee && !o.is_change);
      if (sends.length) items.push(`Sends ${sends.map((o) => `${esc(erg(o.value))} to <code>${esc(shortAddr(o.address))}</code>`).join(', ')}`);
    }
    const problem = a.problem || a.error;
    el.innerHTML = `<div class="analysis ${bad ? 'bad' : 'ok'}">
      ${problem ? `<strong>${esc(problem)}</strong>` : ''}
      ${a.warning ? `<div>${esc(a.warning)}</div>` : ''}
      ${items.length ? `<ul>${items.map((i) => `<li>${i}</li>`).join('')}</ul>` : ''}
    </div>`;
    if (onResult) onResult(a);
    return a;
  }

  // ------------------------------------------------------------------------
  // Transaction detail
  // ------------------------------------------------------------------------
  async function renderDetail(id) {
    const live = viewGuard();
    const view = shell('sign');
    view.innerHTML = '<div class="loading">Loading…</div>';
    try {
      const r = await api('get_transaction', { id });
      if (!live()) return;
      S.detail = r.transaction;
    } catch (e) {
      if (live()) view.innerHTML = `<a class="back" href="#">← All transactions</a>${loadError(e.message)}`;
      return;
    }
    drawDetail();
    // Refresh while someone else holds the lock or it is idle; never while you are mid-turn. An answer is
    // dropped when the route has changed or when a newer answer (a lock, a submit) set the transaction meanwhile.
    poll(async () => {
      if (S.detail?.lock?.mine || dirtyDetail()) return;
      const seen = S.detail;
      const r = await api('get_transaction', { id });
      if (!live() || S.detail !== seen) return;
      S.detail = r.transaction;
      drawDetail();
    }, 12000);
  }

  function dirtyDetail() {
    return ['#comment-body'].some((sel) => ($(sel)?.value || '').trim() !== '');
  }

  function drawDetail(flash) {
    stopQrTimers();
    const t = S.detail;
    const view = $('#view');
    if (!view || !t) return;
    const explorer = t.ergo_tx_id ? `${S.config.explorer_tx_url || ''}${t.ergo_tx_id}` : '';
    view.innerHTML = `
      <a class="back" href="#">← All transactions</a>
      <div class="detail-head">
        <div class="grow">
          <div class="row">${statusPill(t.status)}${t.lock ? `<span class="pill pill-lock">Locked by ${esc(t.lock.mine ? 'you' : t.lock.name)}</span>` : ''}</div>
          <h1 class="mt-8">${esc(t.title)}</h1>
          <div class="meta">
            <span>#${t.id}</span>
            ${t.batch ? `<span class="tag">Batch item ${t.batch.seq} of ${t.batch.count}</span>` : ''}
            <span>${t.wallet ? `<a class="row-link" href="#wallet/${esc(t.wallet.id)}">${esc(walletName(t.wallet))}</a>` : 'No wallet'}</span>
            <span><a href="${esc(releaseUrl(t.minotaur_version))}" target="_blank" rel="noopener">${esc(versionLabel(t.minotaur_version))}</a></span>
            <span>Started by ${esc(t.created_by)} · ${timeTag(t.created_at)}</span>
            ${t.ergo_tx_id ? `<span>TX <a href="${esc(explorer)}" target="_blank" rel="noopener" class="mono">${esc(shortId(t.ergo_tx_id))}</a>
              <button type="button" class="btn btn-ghost btn-sm" data-copy="${esc(t.ergo_tx_id)}" aria-label="Copy transaction ID">Copy</button></span>` : ''}
          </div>
        </div>
      </div>
      ${flash ? `<div class="notice notice-success mb-16">${flash}</div>` : ''}
      <div class="detail">
        <div>
          <section class="panel">
            <div class="panel-title"><h2>About this transaction</h2></div>
            ${t.description ? `<div class="prewrap">${esc(t.description)}</div>` : '<p class="faint">No description.</p>'}
          </section>
          <section class="panel">
            <div class="panel-title"><h2>Progress</h2></div>
            ${progressBars(t)}
            ${signersHtml(t)}
          </section>
          <section class="panel">
            <div class="panel-title"><h2>Activity &amp; comments</h2></div>
            ${timelineHtml(t)}
            <form id="comment-form" class="field mt-16">
              <label for="comment-body">Add a comment</label>
              <textarea id="comment-body" maxlength="4000" rows="3" placeholder="Visible to every signer"></textarea>
              <div class="row mt-8"><span class="spacer"></span><button class="btn" type="submit">Post comment</button></div>
            </form>
          </section>
        </div>
        <aside class="detail-side">
          <section class="panel" id="action-panel">${actionHtml(t)}</section>
          ${t.can.cancel ? `<div class="mt-12 right">
            <button type="button" class="btn btn-sm btn-danger" data-action="cancel">Cancel transaction</button></div>` : ''}
          ${detailsHtml(t)}
        </aside>
      </div>`;
    paintBars(view);
    fillTokenNames(view);
    $$('details[data-tokens-lazy]', view).forEach((d) => d.addEventListener('toggle', () => { if (d.open) fillTokenNames(d); }));
    wireDetail(t);
  }

  // What the transaction does, decoded from the transaction itself.
  function detailsHtml(t) {
    const r = t.review;
    if (!r) return '';
    const outputs = r.outputs || [];
    const decoded = outputs.length > 0;
    const sends = outputs.filter((o) => !o.is_fee && !o.is_change);
    const fee = outputs.filter((o) => o.is_fee);
    const change = outputs.filter((o) => o.is_change);
    const sum = (list) => list.reduce((acc, o) => acc + BigInt(o.value), 0n).toString();
    const addrText = (a) => (a.length > 60 ? `${a.slice(0, 14)}…${a.slice(-10)}` : a);
    const addrLink = (a) => `<a class="addr" href="${esc((S.config.explorer_address_url || '') + a)}" target="_blank" rel="noopener" title="${esc(a)}">${esc(addrText(a))}</a>
      <button type="button" class="btn btn-ghost btn-sm" data-copy="${esc(a)}" aria-label="Copy address">Copy</button>`;
    const tokenLines = (tokens) => (tokens || []).map((tk) => `
      <div class="token-line">${tokenHtml(tk.id, tk.amount)}</div>`).join('');
    const changeTokens = change.reduce((n, o) => n + (o.tokens?.length || 0), 0);
    const inputs = r.inputs || [];
    const outputsHtml = decoded ? `
        <h3 class="mt-16">Sending</h3>
        ${sends.length ? sends.map((o) => `
          <div class="send">
            <div class="send-amount">${esc(erg(o.value))}</div>
            ${tokenLines(o.tokens)}
            <div class="small muted mt-8">to ${o.to_input_address ? '<span class="tag">same address it spends from</span>'
              : o.is_multisig ? '<span class="tag">multi-sig address</span>'
              : o.is_contract ? '<span class="tag">smart contract</span>' : ''}</div>
            <div>${addrLink(o.address)}</div>
          </div>`).join('') : '<p class="small faint">Nothing leaves the wallet except the fee.</p>'}

        <dl class="kv mt-12">
          <dt>Network fee</dt><dd>${esc(erg(sum(fee)))}</dd>
          ${change.length ? `<dt>Change back to the spending address</dt><dd>${esc(erg(sum(change)))}</dd>` : ''}
          <dt><strong>Total sent (incl. fee)</strong></dt><dd><strong>${esc(erg(sum([...sends, ...fee])))}</strong></dd>
        </dl>
        ${changeTokens ? `
          <details class="small mt-8" data-tokens-lazy>
            <summary>${changeTokens} token${changeTokens === 1 ? ' stays' : 's stay'} at the spending address</summary>
            ${change.map((o) => tokenLines(o.tokens)).join('')}
          </details>` : ''}
        ${!r.inputs_unverified && !change.length && sends.length ? `<div class="notice notice-warning small mt-8">No output goes back to the address
          being spent from. If the wallet holds more than is being sent, check where the rest goes.</div>` : ''}
` : `<div class="notice notice-warning small mt-16">Sigma Sync could not work out where this transaction
        sends funds. Check every output in Minotaur.</div>`;

    return `
      <section class="panel mt-12 tx-details" aria-labelledby="details-title">
        <h2 id="details-title">Transaction details</h2>
        <p class="small muted">Decoded from the transaction itself.</p>
        ${r.inputs_unverified ? `<div class="notice notice-warning small mt-8" data-review="unverified"><strong>Inputs unverified.</strong>
          Sigma Sync could not match this request's input boxes to the inputs the transaction spends. It shows no
          spending addresses and marks no output as change.</div>` : ''}

        ${outputsHtml}

        ${inputs.length ? `
          <h3 class="mt-16">Spending from</h3>
          ${inputs.length > 1 ? `<div class="notice notice-warning small">This spends from <strong>${inputs.length} different
            addresses</strong>. Minotaur can pick boxes from every address of the wallet - make sure that is intended.</div>` : ''}
          ${inputs.map((i) => `
            <div class="mt-8">
              <div>${addrLink(i.address)}</div>
              <div class="small muted">${esc(erg(i.value))} in ${i.boxes} box${i.boxes === 1 ? '' : 'es'}${
                i.tokens ? ` · ${i.tokens} token type${i.tokens === 1 ? '' : 's'}` : ''}</div>
            </div>`).join('')}` : ''}

        ${r.outputs_uncertain ? `<div class="notice notice-warning small mt-8">Some outputs pay to contracts Sigma Sync
          cannot read fully, and the decoded amounts could not be cross-checked against the inputs.
          Treat them as a hint and check every amount in Minotaur.</div>` : ''}
        ${r.minotaur_format ? `<p class="small faint mt-12">Request format: Minotaur ${r.minotaur_format === '3' ? '3.0 or later' : '2.x'}.</p>` : ''}

        <div class="notice notice-warning verify mt-12">Please verify this for yourself when signing on Minotaur!</div>
      </section>`;
  }

  // Token amounts are shown raw until the explorer supplies the name and decimals.
  function tokenHtml(id, amount) {
    return `<span data-token="${esc(id)}" data-amount="${esc(amount)}"><strong>${esc(amount)}</strong>
      <span class="faint">token</span> <code class="small">${esc(shortId(id))}</code></span>`;
  }

  // Formats a raw integer amount with `decimals` places, without floating point.
  function units(raw, decimals) {
    const d = Number(decimals) || 0;
    const s = String(raw).padStart(d + 1, '0');
    const whole = d ? s.slice(0, -d) : s;
    const frac = d ? s.slice(-d).replace(/0+$/, '') : '';
    return `${BigInt(whole).toLocaleString()}${frac ? '.' + frac : ''}`;
  }

  async function tokenInfo(id) {
    if (!S.tokens) {
      try { S.tokens = JSON.parse(store('sigmasync.tokens') || '{}'); } catch (e) { S.tokens = {}; }
    }
    if (S.tokens[id]) return S.tokens[id];
    const base = S.config.explorer_token_url;
    if (!base) return null;
    try {
      const res = await fetch(base + encodeURIComponent(id));
      if (!res.ok) return null;
      const j = await res.json();
      S.tokens[id] = { name: String(j.name || '').slice(0, 60), decimals: Number(j.decimals) || 0 };
      store('sigmasync.tokens', JSON.stringify(S.tokens));
      return S.tokens[id];
    } catch (e) { return null; }
  }

  // Fills in token names as text, never HTML: names come from the blockchain.
  function fillTokenNames(root) {
    $$('[data-token]', root).forEach(async (el) => {
      if (el.closest('details:not([open])')) return;
      const info = await tokenInfo(el.dataset.token);
      if (!info || !document.body.contains(el)) return;
      const amount = document.createElement('strong');
      amount.textContent = units(el.dataset.amount, info.decimals);
      const name = document.createElement('span');
      name.textContent = ` ${info.name || 'Unnamed token'} `;
      const id = document.createElement('code');
      id.className = 'small faint';
      id.textContent = shortId(el.dataset.token);
      id.title = el.dataset.token;
      el.replaceChildren(amount, name, id);
    });
  }

  // Every key of the multi-sig wallet, round by round, and who the transaction waits on (SPEC Q3).
  // A Minotaur 2.x request and a final CSTX mark no signature per key: the signing round is a count only.
  function signersHtml(t) {
    const list = t.signers || [];
    if (!list.length) return '';
    const countOnly = t.review?.minotaur_format === '2' || t.review?.format === 'CSTX';
    const initials = (name) => (name || '?').replace(/[^\p{L}\p{N}]/gu, '').slice(0, 2).toUpperCase() || '?';
    // A key's state is 0 empty, 1 committed, 2 signed, 3 not taking part (ErgoKit.pm:431).
    const commitState = (k) => (k.state === 1 || k.state === 2 ? ['Committed', true]
      : [k.state === 0 && t.status === 'commit' ? 'Not started' : 'Not taking part', false]);
    const inPlay = (k) => (k.state === 1 ? isOpen(t) : k.state === 0 && t.status === 'commit');
    const signState = (k) => (k.state === 2 ? ['Signed', true] : [inPlay(k) ? 'Not started' : 'Not taking part', false]);
    const round = (key, label, [text, done]) => `<span class="round" data-round="${key}">
      <span class="round-name">${label}</span><span class="${done ? 'tick' : 'muted'}" data-state>${text}</span></span>`;

    const who = (k) => esc(k.mine ? 'you' : k.name || shortAddr(k.address));
    const andList = (names) => (names.length > 1 ? `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}` : names[0]);
    let waiting = '';
    if (t.status === 'commit' || t.status === 'sign') {
      const commit = t.status === 'commit';
      const need = Math.max(0, t.signers_required - (commit ? t.commits : t.signatures));
      const names = countOnly && !commit ? [] : list.filter((k) => k.state === (commit ? 0 : 1)).map(who);
      const from = !names.length ? ''
        : names.length > need ? ` from any ${need > 1 ? `${need} ` : ''}of ${names.join(', ')}`
        : ` from ${andList(names)}`;
      waiting = `Waiting for ${need} more ${commit ? 'commitment' : 'signature'}${need === 1 ? '' : 's'}${from}.`;
    } else if (t.status === 'complete') {
      waiting = 'All required signatures are in. Ready to broadcast.';
    }
    return `
      <h3 class="mt-16">Signers <span class="faint small">${t.signers_required} of ${list.length} needed</span></h3>
      ${waiting ? `<p class="small" data-waiting-on>${waiting}</p>` : ''}
      ${countOnly ? `<p class="small muted" data-signers-note>This request does not say who signed, so the signing round
        is a count only: ${t.signatures} of ${t.signers_required} signatures are in.</p>` : ''}
      <ul class="people" data-signers>
        ${list.map((k) => `<li data-signer="${esc(k.slot)}">
          <span class="slot slot-${k.state}" aria-hidden="true">${esc(k.name ? initials(k.name) : k.slot + 1)}</span>
          <span class="grow">
            ${k.name ? `<strong data-signer-name>${esc(k.name)}</strong>${k.mine ? ' <span class="faint">(you)</span>' : ''}`
              : '<span class="faint" data-signer-name>Not on Sigma Sync yet</span>'}
            <div><code class="small faint" title="${esc(k.address)}">${esc(shortAddr(k.address))}</code></div>
          </span>
          <span class="rounds small">
            ${round('commit', 'Commitment', commitState(k))}
            ${countOnly ? '' : round('sign', 'Signing', signState(k))}
          </span>
        </li>`).join('')}
      </ul>`;
  }

  const EVENT_TEXT = {
    lock: 'locked the transaction',
    release: 'released the lock',
    unlock_vote: 'voted to force-unlock',
    lock_override: 'force-unlock reached enough votes - lock released',
    cancel: 'cancelled the transaction',
    broadcast: 'marked the transaction as broadcast',
  };

  function timelineHtml(t) {
    if (!t.timeline?.length) return '<p class="faint">Nothing yet.</p>';
    return `<ol class="timeline">${t.timeline.map((e) => {
      let dot = 'comment';
      let head;
      if (e.kind === 'submission') {
        dot = e.round;
        const what = { start: 'started the transaction', commit: 'added a commitment', sign: 'added a signature', final: 'submitted the fully signed transaction' }[e.round] || 'submitted';
        head = `<strong>${esc(e.member)}</strong> ${what}
          <span class="faint small">· ${e.commits} commit${e.commits === 1 ? '' : 's'}, ${e.signatures} sig${e.signatures === 1 ? '' : 's'}
          · <span class="fingerprint" title="SHA-256 fingerprint of the stored payload">${esc(e.fingerprint)}</span></span>`;
      } else if (e.kind === 'comment') {
        head = `<strong>${esc(e.member)}</strong> commented`;
      } else {
        dot = ['lock_override', 'cancel', 'unlock_vote'].includes(e.event) ? 'alert' : 'event';
        head = `<strong>${esc(e.member || 'Someone')}</strong> ${esc(EVENT_TEXT[e.event] || e.event)}${
          (e.event === 'cancel' || e.event === 'release') && e.detail ? `: <em>${esc(e.detail)}</em>` : ''}`;
      }
      return `<li><span class="dot dot-${esc(dot)}"></span>
        <div class="tl-head">${head}</div>
        <div class="tl-time">${esc(fullDate(e.at))}</div>
        ${e.comment ? `<div class="tl-comment">${esc(e.comment)}</div>` : ''}
      </li>`;
    }).join('')}</ol>`;
  }

  function nextInBatchHtml(t) {
    const n = t.batch && t.batch.next;
    if (!n) return '';
    const left = t.batch.waiting_on_you;
    return `<a class="btn btn-primary btn-block mt-12" href="#tx/${n.id}">Next in batch: item ${n.seq} →</a>
      <p class="small faint mt-8 right">${left} more in this batch waiting for you</p>`;
  }

  function actionHtml(t) {
    const p = t.payload;
    if (t.status === 'cancelled') return '<h2>Cancelled</h2><p class="muted">This transaction was cancelled. See the activity log for the reason.</p>';
    if (t.status === 'complete' || t.status === 'broadcast') {
      return `
        <h2>${t.status === 'complete' ? 'Ready to broadcast' : 'Broadcast'}</h2>
        <p class="small muted">${t.status === 'complete'
          ? 'All required signatures are in. Open this in Minotaur (scan or paste) and publish it, then mark it as broadcast here.'
          : 'This transaction has been published.'}</p>
        ${t.ergo_tx_id ? `<div class="notice notice-info small" id="chain-status">Checking the blockchain…</div>` : ''}
        ${p ? payloadBlock(p) : ''}
        ${t.can.broadcast ? '<button type="button" class="btn btn-primary btn-block mt-12" data-action="broadcast">Mark as broadcast</button>' : ''}`;
    }
    const round = t.status === 'commit' ? 'commitment' : 'signature';
    const needed = t.status === 'commit' ? t.signers_required - t.commits : t.signers_required - t.signatures;
    const header = `
      <h2>${t.status === 'commit' ? 'Commitment round' : 'Signing round'}</h2>
      <p class="small muted">${needed} more ${round}${needed === 1 ? '' : 's'} needed.
      ${t.me.awaiting ? '<strong>It is your turn.</strong>' : t.me.signed ? 'You have signed.' : t.me.committed && t.status === 'commit' ? 'You have committed.' : ''}
      </p>`;

    if (!t.lock) {
      if (!t.can.lock) {
        const why = t.status === 'commit'
          ? (t.me.committed ? 'Your commitment is in and final - the next signers build on it. Nothing more to do until signing starts.'
            : 'None of your keys has an open commitment slot.')
          : (t.me.signed ? 'Your signature is in and final.'
            : t.me.committed ? '' : 'Commitments are closed, and only signers who committed can sign.');
        const done = t.status === 'commit' ? t.me.committed : t.me.signed;
        return `${header}<div class="lockbox"><p class="small">${done ? '<span class="tick">✓</span> ' : ''}${esc(why)}</p></div>
          ${nextInBatchHtml(t)}`;
      }
      return `${header}
        <div class="lockbox">
          <p class="small">Lock the transaction while you work so nobody else continues from the same request.
          Submitting releases the lock automatically. You can only add your own
          ${t.status === 'commit' ? 'commitment' : 'signature'}, and once submitted it is final.</p>
          <button type="button" class="btn btn-primary btn-block" data-action="lock">Lock &amp; start my turn</button>
        </div>`;
    }

    if (!t.lock.mine) {
      const votes = t.lock.votes || [];
      const need = S.config.unlock_votes || 2;
      const grace = S.config.unlock_grace_minutes ?? 10;
      const iVoted = votes.some((v) => v.mine);
      const canVote = t.lock.age_minutes >= grace;
      return `${header}
        <div class="lockbox">
          <p><strong>${esc(t.lock.name)}</strong> is working on this - locked ${timeTag(t.lock.since)}
          (${esc(minutesText(t.lock.age_minutes))}).</p>
          <p class="small muted">If they walked away without submitting, ${need} other signers can force-unlock it.
          Votes can be cast at different times.</p>
          <p class="small"><strong>${votes.length} of ${need}</strong> override votes${votes.length
            ? `: ${votes.map((v) => esc(v.name)).join(', ')}` : ''}</p>
          ${iVoted ? '<p class="small tick">You voted to unlock.</p>'
            : canVote ? '<button type="button" class="btn btn-danger btn-block" data-action="vote-unlock">Vote to unlock</button>'
            : `<p class="small faint">Override voting opens ${grace} minutes after the lock was taken.</p>`}
        </div>`;
    }

    return `${header}
      <div class="stack">
        <div>
          <p class="step-label"><span class="step-num">1</span> Copy the latest request into Minotaur</p>
          ${p && p.type === 'CSR' ? `<p class="small muted">Nobody has committed yet, so this is the original
          <strong>cold signing request</strong>. Open it with the QR scanner on Minotaur's <strong>home screen</strong>
          (or paste it there): Minotaur picks the multi-sig wallet and adds the transaction to
          <strong>Multi-sig Communication</strong>. Press Commit there, then copy the new request.</p>`
          : `<p class="small muted">In Minotaur open the <strong>multi-sig wallet</strong> → <strong>Multi-sig Communication</strong>
          → scan or paste there. The scanner on Minotaur's home screen cannot read multi-sig requests
          ("Invalid QR Code").</p>`}
          ${p ? payloadBlock(p) : '<p class="faint">No payload stored yet.</p>'}
        </div>
        <form id="submit-form" class="stack" novalidate>
          <p class="step-label"><span class="step-num">2</span> ${t.status === 'commit' ? 'Commit' : 'Sign'} in Minotaur, then paste the new output</p>
          <textarea class="payload" id="submit-payload" required autocomplete="off" autocapitalize="off" autocorrect="off"
            spellcheck="false" placeholder='{"MSR":"…"} or {"CSTX":"…"}'></textarea>
          <button type="button" class="btn btn-sm" id="submit-scan">Scan QR</button>
          <div id="submit-analysis" hidden></div>
          <div>
            <label for="submit-comment">Comment for other signers <span class="faint">(optional)</span></label>
            <textarea id="submit-comment" maxlength="4000" rows="2"></textarea>
          </div>
          <div id="submit-error"></div>
          <button class="btn btn-primary btn-block" type="submit">Submit &amp; unlock</button>
          <button type="button" class="btn btn-block" data-action="release">Release lock without submitting</button>
        </form>
      </div>`;
  }

  function payloadBlock(p) {
    return `
      <div class="stack">
        <textarea class="payload" readonly id="latest-payload" aria-label="Latest payload">${esc(p.text)}</textarea>
        <div class="row">
          <button type="button" class="btn btn-sm btn-primary" data-action="copy-payload">Copy</button>
          <button type="button" class="btn btn-sm" data-action="show-qr">Show QR</button>
          <button type="button" class="btn btn-sm" data-action="download-payload">Download</button>
          <span class="spacer"></span>
          <span class="fingerprint" title="SHA-256 fingerprint">${esc(p.fingerprint)}</span>
        </div>
        <div id="payload-qr" hidden></div>
        <p class="small faint">From ${esc(p.by)} · ${esc(fullDate(p.at))}</p>
      </div>`;
  }

  function wireDetail(t) {
    const p = t.payload;
    const view = $('#view');

    view.querySelectorAll('[data-action]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const action = btn.dataset.action;
        if (action === 'copy-payload') return copyText(p.text, 'Payload copied');
        if (action === 'download-payload') return download(`sigmasync-${t.id}-${p.fingerprint}.json`, p.text);
        if (action === 'show-qr') {
          const box = $('#payload-qr');
          box.hidden = !box.hidden;
          btn.textContent = box.hidden ? 'Show QR' : 'Hide QR';
          if (!box.hidden) mountQr(box, p.text);
          return;
        }
        await detailAction(action, t, btn);
      });
    });

    const form = $('#submit-form');
    if (form) {
      let timer;
      const input = $('#submit-payload');
      input.addEventListener('input', () => {
        clearTimeout(timer);
        timer = setTimeout(() => analyzeInto(input.value, $('#submit-analysis'), t.id), 350);
      });
      $('#submit-scan').onclick = async () => {
        const text = await scanQr();
        if (text) { input.value = text; input.dispatchEvent(new Event('input')); }
      };
      form.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const btn = $('button[type=submit]', form);
        btn.disabled = true;
        $('#submit-error').innerHTML = '';
        try {
          const r = await api('submit', { id: t.id, payload: cleanPayload(input.value), comment: $('#submit-comment').value });
          S.detail = r.transaction;
          const s = r.submitted;
          const msg = s.status === 'complete'
            ? 'Submitted - all required signatures are in. The transaction is ready to broadcast.'
            : s.status === 'sign' && s.round === 'commit'
              ? 'Commitment saved. That completes the commitment round - signing can begin.'
              : `${s.round === 'commit' ? 'Commitment' : 'Signature'} saved and the lock released. Thank you!`;
          toast('Submitted', 'success');
          S.txs = [];
          drawDetail(esc(msg) + (S.detail.batch?.next
            ? ` <a href="#tx/${S.detail.batch.next.id}"><strong>Next in batch: item ${S.detail.batch.next.seq} →</strong></a>` : ''));
          window.scrollTo({ top: 0, behavior: 'smooth' });
        } catch (e) {
          btn.disabled = false;
          $('#submit-error').innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`;
        }
      });
    }

    $('#comment-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const body = $('#comment-body').value.trim();
      if (!body) return;
      try {
        const r = await api('add_comment', { id: t.id, comment: body });
        S.detail = r.transaction;
        drawDetail();
        toast('Comment posted', 'success');
      } catch (e) { toast(e.message, 'error'); }
    });

    if (t.ergo_tx_id && $('#chain-status')) checkChain(t);
  }

  async function detailAction(action, t, btn) {
    const calls = {
      lock: () => api('lock', { id: t.id }),
      release: async () => (await dialog({
        title: 'Release the lock?', body: 'Nothing will be saved. Other signers can then take their turn.', confirm: 'Release lock',
      })) && api('release_lock', { id: t.id }),
      'vote-unlock': async () => (await dialog({
        title: 'Vote to force-unlock?',
        body: `Only do this if ${esc(t.lock.name)} is not actually working on it. Their unsubmitted work will be lost.`,
        confirm: 'Vote to unlock', danger: true,
      })) && api('vote_unlock', { id: t.id }),
      broadcast: async () => (await dialog({
        title: 'Mark as broadcast?', body: 'Confirm the transaction was published to the Ergo network.', confirm: 'Mark as broadcast',
      })) && api('mark_broadcast', { id: t.id }),
      cancel: async () => {
        const reason = await dialog({
          title: 'Cancel this transaction?', body: 'Signers will no longer be able to work on it. This cannot be undone.',
          confirm: 'Cancel transaction', cancel: 'Keep it', danger: true, input: { label: 'Reason (shown to all signers)', max: 255 },
        });
        if (reason === null) return null;
        if (!reason) { toast('Give a short reason', 'error'); return null; }
        return api('cancel_transaction', { id: t.id, reason });
      },
    };
    if (!calls[action]) return;
    btn.disabled = true;
    try {
      const r = await calls[action]();
      if (r) {
        S.detail = r.transaction;
        S.txs = [];
        drawDetail();
        if (action === 'lock') { toast('Locked - it is your turn', 'success'); $('#action-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
      }
    } catch (e) {
      toast(e.message, 'error');
      try { S.detail = (await api('get_transaction', { id: t.id })).transaction; drawDetail(); } catch (e2) { /* ignore */ }
    } finally {
      btn.disabled = false;
    }
  }

  async function checkChain(t) {
    const el = $('#chain-status');
    const base = S.config.explorer_api_url;
    if (!el || !base) return;
    try {
      const res = await fetch(base + t.ergo_tx_id);
      if (!document.body.contains(el)) return;
      if (res.ok) {
        const tx = await res.json();
        el.className = 'notice notice-success small';
        el.innerHTML = `Confirmed on-chain${tx.inclusionHeight ? ` at block ${esc(tx.inclusionHeight)}` : ''}${tx.numConfirmations ? ` · ${esc(tx.numConfirmations)} confirmations` : ''}.`;
      } else if (res.status === 404) {
        el.className = 'notice notice-warning small';
        el.textContent = t.status === 'complete' ? 'Not on-chain yet.' : 'Not found on the explorer yet - it may still be in the mempool.';
      } else throw new Error();
    } catch (e) {
      if (el) { el.className = 'notice small'; el.textContent = 'Could not reach the blockchain explorer.'; }
    }
  }

  // ------------------------------------------------------------------------
  // Account
  // ------------------------------------------------------------------------
  async function renderAccount() {
    const view = shell('account');
    view.innerHTML = '<div class="loading">Loading…</div>';
    let data;
    try { data = await api('get_account'); } catch (e) { view.innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`; return; }
    drawAccount(data);
  }

  function drawAccount(data) {
    const view = $('#view');
    const me = data.member;
    setMe(me);
    view.innerHTML = `
      ${me.name_chosen ? '' : `<div class="notice notice-info mb-16"><strong>Welcome to Sigma Sync.</strong>
        Choose the name your co-signers will see. You will find transactions under <em>Sign Transactions</em>
        as soon as someone starts one for a multi-sig wallet your address signs for.</div>`}
      <div class="detail">
        <div>
          <form class="panel" id="name-form" novalidate>
            <div class="panel-title"><h2>Your name</h2></div>
            <div class="field">
              <label for="a-name">Display name</label>
              <input type="text" id="a-name" maxlength="40" required value="${me.name_chosen ? esc(me.display_name) : ''}"
                placeholder="${esc(me.display_name)}">
              <p class="hint">Shown to the people you sign with. Must be unique.</p>
            </div>
            <div id="a-name-error"></div>
            <div class="row mt-12"><span class="spacer"></span><button class="btn btn-primary" type="submit">Save name</button></div>
          </form>
          <section class="panel">
            <div class="panel-title"><h2>Your signing addresses</h2></div>
            <p class="small muted">You see a transaction when one of these addresses is a signer of its multi-sig wallet.</p>
            <div class="table-wrap"><table class="list">
              <thead><tr><th>Address</th><th>Transactions</th><th>Linked</th><th></th></tr></thead>
              <tbody>${data.addresses.map((a) => `
                <tr>
                  <td><code title="${esc(a.address)}">${esc(shortAddr(a.address))}</code>
                    <button type="button" class="btn btn-ghost btn-sm" data-copy="${esc(a.address)}" aria-label="Copy address">Copy</button></td>
                  <td>${a.transactions}</td>
                  <td>${timeTag(a.created_at)}</td>
                  <td class="right">${data.addresses.length > 1
                    ? `<button type="button" class="btn btn-sm btn-danger" data-unlink="${esc(a.address)}">Remove</button>` : ''}</td>
                </tr>`).join('')}
              </tbody>
            </table></div>
          </section>
        </div>
        <aside class="panel detail-side" id="link-panel"></aside>
      </div>`;

    $('#name-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      try {
        const r = await api('update_account', { display_name: $('#a-name').value });
        toast('Name saved', 'success');
        if (!me.name_chosen) { setMe(r.member); location.hash = ''; return; }
        drawAccount(r);
      } catch (e) { $('#a-name-error').innerHTML = `<div class="notice notice-error mt-12">${esc(e.message)}</div>`; }
    });
    $$('[data-unlink]', view).forEach((btn) => btn.addEventListener('click', async () => {
      const ok = await dialog({
        title: 'Remove this address?',
        body: 'Transactions for multi-sig wallets that only this address signs for will disappear from your list. You can link it again later.',
        confirm: 'Remove', danger: true,
      });
      if (!ok) return;
      try { drawAccount(await api('unlink_address', { address: btn.dataset.unlink })); } catch (e) { toast(e.message, 'error'); }
    }));
    drawLinkPanel();
  }

  function drawLinkPanel(error = '') {
    const panel = $('#link-panel');
    if (!panel) return;
    panel.innerHTML = `
      <h2>Link another address</h2>
      <p class="small muted">Sign with a different wallet for another multi-sig, or does your multi-sig use a later
      address? Prove that address too and its transactions appear in your list.</p>
      <form id="link-form" class="stack" novalidate>
        <input type="text" id="link-address" required autocomplete="off" autocapitalize="off" autocorrect="off"
          spellcheck="false" placeholder="9…" aria-label="Address to link">
        ${error ? `<div class="notice notice-error">${esc(error)}</div>` : ''}
        <button class="btn btn-block" type="submit">Continue</button>
      </form>
      <div data-nautilus-slot></div>`;
    // The answer may come after the signer left this view: then the new view stays as it is.
    const linked = async () => {
      toast('Address linked', 'success');
      S.txs = [];
      const data = await api('get_account');
      if (panel.isConnected) drawAccount(data);
    };
    offerNautilus($('[data-nautilus-slot]', panel), {
      purpose: 'link',
      label: 'Link with Nautilus',
      hint: 'Choose an address in Nautilus and sign a one-time request. It is not a payment.',
      onDone: linked,
    });
    $('#link-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const address = $('#link-address').value.replace(/\s+/g, '');
      if (!address) return;
      try {
        const ch = await startChallenge(address, 'link');
        mountChallenge(panel, ch, {
          submitLabel: 'Link address',
          onRestart: () => drawLinkPanel(),
          onDone: linked,
        });
      } catch (e) { drawLinkPanel(e.message); }
    });
  }

  // ------------------------------------------------------------------------
  // Wallets: the registry of multi-sig wallets (SPEC W3 to W7)
  // ------------------------------------------------------------------------
  const walletName = (w) => w.name || 'Unnamed wallet';

  // An answer is drawn only while the route that asked for it is still on screen (Q8, Q9).
  function viewGuard() {
    const seq = S.view;
    return () => seq === S.view && !!S.me;
  }

  const loadError = (message) => `
    <div class="notice notice-error">${esc(message)}</div>
    <div class="mt-12"><button type="button" class="btn" data-retry>Try again</button></div>`;

  async function renderWallets() {
    const live = viewGuard();
    const view = shell('wallets');
    view.innerHTML = `
      <div class="detail">
        <section class="panel" aria-labelledby="wallets-title">
          <div class="panel-title"><h2 id="wallets-title">Your wallets</h2></div>
          <div id="wallet-list"></div>
        </section>
        <form class="panel" id="wallet-form" novalidate>
          <div class="panel-title"><h2>Register a wallet</h2></div>
          <p class="muted small">Paste the address of a multi-sig wallet you sign for, not your own signing address.
          One of the addresses on your account must be one of its signers. Its signers then see it here.</p>
          <div class="field">
            <label for="w-address">Wallet address</label>
            <input type="text" id="w-address" required autocomplete="off" autocapitalize="off" autocorrect="off"
              spellcheck="false" placeholder="The multi-sig wallet's address">
          </div>
          <div class="field">
            <label for="w-name">Name <span class="faint">(optional)</span></label>
            <input type="text" id="w-name" maxlength="80" autocomplete="off" placeholder="e.g. Sigmanauts Treasury 2.0">
            <p class="hint">Shared by every signer of the wallet. Any of them can change it.</p>
          </div>
          <div id="w-error"></div>
          <div class="row mt-12"><span class="spacer"></span>
            <button class="btn btn-primary" type="submit">Register wallet</button></div>
        </form>
      </div>`;
    loadWalletList(live);

    $('#wallet-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const btn = $('button[type=submit]', ev.target);
      const error = $('#w-error');
      const address = $('#w-address').value.replace(/\s+/g, '');
      error.innerHTML = '';
      if (!address) { error.innerHTML = '<div class="notice notice-error mt-12">Paste the wallet address.</div>'; return; }
      btn.disabled = true;
      try {
        const r = await api('register_wallet', { address, name: $('#w-name').value });
        toast(r.created ? 'Wallet registered' : 'This wallet was already registered. Its name is unchanged.', 'success');
        if (!live()) return;
        ev.target.reset();
        loadWalletList(live);
      } catch (e) {
        if (live()) error.innerHTML = `<div class="notice notice-error mt-12">${esc(e.message)}</div>`;
      } finally {
        btn.disabled = false;
      }
    });
  }

  async function loadWalletList(live) {
    const box = $('#wallet-list');
    // A second load of this list (after a registration) makes an older answer stale, even on the same route.
    const seq = String((Number(box.dataset.seq) || 0) + 1);
    box.dataset.seq = seq;
    const newest = () => live() && box.dataset.seq === seq;
    if (!box.firstChild) box.innerHTML = '<div class="loading">Loading wallets…</div>';
    let list;
    try {
      list = (await api('list_wallets')).wallets;
    } catch (e) {
      if (newest()) box.innerHTML = loadError(e.message);
      return;
    }
    if (!newest()) return;
    box.innerHTML = list.length
      ? `<div class="cards" data-wallets="list">${list.map((w) => `
          <a class="card" href="#wallet/${esc(w.id)}" data-wallet-card>
            <div class="card-head">
              <div class="grow">
                <div class="card-title">${esc(walletName(w))}</div>
                <div class="card-sub">Wallet #${esc(w.id)}</div>
              </div>
              <span class="tag">${esc(w.signers_required)} of ${esc(w.signers_total)} signatures</span>
            </div>
          </a>`).join('')}</div>`
      : `<div class="empty" data-wallets="empty">No wallets yet. Register the multi-sig wallet you sign for with
          its address. A wallet also appears here when someone starts a transaction for it.</div>`;
  }

  async function renderWallet(id) {
    const live = viewGuard();
    const view = shell('wallets');
    const back = '<a class="back" href="#wallets">← All wallets</a>';
    view.innerHTML = `${back}<div class="loading">Loading wallet…</div>`;
    let wallet;
    try {
      wallet = (await api('get_wallet', { id })).wallet;
    } catch (e) {
      if (live()) view.innerHTML = back + loadError(e.message);
      return;
    }
    if (live()) drawWallet(wallet, live);
  }

  const closedRow = (t) => `
    <tr>
      <td><a class="row-link" href="#tx/${esc(t.id)}">${esc(t.title)}</a><div class="small faint">#${esc(t.id)}</div></td>
      <td>${statusPill(t.status)}</td>
      <td>${t.closed_at ? timeTag(t.closed_at) : ''}</td>
    </tr>`;

  function drawWallet(w, live) {
    const view = $('#view');
    view.innerHTML = `
      <a class="back" href="#wallets">← All wallets</a>
      <div class="detail-head">
        <div class="grow">
          <h1 id="wallet-title">${esc(walletName(w))}</h1>
          <div class="meta">
            <span>Wallet #${esc(w.id)}</span>
            <span>${esc(w.signers_required)} of ${esc(w.signers_total)} signatures needed</span>
          </div>
        </div>
      </div>
      <div class="detail">
        <div>
          <section class="panel">
            <div class="panel-title"><h2>Signers</h2></div>
            <ul class="people" data-wallet="keys">${w.keys.map((k) => `
              <li data-key="${esc(k.slot)}">
                <span class="slot" aria-hidden="true">${esc(k.slot + 1)}</span>
                <span class="grow">
                  ${k.name ? `<strong>${esc(k.name)}</strong>${k.mine ? ' <span class="faint">(you)</span>' : ''}`
                    : '<span class="faint">Not on Sigma Sync yet</span>'}
                  <div><code class="small faint" title="${esc(k.address)}">${esc(shortAddr(k.address))}</code></div>
                </span>
              </li>`).join('')}
            </ul>
          </section>
          <section class="panel" data-wallet="open">
            <div class="panel-title"><h2>Open transactions</h2></div>
            ${w.open.length ? `<div class="cards">${w.open.map((t) => card(t, false)).join('')}</div>`
              : '<p class="faint">No open transactions.</p>'}
          </section>
          <section class="panel" data-wallet="closed">
            <div class="panel-title"><h2>History</h2></div>
            ${w.closed.length ? `<div class="table-wrap"><table class="list">
                <thead><tr><th>Transaction</th><th>Result</th><th>Closed</th></tr></thead>
                <tbody>${w.closed.map(closedRow).join('')}</tbody>
              </table></div>` : '<p class="faint">No closed transactions yet.</p>'}
            ${w.closed_more ? `<div class="mt-12" data-wallet="more">
                <div data-wallet="older-error"></div>
                <button type="button" class="btn" data-wallet="older">Show older</button>
              </div>` : ''}
          </section>
        </div>
        <aside class="detail-side">
          <form class="panel" id="rename-form" novalidate>
            <div class="panel-title"><h2>Name</h2></div>
            <div class="field">
              <label for="w-rename">Wallet name</label>
              <input type="text" id="w-rename" maxlength="80" required autocomplete="off" value="${esc(w.name)}">
              <p class="hint">Shared by every signer of the wallet. Any of them can change it.</p>
            </div>
            <div id="rename-error"></div>
            <div class="row mt-12"><span class="spacer"></span>
              <button class="btn btn-primary" type="submit">Save name</button></div>
          </form>
          <section class="panel">
            <div class="panel-title"><h2>Address</h2></div>
            <code class="wallet-address" data-wallet="address">${esc(w.address)}</code>
            <button type="button" class="btn btn-sm" data-copy="${esc(w.address)}" data-wallet="address-copy"
              aria-label="Copy wallet address">Copy</button>
          </section>
        </aside>
      </div>`;
    paintBars(view);

    $('#rename-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const btn = $('button[type=submit]', ev.target);
      const error = $('#rename-error');
      error.innerHTML = '';
      btn.disabled = true;
      try {
        const r = (await api('rename_wallet', { id: w.id, name: $('#w-rename').value })).wallet;
        if (!live()) return;
        $('#wallet-title').textContent = walletName(r);
        $('#w-rename').value = r.name;
        toast('Name saved', 'success');
      } catch (e) {
        if (live()) error.innerHTML = `<div class="notice notice-error mt-12">${esc(e.message)}</div>`;
      } finally {
        btn.disabled = false;
      }
    });

    const more = $('[data-wallet=more]', view);
    if (!more) return;
    const older = $('[data-wallet=older]', more);
    older.addEventListener('click', async () => {
      const rows = $('[data-wallet=closed] tbody', view);
      const problem = $('[data-wallet=older-error]', more);
      older.disabled = true;
      older.textContent = 'Loading…';
      problem.innerHTML = '';
      try {
        const page = (await api('get_wallet', { id: w.id, before: w.closed[w.closed.length - 1].id })).wallet;
        if (!live()) return;
        const added = rows.children.length;
        w.closed.push(...page.closed);
        rows.insertAdjacentHTML('beforeend', page.closed.map(closedRow).join(''));
        if (page.closed_more) {
          older.disabled = false;
          older.textContent = 'Show older';
        } else {
          more.remove();
          // The button had the focus: put it on the first new row, not on the page.
          rows.children[added]?.querySelector('a')?.focus();
        }
      } catch (e) {
        if (!live()) return;
        problem.innerHTML = `<div class="notice notice-error mb-16">${esc(e.message)}</div>`;
        older.disabled = false;
        older.textContent = 'Show older';
      }
    });
  }

  // ------------------------------------------------------------------------
  // Admin: account moderation and the audit log. No access to transactions.
  // ------------------------------------------------------------------------
  async function renderAdmin() {
    const view = shell('admin');
    view.innerHTML = '<div class="loading">Loading…</div>';
    let members;
    let events;
    try {
      [members, events] = await Promise.all([api('admin_members'), api('recent_events')]);
    } catch (e) { view.innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`; return; }
    drawAdmin(members.members, events.events);
  }

  function drawAdmin(members, events) {
    const view = $('#view');
    view.innerHTML = `
      <section class="panel">
        <div class="panel-title"><h2>Accounts</h2><span class="faint small">${members.filter((m) => m.is_active).length} active</span></div>
        <p class="small muted">Anyone can sign in with a wallet. Admins can disable abusive accounts and see the audit log,
        but cannot see transactions they are not a signer of.</p>
        <div class="table-wrap"><table class="list">
          <thead><tr><th>Name</th><th>Addresses</th><th>Role</th><th>Last sign-in</th><th></th></tr></thead>
          <tbody>${members.map((m) => `
            <tr class="${m.is_active ? '' : 'inactive'}">
              <td><strong>${esc(m.display_name)}</strong>${m.id === S.me.id ? ' <span class="faint">(you)</span>' : ''}</td>
              <td>${m.addresses.map((a) => `<div><code title="${esc(a)}">${esc(shortAddr(a))}</code></div>`).join('')}</td>
              <td>${m.is_active ? (m.is_admin ? 'Admin' : 'Signer') : 'Disabled'}</td>
              <td>${m.last_login_at ? timeTag(m.last_login_at) : '<span class="faint">never</span>'}</td>
              <td class="nowrap right">${m.env_admin ? '<span class="faint small">set in config</span>' : m.id === S.me.id ? '' : `
                <button type="button" class="btn btn-sm" data-member="${m.id}" data-op="admin">${m.is_admin ? 'Remove admin' : 'Make admin'}</button>
                <button type="button" class="btn btn-sm ${m.is_active ? 'btn-danger' : ''}" data-member="${m.id}" data-op="active">${m.is_active ? 'Disable' : 'Enable'}</button>
                <button type="button" class="btn btn-sm btn-danger" data-member="${m.id}" data-op="delete">Delete</button>`}
              </td>
            </tr>`).join('')}
          </tbody>
        </table></div>
      </section>
      <section class="panel">
        <div class="panel-title"><h2>Recent activity</h2><span class="faint small">last 200 events</span></div>
        <div class="table-wrap"><table class="list">
          <thead><tr><th>When</th><th>Who</th><th>Event</th><th>TX</th><th>Detail</th><th>IP</th></tr></thead>
          <tbody>${events.map((e) => `
            <tr>
              <td class="nowrap">${esc(fullDate(e.created_at))}</td>
              <td>${esc(e.member || '-')}</td>
              <td><span class="tag">${esc(e.event)}</span></td>
              <td>${e.transaction_id ? `#${esc(e.transaction_id)}` : ''}</td>
              <td class="small anywhere">${esc(e.detail)}</td>
              <td class="small faint">${esc(e.ip)}</td>
            </tr>`).join('')}
          </tbody>
        </table></div>
      </section>`;

    $$('[data-member]', view).forEach((btn) => btn.addEventListener('click', async () => {
      const m = members.find((x) => x.id === Number(btn.dataset.member));
      const params = { id: m.id };
      if (btn.dataset.op === 'delete') {
        const ok = await dialog({
          title: `Delete ${m.display_name}?`,
          body: `Removes the account and its ${m.addresses.length} linked address${m.addresses.length === 1 ? '' : 'es'}, signs them out
            and releases any lock they hold. Their past commitments, signatures and comments stay on the transactions,
            marked "(deleted)". They can sign in again later and get a fresh account - to keep someone out, use Disable instead.`,
          confirm: 'Delete account', danger: true,
        });
        if (!ok) return;
        try {
          const r = await api('admin_delete', params);
          drawAdmin(r.members, events);
          toast('Account deleted', 'success');
        } catch (e) { toast(e.message, 'error'); }
        return;
      }
      if (btn.dataset.op === 'admin') params.is_admin = m.is_admin ? 0 : 1;
      else {
        if (m.is_active && !(await dialog({
          title: `Disable ${m.display_name}?`, body: 'They are signed out and cannot sign in until re-enabled. Their history is kept.',
          confirm: 'Disable', danger: true,
        }))) return;
        params.is_active = m.is_active ? 0 : 1;
      }
      try {
        const r = await api('admin_update', params);
        drawAdmin(r.members, events);
        toast('Saved', 'success');
      } catch (e) { toast(e.message, 'error'); }
    }));
  }

  // ------------------------------------------------------------------------
  // Global wiring
  // ------------------------------------------------------------------------
  document.addEventListener('click', async (ev) => {
    const nav = ev.target.closest('[data-nav]');
    if (nav) {
      ev.preventDefault();
      const target = nav.dataset.nav === 'list' || nav.dataset.nav === 'sign' ? '' : nav.dataset.nav;
      if (location.hash.replace(/^#/, '') === target) route();
      else location.hash = target;
      return;
    }
    const copy = ev.target.closest('[data-copy]');
    if (copy) { copyText(copy.dataset.copy); return; }
    const filter = ev.target.closest('[data-filter]');
    if (filter) { S.filter = filter.dataset.filter; drawList(); return; }
    if (ev.target.closest('[data-retry]')) { route(); return; }
    const all = ev.target.closest('[data-select-all]');
    if (all) { pickAll(all.dataset.selectAll); return; }
    if (ev.target.closest('[data-clear-selection]')) { clearSelection(); S.selNotes = []; drawList(true); return; }
    if (ev.target.closest('#user-chip [data-action=logout]')) {
      try { await api('logout'); } catch (e) { /* ignore */ }
      S.me = null;
      S.csrf = '';
      S.txs = [];
      renderSignIn();
    }
  });

  document.addEventListener('change', (ev) => {
    const row = ev.target.closest('[data-select]');
    if (row) pick(Number(row.dataset.select), row.checked);
    const ack = ev.target.closest('[data-ack]');
    if (ack) {
      const id = Number(ack.dataset.ack);
      if (ack.checked) S.acks.set(id, S.readings.get(id)); else S.acks.delete(id);
    }
  });

  window.addEventListener('hashchange', route);

  async function init() {
    try {
      const r = await api('session');
      if (r.signed_in) startSession(r);
      else { S.config = { nautilus: r.nautilus }; renderSignIn(); }
    } catch (e) {
      app().innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`;
    }
  }

  init();
})();
