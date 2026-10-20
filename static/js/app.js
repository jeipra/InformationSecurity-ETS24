/*
   OPREC portal frontend. Plain JS, no build step.
   Talks to the Flask endpoints in app.py:
     POST /register  /login  /logout        (JSON)
     POST /profile                          (JSON, includes password)
     POST /upload                           (multipart: kind, password, file)
     GET  /items
     POST /download/<id>/<algo>             (form: password) -> file
     POST /profile/<id>/<algo>              (form: password) -> JSON
   The password is the encryption key material, so every encrypt/decrypt
   request carries it. It is kept in memory only (never localStorage).
  */
(() => {
  'use strict';

  //Config
  const MB = 1024 * 1024;
  const CONFIG = {
    serverLimitMB: 200, // MAX_CONTENT_LENGTH in app.py
    uploads: [
      {
        kind: 'KTM', title: 'ID card (KTM)',
        hint: 'A clear photo or scan of your student card.',
        exts: ['jpg', 'jpeg', 'png', 'webp'], maxMB: 10,
        formats: 'JPG, PNG or WebP, up to 10 MB',
      },
      {
        kind: 'DOCUMENT', title: 'Documents',
        hint: 'Your CV, motivation letter or portfolio.',
        exts: ['pdf', 'doc', 'docx', 'xls', 'xlsx'], maxMB: 25,
        formats: 'PDF, Word or Excel, up to 25 MB',
      },
      {
        kind: 'VIDEO', title: 'Introduction video',
        hint: 'About one minute, introducing yourself.',
        exts: ['mp4', 'mov', 'webm', 'mkv'], maxMB: 190,
        formats: 'MP4, MOV, WebM or MKV, up to 190 MB',
      },
    ],
    algos: [
      { id: 'AES', note: '256-bit, OFB' },
      { id: 'DES', note: 'OFB' },
      { id: 'RC4', note: 'stream' },
    ],
  };

  const GROUPS = [
    { kind: 'PROFILE', title: 'Personal data', empty: 'No personal data saved yet.' },
    { kind: 'KTM', title: 'ID card', empty: 'No ID card uploaded yet.' },
    { kind: 'DOCUMENT', title: 'Documents', empty: 'No documents uploaded yet.' },
    { kind: 'VIDEO', title: 'Videos', empty: 'No video uploaded yet.' },
  ];

  const PROFILE_LABELS = [
    ['nama_lengkap', 'Full name'],
    ['nrp', 'Student ID (NRP)'],
    ['no_hp', 'Phone number'],
    ['domisili', 'Domicile'],
    ['riwayat_medis', 'Medical history'],
  ];

  //helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  //Build an element
  function el(tag, attrs = {}, ...kids) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === false || v == null) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return node;
  }

  const SVG_NS = 'http://www.w3.org/2000/svg';
  function icon(pathD, size = 28) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('width', size); svg.setAttribute('height', size);
    svg.setAttribute('aria-hidden', 'true'); svg.setAttribute('class', 'drop-icon');
    const p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', pathD); p.setAttribute('fill', 'none'); p.setAttribute('stroke', 'currentColor');
    p.setAttribute('stroke-width', '1.6'); p.setAttribute('stroke-linecap', 'round'); p.setAttribute('stroke-linejoin', 'round');
    svg.append(p);
    return svg;
  }
  const ICON_UPLOAD = 'M12 16V4m0 0L7 9m5-5l5 5M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3';

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < MB) return `${(n / 1024).toFixed(0)} KB`;
    return `${(n / MB).toFixed(n < 10 * MB ? 1 : 0)} MB`;
  }
  function formatDate(sqlUtc) {
    // SQLite CURRENT_TIMESTAMP is UTC, "YYYY-MM-DD HH:MM:SS"
    const d = new Date(String(sqlUtc).replace(' ', 'T') + 'Z');
    if (isNaN(d)) return String(sqlUtc);
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }
  const extOf = (name) => (name.includes('.') ? name.split('.').pop().toLowerCase() : '');

  function toast(message, type = 'ok') {
    const t = el('div', { class: 'toast' + (type === 'error' ? ' is-error' : ''), role: type === 'error' ? 'alert' : 'status', text: message });
    $('#toasts').append(t);
    setTimeout(() => t.remove(), type === 'error' ? 8000 : 4500);
  }

  //API layer
  const NETWORK_MSG = 'Cannot reach the server. Check that it is running, then try again.';
  const SERVER_MESSAGES = {
    'Silakan login dulu': 'Your session has expired. Sign in again.',
    'Username min 3 karakter, password min 8 karakter': 'Username needs at least 3 characters and password at least 8.',
    'Username sudah dipakai': 'That username is already taken.',
    'Username atau password salah': 'Wrong username or password.',
    'Password salah': 'Wrong password.',
    'Data tidak ditemukan': 'That item was not found.',
    'nama_lengkap dan nrp wajib diisi': 'Full name and Student ID are required.',
    'kind (KTM/DOCUMENT/VIDEO) dan file wajib diisi': 'Choose a file to upload.',
  };

  class ApiError extends Error {
    constructor(status, raw) {
      let msg = SERVER_MESSAGES[raw] || raw;
      if (!msg) {
        if (status === 413) msg = `That file is too large for the server (limit ${CONFIG.serverLimitMB} MB).`;
        else if (status >= 500) msg = 'The server hit an error while processing this. Try again, and tell the backend owner if it keeps happening.';
        else if (status === 0) msg = NETWORK_MSG;
        else msg = `Something went wrong (error ${status}).`;
      }
      super(msg);
      this.status = status;
      this.wrongPassword = raw === 'Password salah';
      this.sessionExpired = raw === 'Silakan login dulu';
    }
  }

  async function errorFrom(res) {
    let raw = '';
    try {
      if ((res.headers.get('content-type') || '').includes('json')) raw = (await res.json()).error || '';
    } catch { /* non-JSON error page (413, 500): fall through */ }
    return new ApiError(res.status, raw);
  }

  /** fetch wrapper. Returns the Response on 2xx, throws ApiError otherwise. */
  async function request(path, { method = 'GET', json, form } = {}) {
    const init = { method, credentials: 'same-origin' };
    if (json !== undefined) { init.headers = { 'Content-Type': 'application/json' }; init.body = JSON.stringify(json); }
    if (form) init.body = form;
    let res;
    try { res = await fetch(path, init); } catch { throw new ApiError(0, ''); }
    if (!res.ok) throw await errorFrom(res);
    return res;
  }

  function uploadWithProgress(kind, file, password, { onProgress, onSealing }) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/upload');
      xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
      xhr.upload.onload = onSealing;
      xhr.onerror = () => reject(new ApiError(0, ''));
      xhr.onload = () => {
        let body = {};
        try { body = JSON.parse(xhr.responseText); } catch { /* non-JSON */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(body);
        else reject(new ApiError(xhr.status, body.error || ''));
      };
      const fd = new FormData();
      fd.append('kind', kind);
      fd.append('password', password);
      fd.append('file', file);
      xhr.send(fd);
    });
  }

  //State
  const state = { user: null, password: null, items: [], uploading: 0 };
  const CANCELLED = Symbol('cancelled');

  window.addEventListener('beforeunload', (e) => {
    if (state.uploading > 0) { e.preventDefault(); e.returnValue = ''; }
  });

  //Password prompt
  const pwDialog = $('#pw-dialog');
  const pwInput = $('#pw-input');
  const pwError = $('#pw-error');
  const PW_DEFAULT = 'Your password is the key that encrypts and decrypts your data.';

  function askPassword(reason, error = '') {
    return new Promise((resolve) => {
      $('#pw-reason').textContent = reason || PW_DEFAULT;
      pwError.textContent = error;
      pwInput.value = '';
      pwInput.toggleAttribute('aria-invalid', !!error);
      let done = false;
      const finish = (value) => {
        if (done) return;
        done = true;
        pwInput.value = '';
        if (pwDialog.open) pwDialog.close();
        resolve(value);
      };
      $('#pw-form').onsubmit = (e) => {
        e.preventDefault();
        if (!pwInput.value) { pwError.textContent = 'Enter your password.'; pwInput.setAttribute('aria-invalid', 'true'); return; }
        finish(pwInput.value);
      };
      $('#pw-cancel').onclick = () => finish(null);
      pwDialog.oncancel = (e) => { e.preventDefault(); finish(null); };
      pwDialog.showModal();
      pwInput.focus();
    });
  }

  //password: Re-asks if the server says the password is wrong.
  async function withPassword(reason, action) {
    let pw = state.password ?? (await askPassword(reason));
    for (;;) {
      if (pw == null) return CANCELLED;
      try {
        const result = await action(pw);
        state.password = pw;
        updateLock();
        return result;
      } catch (err) {
        if (!err.wrongPassword) throw err;
        state.password = null;
        updateLock();
        pw = await askPassword(reason, 'That password is wrong. Try again.');
      }
    }
  }

  //Views
  const viewAuth = $('#view-auth');
  const viewMain = $('#view-main');

  function showAuth(message = '') {
    viewMain.hidden = true;
    viewAuth.hidden = false;
    setAuthMode('login');
    $('#auth-error').textContent = message;
    $('#a-username').focus();
  }

  function showMain() {
    viewAuth.hidden = true;
    viewMain.hidden = false;
    $('#whoami').textContent = state.user || '';
    updateLock();
    setTab('submit');
  }

  function resetSession(message) {
    state.user = null; state.password = null; state.items = [];
    try { sessionStorage.removeItem('oprec_user'); } catch { /* storage unavailable */ }
    renderVault();
    showAuth(message);
  }

  function handleError(err, { fallbackEl } = {}) {
    if (err.sessionExpired) { resetSession(err.message); return; }
    if (fallbackEl) fallbackEl.textContent = err.message; else toast(err.message, 'error');
  }

  //Lock indicator
  const lockChip = $('#lock-chip');
  function updateLock() {
    const open = !!state.password;
    lockChip.classList.toggle('is-open', open);
    lockChip.disabled = !open;
    $('#lock-text').textContent = open ? 'Unlocked' : 'Locked';
    lockChip.title = open
      ? 'Your password is held in memory for this tab. Click to lock.'
      : 'We will ask for your password when you encrypt or decrypt something.';
  }
  lockChip.addEventListener('click', () => {
    state.password = null; updateLock();
    toast('Locked. You will be asked for your password again.');
  });

  //Tabs
  function wireTabs(tabs, onSelect) {
    tabs.forEach((tab, i) => {
      tab.addEventListener('click', () => onSelect(tab));
      tab.addEventListener('keydown', (e) => {
        const dir = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
        if (!dir) return;
        e.preventDefault();
        const next = tabs[(i + dir + tabs.length) % tabs.length];
        next.focus(); onSelect(next);
      });
    });
  }

  function setTab(name) {
    const isSubmit = name === 'submit';
    $('#nav-submit').setAttribute('aria-selected', String(isSubmit));
    $('#nav-vault').setAttribute('aria-selected', String(!isSubmit));
    $('#panel-submit').hidden = !isSubmit;
    $('#panel-vault').hidden = isSubmit;
    window.scrollTo({ top: 0 });
    if (!isSubmit) refreshItems();
  }
  wireTabs([$('#nav-submit'), $('#nav-vault')], (t) => setTab(t.id === 'nav-submit' ? 'submit' : 'vault'));

  //Auth form
  let authMode = 'login';
  const authForm = $('#auth-form');
  const fUser = $('#a-username');
  const fPass = $('#a-password');
  const fConf = $('#a-confirm');

  function setFieldError(input, message) {
    const err = input.closest('.field').querySelector('.field-error');
    err.textContent = message || '';
    input.toggleAttribute('aria-invalid', !!message);
  }

  function setAuthMode(mode) {
    authMode = mode;
    const reg = mode === 'register';
    $('#tab-login').setAttribute('aria-selected', String(!reg));
    $('#tab-register').setAttribute('aria-selected', String(reg));
    $('#auth-title').textContent = reg ? 'Create your account' : 'Sign in';
    $('#auth-sub').textContent = reg ? 'You need an account to submit and retrieve your application.' : 'Continue your committee application.';
    $('#auth-submit').textContent = reg ? 'Create account' : 'Sign in';
    $('#confirm-field').hidden = !reg;
    $('#register-notice').hidden = !reg;
    const hint = $('#a-password-hint');
    hint.hidden = !reg;
    hint.textContent = 'At least 8 characters.';
    fPass.autocomplete = reg ? 'new-password' : 'current-password';
    [fUser, fPass, fConf].forEach((i) => setFieldError(i, ''));
    $('#auth-error').textContent = '';
    fConf.value = '';
  }
  wireTabs([$('#tab-login'), $('#tab-register')], (t) => setAuthMode(t.id === 'tab-register' ? 'register' : 'login'));

  $('#toggle-pw').addEventListener('click', (e) => {
    const show = fPass.type === 'password';
    fPass.type = show ? 'text' : 'password';
    e.currentTarget.textContent = show ? 'Hide' : 'Show';
    e.currentTarget.setAttribute('aria-pressed', String(show));
    e.currentTarget.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  });

  authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = fUser.value.trim();
    const password = fPass.value;
    const reg = authMode === 'register';
    const errs = {
      user: username.length < 3 ? 'Username needs at least 3 characters.' : '',
      pass: !password ? 'Enter your password.' : reg && password.length < 8 ? 'Password needs at least 8 characters.' : '',
      conf: reg && password !== fConf.value ? 'Passwords do not match.' : '',
    };
    setFieldError(fUser, errs.user); setFieldError(fPass, errs.pass); setFieldError(fConf, errs.conf);
    $('#auth-error').textContent = '';
    const firstBad = [[errs.user, fUser], [errs.pass, fPass], [errs.conf, fConf]].find(([m]) => m);
    if (firstBad) { firstBad[1].focus(); return; }

    const btn = $('#auth-submit');
    const label = btn.textContent;
    btn.disabled = true; btn.textContent = reg ? 'Creating account…' : 'Signing in…';
    try {
      if (reg) await request('/register', { method: 'POST', json: { username, password } });
      await request('/login', { method: 'POST', json: { username, password } });
      state.user = username; state.password = password;
      try { sessionStorage.setItem('oprec_user', username); } catch { /* ignore */ }
      authForm.reset();
      showMain();
      if (reg) toast('Account created. You are signed in.');
      refreshItems();
    } catch (err) {
      if (err.status === 409) setFieldError(fUser, err.message), fUser.focus();
      else $('#auth-error').textContent = err.message;
    } finally {
      btn.disabled = false; btn.textContent = label;
    }
  });

  $('#logout-btn').addEventListener('click', async () => {
    try { await request('/logout', { method: 'POST' }); } catch { /* sign out locally anyway */ }
    resetSession('');
    toast('Signed out.');
  });

  //Personal data form
  const profileForm = $('#profile-form');
  const RULES = {
    nama_lengkap: (v) => (!v ? 'Enter your full name.' : v.length < 3 ? 'Full name needs at least 3 characters.' : ''),
    nrp: (v) => (!v ? 'Enter your Student ID.' : !/^\d{10}$/.test(v) ? 'Student ID is 10 digits, for example 5025241204.' : ''),
    no_hp: (v) => (v && !/^(\+62|62|0)8\d{7,12}$/.test(v.replace(/[\s-]/g, '')) ? 'Use an Indonesian mobile number, like 081234567890.' : ''),
  };

  profileForm.elements.nrp.addEventListener('input', (e) => { e.target.value = e.target.value.replace(/\D/g, '').slice(0, 10); });
  $$('input, textarea', profileForm).forEach((inp) => inp.addEventListener('input', () => setFieldError(inp, '')));

  profileForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = {};
    let firstBad = null;
    for (const [key] of PROFILE_LABELS) {
      const input = profileForm.elements[key];
      data[key] = input.value.trim();
      const msg = RULES[key] ? RULES[key](data[key]) : '';
      setFieldError(input, msg);
      if (msg && !firstBad) firstBad = input;
    }
    if (firstBad) { firstBad.focus(); return; }

    const btn = $('#profile-submit');
    btn.disabled = true; btn.textContent = 'Encrypting…';
    try {
      const out = await withPassword('Your password encrypts your personal data.', (pw) =>
        request('/profile', { method: 'POST', json: { ...data, password: pw } }));
      if (out === CANCELLED) return;
      toast('Personal data saved and encrypted.');
      profileForm.reset();
      refreshItems();
    } catch (err) {
      handleError(err);
    } finally {
      btn.disabled = false; btn.textContent = 'Save and encrypt';
    }
  });

  //File uploaders
  function validateFile(cfg, file) {
    if (!file) return 'Choose a file first.';
    const ext = extOf(file.name);
    if (!cfg.exts.includes(ext)) return `This file type is not accepted. Use ${cfg.formats.split(', up to')[0]}.`;
    if (file.size === 0) return 'This file is empty. Choose a different one.';
    if (file.size > cfg.maxMB * MB) return `This file is ${formatBytes(file.size)}. The limit is ${cfg.maxMB} MB.`;
    return '';
  }

  function buildUploader(cfg) {
    let file = null;
    const inputId = `f-${cfg.kind.toLowerCase()}`;
    const input = el('input', { type: 'file', id: inputId, accept: cfg.exts.map((x) => '.' + x).join(',') });
    const drop = el('label', { class: 'drop', for: inputId },
      icon(ICON_UPLOAD),
      el('span', {}, el('strong', { text: 'Choose a file' }), ' or drop it here'),
      el('span', { class: 'hint', text: cfg.formats }),
      input);
    const chosen = el('div', { class: 'chosen', hidden: true });
    const progress = el('div', { class: 'progress', hidden: true, role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100' }, el('i'));
    const status = el('p', { class: 'status', role: 'status' });
    const btn = el('button', { type: 'button', class: 'btn btn-primary', disabled: true, text: 'Upload and encrypt' });

    const card = el('section', { class: 'card up', 'aria-labelledby': `h-${cfg.kind}` },
      el('div', {}, el('h2', { id: `h-${cfg.kind}`, text: cfg.title }), el('p', { class: 'muted small', text: cfg.hint })),
      drop, chosen, progress, status, btn);

    function setStatus(msg, isError = false) {
      status.textContent = msg;
      status.classList.toggle('is-error', isError);
    }

    function setFile(f) {
      const problem = f ? validateFile(cfg, f) : '';
      drop.classList.toggle('is-bad', !!problem);
      if (problem) { file = null; input.value = ''; }
      else file = f || null;
      chosen.hidden = !file;
      chosen.replaceChildren();
      if (file) {
        chosen.append(
          el('div', { class: 'chosen-main' }, el('span', { class: 'chosen-name', text: file.name }), el('span', { class: 'chosen-size', text: formatBytes(file.size) })),
          el('button', { type: 'button', class: 'ghost-btn', text: 'Remove', 'aria-label': `Remove ${file.name}`, onclick: () => { setFile(null); setStatus(''); } }));
      }
      btn.disabled = !file;
      setStatus(problem, !!problem);
    }

    input.addEventListener('change', () => setFile(input.files[0] || null));
    ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('is-over'); }));
    ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove('is-over')));
    drop.addEventListener('drop', (e) => {
      e.preventDefault();
      const files = e.dataTransfer.files;
      if (files.length > 1) { setFile(null); setStatus('Drop one file at a time.', true); return; }
      if (files[0]) setFile(files[0]);
    });

    btn.addEventListener('click', async () => {
      const problem = validateFile(cfg, file);
      if (problem) { setStatus(problem, true); return; }
      const sending = file;
      btn.disabled = true; input.disabled = true;
      setStatus('');
      state.uploading++;
      try {
        const out = await withPassword(`Your password encrypts ${sending.name}.`, (pw) => {
          progress.hidden = false; progress.classList.remove('is-sealing');
          progress.firstElementChild.style.width = '0%';
          setStatus('Uploading…');
          return uploadWithProgress(cfg.kind, sending, pw, {
            onProgress: (r) => {
              const pct = Math.round(r * 100);
              progress.firstElementChild.style.width = pct + '%';
              progress.setAttribute('aria-valuenow', String(pct));
              setStatus(`Uploading… ${pct}%`);
            },
            onSealing: () => { progress.classList.add('is-sealing'); progress.removeAttribute('aria-valuenow'); setStatus('Encrypting with AES, DES and RC4. Large files take a moment.'); },
          });
        });
        if (out === CANCELLED) { setStatus(''); return; }
        setStatus('');
        setFile(null);
        toast(`${cfg.title} uploaded and encrypted.`);
        refreshItems();
      } catch (err) {
        if (err.sessionExpired) { resetSession(err.message); return; }
        setStatus(err.message, true);
      } finally {
        state.uploading--;
        progress.hidden = true;
        input.disabled = false; btn.disabled = !file;
      }
    });

    return card;
  }
  CONFIG.uploads.forEach((cfg) => $('#uploads').append(buildUploader(cfg)));

  //Vault
  async function refreshItems() {
    try {
      const res = await request('/items');
      state.items = (await res.json()).items || [];
      renderVault();
    } catch (err) {
      if (err.sessionExpired) resetSession(err.message);
      else {
        $('#vault').replaceChildren(el('div', { class: 'empty' }, el('p', { text: err.message }),
          el('button', { class: 'btn btn-quiet', type: 'button', text: 'Try again', onclick: refreshItems })));
      }
    }
  }

  function algoList(item) {
    const have = new Set(String(item.algorithms || '').split(','));
    return CONFIG.algos.filter((a) => have.has(a.id));
  }

  function itemLabel(item) {
    return item.kind === 'PROFILE' ? 'Personal data record' : item.original_name;
  }

  function renderVault() {
    $('#vault-count').textContent = String(state.items.length);
    const root = $('#vault');
    if (!state.items.length) {
      root.replaceChildren(el('div', { class: 'empty' },
        el('p', { text: 'Nothing here yet. Submit your details and files and they will appear here, ready to decrypt.' }),
        el('button', { class: 'btn btn-primary', type: 'button', text: 'Go to Submit', onclick: () => setTab('submit') })));
      return;
    }
    root.replaceChildren(...GROUPS.map((g) => {
      const items = state.items.filter((i) => i.kind === g.kind).sort((a, b) => b.id - a.id);
      return el('section', { class: 'group', 'aria-labelledby': `g-${g.kind}` },
        el('h2', { id: `g-${g.kind}` }, g.title, items.length ? el('span', { class: 'muted', text: String(items.length) }) : null),
        items.length ? el('div', { class: 'items' }, items.map(renderItem)) : el('p', { class: 'muted small', text: g.empty }));
    }));
  }

  function renderItem(item) {
    const isProfile = item.kind === 'PROFILE';
    const verb = isProfile ? 'View' : 'Download';
    const buttons = algoList(item).map((a) => {
      const b = el('button', { type: 'button', class: 'copy-btn', 'aria-label': `${verb} ${itemLabel(item)} decrypted with ${a.id}` },
        a.id, el('small', { text: a.note }));
      b.addEventListener('click', () => runCopyAction(b, item, a.id));
      return b;
    });
    if (item.kind === 'KTM') {
      const p = el('button', { type: 'button', class: 'copy-btn preview-btn', text: 'Preview', 'aria-label': `Preview ${item.original_name}` });
      p.addEventListener('click', () => runCopyAction(p, item, 'AES', 'preview'));
      buttons.push(p);
    }
    return el('div', { class: 'item' },
      el('div', { class: 'item-main' },
        el('div', { class: 'item-name', text: itemLabel(item) }),
        el('div', { class: 'item-meta', text: `Saved ${formatDate(item.created_at)}` })),
      el('div', { class: 'copies', role: 'group', 'aria-label': `${verb} with` },
        el('span', { class: 'muted small', text: `${verb} with` }), buttons));
  }

  async function runCopyAction(btn, item, algo, mode) {
    const original = btn.childNodes.length ? [...btn.childNodes] : [];
    const group = btn.closest('.copies');
    $$('button', group).forEach((b) => { b.disabled = true; });
    btn.classList.add('is-busy');
    btn.replaceChildren('Decrypting…');
    try {
      if (item.kind === 'PROFILE') await viewProfile(item, algo);
      else if (mode === 'preview') await previewImage(item, algo);
      else await downloadItem(item, algo);
    } catch (err) {
      handleError(err);
    } finally {
      btn.classList.remove('is-busy');
      btn.replaceChildren(...original);
      $$('button', group).forEach((b) => { b.disabled = false; });
    }
  }

  const reasonFor = (item) => `Your password decrypts ${itemLabel(item)}.`;

  function fetchDecrypted(item, algo, asJson) {
    return withPassword(reasonFor(item), async (pw) => {
      const form = new FormData();
      form.append('password', pw);
      const path = item.kind === 'PROFILE' ? `/profile/${item.id}/${algo}` : `/download/${item.id}/${algo}`;
      const res = await request(path, { method: 'POST', form });
      return asJson ? res.json() : res.blob();
    });
  }

  async function downloadItem(item, algo) {
    const blob = await fetchDecrypted(item, algo, false);
    if (blob === CANCELLED) return;
    const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: item.original_name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    toast(`${item.original_name} decrypted with ${algo} and downloaded.`);
  }

  async function previewImage(item, algo) {
    const blob = await fetchDecrypted(item, algo, false);
    if (blob === CANCELLED) return;
    const url = URL.createObjectURL(blob);
    const dlg = $('#preview-dialog');
    const img = $('#pv-img');
    img.src = url;
    img.alt = `Decrypted ID card: ${item.original_name}`;
    dlg.addEventListener('close', () => { img.removeAttribute('src'); URL.revokeObjectURL(url); }, { once: true });
    dlg.showModal();
  }

  async function viewProfile(item, algo) {
    const out = await fetchDecrypted(item, algo, true);
    if (out === CANCELLED) return;
    const body = $('#pd-body');
    body.replaceChildren(...PROFILE_LABELS.flatMap(([key, label]) => {
      const v = (out.profile && out.profile[key]) || '';
      return [el('dt', { text: label }), el('dd', { class: v ? '' : 'is-empty', text: v || 'Not provided' })];
    }));
    $('#pd-meta').textContent = `Saved ${formatDate(item.created_at)}. Decrypted with ${algo}.`;
    $('#profile-dialog').showModal();
  }

  $$('dialog [data-close]').forEach((b) => b.addEventListener('click', () => b.closest('dialog').close()));
  // Close a dialog when the backdrop is clicked.
  ['#profile-dialog', '#preview-dialog'].forEach((sel) => {
    const d = $(sel);
    d.addEventListener('click', (e) => { if (e.target === d) d.close(); });
    d.addEventListener('close', () => { if (sel === '#profile-dialog') $('#pd-body').replaceChildren(); });
  });

  //Boot
  (async function boot() {
    try {
      const res = await request('/items'); // doubles as "am I signed in?"
      state.items = (await res.json()).items || [];
      try { state.user = sessionStorage.getItem('oprec_user'); } catch { /* ignore */ }
      showMain();
      renderVault();
    } catch (err) {
      showAuth(err.status === 0 ? err.message : '');
    }
  })();
})();
