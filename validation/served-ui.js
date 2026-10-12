
const chat = document.getElementById('chat');
const input = document.getElementById('input');
const send = document.getElementById('send');
const dot = document.getElementById('status-dot');
let mode = 'chat';
let busy = false;
// Per-tab session id: the server keys conversation memory on it, so two
// browser tabs don't bleed into each other. A page reload regenerates it and
// the server then reattaches to the latest persisted conversation (--resume).
let SESSION = 'tab-' + Math.random().toString(36).slice(2, 10);
// The persisted session file this tab is currently chatting in (the server
// may resume a different id than the tab key — tracked for the sidebar).
let CURRENT = null;

// Tauri updater hook: the shell calls this when a newer release is available
// (safe no-op in the plain browser UI). The shell may re-emit the same message
// while the page is still loading (it cannot detect whether the handler was
// present yet), so identical consecutive messages are shown only once.
window.__blackroseUpdate = (msg) => {
  if (window.__lastUpdateMsg === msg) return;
  window.__lastUpdateMsg = msg;
  const ver = (msg.match(/v([0-9][^s—]*)/) || [])[1] || '';
  el('activity', '⬆ ' + msg);
  // Offer the real install when running inside the Tauri shell. The shell
  // exposes the global Tauri API (withGlobalTauri) and grants the loopback
  // core UI only updater permissions (capabilities/remote-updater.json), so
  // this page can install an update and nothing else.
  const tauri = window.__TAURI__;
  if (!tauri || !ver) return;
  const row = el('activity');
  const btn = document.createElement('button');
  btn.id = 'btn-install-update';
  btn.textContent = '⬇ Install v' + ver + ' & restart';
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = '⬇ installing… (this can take a minute)';
    try {
      // The shell command does check → download → install → restart. It
      // never resolves on success: restarting replaces this process.
      await tauri.core.invoke('update_install');
      // Reaching here means the command returned an error string.
      btn.disabled = false;
      btn.textContent = '⬇ Install v' + ver + ' & restart';
      el('activity', '⚠ update failed: ' + 'see the app log for details');
    } catch (e) {
      btn.disabled = false;
      btn.textContent = '⬇ Install v' + ver + ' & restart';
      el('activity', '⚠ update failed: ' + (e instanceof Error ? e.message : String(e)));
    }
  });
  row.appendChild(btn);
};

// The startup update check races the page load: it can finish after the shell
// has closed its one-shot emit window (checked on this run — the notice was
// parked but never shown). So inside the shell, pull the parked notice until
// one is displayed instead of relying on a timed emit. Stops once a notice is
// shown, and the handler above dedupes anyway.
if (window.__TAURI__) {
  let pulls = 0;
  const pullNotice = () => {
    if (window.__lastUpdateMsg || pulls++ >= 120) return; // ~6 minutes
    window.__TAURI__.core
      .invoke('update_notice')
      .then((msg) => {
        if (msg) window.__blackroseUpdate(String(msg));
      })
      .catch(() => { /* shell not ready yet */ });
    setTimeout(pullNotice, 3000);
  };
  setTimeout(pullNotice, 1500);
}

// ---- Conversations sidebar ----
function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? '' : (d.getMonth() + 1) + '/' + d.getDate();
}
async function refreshSessions() {
  const listEl = document.getElementById('session-list');
  let sessions = [];
  try {
    const r = await fetch('/api/sessions', { headers: authHeaders() });
    sessions = (await r.json()).sessions || [];
  } catch { return; }
  listEl.innerHTML = '';
  const countEl = document.getElementById('g-count');
  if (countEl) countEl.textContent = sessions.length ? String(sessions.length) : '';
  for (const s of sessions) {
    const row = document.createElement('div');
    row.className = 'sess' + (CURRENT && s.id === CURRENT ? ' active' : '');
    const t = document.createElement('span'); t.className = 't'; t.textContent = s.title;
    const d = document.createElement('span'); d.className = 'd'; d.textContent = fmtDate(s.updated);
    const x = document.createElement('button'); x.className = 'x'; x.textContent = '✕'; x.title = 'Delete conversation';
    x.addEventListener('click', async e => {
      e.stopPropagation();
      if (!confirm('Delete "' + s.title.slice(0, 40) + '"? (archived to disk, recoverable)')) return;
      await fetch('/api/sessions/delete', {
        method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ id: s.id, session: SESSION }),
      });
      if (CURRENT === s.id) CURRENT = null;
      refreshSessions();
    });
    row.addEventListener('click', async () => {
      const r = await fetch('/api/sessions/open', {
        method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ id: s.id, session: SESSION }),
      });
      const j = await r.json();
      if (!j.ok) { el('activity', '⚠ could not open ' + s.id); return; }
      CURRENT = j.id;
      chat.innerHTML = '';
      el('activity', '📂 opened ' + s.id);
      for (const m of j.messages) {
        const text = typeof m.content === 'string' ? m.content
          : Array.isArray(m.content) ? m.content.filter(b => b.type === 'text').map(b => b.text).join(' ') : '';
        if (text) el('msg ' + (m.role === 'user' ? 'user' : 'ai'), text);
      }
      refreshSessions();
    });
    row.appendChild(t); row.appendChild(d); row.appendChild(x);
    listEl.appendChild(row);
  }
}
refreshSessions();
// Launch chooser (UI remodel): if a previous conversation exists, show a
// welcome-back dialog instead of silently resuming — Continue latest / pick
// from the recent list / New chat. No sessions → fresh welcome screen.
(async () => {
  let sessions = [];
  try {
    const r = await fetch('/api/sessions', { headers: authHeaders() });
    sessions = (await r.json()).sessions || [];
  } catch { return; } // offline — leave the fresh welcome screen
  if (!sessions.length) return;
  const launch = document.getElementById('launch');
  const list = document.getElementById('launch-list');
  launch.classList.remove('hidden');
  function openSession(id) {
    return fetch('/api/sessions/open', {
      method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ id: id, session: SESSION }),
    }).then(o => o.json()).then(j => {
      if (!j.ok) { el('activity', '⚠ could not open ' + id); return false; }
      CURRENT = j.id;
      chat.innerHTML = '';
      for (const m of j.messages) {
        const text = typeof m.content === 'string' ? m.content
          : Array.isArray(m.content) ? m.content.filter(b => b.type === 'text').map(b => b.text).join(' ') : '';
        if (text) el('msg ' + (m.role === 'user' ? 'user' : 'ai'), text);
      }
      refreshSessions();
      return true;
    });
  }
  function close() { launch.classList.add('hidden'); }
  // recent conversations to pick from (latest first, capped at 8)
  for (const s of sessions.slice(0, 8)) {
    const row = document.createElement('div');
    row.className = 'lrow';
    const t = document.createElement('span'); t.className = 'lt'; t.textContent = s.title;
    const d = document.createElement('span'); d.textContent = fmtDate(s.updated);
    row.appendChild(t); row.appendChild(d);
    row.addEventListener('click', async () => { if (await openSession(s.id)) close(); });
    list.appendChild(row);
  }
  document.getElementById('launch-continue').addEventListener('click', async () => {
    if (await openSession(sessions[0].id)) close();
  });
  document.getElementById('launch-new').addEventListener('click', () => {
    SESSION = 'tab-' + Math.random().toString(36).slice(2, 10);
    CURRENT = null;
    fetch('/api/new', {
      method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ session: SESSION }),
    }).then(refreshSessions).catch(() => {});
    close();
  });
})();
// Optional auth token, delivered via the #token= URL fragment (fragments are
// never sent to the server in request URLs). Read once, then scrub the
// address bar so the token does not linger in visible UI or shared links.
const TOKEN = (location.hash.match(/token=([^&]+)/) || [])[1] || '';
const authHeaders = () => (TOKEN ? { authorization: 'Bearer ' + TOKEN } : {});
if (TOKEN) history.replaceState(null, '', location.pathname + location.search);

function el(cls, text) {
  const d = document.createElement('div');
  d.className = cls;
  if (text !== undefined) d.textContent = text;
  chat.appendChild(d);
  chat.scrollTop = chat.scrollHeight;
  return d;
}

// ---- Route-status tray (UI remodel): one box per gateway route ----
function paintRouteTray(routes) {
  const tray = document.getElementById('route-tray');
  if (!tray) return;
  tray.innerHTML = '';
  const counts = {};
  (routes || []).forEach(r => { counts[r.name] = (counts[r.name] || 0) + 1; });
  for (const r of (routes || [])) {
    const box = document.createElement('span');
    box.className = 'route-box ' + r.state + (r.state === 'ok' ? ' pulse' : '');
    // when a provider name repeats (openai×5), disambiguate with a model hint
    const dup = counts[r.name] > 1 && r.model;
    const hint = dup ? r.model.split('/').pop().slice(0, 14) : '';
    box.textContent = hint ? r.name + ':' + hint : r.name;
    box.title = r.state.toUpperCase() + ' — ' + r.name + (r.model ? ' · ' + r.model : '') + (r.detail ? ' — ' + r.detail : '');
    tray.appendChild(box);
  }
}

// Sidebar memory stats. Repainted on every health poll so an import (which
// changes these numbers) shows up without a reload.
function paintStats(h) {
  const s = document.getElementById('stats');
  if (!s) return;
  s.innerHTML = '';
  const rows = [['Memories', h.memories], ['Knowledge chunks', h.knowledgeChunks], ['Schedules', h.schedules], ['Skills', h.skills]];
  for (const [k, v] of rows) {
    const d = document.createElement('div');
    d.className = 'stat';
    d.innerHTML = '<span>' + k + '</span><b>' + v + '</b>';
    s.appendChild(d);
  }
}

function pollHealth() {
  fetch('/api/health', { headers: authHeaders() }).then(r => r.json()).then(h => {
    document.getElementById('model-badge').textContent = h.provider + ' · ' + h.model;
    dot.classList.add('on');
    dot.title = 'connected';
    paintRouteTray(h.routes);
    paintStats(h);
  }).catch(() => { dot.title = 'offline'; });
}
pollHealth();
setInterval(pollHealth, 30000);

// ---- Drag-and-drop file input (UI remodel) ----
// Accepts ANY file type; shows the file path in the activity feed.
(function setupDropZone() {
  const zone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('audio-input');
  if (!zone || !fileInput) return;
  // Accept ANY file — no extension restriction
  const ACCEPT = /./i;
  let busy = false;

  async function uploadFile(file) {
    if (busy) return;
    busy = true;
    el('activity', '📎 uploading ' + file.name + ' (' + Math.round(file.size / 1024) + ' KB)…');
    try {
      const res = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'x-file-name': file.name, 'content-type': 'application/octet-stream', ...authHeaders() },
        body: file,
      });
      const j = await res.json();
      if (!j.ok) { el('activity', '⚠ upload failed'); busy = false; return; }
      el('activity', '✔ saved → ' + j.path + ' (' + file.name + ')');
      // Hand the path over ready to use: appended to the composer but NOT sent,
      // so the next message can be "learn this", "summarise this" or
      // "transcribe this". Typing it by hand was the whole friction.
      input.value = (input.value ? input.value + ' ' : '') + j.path;
      input.dispatchEvent(new Event('input'));
      input.focus();
    } catch (e) {
      el('activity', '⚠ upload error: ' + e.message);
    }
    busy = false;
  }

  zone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files[0]) uploadFile(fileInput.files[0]);
    fileInput.value = '';
  });
  ['dragenter', 'dragover'].forEach(ev => zone.addEventListener(ev, e => { e.preventDefault(); zone.classList.add('over'); }))
  ['dragleave', 'drop'].forEach(ev => zone.addEventListener(ev, e => { e.preventDefault(); zone.classList.remove('over'); }))
  zone.addEventListener('drop', e => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) uploadFile(f);
  });
})();

// ---- Push-to-talk mic (composer 🎤 button): local offline dictation ----
(function setupMic() {
  const mic = document.getElementById('mic');
  if (!mic) return;
  let listening = false;
  mic.addEventListener('click', async () => {
    if (listening) return;
    listening = true;
    mic.classList.add('listening');
    mic.textContent = '●';
    el('activity', '🎤 listening… speak now (up to 8s, offline local engine)');
    try {
      const res = await fetch('/api/listen', {
        method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ seconds: 8 }),
      });
      const d = await res.json();
      if (d.ok && d.text) {
        input.value = input.value ? input.value + ' ' + d.text : d.text;
        input.dispatchEvent(new Event('input'));
        input.focus();
        el('activity', '🎤 voice captured — edit if needed, then send');
      } else if (d.ok) {
        el('activity', '🎤 heard nothing — try again, and check the mic is the Windows default input');
      } else {
        el('activity', '🎤 ' + (d.detail || 'voice input failed'));
      }
    } catch (e) {
      el('activity', '🎤 voice input failed: ' + e.message);
    }
    listening = false;
    mic.classList.remove('listening');
    mic.textContent = '🎤';
  });
})();

document.querySelectorAll('aside button[data-mode]').forEach(b => {
  b.addEventListener('click', () => { mode = b.dataset.mode; el('activity', 'mode: ' + mode); });
});
document.getElementById('btn-new').addEventListener('click', () => {
  // Non-destructive "New chat": rekey this tab to a brand-new empty
  // conversation. The previous conversation stays persisted and visible
  // in the sidebar. /api/new on the NEW key just allocates the fresh
  // conversation server-side (nothing to archive).
  SESSION = 'tab-' + Math.random().toString(36).slice(2, 10);
  CURRENT = null;
  chat.innerHTML = '';
  el('msg ai', 'Started a new conversation — the previous one is saved in the sidebar.');
  fetch('/api/new', {
    method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ session: SESSION }),
  }).then(refreshSessions).catch(() => {});
});
// 🧹 Clear conversation: rekey to a fresh conversation too (the id used to be
// a duplicate of btn-new, which made this button dead — fixed with btn-clear).
document.getElementById('btn-clear').addEventListener('click', () => {
  SESSION = 'tab-' + Math.random().toString(36).slice(2, 10);
  CURRENT = null;
  chat.innerHTML = '';
  el('msg ai', 'Conversation cleared — the previous one is saved in the sidebar.');
  fetch('/api/new', {
    method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ session: SESSION }),
  }).then(refreshSessions).catch(() => {});
});

// ---- Generic prompt dialog (export / import / shut down) ----
// Resolves with { file, password } on OK, or null when cancelled. The caller
// decides which inputs are shown, so one dialog serves every action.
const modalEl = document.getElementById('modal');
const mTitle = document.getElementById('m-title');
const mMsg = document.getElementById('m-msg');
const mHint = document.getElementById('m-hint');
const mErr = document.getElementById('m-err');
const mFileField = document.getElementById('m-file-field');
const mFile = document.getElementById('m-file');
const mPassField = document.getElementById('m-pass-field');
const mPass = document.getElementById('m-pass');
const mOk = document.getElementById('m-ok');
const mCancel = document.getElementById('m-cancel');

function askModal(opts) {
  return new Promise((resolve) => {
    mTitle.textContent = opts.title || '';
    mMsg.textContent = opts.msg || '';
    mHint.textContent = opts.hint || '';
    mErr.textContent = '';
    mErr.classList.remove('show');
    mFileField.style.display = opts.file ? 'block' : 'none';
    mPassField.style.display = opts.password ? 'block' : 'none';
    mFile.value = '';
    mPass.value = '';
    mOk.textContent = opts.ok || 'OK';
    mOk.className = 'allow' + (opts.danger ? ' danger' : '');
    modalEl.classList.add('show');
    (opts.password ? mPass : mOk).focus();

    const close = (value) => {
      modalEl.classList.remove('show');
      mOk.removeEventListener('click', onOk);
      mCancel.removeEventListener('click', onCancel);
      document.removeEventListener('keydown', onKey);
      resolve(value);
    };
    const complain = (text) => { mErr.textContent = text; mErr.classList.add('show'); };
    const onOk = () => {
      const file = (mFile.files && mFile.files[0]) || null;
      if (opts.file && !file) return complain('Choose a .aistate file first.');
      if (opts.password && !mPass.value) return complain('A password is required — state holds private data.');
      close({ file, password: mPass.value });
    };
    const onCancel = () => close(null);
    const onKey = (e) => { if (e.key === 'Escape') onCancel(); };
    mOk.addEventListener('click', onOk);
    mCancel.addEventListener('click', onCancel);
    document.addEventListener('keydown', onKey);
  });
}

// Shared driver for the sidebar actions below: ask, run with the button
// disabled, report the outcome in the activity feed.
const runAction = (btn) => async (opts, work) => {
  const p = await askModal(opts);
  if (!p) return;
  btn.disabled = true;
  try {
    el('activity', await work(p));
  } catch (e) {
    el('activity', '⚠ ' + (e instanceof Error ? e.message : String(e)));
  } finally {
    btn.disabled = false;
  }
};

const btnExport = document.getElementById('btn-export');
const askExport = runAction(btnExport);
btnExport.addEventListener('click', () => askExport({
  title: '⬇ Export state',
  msg: 'Writes an encrypted snapshot of memories, knowledge, skills and schedules.',
  hint: 'The .aistate file is sealed with this password — keep it, or the backup cannot be restored.',
  password: true, ok: 'Export',
}, async (p) => {
  const res = await fetch('/api/export', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ password: p.password }),
  });
  const j = await res.json();
  if (!res.ok || !j.ok) throw new Error(j.error || ('HTTP ' + res.status));
  return 'exported ' + j.files + ' file(s), ' + Math.max(1, Math.round(j.bytes / 1024)) + ' KB → ' + j.path;
}));

const btnImport = document.getElementById('btn-import');
const askImport = runAction(btnImport);
btnImport.addEventListener('click', () => askImport({
  title: '⬆ Import state',
  msg: 'Restores memories, knowledge, skills and schedules from an encrypted .aistate backup.',
  hint: 'Matching files in your data folder are replaced. Conversations are not touched.',
  file: true, password: true, ok: 'Import', danger: true,
}, async (p) => {
  // The bytes are posted to the local core (a browser file picker hands over
  // content, not a path), which writes them next to the data folder first.
  const buf = await p.file.arrayBuffer();
  const res = await fetch('/api/import', {
    method: 'POST',
    headers: {
      'content-type': 'application/octet-stream',
      'x-file-name': p.file.name,
      'x-state-password': p.password,
      ...authHeaders(),
    },
    body: buf,
  });
  const j = await res.json();
  if (!res.ok || !j.ok) throw new Error(j.error || ('HTTP ' + res.status));
  pollHealth();  // the memory counters just changed
  return 'restored ' + j.restored + ' file(s) from ' + p.file.name;
}));

// 🔄 Check for update — the shell owns the updater, so this is a shell command.
// Its answer is rendered through the same path as the automatic notice (which
// is also what adds the "Install vX & restart" button).
const btnUpdate = document.getElementById('btn-update');
btnUpdate.addEventListener('click', async () => {
  if (!window.__TAURI__) {
    el('activity', 'update checks run inside the desktop app');
    return;
  }
  btnUpdate.disabled = true;
  el('activity', 'checking for updates…');
  try {
    const msg = await window.__TAURI__.core.invoke('update_check');
    window.__lastUpdateMsg = undefined;   // a manual check always re-renders
    if (window.__blackroseUpdate) window.__blackroseUpdate(String(msg));
  } catch (e) {
    el('activity', '⚠ update check failed: ' + (e instanceof Error ? e.message : String(e)));
  } finally {
    btnUpdate.disabled = false;
  }
});

// 🛑 Shut down — stops the core and closes the shell, so no daemon is left over.
const btnShutdown = document.getElementById('btn-shutdown');
btnShutdown.addEventListener('click', async () => {
  const p = await askModal({
    title: '🛑 Shut down BlackRose',
    msg: 'Stops the assistant and closes the window.',
    hint: 'Conversations and memory are already saved to disk. Running work is interrupted.',
    ok: 'Shut down', danger: true,
  });
  if (!p) return;
  el('activity', 'shutting down — the window will close');
  if (!window.__TAURI__) {
    el('activity', 'close this browser tab to stop the UI (the core keeps running here)');
    return;
  }
  btnShutdown.disabled = true;
  try {
    await window.__TAURI__.core.invoke('app_shutdown');
  } catch (e) {
    btnShutdown.disabled = false;
    el('activity', '⚠ shutdown failed: ' + (e instanceof Error ? e.message : String(e)));
  }
});

// ---- Capability inspector ------------------------------------------------
// The sidebar can show what the agent already knows and can do, by running
// READ-ONLY tools through POST /api/tool. The server holds a fixed allowlist,
// so these buttons can never mutate state or touch the machine — anything that
// does belongs in chat, where it can ask for approval first.
const panel = document.getElementById('panel');
const pnTitle = document.getElementById('pn-title');
const pnBody = document.getElementById('pn-body');
document.getElementById('pn-close').addEventListener('click', () => panel.classList.add('hidden'));
panel.addEventListener('click', (e) => { if (e.target === panel) panel.classList.add('hidden'); });

function showPanel(title, text) {
  pnTitle.textContent = title;
  pnBody.textContent = text;
  panel.classList.remove('hidden');
}

async function runTool(btn, title, tool, input) {
  const restore = btn.textContent;
  btn.disabled = true;
  btn.textContent = '…';
  try {
    const r = await fetch('/api/tool', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ name: tool, input: input || {} }),
    });
    const j = await r.json();
    showPanel(title, j.content || j.error || '(no output)');
  } catch (e) {
    showPanel(title, '⚠ ' + (e instanceof Error ? e.message : String(e)));
  } finally {
    btn.disabled = false;
    btn.textContent = restore;
  }
}

async function askQuery(btn, title, tool) {
  const q = prompt('Search query:');
  if (q === null) return;
  if (!q.trim()) { el('activity', '⚠ empty query — nothing searched'); return; }
  await runTool(btn, title, tool, { query: q.trim() });
}

const bind = (id, title, tool, input) => {
  const b = document.getElementById(id);
  if (b) b.addEventListener('click', () => runTool(b, title, tool, input));
};
const bindQ = (id, title, tool) => {
  const b = document.getElementById(id);
  if (b) b.addEventListener('click', () => askQuery(b, title, tool));
};

bind('btn-skills', '🧩 Skills', 'skill_list', {});
bind('btn-missions', '⏰ Scheduled missions', 'schedule_list', {});
bind('btn-jobs', '⚙️ Background jobs', 'job_list', {});
bind('btn-klist', '📚 Learned sources', 'knowledge_list', {});
bind('btn-projects', '📁 Project notes', 'project_read', {});
bindQ('btn-ksearch', '🔎 Knowledge search', 'knowledge_search');
bindQ('btn-msearch', '🧠 Memory search', 'memory_search');

// Tool catalogue: metadata only, straight from /api/tools (no tool is run).
document.getElementById('btn-toolcat').addEventListener('click', async (e) => {
  const b = e.currentTarget;
  b.disabled = true;
  try {
    const r = await fetch('/api/tools', { headers: authHeaders() });
    const j = await r.json();
    // NOTE: this page lives inside a TS template literal, so a JS newline escape
    // must be doubled here — a single one emits a REAL newline into the script
    // text and breaks parsing.
    const rows = (j.tools || []).map(t => (t.readOnly ? '[view] ' : '      ') + t.name);
    showPanel('🧰 Tool catalogue (' + (j.tools || []).length + ')', rows.join('\n'));
  } catch (err) {
    showPanel('🧰 Tool catalogue', '⚠ ' + (err instanceof Error ? err.message : String(err)));
  } finally {
    b.disabled = false;
  }
});

// In-app API Key Manager dialog
const keysModal = document.getElementById('keys-modal');
const keysList = document.getElementById('keys-list');
const btnKeys = document.getElementById('btn-keys');
const keysClose = document.getElementById('keys-close');

if (keysClose) keysClose.addEventListener('click', () => keysModal.classList.add('hidden'));
if (keysModal) keysModal.addEventListener('click', (e) => { if (e.target === keysModal) keysModal.classList.add('hidden'); });

async function loadKeysUI() {
  keysList.innerHTML = '<div style="color:var(--dim); font-size:12px;">Loading keys…</div>';
  try {
    const r = await fetch('/api/keys', { headers: authHeaders() });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || 'Failed to load keys');
    keysList.innerHTML = '';
    for (const k of j.keys) {
      const item = document.createElement('div');
      item.className = 'key-item';
      const top = document.createElement('div');
      top.className = 'top';
      const lbl = document.createElement('span');
      lbl.className = 'lbl';
      lbl.textContent = k.label;
      const st = document.createElement('span');
      st.className = 'status ' + (k.hasKey ? 'ok' : 'missing');
      st.textContent = k.hasKey ? ('configured (' + k.preview + ')') : 'not set';
      top.appendChild(lbl);
      top.appendChild(st);
      item.appendChild(top);

      const vr = document.createElement('div');
      vr.className = 'var';
      vr.textContent = k.envVar;
      item.appendChild(vr);

      const inRow = document.createElement('div');
      inRow.className = 'input-row';
      const inp = document.createElement('input');
      inp.type = 'password';
      inp.placeholder = k.hasKey ? 'Paste new key to update…' : 'Enter API key…';
      inp.autocomplete = 'off';
      const bSave = document.createElement('button');
      bSave.className = 'save';
      bSave.textContent = 'Save';
      bSave.addEventListener('click', async () => {
        const val = inp.value.trim();
        if (!val) return;
        bSave.disabled = true;
        try {
          const res = await fetch('/api/keys', {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...authHeaders() },
            body: JSON.stringify({ envVar: k.envVar, value: val }),
          });
          const resJ = await res.json();
          if (!resJ.ok) throw new Error(resJ.error || 'save failed');
          el('activity', '🔑 updated key for ' + k.label);
          await loadKeysUI();
          pollHealth();
        } catch (err) {
          alert('Failed to save key: ' + (err instanceof Error ? err.message : String(err)));
          bSave.disabled = false;
        }
      });

      inRow.appendChild(inp);
      inRow.appendChild(bSave);

      if (k.hasKey) {
        const bClear = document.createElement('button');
        bClear.className = 'clear';
        bClear.textContent = 'Clear';
        bClear.addEventListener('click', async () => {
          if (!confirm('Clear key for ' + k.label + '?')) return;
          bClear.disabled = true;
          try {
            const res = await fetch('/api/keys', {
              method: 'POST',
              headers: { 'content-type': 'application/json', ...authHeaders() },
              body: JSON.stringify({ envVar: k.envVar, value: '' }),
            });
            const resJ = await res.json();
            if (!resJ.ok) throw new Error(resJ.error || 'clear failed');
            el('activity', '🔑 cleared key for ' + k.label);
            await loadKeysUI();
            pollHealth();
          } catch (err) {
            alert('Failed to clear key: ' + (err instanceof Error ? err.message : String(err)));
            bClear.disabled = false;
          }
        });
        inRow.appendChild(bClear);
      }

      item.appendChild(inRow);
      keysList.appendChild(item);
    }
  } catch (e) {
    keysList.innerHTML = '<div style="color:var(--err); font-size:12px;">⚠ Error: ' + (e instanceof Error ? e.message : String(e)) + '</div>';
  }
}

if (btnKeys) {
  btnKeys.addEventListener('click', () => {
    keysModal.classList.remove('hidden');
    loadKeysUI();
  });
}

input.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); }
});
send.addEventListener('click', submit);
input.addEventListener('input', () => {
  input.style.height = 'auto';
  input.style.height = Math.min(input.scrollHeight, 160) + 'px';
});

async function submit() {
  const text = input.value.trim();
  if (!text || busy) return;
  busy = true; send.disabled = true; input.value = ''; input.style.height = 'auto';
  el('msg user', text);
  const think = el('msg ai thinking', 'working…');
  const route = mode === 'goal' ? '/api/goal' : '/api/ask';
  try {
    const res = await fetch(route, {
      method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ prompt: text, session: mode === 'goal' ? undefined : SESSION }),
    });
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const ev = JSON.parse(line);
        if (ev.type === 'tool') {
          el('activity', '⚙ ' + ev.name + ' ' + (ev.detail || ''));
          if (ev.name === 'session') {
            const m = (ev.detail || '').match(/resumed (S+)/);
            if (m) CURRENT = m[1];
          }
        }
        else if (ev.type === 'approval') await handleApproval(ev);
        else if (ev.type === 'text') think.textContent = ev.text;
        else if (ev.type === 'final') { think.remove(); el('msg ai', ev.text); }
        else if (ev.type === 'error') { think.remove(); el('msg ai', '⚠ ' + ev.text); }
      }
    }
  } catch (e) {
    think.remove();
    el('msg ai', '⚠ connection error: ' + e.message);
  }
  if (think.isConnected) think.remove();
  busy = false; send.disabled = false; input.focus();
  refreshSessions();
}

function handleApproval(ev) {
  return new Promise(resolve => {
    const ov = document.getElementById('overlay');
    document.getElementById('dl-reason').textContent = ev.tool + ': ' + (ev.reason || '');
    ov.classList.add('show');
    const done = allow => {
      ov.classList.remove('show');
      allowBtn.removeEventListener('click', onA);
      denyBtn.removeEventListener('click', onD);
      el('activity', (allow ? '✓ allowed' : '✗ denied') + ' — ' + ev.tool);
      fetch('/api/approve', {
        method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ id: ev.id, allow }),
      }).finally(resolve);
    };
    const allowBtn = document.getElementById('dl-allow');
    const denyBtn = document.getElementById('dl-deny');
    const onA = () => done(true);
    const onD = () => done(false);
    allowBtn.addEventListener('click', onA);
    denyBtn.addEventListener('click', onD);
  });
}
