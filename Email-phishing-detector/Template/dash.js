const state = {
  scanned: 0, threats: 0, headerFails: 0, clean: 0,
  vtHits: 0, spfFails: 0, dkimFails: 0,
  threatLog: [],
  allEmails: [],
  scanHistory: [],       // [{safe,threat}, ...] last 7
  autoTimer: null,
  scanRunning: false,
};

// ─────────────────────────────────────────────
//  Clock
// ─────────────────────────────────────────────
setInterval(() => {
  document.getElementById('clock').textContent =
    new Date().toLocaleTimeString('en-GB', {hour12: false});
}, 1000);
document.getElementById('clock').textContent =
  new Date().toLocaleTimeString('en-GB', {hour12: false});

// ─────────────────────────────────────────────
//  Navigation
// ─────────────────────────────────────────────
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  document.querySelector(`[data-page="${name}"]`).classList.add('active');
  if (name === 'config') refreshEnvPreview();
}
document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => showPage(el.dataset.page));
});

// ─────────────────────────────────────────────
//  Toast
// ─────────────────────────────────────────────
function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ─────────────────────────────────────────────
//  Terminal log
// ─────────────────────────────────────────────
function logLine(text, cls = '') {
  const t = document.getElementById('terminal-log');
  const now = new Date().toLocaleTimeString('en-GB', {hour12:false});
  t.innerHTML += `\n<span class="t-time">[${now}]</span> <span class="${cls}">${text}</span>`;
  t.scrollTop = t.scrollHeight;
}

function scanLog(text, cls = '') {
  const t = document.getElementById('scan-terminal');
  if (!t) return;
  const now = new Date().toLocaleTimeString('en-GB', {hour12:false});
  t.innerHTML += `<span class="t-time">[${now}]</span> <span class="${cls}">${text}</span>\n`;
  t.scrollTop = t.scrollHeight;
}

function clearLog() {
  document.getElementById('terminal-log').innerHTML =
    '<span class="t-info">// Log cleared.</span>';
}

// ─────────────────────────────────────────────
//  Stats update
// ─────────────────────────────────────────────
function updateStats() {
  document.getElementById('stat-scanned').textContent    = state.scanned;
  document.getElementById('stat-threats').textContent    = state.threats;
  document.getElementById('stat-header-fail').textContent= state.headerFails;
  document.getElementById('stat-clean').textContent      = state.clean;
  document.getElementById('threat-badge').textContent    = state.threats;
  document.getElementById('threat-count-label').textContent = state.threatLog.length + ' records';
  document.getElementById('leg-vt').textContent   = state.vtHits;
  document.getElementById('leg-spf').textContent  = state.spfFails;
  document.getElementById('leg-dkim').textContent = state.dkimFails;
  document.getElementById('leg-clean').textContent= state.clean;
  updateDonut();
  updateBarChart();
}

function updateDonut() {
  const total = state.vtHits + state.spfFails + state.dkimFails + state.clean;
  if (total === 0) return;
  const circ = 201;
  function seg(val) { return (val / total) * circ; }
  const vtSeg   = seg(state.vtHits);
  const spfSeg  = seg(state.spfFails);
  const dkimSeg = seg(state.dkimFails);

  document.getElementById('donut-vt').setAttribute('stroke-dasharray',   `${vtSeg} ${circ - vtSeg}`);
  document.getElementById('donut-spf').setAttribute('stroke-dasharray',  `${spfSeg} ${circ - spfSeg}`);
  document.getElementById('donut-spf').setAttribute('stroke-dashoffset', -vtSeg);
  document.getElementById('donut-dkim').setAttribute('stroke-dasharray', `${dkimSeg} ${circ - dkimSeg}`);
  document.getElementById('donut-dkim').setAttribute('stroke-dashoffset',-(vtSeg + spfSeg));
}

function updateBarChart() {
  const chart = document.getElementById('bar-chart');
  if (state.scanHistory.length === 0) {
    chart.innerHTML = '<div class="empty">No scan data yet</div>';
    return;
  }
  const maxTotal = Math.max(...state.scanHistory.map(s => s.safe + s.threat), 1);
  chart.innerHTML = state.scanHistory.slice(-7).map((s, i) => {
    const safeH   = Math.round((s.safe / maxTotal) * 80);
    const threatH = Math.round((s.threat / maxTotal) * 80);
    return `<div class="bar-col">
      <div class="bar threat" style="height:${threatH}px"></div>
      <div class="bar safe"   style="height:${safeH}px"></div>
      <div class="bar-lbl">#${i+1}</div>
    </div>`;
  }).join('');
}

// ─────────────────────────────────────────────
//  Tables
// ─────────────────────────────────────────────
function spfBadge(r) {
  const map = {pass:'pass', softfail:'warn', fail:'fail', neutral:'none'};
  return `<span class="badge ${map[r]||'none'}">${r||'—'}</span>`;
}
function dkimBadge(r) {
  const map = {pass:'pass', fail:'fail', none:'none'};
  return `<span class="badge ${map[r]||'none'}">${r||'—'}</span>`;
}
function scoreColor(s) {
  if (s >= 5) return 'var(--red)';
  if (s >= 3) return 'var(--amber)';
  return 'var(--green)';
}
function scoreBar(s) {
  const pct = Math.min((s / 11) * 100, 100);
  const col = s >= 5 ? 'var(--red)' : s >= 3 ? 'var(--amber)' : 'var(--green)';
  return `<div class="score-bar-wrap">
    <div class="score-bar-track">
      <div class="score-bar-fill" style="width:${pct}%;background:${col}"></div>
    </div>
    <span class="score-num" style="color:${col}">${s}</span>
  </div>`;
}

function rebuildThreatTable() {
  const tbody = document.getElementById('threat-tbody');
  const recent = document.getElementById('recent-tbody');
  if (state.threatLog.length === 0) {
    tbody.innerHTML  = '<tr><td colspan="8" style="text-align:center;color:var(--text3);font-family:var(--mono);padding:40px">No threats logged yet</td></tr>';
    recent.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text3);font-family:var(--mono);padding:28px">No threats detected yet</td></tr>';
    return;
  }
  const rows = state.threatLog.map((e, i) => `
    <tr>
      <td class="mono">${e.time}</td>
      <td class="sender">${e.from}</td>
      <td class="subject">${e.subject}</td>
      <td>${spfBadge(e.spf)}</td>
      <td>${dkimBadge(e.dkim)}</td>
      <td>${e.vt ? '<span class="badge fail">hit</span>' : '<span class="badge none">clean</span>'}</td>
      <td>${scoreBar(e.score)}</td>
      <td><button class="btn btn-ghost" style="font-size:10px;padding:3px 8px" onclick="openModal(${i})">detail</button></td>
    </tr>`).join('');
  tbody.innerHTML = rows;

  const recentRows = state.threatLog.slice(-5).reverse().map((e, i) => `
    <tr>
      <td class="mono">${e.time}</td>
      <td class="sender">${e.from}</td>
      <td class="subject">${e.subject}</td>
      <td>${spfBadge(e.spf)}</td>
      <td>${dkimBadge(e.dkim)}</td>
      <td>${scoreBar(e.score)}</td>
      <td><button class="btn btn-ghost" style="font-size:10px;padding:3px 8px" onclick="openModal(${state.threatLog.length - 5 + i})">→</button></td>
    </tr>`).join('');
  recent.innerHTML = recentRows;
}

function rebuildAllTable() {
  const tbody = document.getElementById('all-tbody');
  if (state.allEmails.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text3);font-family:var(--mono);padding:32px">No emails scanned yet</td></tr>';
    return;
  }
  tbody.innerHTML = state.allEmails.slice().reverse().map(e => `
    <tr>
      <td class="mono">${e.time}</td>
      <td class="sender">${e.from}</td>
      <td class="subject">${e.subject}</td>
      <td>${spfBadge(e.spf)}</td>
      <td>${dkimBadge(e.dkim)}</td>
      <td>${scoreBar(e.score)}</td>
      <td>${e.threat ? '<span class="badge fail">THREAT</span>' : '<span class="badge pass">CLEAN</span>'}</td>
    </tr>`).join('');
}

// ─────────────────────────────────────────────
//  Modal
// ─────────────────────────────────────────────
function openModal(idx) {
  const e = state.threatLog[idx];
  if (!e) return;
  document.getElementById('modal-body').innerHTML = `
    <div class="detail-row"><div class="detail-key">Time</div><div class="detail-val mono">${e.time}</div></div>
    <div class="detail-row"><div class="detail-key">From</div><div class="detail-val">${e.from}</div></div>
    <div class="detail-row"><div class="detail-key">Subject</div><div class="detail-val">${e.subject}</div></div>
    <div class="detail-row"><div class="detail-key">SPF</div><div class="detail-val">${spfBadge(e.spf)}</div></div>
    <div class="detail-row"><div class="detail-key">DKIM</div><div class="detail-val">${dkimBadge(e.dkim)}</div></div>
    <div class="detail-row"><div class="detail-key">VirusTotal</div><div class="detail-val">${e.vt ? '<span class="badge fail">Malicious URL detected</span>' : '<span class="badge pass">No malicious URLs</span>'}</div></div>
    <div class="detail-row"><div class="detail-key">Score</div><div class="detail-val">${scoreBar(e.score)}</div></div>
    <div class="detail-row"><div class="detail-key">Flags</div><div class="detail-val">${(e.flags||[]).map(f => `<div>• ${f}</div>`).join('') || '—'}</div></div>
    <div class="detail-row"><div class="detail-key">Action</div><div class="detail-val"><span class="badge fail">Quarantined + Alerted</span></div></div>
  `;
  document.getElementById('modal').classList.add('open');
}
function closeModal() { document.getElementById('modal').classList.remove('open'); }
document.getElementById('modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });

// ─────────────────────────────────────────────
//  Clear threats
// ─────────────────────────────────────────────
function clearThreats() {
  state.threatLog = [];
  state.threats = 0;
  rebuildThreatTable();
  updateStats();
  toast('Threat log cleared.', 'info');
}

// ─────────────────────────────────────────────
//  Simulation data
// ─────────────────────────────────────────────
const FAKE_SENDERS = [
  'support@paypal-secure.xyz', 'noreply@amazon-login.info',
  'alerts@bankofamerica.verify-now.com', 'admin@microsoft365-update.net',
  'no-reply@apple.com', 'newsletter@github.com',
  'hr@yourcompany.com', 'boss@outlook.com',
];
const FAKE_SUBJECTS = [
  'Urgent: Your account has been suspended',
  'Verify your identity immediately',
  'You have a pending security alert',
  'Meeting notes — Q3 planning',
  'Your invoice is ready',
  'Action required: Update your password',
  'Re: Project deadline',
  'Congratulations! You have been selected',
];
const SPF_RESULTS  = ['pass','pass','pass','fail','softfail','neutral'];
const DKIM_RESULTS = ['pass','pass','pass','fail','none'];

function fakeEmail() {
  const idx = Math.floor(Math.random() * FAKE_SENDERS.length);
  const spf  = SPF_RESULTS[Math.floor(Math.random() * SPF_RESULTS.length)];
  const dkim = DKIM_RESULTS[Math.floor(Math.random() * DKIM_RESULTS.length)];
  const vt   = Math.random() < 0.25;
  let score = 0;
  const flags = [];
  if (dkim === 'fail') { score += 3; flags.push('DKIM signature invalid'); }
  else if (dkim === 'none') { score += 1; flags.push('No DKIM signature'); }
  if (spf === 'fail') { score += 3; flags.push('SPF hard fail'); }
  else if (spf === 'softfail') { score += 1; flags.push('SPF soft fail'); }
  if (vt) { score += 5; flags.push('Malicious URL detected by VirusTotal'); }
  return {
    from: FAKE_SENDERS[idx],
    subject: FAKE_SUBJECTS[Math.floor(Math.random() * FAKE_SUBJECTS.length)],
    spf, dkim, vt, score, flags,
    time: new Date().toLocaleTimeString('en-GB', {hour12:false}),
    threat: score >= parseInt(document.getElementById('thresh-slider').value),
  };
}

// ─────────────────────────────────────────────
//  Simulate scan
// ─────────────────────────────────────────────
async function simulateScan() {
  if (state.scanRunning) return;
  state.scanRunning = true;

  const btn = document.getElementById('run-btn');
  const panel = document.getElementById('scan-progress-panel');
  const st = document.getElementById('scan-terminal');
  panel.style.display = 'block';
  st.innerHTML = '';

  const dot = document.getElementById('pulse-dot');
  dot.className = 'pulse scanning';
  document.getElementById('status-text').textContent = 'SCANNING';

  const count = parseInt(document.getElementById('max-emails').value);
  const mode  = document.getElementById('scan-mode').value;
  const thresh = parseInt(document.getElementById('thresh-slider').value);

  scanLog('Connecting to IMAP server...', 't-info');
  await delay(400);
  scanLog('✅ IMAP login successful.', 't-ok');
  await delay(300);
  scanLog(`📨 ${count} unread email(s) fetched.`, 't-info');
  await delay(200);

  let safeCount = 0, threatCount = 0;

  for (let i = 0; i < count; i++) {
    const em = fakeEmail();
    await delay(300 + Math.random() * 300);

    scanLog(`─── Email ${i+1}/${count}: ${em.from}`, '');

    if (mode === 'full' || mode === 'headers') {
      await delay(200);
      const spfIcon = em.spf === 'pass' ? 't-ok' : em.spf === 'softfail' ? 't-warn' : 't-err';
      scanLog(`   SPF: ${em.spf}`, spfIcon);
      await delay(150);
      const dkimIcon = em.dkim === 'pass' ? 't-ok' : 't-warn';
      scanLog(`   DKIM: ${em.dkim}`, dkimIcon);
    }

    if (mode === 'full' || mode === 'urls') {
      await delay(250);
      scanLog(`   VirusTotal: ${em.vt ? 'MALICIOUS URL FOUND' : 'clean'}`, em.vt ? 't-err' : 't-ok');
    }

    await delay(100);
    scanLog(`   Score: ${em.score} | Threshold: ${thresh}`, em.threat ? 't-warn' : '');

    if (em.threat) {
      scanLog(`   🚨 QUARANTINED — alert sent.`, 't-err');
      state.threats++;
      state.threatLog.push(em);
      threatCount++;
      logLine(`Threat quarantined: ${em.from} | score ${em.score}`, 't-err');
    } else {
      scanLog(`   ✅ Clean.`, 't-ok');
      safeCount++;
      logLine(`Clean: ${em.from}`, 't-ok');
    }

    if (em.spf !== 'pass') state.spfFails++;
    if (em.dkim !== 'pass') state.dkimFails++;
    if (em.vt) state.vtHits++;
    if (!em.threat) state.clean++;
    if (em.spf !== 'pass' || em.dkim !== 'pass') state.headerFails++;

    state.scanned++;
    state.allEmails.push(em);
    updateStats();
    rebuildThreatTable();
    rebuildAllTable();
  }

  state.scanHistory.push({ safe: safeCount, threat: threatCount });
  updateBarChart();

  await delay(200);
  scanLog(`\n✅ Scan complete. ${threatCount} threat(s) found, ${safeCount} clean.`, 't-ok');
  logLine(`Scan complete. ${threatCount} threats / ${safeCount} clean.`, 't-info');

  dot.className = 'pulse';
  document.getElementById('status-text').textContent = 'IDLE';
  state.scanRunning = false;

  toast(`Scan done — ${threatCount} threat(s) found.`, threatCount > 0 ? 'err' : 'ok');
}

async function runScan() {
  toast('This dashboard simulates scanning. Connect main.py to add real Gmail output.', 'info');
  await simulateScan();
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─────────────────────────────────────────────
//  Auto-scheduler
// ─────────────────────────────────────────────
function toggleAutoScan(on) {
  if (on) {
    startScheduler();
  } else {
    stopScheduler();
  }
}

function startScheduler() {
  const mins = parseInt(document.getElementById('interval-slider').value);
  document.getElementById('scheduler-status').innerHTML =
    `<span style="color:var(--green)">● RUNNING</span> — every ${mins} min`;
  updateNextRun(mins);
  if (state.autoTimer) clearInterval(state.autoTimer);
  state.autoTimer = setInterval(() => {
    simulateScan();
    updateNextRun(mins);
  }, mins * 60 * 1000);
  logLine(`Auto-scheduler started — interval ${mins} min.`, 't-info');
  toast(`Scheduler started. Next scan in ${mins} min.`, 'ok');
}

function stopScheduler() {
  if (state.autoTimer) { clearInterval(state.autoTimer); state.autoTimer = null; }
  document.getElementById('scheduler-status').innerHTML = `<span style="color:var(--text3)">● STOPPED</span>`;
  document.getElementById('next-run').textContent = '—';
  document.getElementById('auto-scan-toggle').checked = false;
  logLine('Auto-scheduler stopped.', 't-warn');
  toast('Scheduler stopped.', 'info');
}

function updateNextRun(mins) {
  const next = new Date(Date.now() + mins * 60 * 1000);
  document.getElementById('next-run').textContent =
    next.toLocaleTimeString('en-GB', {hour12:false});
}

// ─────────────────────────────────────────────
//  Settings
// ─────────────────────────────────────────────
function saveSettings() {
  toast('Settings saved.', 'ok');
  logLine('Settings updated by user.', 't-info');
}
function resetSettings() {
  document.getElementById('thresh-slider').value = 3;
  document.getElementById('thresh-val').textContent = '3';
  document.getElementById('tog-spf').checked = true;
  document.getElementById('tog-dkim').checked = true;
  document.getElementById('tog-vt').checked = true;
  document.getElementById('tog-quarantine').checked = true;
  document.getElementById('tog-alert').checked = true;
  toast('Settings reset to defaults.', 'info');
}

// ─────────────────────────────────────────────
//  Config / .env
// ─────────────────────────────────────────────
function mask(val) {
  if (!val) return '""';
  if (val.length <= 4) return '"****"';
  return '"' + val.slice(0,2) + '*'.repeat(Math.min(val.length-2, 6)) + '"';
}

function refreshEnvPreview() {
  const e  = document.getElementById('cfg-email').value;
  const p  = document.getElementById('cfg-pass').value;
  const im = document.getElementById('cfg-imap').value || 'imap.gmail.com';
  const ip = document.getElementById('cfg-imap-port').value || '993';
  const ae = document.getElementById('cfg-alert-email').value;
  const su = document.getElementById('cfg-smtp-user').value;
  const sp = document.getElementById('cfg-smtp-pass').value;
  const vt = document.getElementById('cfg-vt-key').value;

  document.getElementById('env-preview').innerHTML =
    `<span class="env-key">EMAIL_ADDRESS</span><span class="env-eq">=</span><span class="env-val">"${e || 'your@gmail.com'}"</span>
<span class="env-key">EMAIL_PASSWORD</span><span class="env-eq">=</span><span class="env-mask">${mask(p)}</span>
<span class="env-key">IMAP_SERVER</span><span class="env-eq">=</span><span class="env-val">"${im}"</span>
<span class="env-key">IMAP_PORT</span><span class="env-eq">=</span><span class="env-val">${ip}</span>

<span class="env-key">ALERT_EMAIL</span><span class="env-eq">=</span><span class="env-val">"${ae || 'security@yourorg.com'}"</span>
<span class="env-key">SMTP_USER</span><span class="env-eq">=</span><span class="env-val">"${su || 'sender@gmail.com'}"</span>
<span class="env-key">SMTP_PASSWORD</span><span class="env-eq">=</span><span class="env-mask">${mask(sp)}</span>
<span class="env-key">SMTP_SERVER</span><span class="env-eq">=</span><span class="env-val">"smtp.gmail.com"</span>
<span class="env-key">SMTP_PORT</span><span class="env-eq">=</span><span class="env-val">587</span>

<span class="env-key">VIRUSTOTAL_API_KEY</span><span class="env-eq">=</span><span class="env-mask">${mask(vt)}</span>`;
}

function generateEnv() {
  const e  = document.getElementById('cfg-email').value;
  const p  = document.getElementById('cfg-pass').value;
  const im = document.getElementById('cfg-imap').value || 'imap.gmail.com';
  const ip = document.getElementById('cfg-imap-port').value || '993';
  const ae = document.getElementById('cfg-alert-email').value;
  const su = document.getElementById('cfg-smtp-user').value;
  const sp = document.getElementById('cfg-smtp-pass').value;
  const vt = document.getElementById('cfg-vt-key').value;

  const content = [
    `EMAIL_ADDRESS="${e}"`,
    `EMAIL_PASSWORD="${p}"`,
    `IMAP_SERVER="${im}"`,
    `IMAP_PORT=${ip}`,
    ``,
    `ALERT_EMAIL="${ae}"`,
    `SMTP_USER="${su}"`,
    `SMTP_PASSWORD="${sp}"`,
    `SMTP_SERVER="smtp.gmail.com"`,
    `SMTP_PORT=587`,
    ``,
    `VIRUSTOTAL_API_KEY="${vt}"`,
  ].join('\n');

  const blob = new Blob([content], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = '.env';
  a.click();
  toast('.env file downloaded.', 'ok');
}

function copyEnv() {
  const text = document.getElementById('env-preview').innerText;
  navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard.', 'ok'));
}

// ─────────────────────────────────────────────
//  Live .env preview on input
// ─────────────────────────────────────────────
['cfg-email','cfg-pass','cfg-imap','cfg-imap-port',
 'cfg-alert-email','cfg-smtp-user','cfg-smtp-pass','cfg-vt-key']
.forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('input', refreshEnvPreview);
});

// Init
refreshEnvPreview();
updateStats();