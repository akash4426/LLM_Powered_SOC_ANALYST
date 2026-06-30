// src/pages/Investigate/Investigate.jsx
import { useState, useRef, useCallback, useEffect } from 'react';
import { investigate, investigateAgent } from '../../api/socApi';
import { SCENARIOS, AGENT_PHASES } from '../../constants/scenarios';
import { Upload, Trash2, Play, Info } from 'lucide-react';

import styles from './Investigate.module.css';
import AgentPhaseTracker from './components/AgentPhaseTracker';
import InvestigationConsole from './components/InvestigationConsole';
import EmptyState from './components/EmptyState';
import LoadingState from './components/LoadingState';

/* ── Feed helpers ─────────────────────────────────────────────── */
const MAX_FEED = 60;

export default function Investigate() {
  const [logs, setLogs] = useState('');
  const [filename, setFilename] = useState('');
  const [entityId, setEntityId] = useState('');
  const [activeScenario, setActiveScenario] = useState(null);

  const [status, setStatus] = useState('idle'); // idle | loading | success | error
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [pipeStep, setPipeStep] = useState(-1);

  const [feedEntries, setFeedEntries] = useState([
    { cls: 'feedSys', msg: 'System initialised' },
    { cls: 'feedSys', msg: 'MITRE ATT&CK DB loaded (ChromaDB)' },
    { cls: 'feedSys', msg: 'LSTM model: ready' },
    { cls: 'feedSys', msg: 'Awaiting investigation request…' },
  ]);

  const feedRef = useRef(null);
  const startRef = useRef(null);
  const timerRef = useRef(null);

  const addFeed = useCallback((cls, msg) => {
    setFeedEntries(prev => {
      const next = [...prev, { cls, msg }];
      return next.slice(-MAX_FEED);
    });
  }, []);

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [feedEntries]);

  /* ── Scenario load ── */
  const loadScenario = (key) => {
    const s = SCENARIOS[key];
    setLogs(s.logs);
    setActiveScenario(key);
    setFilename('');
    addFeed('feedInfo', `Loaded scenario: ${s.name}`);
  };

  /* ── File upload ── */
  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      setLogs(ev.target.result);
      setFilename(file.name);
      setActiveScenario(null);
      addFeed('feedInfo', `Uploaded: ${file.name}`);
    };
    reader.readAsText(file);
  };

  /* ── Pipeline animation ── */
  const animatePipeline = useCallback((stepCount) => {
    setPipeStep(0);
    let step = 0;
    // Spread steps evenly over an estimated analysis window (ms per step)
    const msPerStep = 4500;
    timerRef.current = setInterval(() => {
      step += 1;
      if (step >= stepCount) { clearInterval(timerRef.current); return; }
      setPipeStep(step);
      const labels = AGENT_PHASES.map(p => p.label);
      addFeed('feedCyan', `[Phase ${step}] ${labels[step-1] || 'Orchestration'} progressing...`);
    }, msPerStep);
  }, [addFeed]);

  /* ── Run investigation ── */
  const runInvestigation = async () => {
    if (!logs.trim()) {
      addFeed('feedError', 'No logs provided — load a scenario or paste logs');
      return;
    }
    setStatus('loading');
    setResult(null);
    setErrorMsg('');
    setPipeStep(0);
    startRef.current = Date.now();

    const stepCount = 8;
    addFeed('feedCyan', 'Starting investigation…');
    animatePipeline(stepCount);

    try {
      const data = await investigateAgent(logs, entityId || null);

      clearInterval(timerRef.current);
      setPipeStep(stepCount);

      const elapsed = ((Date.now() - startRef.current) / 1000).toFixed(1);
      const risk = data.risk_score || 0;
      addFeed('feedSuccess', `Investigation complete in ${elapsed}s — Risk Score: ${risk}/100`);

      setResult(data);
      setStatus('success');
    } catch (err) {
      clearInterval(timerRef.current);
      const msg = err?.response?.data?.detail || err.message || 'Unknown error';
      addFeed('feedError', `Investigation failed: ${msg}`);
      setErrorMsg(msg);
      setStatus('error');
    }
  };

  /* ── Keyboard shortcut ── */
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runInvestigation();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [logs, entityId]);

  const lineCount = logs ? logs.split('\n').length : 0;

  return (
    <div className={styles.page}>
      {/* ──────────────── LEFT PANEL ──────────────── */}
      <aside className={styles.leftPanel}>

        {/* Scenario picker */}
        <div className={styles.module}>
          <div className={styles.moduleHeader}>
            <span className={styles.moduleLabel}>PRELOADED SCENARIOS</span>
          </div>
          <div className={styles.scenarioList}>
            {Object.entries(SCENARIOS).map(([key, s]) => (
              <button
                key={key}
                className={`${styles.scenarioItem} ${activeScenario === key ? styles.active : ''}`}
                onClick={() => loadScenario(key)}
              >
                <span className={`${styles.scenarioTag} ${s.severity === 'CRITICAL' ? styles.tagCrit : styles.tagHigh}`}>
                  {s.severity.slice(0, 4)}
                </span>
                <span className={styles.scenarioName}>{s.name}</span>
                <span className={styles.scenarioMitre}>{s.mitre}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Log input */}
        <div className={`${styles.module} ${styles.moduleGrow}`}>
          <div className={styles.moduleHeader}>
            <span className={styles.moduleLabel}>RAW LOG INPUT</span>
            <div className={styles.moduleActions}>
              <label className={styles.uploadBtn} htmlFor="file-upload">
                <Upload size={10} />UPLOAD
              </label>
              <input
                id="file-upload"
                type="file"
                accept=".log,.txt,.csv,.json"
                style={{ display: 'none' }}
                onChange={handleFile}
              />
              <button className={styles.linkBtn} onClick={() => { setLogs(''); setFilename(''); setActiveScenario(null); }}>
                <Trash2 size={10} />
              </button>
            </div>
          </div>
          <div className={styles.terminalWrap}>
            <div className={styles.terminalChrome}>
              <span className={`${styles.tDot} ${styles.tRed}`} />
              <span className={`${styles.tDot} ${styles.tAmber}`} />
              <span className={`${styles.tDot} ${styles.tGreen}`} />
              <span className={styles.tPrompt}>analyst@soc ~ logs</span>
              {filename && <span className={styles.tFilename}>{filename}</span>}
            </div>
            <textarea
              className={styles.textarea}
              value={logs}
              onChange={e => setLogs(e.target.value)}
              placeholder={`Paste raw security logs here…\n\nSupported formats:\n  · Syslog / auth.log\n  · JSON event objects\n  · CSV log exports\n  · Windows Event Log text`}
              spellCheck={false}
            />
            <div className={styles.termFoot}>
              <span className={styles.termStat}>{lineCount} lines</span>
              <span className={styles.termStat}>{logs.length} chars</span>
            </div>
          </div>
        </div>

        {/* Agent Specialists */}
        <div className={styles.module}>
          <div className={styles.moduleHeader}>
            <span className={styles.moduleLabel}>ORCHESTRATOR SPECIALISTS</span>
          </div>
          <div className={styles.stackTable}>
            {[
              ['BEHAVIOR', 'LSTM behavioral scoring'],
              ['PATTERN', 'Heuristic attack patterns'],
              ['THREAT CTX', 'IP/hash reputation'],
              ['IOC ANALYST', 'Automated extraction'],
              ['MITRE RAG', 'ATT&CK semantic search'],
              ['ORCHESTRATOR', 'ReAct cross-session agent'],
            ].map(([k, v]) => (
              <div className={styles.stackRow} key={k}>
                <span className={styles.stackKey}>{k}</span>
                <span className={styles.stackVal}>{v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Agent Config */}
        <div className={styles.module}>
          <div className={styles.moduleHeader}>
            <span className={styles.moduleLabel}>AGENT CONFIGURATION</span>
          </div>
          <div className={styles.agentConfig}>
            <input
              type="text"
              className={styles.agentInput}
              placeholder="Entity ID (auto-detect)"
              value={entityId}
              onChange={e => setEntityId(e.target.value)}
            />
            <div className={styles.agentInfo}>
              <Info size={10} />
              <span>Submit multiple sessions for same entity to see cross-session correlation</span>
            </div>
          </div>
        </div>

        {/* Run button */}
        <button
          className={styles.runBtn}
          onClick={runInvestigation}
          disabled={status === 'loading'}
        >
          {status === 'loading' ? (
            <><span className={styles.spinner} />ANALYSING…</>
          ) : (
            <><Play size={14} strokeWidth={2.5} />RUN INVESTIGATION<span className={styles.runKbd}>⌘↵</span></>
          )}
        </button>

      </aside>

      {/* ──────────────── CENTER PANEL ──────────────── */}
      <main className={styles.centerPanel}>
        {status === 'idle' && <EmptyState />}
        {status === 'loading' && <LoadingState pipeStep={pipeStep} startTime={startRef.current} />}
        {status === 'success' && result && (
          <InvestigationConsole data={result} />
        )}
        {status === 'error' && (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 32, color: 'var(--red)', opacity: 0.4 }}>ERR</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--red)' }}>INVESTIGATION FAILED</div>
            <div style={{ fontSize: 12, color: 'var(--text-2)', maxWidth: 400, textAlign: 'center' }}>{errorMsg}</div>
            <button onClick={() => setStatus('idle')} style={{ marginTop: 8, padding: '8px 20px', background: 'rgba(255,68,68,0.1)', border: '1px solid rgba(255,68,68,0.3)', borderRadius: 6, color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: 11, cursor: 'pointer', letterSpacing: '0.06em' }}>RETRY</button>
          </div>
        )}
      </main>

      {/* ──────────────── RIGHT PANEL ──────────────── */}
      <aside className={styles.rightPanel}>

        {/* Event taxonomy */}
        <div className={styles.module}>
          <div className={styles.moduleHeader}>
            <span className={styles.moduleLabel}>EVENT TAXONOMY</span>
          </div>
          <div className={styles.taxonomyList}>
            {[
              ['EXFIL', '#ff4444', 'Data exfiltration'],
              ['EVADE', '#ff6b35', 'Defense evasion'],
              ['LATMOV', '#ff9800', 'Lateral movement'],
              ['SUSEXEC', '#ffd740', 'Suspicious execution'],
              ['PRIVESC', '#c6ff00', 'Privilege escalation'],
              ['RECON', '#69ff47', 'Reconnaissance'],
              ['OUTCONN', '#18ffff', 'Outbound connection'],
              ['FILEACC', '#4488ff', 'File access'],
              ['LOGIN', '#aa66ff', 'Authentication event'],
              ['NORMAL', '#546e7a', 'Benign activity'],
            ].map(([code, color, desc]) => (
              <div className={styles.taxRow} key={code}>
                <span className={styles.taxCode} style={{ background: `${color}18`, color, border: `1px solid ${color}40` }}>{code}</span>
                <span className={styles.taxDesc}>{desc}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Detection feed */}
        <div className={`${styles.module} ${styles.moduleGrow}`}>
          <div className={styles.moduleHeader}>
            <span className={styles.moduleLabel}>DETECTION LOG</span>
            <button className={styles.linkBtn} onClick={() => setFeedEntries([])}>CLR</button>
          </div>
          <div className={styles.feed} ref={feedRef}>
            {feedEntries.map((e, i) => (
              <div key={i} className={`${styles.feedEntry} ${styles[e.cls]}`}>{e.msg}</div>
            ))}
          </div>
        </div>

        {/* Severity scale */}
        <div className={styles.module}>
          <div className={styles.moduleHeader}>
            <span className={styles.moduleLabel}>SEVERITY SCALE</span>
          </div>
          <div className={styles.sevScale}>
            {[
              ['CRITICAL', 'sevC', 'Immediate containment'],
              ['HIGH', 'sevH', 'Urgent triage & response'],
              ['MEDIUM', 'sevM', 'Investigate within 4h'],
              ['LOW', 'sevL', 'Log and monitor'],
            ].map(([label, cls, desc]) => (
              <div className={styles.sevRow} key={label}>
                <span className={`${styles.sevBadge} ${styles[cls]}`}>{label}</span>
                <span className={styles.sevDesc}>{desc}</span>
              </div>
            ))}
          </div>
        </div>

      </aside>
    </div>
  );
}
