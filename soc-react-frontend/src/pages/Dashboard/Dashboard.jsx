// src/pages/Dashboard/Dashboard.jsx
import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../context/AuthContext';
import { getDashboardStats, evaluate } from '../../api/socApi';
import { SPECIALISTS, AGENT_PHASES } from '../../constants/scenarios';
import {
  Shield, Activity, Cpu, Database, Zap, Target, BarChart2,
  Clock, GitBranch, AlertTriangle, CheckCircle2, Circle,
  ArrowRight, Terminal, Layers, RefreshCw
} from 'lucide-react';
import styles from './Dashboard.module.css';

/* ── Ring Chart ── */
function RingChart({ value, max = 1, color, size = 90, label, sublabel }) {
  const r = 40;
  const circumference = 2 * Math.PI * r;
  const pct = Math.min(value / max, 1);
  const offset = circumference * (1 - pct);
  return (
    <div className={styles.ringWrap}>
      <svg width={size} height={size} viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--border-2)" strokeWidth="9" />
        <circle
          cx="50" cy="50" r={r} fill="none"
          stroke={color} strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={styles.ringFill}
        />
      </svg>
      <div className={styles.ringCenter}>
        <div className={styles.ringVal} style={{ color }}>{label}</div>
        {sublabel && <div className={styles.ringSubLabel}>{sublabel}</div>}
      </div>
    </div>
  );
}

/* ── Stat Card ── */
function StatCard({ icon: Icon, label, value, sub, color, delay = 0 }) {
  return (
    <div className={styles.statCard} style={{ animationDelay: `${delay}ms` }}>
      <div className={styles.statIcon} style={{ background: `${color}15`, border: `1px solid ${color}30` }}>
        <Icon size={16} color={color} />
      </div>
      <div className={styles.statBody}>
        <div className={styles.statVal} style={{ color }}>{value}</div>
        <div className={styles.statLabel}>{label}</div>
        {sub && <div className={styles.statSub}>{sub}</div>}
      </div>
    </div>
  );
}

/* ── Specialist Card ── */
function AgentCard({ agent, delay = 0 }) {
  return (
    <div className={styles.agentCard} style={{ animationDelay: `${delay}ms` }}>
      <div className={styles.agentHeader}>
        <div className={styles.agentId} style={{ color: agent.color }}>{String(agent.id).padStart(2,'0')}</div>
        <div className={styles.agentPhaseBadge} style={{ background: `${agent.color}18`, color: agent.color, border: `1px solid ${agent.color}35` }}>
          SPECIALIST
        </div>
      </div>
      <div className={styles.agentName}>{agent.name}</div>
      <div className={styles.agentRole}>{agent.role}</div>
      <div className={styles.agentWeightRow}>
        <div className={styles.agentWeightTrack}>
          <div className={styles.agentWeightFill} style={{ width: '80%', background: `linear-gradient(90deg, ${agent.color}99, ${agent.color})` }} />
        </div>
        <span className={styles.agentWeightPct} style={{ color: agent.color }}>ON-DEMAND</span>
      </div>
    </div>
  );
}

/* ── Pipeline Stage ── */
function PipelineRow({ step, i, active }) {
  return (
    <div className={`${styles.pipeRow} ${active ? styles.pipeActive : ''}`} style={{ animationDelay: `${i * 60}ms` }}>
      <div className={styles.pipeNum}>{String(i + 1).padStart(2, '0')}</div>
      <div className={styles.pipeIcon}>{step.icon}</div>
      <div className={styles.pipeInfo}>
        <div className={styles.pipeLabel}>{step.label}</div>
        <div className={styles.pipeDesc}>{step.desc}</div>
      </div>
      {active && <div className={styles.pipeDot} />}
    </div>
  );
}

/* ── ReAct Flow Diagram ── */
function ReActFlow() {
  const phases = [
    { id: 'observe',   label: 'OBSERVE',   color: 'var(--blue)',   desc: 'Collect facts' },
    { id: 'think',     label: 'THINK',     color: 'var(--purple)', desc: 'Suspicion assessment' },
    { id: 'plan',      label: 'PLAN',      color: 'var(--orange)', desc: 'Dynamic tool selection' },
    { id: 'execute',   label: 'EXECUTE',   color: 'var(--cyan)',   desc: 'Run specialists' },
    { id: 'evaluate',  label: 'EVALUATE',  color: 'var(--yellow)', desc: 'Assess & escalate' },
    { id: 'fuse',      label: 'FUSE',      color: 'var(--green)',  desc: 'Merge memory' },
    { id: 'decide',    label: 'DECIDE',    color: 'var(--red)',    desc: 'Deterministic verdict' },
    { id: 'explain',   label: 'EXPLAIN',   color: 'var(--green)',  desc: 'LLM narrative' },
  ];

  return (
    <div className={styles.reactFlow}>
      {phases.map((p, i) => (
        <div key={p.id} className={styles.reactPhaseWrap}>
          <div className={styles.reactPhase} style={{ borderColor: `${p.color}40`, background: `${p.color}08` }}>
            <div className={styles.reactPhaseLabel} style={{ color: p.color }}>{p.label}</div>
            <div className={styles.reactPhaseDesc}>{p.desc}</div>
          </div>
          {i < phases.length - 1 && (
            <div className={styles.reactArrow}>
              <ArrowRight size={14} color="var(--text-3)" />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ── Confidence Formula ── */
function ConfidenceFormula() {
  const terms = [
    { label: '0.35 × LSTM', color: '#ff4444' },
    { label: '0.20 × RAG', color: '#4488ff' },
    { label: '0.15 × Correlation', color: '#aa66ff' },
    { label: '0.10 × ThreatIntel', color: '#ff9800' },
    { label: '0.10 × Pattern', color: '#ffd740' },
    { label: '0.10 × IOC', color: '#00e676' },
  ];
  return (
    <div className={styles.formula}>
      <div className={styles.formulaLabel}>Confidence =</div>
      <div className={styles.formulaTerms}>
        {terms.map((t, i) => (
          <span key={i}>
            <span className={styles.formulaTerm} style={{ color: t.color }}>{t.label}</span>
            {i < terms.length - 1 && <span className={styles.formulaPlus}>+</span>}
          </span>
        ))}
      </div>
    </div>
  );
}

/* ── Main Dashboard ── */
export default function Dashboard({ onNavigate }) {
  const { apiOnline } = useAuth();
  const [stats, setStats] = useState(null);
  const [evalMetrics, setEvalMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [evalLoading, setEvalLoading] = useState(false);
  const [activePipeStep, setActivePipeStep] = useState(0);

  const loadStats = useCallback(async () => {
    try {
      const data = await getDashboardStats();
      setStats(data);
    } catch {
      // Graceful degradation
    } finally {
      setLoading(false);
    }
  }, []);

  const loadEval = useCallback(async () => {
    setEvalLoading(true);
    try {
      const data = await evaluate();
      setEvalMetrics(data.metrics);
    } catch {
      // silent
    } finally {
      setEvalLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStats();
    loadEval();
    // Animate pipeline steps
    const pipeIv = setInterval(() => {
      setActivePipeStep(s => (s + 1) % AGENT_PHASES.length);
    }, 2000);
    return () => clearInterval(pipeIv);
  }, [loadStats, loadEval]);

  const components = stats?.components || {};
  const compEntries = Object.entries(components);

  return (
    <div className={styles.page}>
      {/* ── Hero Header ── */}
      <div className={styles.hero}>
        <div className={styles.heroLeft}>
          <div className={styles.heroBadge}>
            <div className={styles.heroBadgeDot} />
            <span>LLM-Powered · Agentic AI · v5.0</span>
          </div>
          <h1 className={styles.heroTitle}>SOC Analyst Dashboard</h1>
          <p className={styles.heroSub}>
            Multi-agent autonomous security investigation platform with LSTM anomaly detection,
            MITRE ATT&CK RAG, and ReAct-style reasoning engine.
          </p>
          <div className={styles.heroActions}>
            <button className={styles.heroCta} onClick={() => onNavigate?.('investigate')}>
              <Zap size={14} />
              Run Investigation
            </button>
            <button className={styles.heroCtaOutline} onClick={() => onNavigate?.('evaluate')}>
              <BarChart2 size={14} />
              View Metrics
            </button>
          </div>
        </div>
        <div className={styles.heroRight}>
          <div className={styles.heroOrb}>
            <Shield size={56} strokeWidth={1} color="var(--cyan)" />
            <div className={styles.heroOrbRing1} />
            <div className={styles.heroOrbRing2} />
          </div>
        </div>
      </div>

      {/* ── Stat Cards ── */}
      <div className={styles.statsGrid}>
        <StatCard icon={Layers} label="Pipeline Stages" value={stats?.pipeline_stages ?? '10'} sub="End-to-end" color="var(--cyan)" delay={0} />
        <StatCard icon={Activity} label="Agent Tools" value={stats?.agent_tools ?? '6'} sub="ReAct loop" color="var(--blue)" delay={60} />
        <StatCard icon={GitBranch} label="Campaign Patterns" value={stats?.campaign_patterns ?? '7'} sub="Multi-stage" color="var(--purple)" delay={120} />
        <StatCard icon={Target} label="Event Types" value={stats?.attack_event_types ?? '10'} sub="Classified" color="var(--orange)" delay={180} />
        <StatCard icon={Database} label="MITRE Techniques" value={stats?.mitre_techniques_indexed ?? '500'} sub="ChromaDB" color="var(--green)" delay={240} />
        <StatCard icon={Clock} label="Entities Tracked" value={loading ? '…' : (stats?.entities_tracked ?? '0')} sub="24h window" color="var(--red)" delay={300} />
      </div>

      {/* ── Main Grid ── */}
      <div className={styles.mainGrid}>

        {/* LEFT column */}
        <div className={styles.leftCol}>

          {/* System Components */}
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <Cpu size={13} color="var(--cyan)" />
              <span>System Components</span>
              <button className={styles.refreshBtn} onClick={loadStats}>
                <RefreshCw size={11} />
              </button>
            </div>
            <div className={styles.componentList}>
              {loading ? (
                [1,2,3,4,5].map(i => (
                  <div key={i} className={`${styles.componentRow} skeleton`} style={{ height: 28 }} />
                ))
              ) : compEntries.length ? compEntries.map(([key, val]) => (
                <div className={styles.componentRow} key={key}>
                  <CheckCircle2 size={12} color="var(--green)" />
                  <span className={styles.componentKey}>{key.replace(/_/g, ' ').toUpperCase()}</span>
                  <span className={styles.componentVal}>{val}</span>
                </div>
              )) : (
                <div className={styles.componentRow}>
                  <Circle size={12} color="var(--text-3)" />
                  <span className={styles.componentKey}>API OFFLINE</span>
                </div>
              )}
            </div>
          </div>

          {/* Pipeline Stages */}
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <Terminal size={13} color="var(--cyan)" />
              <span>Agent Orchestration Phases</span>
              <span className={styles.panelBadge}>8 phases</span>
            </div>
            <div className={styles.pipelineList}>
              {AGENT_PHASES.map((step, i) => (
                <PipelineRow key={step.id} step={step} i={i} active={i === activePipeStep} />
              ))}
            </div>
          </div>
        </div>

        {/* CENTER column */}
        <div className={styles.centerCol}>

          {/* Multi-Agent Architecture */}
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <Shield size={13} color="var(--cyan)" />
              <span>Agent-Oriented Architecture</span>
              <span className={styles.panelBadge}>5 specialists</span>
            </div>

            {/* ReAct Flow */}
            <div className={styles.sectionTitle}>ReAct Reasoning Loop</div>
            <ReActFlow />

            {/* Confidence formula */}
            <div className={styles.sectionTitle} style={{ marginTop: 20 }}>Confidence Scoring Formula</div>
            <ConfidenceFormula />

            {/* Agent cards */}
            <div className={styles.sectionTitle} style={{ marginTop: 20 }}>Agent Registry</div>
            <div className={styles.agentsGrid}>
              {SPECIALISTS.map((a, i) => (
                <AgentCard key={a.id} agent={a} delay={i * 80} />
              ))}
            </div>

            {/* Communication flow */}
            <div className={styles.sectionTitle} style={{ marginTop: 20 }}>Agent Communication</div>
            <div className={styles.commFlow}>
              <div className={styles.commNode} style={{ borderColor: 'var(--cyan)30', color: 'var(--cyan)' }}>Orchestrator</div>
              <div className={styles.commArrow}>
                <ArrowRight size={14} color="var(--text-3)" />
                <span className={styles.commArrowLabel}>parallel dispatch</span>
              </div>
              <div className={styles.commGroup}>
                {SPECIALISTS.map(a => (
                  <div key={a.id} className={styles.commAgentNode} style={{ borderColor: `${a.color}40`, color: a.color }}>
                    {a.name}
                  </div>
                ))}
              </div>
              <div className={styles.commArrow}>
                <ArrowRight size={14} color="var(--text-3)" />
                <span className={styles.commArrowLabel}>synthesize</span>
              </div>
              <div className={styles.commNode} style={{ borderColor: 'var(--purple)30', color: 'var(--purple)' }}>Synthesizer</div>
              <div className={styles.commArrow}>
                <ArrowRight size={14} color="var(--text-3)" />
                <span className={styles.commArrowLabel}>decide + explain</span>
              </div>
              <div className={styles.commNode} style={{ borderColor: `rgba(170, 102, 255, 0.3)`, color: '#aa66ff' }}>
                Orchestrator
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT column */}
        <div className={styles.rightCol}>

          {/* Evaluation Metrics */}
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <BarChart2 size={13} color="var(--cyan)" />
              <span>Evaluation Metrics</span>
              <button className={styles.refreshBtn} onClick={loadEval}>
                <RefreshCw size={11} className={evalLoading ? styles.spinning : ''} />
              </button>
            </div>

            {evalLoading ? (
              <div className={styles.evalLoading}>
                <div className={styles.miniSpinner} />
                <span>Running evaluation…</span>
              </div>
            ) : evalMetrics ? (
              <>
                <div className={styles.ringsRow}>
                  <RingChart
                    value={evalMetrics.precision} max={1}
                    color="var(--cyan)" size={90}
                    label={`${(evalMetrics.precision * 100).toFixed(0)}%`}
                    sublabel="Precision"
                  />
                  <RingChart
                    value={evalMetrics.recall} max={1}
                    color="var(--green)" size={90}
                    label={`${(evalMetrics.recall * 100).toFixed(0)}%`}
                    sublabel="Recall"
                  />
                  <RingChart
                    value={evalMetrics.f1_score} max={1}
                    color="var(--blue)" size={90}
                    label={`${(evalMetrics.f1_score * 100).toFixed(0)}%`}
                    sublabel="F1 Score"
                  />
                </div>
                <div className={styles.metricsList}>
                  {[
                    ['Accuracy', evalMetrics.accuracy, 'var(--purple)'],
                    ['Specificity', evalMetrics.specificity, 'var(--orange)'],
                    ['False Pos. Rate', evalMetrics.false_positive_rate, 'var(--red)'],
                  ].map(([k, v, c]) => (
                    <div className={styles.metricRow} key={k}>
                      <span className={styles.metricKey}>{k}</span>
                      <div className={styles.metricBarWrap}>
                        <div className={styles.metricBarFill} style={{ width: `${Math.min(v * 100, 100)}%`, background: c }} />
                      </div>
                      <span className={styles.metricPct} style={{ color: c }}>{(v * 100).toFixed(1)}%</span>
                    </div>
                  ))}
                </div>
                <button className={styles.evalDetailBtn} onClick={() => onNavigate?.('evaluate')}>
                  View Full Evaluation →
                </button>
              </>
            ) : (
              <div className={styles.evalEmpty}>
                <AlertTriangle size={18} color="var(--orange)" />
                <span>Evaluation unavailable — ensure backend is running</span>
              </div>
            )}
          </div>

          {/* API Status */}
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <Zap size={13} color="var(--cyan)" />
              <span>API Status</span>
            </div>
            <div className={`${styles.apiStatusBlock} ${apiOnline ? styles.apiOnline : styles.apiOffline}`}>
              <div className={styles.apiDot} />
              <div>
                <div className={styles.apiStatusLabel}>{apiOnline ? 'BACKEND ONLINE' : 'BACKEND OFFLINE'}</div>
                <div className={styles.apiStatusSub}>{apiOnline ? 'All systems operational' : 'Start uvicorn on port 8000'}</div>
              </div>
            </div>
            <div className={styles.endpointList}>
              {[
                ['POST', '/investigate', 'Full 10-stage pipeline'],
                ['POST', '/investigate/agent', 'Agent + correlation'],
                ['POST', '/rag-test', 'MITRE semantic search'],
                ['GET',  '/evaluate', 'Evaluation metrics'],
                ['GET',  '/dashboard/stats', 'System stats'],
                ['GET',  '/health', 'Health check'],
              ].map(([m, p, d]) => (
                <div className={styles.endpoint} key={p}>
                  <span className={`${styles.method} ${m === 'POST' ? styles.methodPost : styles.methodGet}`}>{m}</span>
                  <span className={styles.endpointPath}>{p}</span>
                  <span className={styles.endpointDesc}>{d}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
