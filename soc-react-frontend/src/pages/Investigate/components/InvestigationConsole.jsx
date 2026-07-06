import React, { useState, useRef, useEffect } from 'react';
import {
  Shield, Activity, ChevronDown, ChevronUp, Brain, Eye,
  Target, Zap, RotateCcw, CheckCircle, FileText, AlertTriangle,
  TrendingUp, ArrowLeft, Copy, ExternalLink, List, Hash
} from 'lucide-react';
import { SEVERITY_COLORS } from '../../../constants/scenarios';
import styles from './InvestigationConsole.module.css';

/* ─── Helpers ──────────────────────────────────────────────────────── */
function MetricBar({ value, max = 1, color }) {
  const p = Math.min(100, Math.round((value / max) * 100));
  return (
    <div className={styles.barWrap}>
      <div className={styles.barFill} style={{ width: `${p}%`, background: color || 'var(--cyan)' }} />
    </div>
  );
}

function Section({ title, children, accent, icon: Icon, defaultOpen = true, count }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={styles.section} style={accent ? { borderLeftColor: accent } : {}}>
      <div className={styles.sectionHead} onClick={() => setOpen(o => !o)}>
        <div className={styles.sectionTitle}>
          {Icon && <Icon size={13} style={{ color: accent || 'var(--cyan)', flexShrink: 0 }} />}
          <span>{title}</span>
          {count !== undefined && <span className={styles.sectionCount}>{count}</span>}
        </div>
        {open ? <ChevronUp size={12} style={{ color: 'var(--text-3)', flexShrink: 0 }} /> : <ChevronDown size={12} style={{ color: 'var(--text-3)', flexShrink: 0 }} />}
      </div>
      {open && <div className={styles.sectionBody}>{children}</div>}
    </div>
  );
}

function ResponsiveSparkline({ values = [] }) {
  const svgRef = useRef(null);
  const [width, setWidth] = useState(300);

  useEffect(() => {
    if (!svgRef.current) return;
    const ro = new ResizeObserver(entries => {
      const w = entries[0]?.contentRect.width;
      if (w > 0) setWidth(w);
    });
    ro.observe(svgRef.current.parentElement);
    return () => ro.disconnect();
  }, []);

  // Normalise — accept both float[] and dict[]
  const floats = values
    .map(v => (typeof v === 'object' ? v?.confidence ?? v?.value ?? 0 : v))
    .filter(v => typeof v === 'number');

  if (floats.length < 2) {
    return (
      <div className={styles.sparkEmpty}>
        <span>{floats.length === 1 ? `${(floats[0] * 100).toFixed(0)}%` : '—'}</span>
        <span>No evolution data</span>
      </div>
    );
  }

  const h = 48;
  const max = Math.max(...floats, 0.01);
  const min = Math.min(...floats, 0);
  const range = max - min || 0.01;
  const step = width / Math.max(floats.length - 1, 1);
  const pts = floats.map((v, i) => `${(i * step).toFixed(1)},${(h - ((v - min) / range) * (h - 4) - 2).toFixed(1)}`).join(' ');
  const dots = floats.map((v, i) => ({
    cx: (i * step).toFixed(1),
    cy: (h - ((v - min) / range) * (h - 4) - 2).toFixed(1),
    v,
  }));

  return (
    <div className={styles.sparklineWrap}>
      <svg ref={svgRef} width="100%" height={h} viewBox={`0 0 ${width} ${h}`} preserveAspectRatio="none" className={styles.sparklineSvg}>
        <defs>
          <linearGradient id="sparkGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--cyan)" stopOpacity="0.3" />
            <stop offset="100%" stopColor="var(--cyan)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <polyline fill="none" stroke="var(--cyan)" strokeWidth="1.8" strokeLinejoin="round" points={pts} />
        {dots.map((d, i) => (
          <circle key={i} cx={d.cx} cy={d.cy} r="2.5" fill="var(--cyan)" opacity={i === dots.length - 1 ? 1 : 0.5} />
        ))}
      </svg>
      <div className={styles.sparklineLabels}>
        <span>{(floats[0] * 100).toFixed(0)}% start</span>
        <span className={styles.sparklineFinal}>{(floats[floats.length - 1] * 100).toFixed(0)}% final</span>
      </div>
    </div>
  );
}

/* Phase color/icon mapping */
const PHASE_META = {
  perceive: { color: '#4488ff', icon: Eye,       label: 'PERCEIVE' },
  plan:     { color: '#aa66ff', icon: Brain,      label: 'PLAN' },
  validate: { color: '#ffd740', icon: Shield,     label: 'VALIDATE' },
  execute:  { color: '#ff9800', icon: Zap,        label: 'EXECUTE' },
  reflect:  { color: '#18ffff', icon: RotateCcw,  label: 'REFLECT' },
  replan:   { color: '#ff6b35', icon: Target,     label: 'REPLAN' },
  fuse:     { color: '#c6ff00', icon: Activity,   label: 'FUSE' },
  decide:   { color: '#00e676', icon: CheckCircle,label: 'DECIDE' },
  report:   { color: '#69ff47', icon: FileText,   label: 'REPORT' },
};

/* ─── Main Console Component ──────────────────────────────────────── */
export default function InvestigationConsole({ data, onBack }) {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState('summary');
  if (!data) return null;

  const sevColor = SEVERITY_COLORS[data.severity?.toUpperCase()] || 'var(--cyan)';
  const phases   = data.reasoning_trace || data.investigation_phases || [];
  const mitreTechniques = [
    ...(data.mitre_mappings || []),
    ...(data.compound_mitre_mappings || []),
  ].filter((v, i, a) => a.indexOf(v) === i); // deduplicate

  const iocs = data.iocs_extracted || {};
  const iocEntries = Object.entries(iocs).filter(([, v]) => Array.isArray(v) && v.length > 0);

  const handleCopyReport = () => {
    const text = JSON.stringify(data, null, 2);
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className={styles.consoleContainer}>

      {/* ══ STICKY TOOLBAR ══ */}
      <div className={styles.toolbar}>
        {onBack && (
          <button className={styles.backBtn} onClick={onBack}>
            <ArrowLeft size={12} /> Back to Input
          </button>
        )}
        <div className={styles.toolbarTitle}>
          <Shield size={12} style={{ color: sevColor }} />
          <span>INCIDENT // {data.incident_id || 'UNKNOWN'}</span>
        </div>
        <button className={styles.copyBtn} onClick={handleCopyReport} title="Copy full JSON report">
          <Copy size={11} />
          {copied ? 'Copied!' : 'Copy JSON'}
        </button>
      </div>

      {/* ══ HEADER METRICS ══ */}
      <div className={styles.headerPanel} style={{ borderLeftColor: sevColor }}>
        <div className={styles.headerRow}>
          <div className={styles.headerBadges}>
            <div className={styles.statusBadge}>
              <CheckCircle size={11} /> {data.investigation_status || 'COMPLETED'}
            </div>
            {(data.plan_iterations || 1) > 1 && (
              <div className={styles.iterBadge}>
                <RotateCcw size={11} /> {data.plan_iterations} iterations
              </div>
            )}
            <div className={styles.timeBadge}>
              {data.total_analysis_ms?.toFixed(0) || '0'}ms
            </div>
          </div>
        </div>

        <div className={styles.primaryMetrics}>
          <div className={styles.metricCard} style={{ borderColor: `${sevColor}30` }}>
            <span className={styles.metricLabel}>SEVERITY</span>
            <span className={styles.metricValue} style={{ color: sevColor }}>{data.severity || '—'}</span>
          </div>
          <div className={styles.metricCard}>
            <span className={styles.metricLabel}>DECISION</span>
            <span className={styles.metricValue} style={{ color: 'var(--orange)' }}>{data.decision || '—'}</span>
          </div>
          <div className={styles.metricCard}>
            <span className={styles.metricLabel}>RISK SCORE</span>
            <span className={styles.metricValue}>
              {data.risk_score ?? '0'}<span className={styles.metricSub}>/100</span>
            </span>
            <MetricBar value={data.risk_score ?? 0} max={100} color={sevColor} />
          </div>
          <div className={styles.metricCard}>
            <span className={styles.metricLabel}>CONFIDENCE</span>
            <span className={styles.metricValue}>
              {((data.confidence ?? 0) * 100).toFixed(0)}<span className={styles.metricSub}>%</span>
            </span>
            <MetricBar value={data.confidence ?? 0} max={1} color="var(--cyan)" />
          </div>
          <div className={styles.metricCard}>
            <span className={styles.metricLabel}>ANOMALY</span>
            <span className={styles.metricValue}>
              {((data.anomaly_score ?? 0) * 100).toFixed(0)}<span className={styles.metricSub}>%</span>
            </span>
            <MetricBar value={data.anomaly_score ?? 0} max={1} color="var(--purple)" />
          </div>
          <div className={styles.metricCard}>
            <span className={styles.metricLabel}>ENTITIES</span>
            <span className={styles.metricValue} style={{ fontSize: 14 }}>
              {(data.entities || []).length}
            </span>
            <div className={styles.entityList}>
              {(data.entities || []).slice(0, 2).map((e, i) => (
                <span key={i} className={styles.entityTag}>{e}</span>
              ))}
            </div>
          </div>
        </div>

        {/* Severity factor pills */}
        {(data.severity_factors || []).length > 0 && (
          <div className={styles.factorsRow}>
            {data.severity_factors.map((f, i) => (
              <span key={i} className={styles.factorTag}>{f}</span>
            ))}
          </div>
        )}
      </div>

      {/* ══ TABS ══ */}
      <div className={styles.tabs}>
        <button 
          className={`${styles.tab} ${activeTab === 'summary' ? styles.tabActive : ''}`}
          onClick={() => setActiveTab('summary')}
        >
          <FileText size={12} /> INVESTIGATION SUMMARY
        </button>
        <button 
          className={`${styles.tab} ${activeTab === 'trace' ? styles.tabActive : ''}`}
          onClick={() => setActiveTab('trace')}
        >
          <Activity size={12} /> AGENTIC TRACE
        </button>
      </div>

      <div className={styles.tabContent}>
        {activeTab === 'summary' && (
          <div className={styles.tabPane}>

      {/* ══ HYPOTHESIS & TOOLS ══ */}
      <Section title="INVESTIGATION HYPOTHESIS" accent="var(--purple)" icon={Brain}>
        <div className={styles.hypothesisBox}>
          <p className={styles.hypothesisText}>
            {data.investigation_hypothesis || 'No hypothesis generated. Investigation ran in pipeline mode.'}
          </p>
          <div className={styles.toolLists}>
            {(data.planned_tools || []).length > 0 && (
              <div className={styles.toolList}>
                <span className={styles.toolListLabel}>PLANNED</span>
                <div className={styles.tags}>
                  {data.planned_tools.map((t, i) => <span key={i} className={styles.tag}>{t}</span>)}
                </div>
              </div>
            )}
            {(data.completed_tools || []).length > 0 && (
              <div className={styles.toolList}>
                <span className={styles.toolListLabel} style={{ color: 'var(--green)' }}>COMPLETED</span>
                <div className={styles.tags}>
                  {data.completed_tools.map((t, i) => <span key={i} className={`${styles.tag} ${styles.tagSuccess}`}>{t}</span>)}
                </div>
              </div>
            )}
            {(data.escalation_tools || []).length > 0 && (
              <div className={styles.toolList}>
                <span className={styles.toolListLabel} style={{ color: 'var(--orange)' }}>ESCALATION</span>
                <div className={styles.tags}>
                  {data.escalation_tools.map((t, i) => <span key={i} className={`${styles.tag} ${styles.tagWarning}`}>{t}</span>)}
                </div>
              </div>
            )}
            {(data.skipped_tools || []).length > 0 && (
              <div className={styles.toolList}>
                <span className={styles.toolListLabel}>SKIPPED</span>
                <div className={styles.tags}>
                  {data.skipped_tools.map((t, i) => <span key={i} className={`${styles.tag} ${styles.tagMuted}`}>{t}</span>)}
                </div>
              </div>
            )}
          </div>
        </div>
      </Section>

      {/* ══ TWO-COLUMN: MITRE + IOCs ══ */}
      <div className={styles.panelGrid}>
        {/* MITRE Techniques */}
        <Section title="MITRE ATT&CK TECHNIQUES" accent="var(--red)" icon={Target} count={mitreTechniques.length}>
          {mitreTechniques.length > 0 ? (
            <div className={styles.mitreList}>
              {mitreTechniques.map((t, i) => (
                <a
                  key={i}
                  className={styles.mitreTag}
                  href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={`View ${t} on MITRE ATT&CK`}
                >
                  <Hash size={9} />
                  {t}
                  <ExternalLink size={8} style={{ opacity: 0.5 }} />
                </a>
              ))}
            </div>
          ) : (
            <div className={styles.muted}>No MITRE techniques identified. Activity may not match known patterns.</div>
          )}
          {data.campaign_pattern && (
            <div className={styles.campaignBadge}>
              <Activity size={10} /> {data.campaign_pattern.replace('_', ' ')}
            </div>
          )}
        </Section>

        {/* IOCs */}
        <Section title="EXTRACTED IOCs" accent="var(--orange)" icon={List} count={iocEntries.reduce((s, [,v]) => s + v.length, 0)}>
          {iocEntries.length > 0 ? (
            <div className={styles.iocGrid}>
              {iocEntries.map(([type, vals]) => (
                <div key={type} className={styles.iocGroup}>
                  <div className={styles.iocType}>{type.replace(/_/g, ' ').toUpperCase()}</div>
                  <div className={styles.iocValues}>
                    {vals.slice(0, 5).map((v, i) => (
                      <span key={i} className={styles.iocValue}>
                        {typeof v === 'object' && v !== null ? (v.value || v.ip || v.domain || v.hash || v.url || v.filepath || JSON.stringify(v)) : String(v)}
                      </span>
                    ))}
                    {vals.length > 5 && <span className={styles.iocMore}>+{vals.length - 5} more</span>}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className={styles.muted}>No IOCs extracted from this session.</div>
          )}
        </Section>
      </div>

          </div>
        )}

        {/* === TRACE CONTENT === */}
        {activeTab === 'trace' && (
          <div className={styles.tabPane}>
      {/* ══ REASONING TRACE ══ */}
      <Section title="REASONING TRACE" accent="var(--cyan)" icon={Activity} count={phases.length}>
        <div className={styles.phaseTimeline}>
          {phases.length > 0 ? phases.map((phase, idx) => {
            const key = (phase.phase || phase.step || '').toLowerCase();
            const meta = PHASE_META[key] || { color: 'var(--text-3)', label: key.toUpperCase() || `STEP ${idx + 1}` };
            const PhaseIcon = meta.icon || Zap;
            return (
              <div key={idx} className={styles.phaseStep}>
                <div className={styles.phaseConnector}>
                  <div className={styles.phaseDot} style={{ background: meta.color, boxShadow: `0 0 6px ${meta.color}66` }} />
                  {idx < phases.length - 1 && <div className={styles.phaseLine} />}
                </div>
                <div className={styles.phaseContent}>
                  <div className={styles.phaseHeader}>
                    <PhaseIcon size={11} style={{ color: meta.color, flexShrink: 0 }} />
                    <span className={styles.phaseLabel} style={{ color: meta.color }}>{meta.label}</span>
                    {phase.duration_ms !== undefined && (
                      <span className={styles.phaseTime}>{phase.duration_ms.toFixed(0)}ms</span>
                    )}
                  </div>
                  <p className={styles.phaseDesc}>{phase.description || phase.desc || '—'}</p>
                </div>
              </div>
            );
          }) : (
            <div className={styles.muted}>No reasoning trace available.</div>
          )}
        </div>
      </Section>

      {/* ══ TWO-COLUMN: REFLECTION + CONFIDENCE ══ */}
      <div className={styles.panelGrid}>
        <Section
          title="REFLECTION HISTORY"
          accent="#18ffff"
          icon={RotateCcw}
          defaultOpen={(data.reflection_history || []).length > 0}
          count={(data.reflection_history || []).length}
        >
          <div className={styles.reflectionList}>
            {(data.reflection_history || []).length > 0 ? (
              data.reflection_history.map((r, i) => (
                <div key={i} className={styles.reflectionItem}>
                  <div className={styles.reflectionHeader}>
                    <span className={styles.reflectionIter}>Iteration {i + 1}</span>
                    <span className={`${styles.reflectionBadge} ${r.needs_more_evidence ? styles.badgeWarn : styles.badgeOk}`}>
                      {r.needs_more_evidence ? 'MORE EVIDENCE' : 'SUFFICIENT'}
                    </span>
                  </div>
                  <p className={styles.reflectionReasoning}>{r.reasoning || r.assessment || '—'}</p>
                  {r.updated_hypothesis && (
                    <div className={styles.reflectionHypUpdate}>
                      <AlertTriangle size={10} /> {r.updated_hypothesis}
                    </div>
                  )}
                  {(r.additional_tools_needed || []).length > 0 && (
                    <div className={styles.reflectionTools}>
                      Requested: {r.additional_tools_needed.join(', ')}
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className={styles.muted}>No reflections recorded — single-pass investigation.</div>
            )}
          </div>
        </Section>

        <Section title="CONFIDENCE EVOLUTION" accent="var(--cyan)" icon={TrendingUp}>
          <div className={styles.confidenceEvolution}>
            <ResponsiveSparkline values={data.confidence_evolution || []} />
            {data.confidence_breakdown && Object.keys(data.confidence_breakdown).length > 0 && (
              <div className={styles.breakdownGrid}>
                {Object.entries(data.confidence_breakdown).map(([key, val]) => (
                  <div key={key} className={styles.breakdownItem}>
                    <span className={styles.breakdownKey}>{key.replace(/_/g, ' ').toUpperCase()}</span>
                    <MetricBar value={val} max={0.35} color="var(--cyan)" />
                    <span className={styles.breakdownVal}>{(val * 100).toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            )}
            {data.risk_breakdown && Object.keys(data.risk_breakdown).length > 0 && (
              <>
                <div className={styles.breakdownSectionLabel}>RISK FACTORS</div>
                <div className={styles.breakdownGrid}>
                  {Object.entries(data.risk_breakdown).map(([key, val]) => (
                    <div key={key} className={styles.breakdownItem}>
                      <span className={styles.breakdownKey}>{key.replace(/_/g, ' ')}</span>
                      <MetricBar value={val} max={40} color="var(--red)" />
                      <span className={styles.breakdownVal}>{val}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </Section>
      </div>

          </div>
        )}

        {/* === SUMMARY CONTENT === */}
        {activeTab === 'summary' && (
          <div className={styles.tabPane}>
      {/* ══ TWO-COLUMN: EVIDENCE + MEMORY ══ */}
      <div className={styles.panelGrid}>
        <Section
          title="EVIDENCE BOARD"
          accent="var(--green)"
          icon={Shield}
          count={(data.evidence_board || []).length}
        >
          <div className={styles.evidenceBoard}>
            {(data.evidence_board || []).length > 0 ? (
              data.evidence_board.map((ev, idx) => (
                <div key={idx} className={styles.evidenceItem}>
                  <div className={styles.evHeader}>
                    <span className={styles.evSource}>{ev.source || 'Unknown'}</span>
                    <span className={styles.evWeight}>
                      {ev.contribution !== undefined ? `Wt: ${(ev.contribution * 100).toFixed(1)}%` : ''}
                    </span>
                  </div>
                  <p className={styles.evDesc}>{ev.description || '—'}</p>
                  {(ev.tags || []).length > 0 && (
                    <div className={styles.evTags}>
                      {ev.tags.slice(0, 4).map((t, i) => <span key={i} className={styles.evTag}>{t}</span>)}
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className={styles.muted}>No significant evidence accumulated.</div>
            )}
          </div>
        </Section>

        <Section title="ENTITY MEMORY & CORRELATION" accent="var(--blue)" icon={Eye}>
          <div className={styles.memoryBox}>
            <div className={styles.memoryStats}>
              <div className={styles.memoryStat}>
                <span className={styles.memoryValue} style={{ color: 'var(--blue)' }}>
                  {data.correlation_depth ?? 0}
                </span>
                <span className={styles.memoryLabel}>Correlated Sessions</span>
              </div>
              <div className={styles.memoryStat}>
                <span className={styles.memoryValue} style={{ color: 'var(--purple)' }}>
                  {(data.entities || []).length}
                </span>
                <span className={styles.memoryLabel}>Tracked Entities</span>
              </div>
            </div>
            <div className={styles.entityPills}>
              {(data.entities || []).map((e, i) => (
                <span key={i} className={styles.entityPill}>{e}</span>
              ))}
            </div>
            <p className={styles.memoryDesc}>
              {(data.correlation_depth ?? 0) > 1
                ? `Cross-session correlation across ${data.correlation_depth} sessions from the same entity influenced the final decision.`
                : 'No prior suspicious sessions found for this entity within the 24-hour window.'}
            </p>
            {data.campaign_pattern && (
              <div className={styles.campaignBadge} style={{ marginTop: 8 }}>
                <Activity size={10} /> Campaign Pattern: {data.campaign_pattern.replace(/_/g, ' ')}
              </div>
            )}
          </div>
        </Section>
      </div>

      {/* ══ REPORTS ══ */}
      <div className={styles.panelGrid}>
        <Section title="EXECUTIVE REPORT" accent="var(--cyan)" icon={FileText}>
          <div className={styles.reportSections}>
            {data.investigation_report?.executive_summary && (
              <div className={styles.reportBlock}>
                <div className={styles.reportLabel}>EXECUTIVE SUMMARY</div>
                <p>{data.investigation_report.executive_summary}</p>
              </div>
            )}
            {data.investigation_report?.root_cause && (
              <div className={styles.reportBlock}>
                <div className={styles.reportLabel}>ROOT CAUSE</div>
                <p>{data.investigation_report.root_cause}</p>
              </div>
            )}
            {data.investigation_report?.mitre_explanation && (
              <div className={styles.reportBlock}>
                <div className={styles.reportLabel}>MITRE ATT&CK</div>
                <p>{data.investigation_report.mitre_explanation}</p>
              </div>
            )}
            {data.investigation_report?.recommendations?.length > 0 && (
              <div className={styles.reportBlock}>
                <div className={styles.reportLabel}>RECOMMENDATIONS</div>
                {data.investigation_report.recommendations.map((r, i) => (
                  <p key={i} style={{ marginBottom: 4 }}>▸ {typeof r === 'string' ? r : r.action || JSON.stringify(r)}</p>
                ))}
              </div>
            )}
            {!data.investigation_report?.executive_summary && (
              <div className={styles.narrative}>
                <p>{data.llm_explanation || 'No narrative generated.'}</p>
              </div>
            )}
          </div>
        </Section>

        <Section title="RESPONSE PLAYBOOK" accent="var(--red)" icon={Target}>
          <div className={styles.playbook}>
            <div className={styles.pbName}>{data.response_playbook?.name || 'Monitor Mode'}</div>
            {['IMMEDIATE', 'SHORT_TERM', 'LONG_TERM'].map(p => {
              const actions = data.response_playbook?.[p] || data.response_playbook?.[p.toLowerCase()];
              if (!actions?.length) return null;
              return (
                <div key={p} className={styles.pbGroup}>
                  <div className={styles.pbPriority}>{p.replace('_', ' ')}</div>
                  {actions.map((act, i) => (
                    <div key={i} className={styles.pbAction}>
                      ▸ {typeof act === 'string' ? act : act.action || act.description || JSON.stringify(act)}
                    </div>
                  ))}
                </div>
              );
            })}
            {/* Fallback for flat action arrays */}
            {(data.response_playbook?.actions || []).map((act, i) => (
              <div key={i} className={styles.pbAction}>
                ▸ {typeof act === 'string' ? act : act.action || ''}
              </div>
            ))}
          </div>
        </Section>
      </div>

          </div>
        )}

        {/* === TRACE CONTENT === */}
        {activeTab === 'trace' && (
          <div className={styles.tabPane}>
      {/* ══ SPECIALIST EXECUTION LOG ══ */}
      <Section
        title="SPECIALIST EXECUTION LOG"
        accent="var(--text-3)"
        icon={Zap}
        defaultOpen={true}
        count={(data.tool_results || []).length}
      >
        <div className={styles.specialistGrid}>
          {(data.tool_results || []).length > 0 ? (
            data.tool_results.map((res, i) => (
              <div key={i} className={styles.specialistCard}>
                <div className={styles.spHeader}>
                  <span className={styles.spName}>{res.tool_name || 'Specialist'}</span>
                  <span className={`${styles.spStatus} ${res.status === 'success' ? styles.spOk : styles.spErr}`}>
                    {res.status}
                  </span>
                </div>
                <div className={styles.spMetrics}>
                  <span>Exec: {res.execution_time_ms?.toFixed(0) || '0'}ms</span>
                  {res.confidence_contribution > 0 && (
                    <span>+{(res.confidence_contribution * 100).toFixed(1)}%</span>
                  )}
                </div>
                {(res.evidence_tags || []).length > 0 && (
                  <div className={styles.spTags}>
                    {res.evidence_tags.slice(0, 3).map((tag, j) => (
                      <span key={j} className={styles.spTag}>{tag}</span>
                    ))}
                  </div>
                )}
              </div>
            ))
          ) : (
            <div className={styles.muted}>No specialist tools were executed during this investigation.</div>
          )}
        </div>
      </Section>

      {/* ══ REPLAN EVENTS ══ */}
      <Section
        title="REPLAN EVENTS"
        accent="var(--orange)"
        icon={RotateCcw}
        defaultOpen={false}
        count={(data.replan_events || []).length}
      >
        <div className={styles.replanList}>
          {(data.replan_events || []).length > 0 ? (
            data.replan_events.map((ev, i) => (
              <div key={i} className={styles.replanItem}>
                <span className={styles.replanIter}>Iteration {ev.iteration || i + 1}</span>
                <p className={styles.replanReason}>{ev.reason || '—'}</p>
                {ev.old_hypothesis && (
                  <div className={styles.replanHyp}>
                    <span className={styles.replanOld}>{ev.old_hypothesis}</span>
                    <span className={styles.replanArrow}>→</span>
                    <span className={styles.replanNew}>{ev.new_hypothesis}</span>
                  </div>
                )}
              </div>
            ))
          ) : (
            <div className={styles.muted}>No replan events occurred. Investigation followed the primary plan.</div>
          )}
        </div>
      </Section>

          </div>
        )}
      </div>

      {/* ══ FOOTER ══ */}
      <div className={styles.footer}>
        <span>Analysis: {data.total_analysis_ms?.toFixed(0) || '0'}ms</span>
        <span>Iterations: {data.plan_iterations || 1}</span>
        <span>Tools: {(data.completed_tools || []).length}</span>
        <span>Techniques: {mitreTechniques.length}</span>
        <span>Entities: {(data.entities || []).length}</span>
      </div>

    </div>
  );
}
