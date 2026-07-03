import React, { useState } from 'react';
import { Shield, Activity, ChevronDown, ChevronUp, Brain, Eye, Target, Zap, RotateCcw, CheckCircle, FileText, AlertTriangle, TrendingUp } from 'lucide-react';
import { SEVERITY_COLORS } from '../../../constants/scenarios';
import styles from './InvestigationConsole.module.css';

/* ── Helpers ── */
function MetricBar({ value, max = 1, color }) {
  const p = Math.min(100, Math.round((value / max) * 100));
  return (
    <div className={styles.barWrap}>
      <div className={styles.bar} style={{ width: `${p}%`, background: color || 'var(--cyan)' }} />
    </div>
  );
}

function Section({ title, children, accent, icon: Icon, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={styles.section} style={accent ? { borderLeftColor: accent } : {}}>
      <div className={styles.sectionHead} onClick={() => setOpen(o => !o)}>
        <div className={styles.sectionTitle}>
          {Icon && <Icon size={14} />}
          <span>{title}</span>
        </div>
        {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
      </div>
      {open && <div className={styles.sectionBody}>{children}</div>}
    </div>
  );
}

function ConfidenceSparkline({ values = [] }) {
  if (!values.length) return null;
  const max = Math.max(...values, 0.01);
  const w = 200;
  const h = 40;
  const step = w / Math.max(values.length - 1, 1);
  const points = values.map((v, i) => `${i * step},${h - (v / max) * h}`).join(' ');
  return (
    <div className={styles.sparklineWrap}>
      <svg width={w} height={h} className={styles.sparkline}>
        <polyline fill="none" stroke="var(--cyan)" strokeWidth="2" points={points} />
        {values.map((v, i) => (
          <circle key={i} cx={i * step} cy={h - (v / max) * h} r="3" fill="var(--cyan)" />
        ))}
      </svg>
      <div className={styles.sparklineLabels}>
        <span>{(values[0] * 100).toFixed(0)}%</span>
        <span>{(values[values.length - 1] * 100).toFixed(0)}%</span>
      </div>
    </div>
  );
}

/* Phase color/icon mapping */
const PHASE_META = {
  perceive: { color: '#4488ff', icon: Eye, label: 'PERCEIVE' },
  plan:     { color: '#aa66ff', icon: Brain, label: 'PLAN' },
  validate: { color: '#ffd740', icon: Shield, label: 'VALIDATE' },
  execute:  { color: '#ff9800', icon: Zap, label: 'EXECUTE' },
  reflect:  { color: '#18ffff', icon: RotateCcw, label: 'REFLECT' },
  replan:   { color: '#ff6b35', icon: Target, label: 'REPLAN' },
  fuse:     { color: '#c6ff00', icon: Activity, label: 'FUSE' },
  decide:   { color: '#00e676', icon: CheckCircle, label: 'DECIDE' },
  report:   { color: '#69ff47', icon: FileText, label: 'REPORT' },
};

/* ── Main Console Component ── */
export default function InvestigationConsole({ data }) {
  if (!data) return null;

  const sevColor = SEVERITY_COLORS[data.severity?.toUpperCase()] || 'var(--cyan)';
  const phases = data.reasoning_trace || data.investigation_phases || [];

  return (
    <div className={styles.consoleContainer}>

      {/* ═══ HEADER PANEL ═══ */}
      <div className={styles.headerPanel} style={{ borderColor: sevColor }}>
        <div className={styles.headerTop}>
          <div className={styles.incidentId}>
            <Shield size={14} /> INCIDENT // {data.incident_id || 'UNKNOWN'}
          </div>
          <div className={styles.headerBadges}>
            <div className={styles.statusBadge}>
              <CheckCircle size={12} /> {data.investigation_status || 'COMPLETED'}
            </div>
            {data.plan_iterations > 1 && (
              <div className={styles.iterBadge}>
                <RotateCcw size={12} /> {data.plan_iterations} iterations
              </div>
            )}
          </div>
        </div>

        <div className={styles.primaryMetrics}>
          <div className={styles.metricCard}>
            <span className={styles.metricLabel}>SEVERITY</span>
            <span className={styles.metricValue} style={{ color: sevColor }}>{data.severity}</span>
          </div>
          <div className={styles.metricCard}>
            <span className={styles.metricLabel}>DECISION</span>
            <span className={styles.metricValue}>{data.decision}</span>
          </div>
          <div className={styles.metricCard}>
            <span className={styles.metricLabel}>RISK SCORE</span>
            <span className={styles.metricValue}>{data.risk_score}<span className={styles.metricSub}>/100</span></span>
            <MetricBar value={data.risk_score} max={100} color={sevColor} />
          </div>
          <div className={styles.metricCard}>
            <span className={styles.metricLabel}>CONFIDENCE</span>
            <span className={styles.metricValue}>{(data.confidence * 100).toFixed(0)}<span className={styles.metricSub}>%</span></span>
            <MetricBar value={data.confidence} max={1} color="var(--cyan)" />
          </div>
        </div>

        {/* Severity factors */}
        {data.severity_factors?.length > 0 && (
          <div className={styles.factorsRow}>
            {data.severity_factors.map((f, i) => (
              <span key={i} className={styles.factorTag}>{f}</span>
            ))}
          </div>
        )}
      </div>

      {/* ═══ HYPOTHESIS & STRATEGY ═══ */}
      <Section title="INVESTIGATION HYPOTHESIS" accent="var(--purple)" icon={Brain}>
        <div className={styles.hypothesisBox}>
          <p className={styles.hypothesisText}>{data.investigation_hypothesis || 'No hypothesis generated.'}</p>
          <div className={styles.toolLists}>
            <div className={styles.toolList}>
              <span className={styles.label}>PLANNED SPECIALISTS</span>
              <div className={styles.tags}>
                {(data.planned_tools || []).map((t, i) => <span key={i} className={styles.tag}>{t}</span>)}
              </div>
            </div>
            <div className={styles.toolList}>
              <span className={styles.label}>COMPLETED</span>
              <div className={styles.tags}>
                {(data.completed_tools || []).map((t, i) => <span key={i} className={`${styles.tag} ${styles.tagSuccess}`}>{t}</span>)}
              </div>
            </div>
            {data.escalation_tools?.length > 0 && (
              <div className={styles.toolList}>
                <span className={styles.label} style={{ color: 'var(--orange)' }}>ESCALATION</span>
                <div className={styles.tags}>
                  {data.escalation_tools.map((t, i) => <span key={i} className={`${styles.tag} ${styles.tagWarning}`}>{t}</span>)}
                </div>
              </div>
            )}
            {data.skipped_tools?.length > 0 && (
              <div className={styles.toolList}>
                <span className={styles.label}>SKIPPED</span>
                <div className={styles.tags}>
                  {data.skipped_tools.map((t, i) => <span key={i} className={`${styles.tag} ${styles.tagMuted}`}>{t}</span>)}
                </div>
              </div>
            )}
          </div>
        </div>
      </Section>

      {/* ═══ REASONING TRACE (7 Phases) ═══ */}
      <Section title="REASONING TRACE" accent="var(--cyan)" icon={Activity}>
        <div className={styles.phaseTimeline}>
          {phases.map((phase, idx) => {
            const meta = PHASE_META[phase.phase] || { color: 'var(--text-3)', label: phase.phase?.toUpperCase() };
            const PhaseIcon = meta.icon || Zap;
            return (
              <div key={idx} className={styles.phaseStep}>
                <div className={styles.phaseConnector}>
                  <div className={styles.phaseDot} style={{ background: meta.color }} />
                  {idx < phases.length - 1 && <div className={styles.phaseLine} />}
                </div>
                <div className={styles.phaseContent}>
                  <div className={styles.phaseHeader}>
                    <PhaseIcon size={12} style={{ color: meta.color }} />
                    <span className={styles.phaseLabel} style={{ color: meta.color }}>{meta.label}</span>
                    <span className={styles.phaseTime}>{phase.duration_ms?.toFixed(0) || '0'}ms</span>
                  </div>
                  <p className={styles.phaseDesc}>{phase.description}</p>
                </div>
              </div>
            );
          })}
        </div>
      </Section>

      {/* ═══ TWO-COLUMN: REFLECTION + CONFIDENCE ═══ */}
      <div className={styles.panelGrid}>
        {/* Reflection History */}
        <Section title="REFLECTION HISTORY" accent="#18ffff" icon={RotateCcw} defaultOpen={data.reflection_history?.length > 0}>
          <div className={styles.reflectionList}>
            {(data.reflection_history || []).map((r, i) => (
              <div key={i} className={styles.reflectionItem}>
                <div className={styles.reflectionHeader}>
                  <span className={styles.reflectionIter}>Iteration {i + 1}</span>
                  <span className={`${styles.reflectionBadge} ${r.needs_more_evidence ? styles.badgeWarn : styles.badgeOk}`}>
                    {r.needs_more_evidence ? 'MORE EVIDENCE' : 'SUFFICIENT'}
                  </span>
                </div>
                <p className={styles.reflectionReasoning}>{r.reasoning}</p>
                {r.updated_hypothesis && (
                  <div className={styles.reflectionHypUpdate}>
                    <AlertTriangle size={10} /> Hypothesis updated: {r.updated_hypothesis}
                  </div>
                )}
                {r.additional_tools_needed?.length > 0 && (
                  <div className={styles.reflectionTools}>
                    Requested: {r.additional_tools_needed.join(', ')}
                  </div>
                )}
              </div>
            ))}
            {(!data.reflection_history || data.reflection_history.length === 0) && (
              <div className={styles.muted}>No reflections recorded — single-pass investigation.</div>
            )}
          </div>
        </Section>

        {/* Confidence Evolution */}
        <Section title="CONFIDENCE EVOLUTION" accent="var(--cyan)" icon={TrendingUp}>
          <div className={styles.confidenceEvolution}>
            <ConfidenceSparkline values={data.confidence_evolution || []} />
            {data.confidence_breakdown && Object.keys(data.confidence_breakdown).length > 0 && (
              <div className={styles.breakdownGrid}>
                {Object.entries(data.confidence_breakdown).map(([key, val]) => (
                  <div key={key} className={styles.breakdownItem}>
                    <span className={styles.breakdownKey}>{key.toUpperCase()}</span>
                    <MetricBar value={val} max={0.35} color="var(--cyan)" />
                    <span className={styles.breakdownVal}>{(val * 100).toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Section>
      </div>

      {/* ═══ INVESTIGATION MEMORY ═══ */}
      <Section title="INVESTIGATION MEMORY" accent="var(--blue)" icon={Eye}>
        <div className={styles.memoryBox}>
          <div className={styles.memoryHeader}>
            <Eye size={16} />
            <span>Entity: {data.entities?.[0] || 'Unknown'}</span>
          </div>
          <div className={styles.memoryStat}>
            <span className={styles.memoryValue}>{data.correlation_depth}</span>
            <span className={styles.memoryLabel}>Correlated Sessions</span>
          </div>
          <p className={styles.memoryDesc}>
            {data.correlation_depth > 1
              ? "Historical investigations linked to this entity influenced the current decision."
              : "No significant prior suspicious sessions found within the time window."}
          </p>
        </div>
      </Section>

      {/* ═══ EVIDENCE BOARD ═══ */}
      <Section title="EVIDENCE BOARD" accent="var(--green)" icon={Shield}>
        <div className={styles.evidenceBoard}>
          {(data.evidence_board || []).map((ev, idx) => (
            <div key={idx} className={styles.evidenceItem}>
              <div className={styles.evHeader}>
                <span className={styles.evSource}>{ev.source}</span>
                <span className={styles.evWeight}>Wt: {(ev.contribution * 100).toFixed(1)}%</span>
              </div>
              <p className={styles.evDesc}>{ev.description}</p>
            </div>
          ))}
          {(!data.evidence_board || data.evidence_board.length === 0) && (
            <div className={styles.muted}>No significant evidence accumulated.</div>
          )}
        </div>
      </Section>

      {/* ═══ REPORT SECTIONS ═══ */}
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
            {!data.investigation_report?.executive_summary && (
              <div className={styles.narrative}>
                <p>{data.llm_explanation}</p>
              </div>
            )}
          </div>
        </Section>

        <Section title="RESPONSE PLAYBOOK" accent="var(--red)" icon={Target}>
          <div className={styles.playbook}>
            <div className={styles.pbName}>{data.response_playbook?.name || 'Monitor Mode'}</div>
            {['IMMEDIATE', 'SHORT_TERM', 'LONG_TERM'].map(p => {
              const actions = data.response_playbook?.[p] || data.response_playbook?.[p.toLowerCase()];
              if (!actions || !actions.length) return null;
              return (
                <div key={p} className={styles.pbGroup}>
                  <div className={styles.pbPriority}>{p.replace('_', ' ')}</div>
                  {actions.map((act, i) => (
                    <div key={i} className={styles.pbAction}>▸ {typeof act === 'string' ? act : act.action}</div>
                  ))}
                </div>
              );
            })}
          </div>
        </Section>
      </div>

      {/* ═══ SPECIALIST EXECUTION LOG ═══ */}
      <Section title="SPECIALIST EXECUTION LOG" accent="var(--text-3)" icon={Zap} defaultOpen={false}>
        <div className={styles.specialistGrid}>
          {(data.tool_results || []).map((res, i) => (
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
                  <span>Conf: +{(res.confidence_contribution * 100).toFixed(1)}%</span>
                )}
              </div>
              {res.evidence_tags?.length > 0 && (
                <div className={styles.spTags}>
                  {res.evidence_tags.slice(0, 3).map((tag, j) => (
                    <span key={j} className={styles.spTag}>{tag}</span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </Section>

      {/* ═══ REPLAN EVENTS ═══ */}
      {data.replan_events?.length > 0 && (
        <Section title="REPLAN EVENTS" accent="var(--orange)" icon={RotateCcw} defaultOpen={false}>
          <div className={styles.replanList}>
            {data.replan_events.map((ev, i) => (
              <div key={i} className={styles.replanItem}>
                <span className={styles.replanIter}>Iteration {ev.iteration}</span>
                <p className={styles.replanReason}>{ev.reason}</p>
                {ev.old_hypothesis && (
                  <div className={styles.replanHyp}>
                    <span className={styles.replanOld}>{ev.old_hypothesis}</span>
                    <span className={styles.replanArrow}>→</span>
                    <span className={styles.replanNew}>{ev.new_hypothesis}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ═══ FOOTER TIMING ═══ */}
      <div className={styles.footer}>
        <span>Total Analysis: {data.total_analysis_ms?.toFixed(0) || '0'}ms</span>
        <span>Plan Iterations: {data.plan_iterations || 1}</span>
        <span>Tools Executed: {data.completed_tools?.length || 0}</span>
      </div>

    </div>
  );
}
