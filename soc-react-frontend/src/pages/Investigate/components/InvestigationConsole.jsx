import React, { useState } from 'react';
import { Copy, Shield, Activity, AlertTriangle, Eye, RefreshCw, ChevronDown, ChevronUp } from 'lucide-react';
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

function Section({ title, children, accent }) {
  const [open, setOpen] = useState(true);
  return (
    <div className={styles.section} style={accent ? { borderLeftColor: accent } : {}}>
      <div className={styles.sectionHead} onClick={() => setOpen(o => !o)}>
        <span>{title}</span>
        {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
      </div>
      {open && <div className={styles.sectionBody}>{children}</div>}
    </div>
  );
}

/* ── Console Component ── */
export default function InvestigationConsole({ data }) {
  if (!data) return null;

  const sevColor = SEVERITY_COLORS[data.severity?.toUpperCase()] || 'var(--cyan)';
  
  return (
    <div className={styles.consoleContainer}>
      
      {/* HEADER PANEL */}
      <div className={styles.headerPanel} style={{ borderColor: sevColor }}>
        <div className={styles.headerTop}>
          <div className={styles.incidentId}>INCIDENT // {data.incident_id || 'UNKNOWN'}</div>
          <div className={styles.statusBadge}>
            <RefreshCw size={12} /> {data.investigation_status || 'COMPLETED'}
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
      </div>

      {/* STRATEGY PANEL */}
      <div className={styles.panelGrid}>
        <Section title="INVESTIGATION STRATEGY" accent="var(--purple)">
          <div className={styles.strategyBox}>
            <div className={styles.hypothesis}>
              <span className={styles.label}>HYPOTHESIS:</span>
              <p>{data.investigation_hypothesis || 'No hypothesis generated.'}</p>
            </div>
            <div className={styles.toolLists}>
              <div className={styles.toolList}>
                <span className={styles.label}>PLANNED SPECIALISTS</span>
                <div className={styles.tags}>
                  {(data.planned_tools || []).map((t, i) => <span key={i} className={styles.tag}>{t}</span>)}
                </div>
              </div>
              {data.escalation_tools?.length > 0 && (
                <div className={styles.toolList}>
                  <span className={styles.label} style={{color: 'var(--orange)'}}>ESCALATION</span>
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
        
        {/* CROSS-SESSION MEMORY */}
        <Section title="INVESTIGATION MEMORY" accent="var(--blue)">
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
                : "No significant prior suspicious sessions found for this entity within the time window."}
            </p>
          </div>
        </Section>
      </div>

      {/* EVIDENCE BOARD */}
      <Section title="EVIDENCE BOARD" accent="var(--green)">
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

      {/* NARRATIVE & PLAYBOOK */}
      <div className={styles.panelGrid}>
        <Section title="EXECUTIVE NARRATIVE" accent="var(--cyan)">
          <div className={styles.narrative}>
            <p>{data.llm_explanation}</p>
          </div>
        </Section>

        <Section title="RESPONSE PLAYBOOK" accent="var(--red)">
          <div className={styles.playbook}>
            <div className={styles.pbName}>{data.response_playbook?.name || 'Monitor Mode'}</div>
            {['IMMEDIATE', 'SHORT_TERM'].map(p => {
              const actions = data.response_playbook?.[p] || data.response_playbook?.[p.toLowerCase()];
              if (!actions || !actions.length) return null;
              return (
                <div key={p} className={styles.pbGroup}>
                  <div className={styles.pbPriority}>{p}</div>
                  {actions.map((act, i) => (
                    <div key={i} className={styles.pbAction}>▸ {typeof act === 'string' ? act : act.action}</div>
                  ))}
                </div>
              );
            })}
          </div>
        </Section>
      </div>

      {/* SPECIALIST CARDS */}
      <Section title="SPECIALIST EXECUTION LOG" accent="var(--text-3)">
        <div className={styles.specialistGrid}>
          {(data.tool_results || []).map((res, i) => (
            <div key={i} className={styles.specialistCard}>
              <div className={styles.spHeader}>
                <span className={styles.spName}>{res.tool_name || res.tool || 'Specialist'}</span>
                <span className={styles.spStatus}>{res.status}</span>
              </div>
              <div className={styles.spMetrics}>
                <span>Exec: {res.execution_time_ms}ms</span>
              </div>
            </div>
          ))}
        </div>
      </Section>

    </div>
  );
}
