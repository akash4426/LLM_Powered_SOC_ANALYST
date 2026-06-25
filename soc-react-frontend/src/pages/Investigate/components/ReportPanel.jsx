// src/pages/Investigate/components/ReportPanel.jsx
import { useState, useRef } from 'react';
import { Copy, Check, ChevronDown, ChevronUp, Shield, Activity, AlertTriangle, Eye, Printer, Download } from 'lucide-react';
import { SEVERITY_COLORS } from '../../../constants/scenarios';
import styles from './ReportPanel.module.css';

/* ── Helpers ────────────────────────────────────────────────────── */
function pct(v, max = 1) { return Math.min(100, Math.round((v / max) * 100)); }

function MetricBar({ value, max = 1, color }) {
  const p = pct(value, max);
  return (
    <div className={styles.barWrap}>
      <div className={styles.bar} style={{ width: `${p}%`, background: color || 'var(--cyan)' }} />
    </div>
  );
}

function SeverityPill({ severity }) {
  const color = SEVERITY_COLORS[severity?.toUpperCase()] || '#4488ff';
  return (
    <span className={styles.sevPill} style={{ background: `${color}18`, color, borderColor: `${color}40` }}>
      {severity?.toUpperCase()}
    </span>
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

/* ── IOC Table ── */
function IocTable({ iocs }) {
  if (!iocs) return <span className={styles.muted}>No IOCs extracted</span>;
  const rows = [];
  Object.entries(iocs).forEach(([type, items]) => {
    if (Array.isArray(items)) {
      items.forEach(item => {
        const val = typeof item === 'string' ? item : item.value || JSON.stringify(item);
        const status = typeof item === 'object' ? (item.classification || item.type) : 'UNKNOWN';
        rows.push({ type, val, status });
      });
    }
  });
  if (!rows.length) return <span className={styles.muted}>No IOCs extracted</span>;
  return (
    <table className={styles.iocTable}>
      <thead>
        <tr>
          <th>TYPE</th>
          <th>INDICATOR</th>
          <th>STATUS</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            <td><span className={styles.iocType}>{r.type.toUpperCase()}</span></td>
            <td className={styles.iocVal}>{r.val}</td>
            <td>
              <span className={styles.iocStatus} style={{
                color: r.status === 'SUSPICIOUS' ? 'var(--red)' : r.status === 'PRIVATE' ? 'var(--orange)' : 'var(--text-3)'
              }}>{r.status}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/* ── Playbook ── */
function Playbook({ playbook }) {
  if (!playbook || !playbook.name) return <span className={styles.muted}>No playbook generated</span>;
  const priorities = ['IMMEDIATE', 'SHORT_TERM', 'LONG_TERM'];
  return (
    <div className={styles.playbook}>
      <div className={styles.playbookName}>{playbook.name}</div>
      {playbook.sla && <div className={styles.playbookSla}>SLA: {playbook.sla}</div>}
      {priorities.map(p => {
        const actions = playbook[p.toLowerCase()] || playbook[p] || [];
        if (!actions.length) return null;
        return (
          <div key={p} className={styles.pbGroup}>
            <div className={styles.pbPriority} style={{
              color: p === 'IMMEDIATE' ? 'var(--red)' : p === 'SHORT_TERM' ? 'var(--orange)' : 'var(--text-2)'
            }}>{p}</div>
            {actions.map((a, i) => (
              <div key={i} className={styles.pbAction}>
                <span className={styles.pbBullet}>▸</span>
                <span>{typeof a === 'string' ? a : a.action || JSON.stringify(a)}</span>
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}

/* ── Reasoning Trace ── */
/** Extract a short, human-readable description from a trace step. */
function extractTraceContent(step) {
  // Prefer explicit human-readable fields first
  if (step.description && typeof step.description === 'string') return step.description;
  if (step.summary   && typeof step.summary   === 'string') return step.summary;
  if (step.thought   && typeof step.thought   === 'string') return step.thought;
  // For tool_results, show a compact summary of what ran
  if (Array.isArray(step.tool_results) && step.tool_results.length) {
    const names = step.tool_results.map(t => t.tool_name || t.name || '?').join(', ');
    return `Ran ${step.tool_results.length} tool(s): ${names}`;
  }
  // For output objects, pull the top-level string values only
  if (step.output && typeof step.output === 'object') {
    const parts = Object.entries(step.output)
      .filter(([, v]) => typeof v === 'string' || typeof v === 'number')
      .slice(0, 3)
      .map(([k, v]) => `${k}: ${v}`);
    if (parts.length) return parts.join(' · ');
  }
  // Last resort: a trimmed 120-char excerpt of the JSON (no full dump)
  const raw = JSON.stringify(step);
  return raw.length > 120 ? raw.slice(0, 120) + '…' : raw;
}

const PHASE_COLORS = {
  observe:    'var(--blue)',
  think:      'var(--purple)',
  act:        'var(--orange)',
  synthesize: 'var(--cyan)',
  decide:     'var(--red)',
  explain:    'var(--green)',
};

function ReasoningTrace({ trace }) {
  if (!trace?.length) return <span className={styles.muted}>No reasoning trace available</span>;
  return (
    <div className={styles.trace}>
      {trace.map((step, i) => {
        const phase = (step.phase || step.action || `step_${i + 1}`).toLowerCase();
        const color = PHASE_COLORS[phase] || 'var(--text-2)';
        const content = extractTraceContent(step);
        return (
          <div key={i} className={styles.traceStep}>
            <div className={styles.traceHeader}>
              <span className={styles.tracePhase} style={{ color }}>
                {(step.phase || step.action || `STEP ${i + 1}`).toUpperCase()}
              </span>
              {step.duration_ms != null && (
                <span className={styles.traceDuration}>{step.duration_ms}ms</span>
              )}
            </div>
            <div className={styles.traceContent}>{content}</div>
          </div>
        );
      })}
    </div>
  );
}

/* ── Timeline ── */
function Timeline({ timeline }) {
  if (!timeline?.length) return <span className={styles.muted}>No timeline data</span>;
  return (
    <div className={styles.timeline}>
      {timeline.map((ev, i) => (
        <div key={i} className={styles.tlRow}>
          <div className={styles.tlDot} />
          <div className={styles.tlContent}>
            <span className={styles.tlTs}>{ev.timestamp?.slice(0, 19) || '—'}</span>
            <span className={styles.tlEvt}>{ev.event_type || ev.type || '—'}</span>
            {ev.description && <span className={styles.tlDesc}>{ev.description}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ── Collapsible Trace Accordion ── */
function CollapsibleTrace({ trace }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={styles.traceSection}>
      <button className={styles.traceSectionHead} onClick={() => setOpen(o => !o)}>
        <Activity size={12} />
        <span>AGENT REASONING TRACE</span>
        <span className={styles.traceBadge}>{trace.length} steps</span>
        <span className={styles.traceChevron}>{open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}</span>
      </button>
      {open && <ReasoningTrace trace={trace} />}
    </div>
  );
}

/* ── Main ReportPanel ───────────────────────────────────────────── */
export default function ReportPanel({ data, agentMode }) {
  const [copied, setCopied] = useState(false);
  const [showRaw, setShowRaw] = useState(false);

  // For agent mode, dig into pipeline_report for standard fields
  const report = agentMode && data.pipeline_report ? data.pipeline_report : data;
  const agent  = agentMode ? data : null;

  const sev        = (agent?.severity || report?.severity || 'UNKNOWN').toUpperCase();
  const anomaly    = agent?.compound_anomaly_score ?? agent?.anomaly_score ?? report?.anomaly_score ?? 0;
  const confidence = agent?.confidence ?? report?.confidence ?? 0;
  const riskScore  = agent?.risk_score ?? 0;
  const decision   = agent?.decision ?? null;

  const copyReport = async () => {
    await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const exportPDF = () => {
    const printWin = window.open('', '_blank', 'width=900,height=700');
    const incidentId = report?.incident_id || agent?.incident_id || 'INCIDENT';
    const ts = (report?.timestamp || '').slice(0, 19);
    const sevColor = SEVERITY_COLORS[sev] || '#4488ff';
    const mitreTechs = (report?.mitre_techniques || []).join(', ') || 'None';
    const explanation = report?.llm_explanation || agent?.llm_explanation || '—';
    const recommendations = (report?.recommended_response || []).map(r => `<li>${r}</li>`).join('');
    const whyFlagged = (agent?.why_flagged || []).map(r => `<li>${r}</li>`).join('');
    printWin.document.write(`
      <!DOCTYPE html><html><head>
      <title>SOC Incident Report — ${incidentId}</title>
      <style>
        body { font-family: 'Segoe UI', sans-serif; background: #fff; color: #111; margin: 40px; }
        h1 { font-size: 22px; color: #111; border-bottom: 2px solid #ddd; padding-bottom: 8px; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: 700; font-size: 12px; }
        .meta { color: #555; font-size: 12px; margin: 8px 0 20px; }
        h2 { font-size: 14px; margin: 20px 0 6px; text-transform: uppercase; letter-spacing: 0.05em; color: #333; }
        p, li { font-size: 13px; line-height: 1.7; color: #333; }
        .metric-row { display: flex; gap: 20px; margin: 10px 0; }
        .metric-box { border: 1px solid #ddd; border-radius: 6px; padding: 10px 16px; min-width: 100px; }
        .metric-val { font-size: 20px; font-weight: 700; }
        .metric-key { font-size: 10px; color: #888; text-transform: uppercase; }
        @media print { body { margin: 20px; } }
      </style></head><body>
      <h1>🛡 LLM-Powered SOC Analyst — Incident Report</h1>
      <div class='meta'>ID: ${incidentId} &nbsp;|&nbsp; ${ts} &nbsp;|&nbsp;
        <span class='badge' style='background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}44'>${sev}</span>
        ${decision ? `&nbsp;|&nbsp; Decision: <strong>${decision}</strong>` : ''}
      </div>
      <div class='metric-row'>
        <div class='metric-box'><div class='metric-val'>${(anomaly * 100).toFixed(1)}%</div><div class='metric-key'>Anomaly Score</div></div>
        <div class='metric-box'><div class='metric-val'>${(confidence * 100).toFixed(1)}%</div><div class='metric-key'>Confidence</div></div>
        ${agentMode ? `<div class='metric-box'><div class='metric-val'>${riskScore.toFixed(1)}/100</div><div class='metric-key'>Risk Score</div></div>` : ''}
      </div>
      <h2>MITRE ATT&CK Techniques</h2><p>${mitreTechs}</p>
      <h2>Analyst Findings</h2><p>${explanation.replace(/\n/g,'<br>')}</p>
      <h2>Recommended Response</h2><ul>${recommendations || '<li>No recommendations generated</li>'}</ul>
      ${whyFlagged ? `<h2>Why Flagged</h2><ul>${whyFlagged}</ul>` : ''}
      <p style='margin-top:30px;font-size:11px;color:#aaa'>Generated by LLM-Powered SOC Analyst v5.0 &mdash; ${new Date().toLocaleString()}</p>
      </body></html>`);
    printWin.document.close();
    setTimeout(() => printWin.print(), 400);
  };

  const decisionColor = {
    AUTO_REMEDIATE: 'var(--red)',
    ESCALATE_L2: 'var(--orange)',
    MONITOR: 'var(--yellow)',
  }[decision] || 'var(--text-2)';

  const decisionBgGradient = {
    AUTO_REMEDIATE: 'linear-gradient(90deg, rgba(255,68,68,0.12), transparent)',
    ESCALATE_L2: 'linear-gradient(90deg, rgba(255,152,0,0.08), transparent)',
    MONITOR: 'linear-gradient(90deg, rgba(255,215,64,0.06), transparent)',
  }[decision] || 'transparent';

  return (
    <div className={styles.wrapper}>
      {/* ── Decision Banner (agent mode) ── */}
      {agentMode && decision && (
        <div className={styles.decisionBanner} style={{ background: decisionBgGradient, borderLeftColor: decisionColor }}>
          <div className={styles.decisionIcon} style={{ color: decisionColor }}>⚡</div>
          <div>
            <div className={styles.decisionLabel} style={{ color: decisionColor }}>{decision.replace('_', ' ')}</div>
            <div className={styles.decisionSub}>Agent autonomous decision · Risk: {riskScore.toFixed(1)}/100</div>
          </div>
        </div>
      )}
      <div className={styles.reportBar}>
        <div className={styles.reportBarLeft}>
          <Shield size={13} color="var(--cyan)" />
          <span className={styles.incidentId}>{report?.incident_id || agent?.incident_id || '—'}</span>
          <span className={styles.ts}>{(report?.timestamp || '').slice(0, 19)}</span>
        </div>
        <div className={styles.reportBarRight}>
          <SeverityPill severity={sev} />
          {decision && (
            <span className={styles.decision} style={{ color: decisionColor, borderColor: `${decisionColor}40` }}>
              {decision}
            </span>
          )}
          <button className={styles.copyBtn} onClick={copyReport}>
            {copied ? <Check size={12} /> : <Copy size={12} />}
            {copied ? 'COPIED' : 'COPY'}
          </button>
          <button className={styles.copyBtn} onClick={exportPDF} title="Export PDF">
            <Printer size={12} />
            PDF
          </button>
        </div>
      </div>

      {/* ── Metric strip ── */}
      <div className={styles.metricStrip}>
        <div className={styles.metricBlock}>
          <div className={styles.metricKey}>ANOMALY SCORE</div>
          <div className={styles.metricVal} style={{ color: anomaly > 0.7 ? 'var(--red)' : anomaly > 0.4 ? 'var(--orange)' : 'var(--green)' }}>
            {anomaly.toFixed(3)}
          </div>
          <MetricBar value={anomaly} color={anomaly > 0.7 ? 'var(--red)' : anomaly > 0.4 ? 'var(--orange)' : 'var(--green)'} />
        </div>
        <div className={styles.metricBlock}>
          <div className={styles.metricKey}>CONFIDENCE</div>
          <div className={styles.metricVal}>{(confidence * 100).toFixed(1)}%</div>
          <MetricBar value={confidence} color="var(--blue)" />
        </div>
        {agentMode && (
          <div className={styles.metricBlock}>
            <div className={styles.metricKey}>RISK SCORE</div>
            <div className={styles.metricVal} style={{ color: riskScore > 70 ? 'var(--red)' : riskScore > 40 ? 'var(--orange)' : 'var(--green)' }}>
              {riskScore.toFixed(1)}
            </div>
            <MetricBar value={riskScore} max={100} color={riskScore > 70 ? 'var(--red)' : riskScore > 40 ? 'var(--orange)' : 'var(--green)'} />
          </div>
        )}
        <div className={styles.metricBlock}>
          <div className={styles.metricKey}>EVENTS</div>
          <div className={styles.metricVal}>{report?.events_analyzed ?? '—'}</div>
        </div>
        <div className={styles.metricBlock}>
          <div className={styles.metricKey}>SESSIONS</div>
          <div className={styles.metricVal}>{report?.session_count ?? '—'}</div>
        </div>
        {agentMode && agent?.correlation_depth != null && (
          <div className={styles.metricBlock}>
            <div className={styles.metricKey}>CORRELATION</div>
            <div className={styles.metricVal}>{agent.correlation_depth}</div>
          </div>
        )}
      </div>

      {/* ── Report body ── */}
      <div className={styles.reportBody}>

        {/* LEFT column */}
        <div className={styles.colLeft}>

          <Section title="KILL CHAIN STAGE">
            <div className={styles.killChainPath}>
              {(report?.kill_chain_path || []).map((stage, i) => (
                <span key={i} className={styles.kcStage}>{stage}</span>
              ))}
              {!report?.kill_chain_path?.length && <span className={styles.muted}>{report?.kill_chain_stage || '—'}</span>}
            </div>
          </Section>

          <Section title="MITRE ATT&CK TECHNIQUES">
            <div className={styles.mitreTags}>
              {(report?.mitre_techniques || []).map((t, i) => (
                <span key={i} className={styles.mitreTag}>{t}</span>
              ))}
              {!report?.mitre_techniques?.length && <span className={styles.muted}>No techniques mapped</span>}
            </div>
            {agentMode && agent?.compound_mitre_mappings?.length > 0 && (
              <>
                <div className={styles.subLabel}>COMPOUND (AGENT)</div>
                <div className={styles.mitreTags}>
                  {agent.compound_mitre_mappings.map((t, i) => (
                    <span key={i} className={`${styles.mitreTag} ${styles.mitreTagAgent}`}>{t}</span>
                  ))}
                </div>
              </>
            )}
          </Section>

          <Section title="ATTACK GRAPH PATH">
            <div className={styles.graphPath}>
              {(report?.attack_graph?.attack_path || []).map((node, i) => (
                <span key={i} className={styles.graphNode}>
                  {node}
                  {i < (report.attack_graph.attack_path.length - 1) && <span className={styles.arrow}>→</span>}
                </span>
              ))}
              {!report?.attack_graph?.attack_path?.length && <span className={styles.muted}>No attack path reconstructed</span>}
            </div>
          </Section>

          <Section title="THREAT INTEL HITS">
            <div className={styles.tiList}>
              {(report?.threat_intel?.indicators || []).filter(i => i.is_malicious).map((ind, i) => (
                <div key={i} className={styles.tiRow}>
                  <span className={styles.tiBadge} style={{ background: 'rgba(255,68,68,0.1)', color: 'var(--red)' }}>
                    {ind.indicator_type}
                  </span>
                  <span className={styles.tiVal}>{ind.indicator}</span>
                  <span className={styles.tiScore}>{ind.risk_score}</span>
                </div>
              ))}
              {!(report?.threat_intel?.indicators || []).filter(i => i.is_malicious).length && (
                <span className={styles.muted}>No malicious indicators found</span>
              )}
            </div>
          </Section>

          <Section title="MITRE ATT&CK RAG KNOWLEDGE">
            {(report?.rag_snippets || []).map((snip, i) => (
              <div key={i} className={styles.ragSnip}>{snip}</div>
            ))}
            {!report?.rag_snippets?.length && <span className={styles.muted}>No RAG context retrieved</span>}
          </Section>

          {agentMode && agent?.iocs_extracted && Object.keys(agent.iocs_extracted).length > 0 && (
            <Section title="EXTRACTED IOCs" accent="var(--cyan)">
              <IocTable iocs={agent.iocs_extracted} />
            </Section>
          )}

        </div>

        {/* RIGHT column */}
        <div className={styles.colRight}>

          <Section title="ANALYST FINDINGS">
            <div className={styles.explanation}>
              {report?.llm_explanation || agent?.llm_explanation || '—'}
            </div>
            {report?.llm_warning && (
              <div className={styles.warning}>
                <AlertTriangle size={12} />
                {report.llm_warning}
              </div>
            )}
          </Section>

          <Section title="RECOMMENDED RESPONSE">
            <ol className={styles.responseList}>
              {(report?.recommended_response || []).map((r, i) => (
                <li key={i}>{r}</li>
              ))}
              {!report?.recommended_response?.length && <span className={styles.muted}>No recommendations generated</span>}
            </ol>
          </Section>

          {agentMode && agent?.response_playbook && (
            <Section title="RESPONSE PLAYBOOK" accent="var(--cyan)">
              <Playbook playbook={agent.response_playbook} />
            </Section>
          )}

          {agentMode && agent?.correlated_timeline?.length > 0 && (
            <Section title="CORRELATED ATTACK TIMELINE" accent="var(--cyan)">
              <Timeline timeline={agent.correlated_timeline} />
            </Section>
          )}

          {agentMode && agent?.why_flagged?.length > 0 && (
            <Section title="WHY FLAGGED" accent="var(--orange)">
              <ul className={styles.whyList}>
                {agent.why_flagged.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </Section>
          )}

          {agentMode && agent?.campaign_pattern && (
            <Section title="CAMPAIGN PATTERN" accent="var(--purple)">
              <div className={styles.campaignBadge}>{agent.campaign_pattern}</div>
            </Section>
          )}

        </div>
      </div>

      {/* ── Reasoning Trace — collapsed by default ── */}
      {agentMode && agent?.reasoning_trace?.length > 0 && (
        <CollapsibleTrace trace={agent.reasoning_trace} />
      )}

      {/* ── Raw JSON toggle ── */}
      <div className={styles.rawSection}>
        <button className={styles.rawToggle} onClick={() => setShowRaw(v => !v)}>
          <Eye size={11} />
          {showRaw ? 'HIDE' : 'SHOW'} RAW OUTPUT
        </button>
        {showRaw && (
          <pre className={styles.rawBody}>{JSON.stringify(data, null, 2)}</pre>
        )}
      </div>
    </div>
  );
}
