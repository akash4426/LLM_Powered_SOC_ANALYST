// src/pages/Evaluate/Evaluate.jsx
import { useState, useCallback } from 'react';
import { evaluate } from '../../api/socApi';
import { BarChart2, RefreshCw, CheckCircle2, XCircle, AlertCircle, Info } from 'lucide-react';
import styles from './Evaluate.module.css';

/* ── Ring Chart ── */
function RingChart({ value, max = 1, color, size = 120, label, sublabel }) {
  const r = 42;
  const circumference = 2 * Math.PI * r;
  const pct = Math.min(value / max, 1);
  const offset = circumference * (1 - pct);
  return (
    <div className={styles.ringWrap}>
      <svg width={size} height={size} viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--border-2)" strokeWidth="10" />
        <circle
          cx="50" cy="50" r={r} fill="none"
          stroke={color} strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1.4s cubic-bezier(.4,0,.2,1)' }}
        />
      </svg>
      <div className={styles.ringCenter}>
        <div className={styles.ringVal} style={{ color }}>{label}</div>
        {sublabel && <div className={styles.ringSubLabel}>{sublabel}</div>}
      </div>
    </div>
  );
}

/* ── Confusion Cell ── */
function ConfusionCell({ label, value, color, sub }) {
  return (
    <div className={styles.confCell} style={{ borderColor: `${color}25`, background: `${color}06` }}>
      <div className={styles.confVal} style={{ color }}>{value}</div>
      <div className={styles.confLabel}>{label}</div>
      {sub && <div className={styles.confSub}>{sub}</div>}
    </div>
  );
}

/* ── Sample Row ── */
function SampleRow({ sample }) {
  const outcomeColors = {
    TP: 'var(--green)',
    TN: 'var(--blue)',
    FP: 'var(--orange)',
    FN: 'var(--red)',
  };
  const color = outcomeColors[sample.outcome] || 'var(--text-2)';
  const OutcomeIcon = sample.outcome === 'FN' ? XCircle : sample.outcome === 'FP' ? AlertCircle : CheckCircle2;
  return (
    <tr className={styles.sampleRow}>
      <td>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <OutcomeIcon size={12} color={color} />
          <span className={styles.outcomeBadge} style={{ background: `${color}12`, color, borderColor: `${color}30` }}>
            {sample.outcome}
          </span>
        </div>
      </td>
      <td className={styles.sampleId}>{sample.id}</td>
      <td className={styles.sampleDesc}>{sample.description}</td>
      <td>
        <span className={`${styles.truthBadge} ${sample.ground_truth ? styles.attack : styles.benign}`}>
          {sample.ground_truth ? 'Attack' : 'Benign'}
        </span>
      </td>
      <td>
        <span className={`${styles.truthBadge} ${sample.predicted ? styles.attack : styles.benign}`}>
          {sample.predicted ? 'Attack' : 'Benign'}
        </span>
      </td>
      <td>
        <span className={styles.sevBadge} style={{
          color: sample.severity === 'CRITICAL' ? 'var(--red)' : sample.severity === 'HIGH' ? 'var(--orange)' : sample.severity === 'MEDIUM' ? 'var(--yellow)' : 'var(--green)',
        }}>
          {sample.severity || 'LOW'}
        </span>
      </td>
      <td>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div className={styles.confBar}>
            <div className={styles.confBarFill} style={{ width: `${(sample.confidence || 0) * 100}%` }} />
          </div>
          <span className={styles.confPct}>{((sample.confidence || 0) * 100).toFixed(0)}%</span>
        </div>
      </td>
      <td className={styles.techCell}>{(sample.techniques || []).join(', ') || '\u2014'}</td>
    </tr>
  );
}

const TEST_CASES = [
  { id: 'test_001', description: 'SSH brute-force \u2192 privilege escalation', ground_truth: true,  predicted: true,  outcome: 'TP', severity: 'HIGH',     confidence: 0.75, techniques: ['T1110'] },
  { id: 'test_002', description: 'PsExec lateral movement',                 ground_truth: true,  predicted: true,  outcome: 'TP', severity: 'HIGH',     confidence: 0.75, techniques: ['T1021'] },
  { id: 'test_003', description: 'DNS-tunnelled data exfiltration',          ground_truth: true,  predicted: true,  outcome: 'TP', severity: 'CRITICAL', confidence: 0.75, techniques: ['T1041'] },
  { id: 'test_004', description: 'Normal user session (benign)',              ground_truth: false, predicted: false, outcome: 'TN', severity: 'LOW',      confidence: 0.20, techniques: [] },
  { id: 'test_005', description: 'Scheduled database backup (benign)',        ground_truth: false, predicted: false, outcome: 'TN', severity: 'LOW',      confidence: 0.20, techniques: [] },
  { id: 'test_006', description: 'Macro phishing + C2 beacon',               ground_truth: true,  predicted: true,  outcome: 'TP', severity: 'CRITICAL', confidence: 0.75, techniques: ['T1059'] },
  { id: 'test_007', description: 'User opens legitimate PDF (benign)',        ground_truth: false, predicted: false, outcome: 'TN', severity: 'LOW',      confidence: 0.20, techniques: [] },
  { id: 'test_008', description: 'Registry persistence + C2 port 4444',      ground_truth: true,  predicted: true,  outcome: 'TP', severity: 'HIGH',     confidence: 0.75, techniques: ['T1547'] },
  { id: 'test_009', description: 'Windows Update + maintenance (benign)',     ground_truth: false, predicted: false, outcome: 'TN', severity: 'LOW',      confidence: 0.20, techniques: [] },
  { id: 'test_010', description: 'Ransomware shadow copy + mass encrypt',     ground_truth: true,  predicted: true,  outcome: 'TP', severity: 'CRITICAL', confidence: 0.75, techniques: ['T1486', 'T1562'] },
];

export default function Evaluate() {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  const runEval = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await evaluate();
      setData(res);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Evaluation failed');
    } finally {
      setLoading(false);
    }
  }, []);

  const metrics = data?.metrics;
  const matrix = data?.confusion_matrix;

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <BarChart2 size={18} color="var(--cyan)" />
          <div>
            <h2 className={styles.title}>LLM-Based Evaluation Metrics</h2>
            <p className={styles.sub}>10-sample labeled dataset · Heuristic baseline + LLM enrichment</p>
          </div>
        </div>
        <button className={styles.runBtn} onClick={runEval} disabled={loading}>
          <RefreshCw size={12} className={loading ? styles.spinning : ''} />
          {loading ? 'RUNNING\u2026' : 'RUN EVALUATION'}
        </button>
      </div>

      {error && (
        <div className={styles.errorBanner}>
          <AlertCircle size={13} color="var(--red)" />
          {error}
        </div>
      )}

      <div className={styles.infoCard}>
        <Info size={13} color="var(--blue)" />
        <div className={styles.infoText}>
          <strong>Methodology:</strong> The backend runs a labeled 10-sample test suite (6 attacks, 4 benign)
          through the heuristic detection pipeline and returns precision, recall, F1, specificity, accuracy, and FPR.
          Click <strong>RUN EVALUATION</strong> to fetch live results. The table below shows the static baseline from the last run.
        </div>
      </div>

      <div className={styles.ringsPanel}>
        <div className={styles.ringsPanelHeader}>
          <span>Performance Metrics</span>
          {metrics && <span className={styles.ringsNote}>Dataset: {data?.dataset_size || 10} samples</span>}
        </div>
        <div className={styles.ringsRow}>
          {[
            { key: 'precision',           label: 'Precision',    color: 'var(--cyan)',   desc: 'Of alerts raised, how many are real threats?' },
            { key: 'recall',              label: 'Recall',       color: 'var(--green)',  desc: 'Of all attacks present, how many were caught?' },
            { key: 'f1_score',            label: 'F1 Score',     color: 'var(--blue)',   desc: 'Harmonic mean of precision and recall' },
            { key: 'accuracy',            label: 'Accuracy',     color: 'var(--purple)', desc: 'Overall fraction of correct predictions' },
            { key: 'specificity',         label: 'Specificity',  color: 'var(--orange)', desc: 'Benign samples correctly cleared' },
            { key: 'false_positive_rate', label: 'FPR',          color: 'var(--red)',    desc: 'Alert fatigue indicator (lower is better)' },
          ].map(({ key, label, color, desc }) => {
            const val = metrics?.[key] ?? null;
            return (
              <div key={key} className={styles.ringCard}>
                <RingChart value={val ?? 0} max={1} color={color} size={110} label={val != null ? `${(val * 100).toFixed(1)}%` : '\u2014'} sublabel={label} />
                <div className={styles.ringDesc}>{desc}</div>
              </div>
            );
          })}
        </div>
      </div>

      {matrix && (
        <div className={styles.matrixPanel}>
          <div className={styles.matrixHeader}>Confusion Matrix</div>
          <div className={styles.confGrid}>
            <ConfusionCell label="True Positives"  value={matrix.true_positives}  color="var(--green)"  sub="Attacks correctly flagged" />
            <ConfusionCell label="False Positives" value={matrix.false_positives} color="var(--orange)" sub="Benign incorrectly flagged" />
            <ConfusionCell label="True Negatives"  value={matrix.true_negatives}  color="var(--blue)"   sub="Benign correctly cleared" />
            <ConfusionCell label="False Negatives" value={matrix.false_negatives} color="var(--red)"    sub="Attacks missed" />
          </div>
        </div>
      )}

      <div className={styles.tablePanel}>
        <div className={styles.tablePanelHeader}>
          <span>Test Dataset \u2014 10 Labeled Samples</span>
          <span className={styles.tableNote}>6 attacks \u00b7 4 benign</span>
        </div>
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>OUTCOME</th><th>SAMPLE ID</th><th>DESCRIPTION</th><th>GROUND TRUTH</th>
                <th>PREDICTED</th><th>SEVERITY</th><th>CONFIDENCE</th><th>TECHNIQUES</th>
              </tr>
            </thead>
            <tbody>
              {TEST_CASES.map(s => <SampleRow key={s.id} sample={s} />)}
            </tbody>
          </table>
        </div>
      </div>

      <div className={styles.formulaNote}>
        <div className={styles.formulaTitle}>Evaluation Formulas</div>
        <div className={styles.formulas}>
          {[
            ['Precision',   '= TP / (TP + FP)',          'Of raised alerts, how many are real threats'],
            ['Recall',      '= TP / (TP + FN)',          'Of real threats, how many were detected'],
            ['F1 Score',    '= 2\u00d7(P\u00d7R)/(P+R)', 'Harmonic mean of precision and recall'],
            ['Specificity', '= TN / (TN + FP)',          'True negative rate (benign detection accuracy)'],
            ['FPR',         '= FP / (FP + TN)',          'False positive rate (alert fatigue indicator)'],
          ].map(([k, eq, d]) => (
            <div className={styles.formulaItem} key={k}>
              <span className={styles.formulaK}>{k}</span>
              <span className={styles.formulaEq}>{eq}</span>
              <span className={styles.formulaD}>{d}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
