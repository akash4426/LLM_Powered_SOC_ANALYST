// src/pages/Evaluate/Evaluate.jsx
import { useState } from 'react';
import { evaluate } from '../../api/socApi';
import { BarChart2, CheckCircle, XCircle, Target, TrendingUp } from 'lucide-react';
import styles from './Evaluate.module.css';

function MetricCard({ label, value, color, sub }) {
  return (
    <div className={styles.metricCard} style={{ borderTopColor: color }}>
      <div className={styles.metricLabel}>{label}</div>
      <div className={styles.metricValue} style={{ color }}>{value}</div>
      {sub && <div className={styles.metricSub}>{sub}</div>}
    </div>
  );
}

function ConfusionMatrix({ cm }) {
  const { true_positives: tp, false_positives: fp, true_negatives: tn, false_negatives: fn } = cm;
  return (
    <div className={styles.cmWrap}>
      <div className={styles.cmTitle}>CONFUSION MATRIX</div>
      <div className={styles.cmGrid}>
        <div />
        <div className={styles.cmHeader}>Predicted Positive</div>
        <div className={styles.cmHeader}>Predicted Negative</div>
        <div className={styles.cmSideHeader}>Actual Positive</div>
        <div className={`${styles.cmCell} ${styles.cmTp}`}><span className={styles.cmLabel}>TP</span><span className={styles.cmNum}>{tp}</span></div>
        <div className={`${styles.cmCell} ${styles.cmFn}`}><span className={styles.cmLabel}>FN</span><span className={styles.cmNum}>{fn}</span></div>
        <div className={styles.cmSideHeader}>Actual Negative</div>
        <div className={`${styles.cmCell} ${styles.cmFp}`}><span className={styles.cmLabel}>FP</span><span className={styles.cmNum}>{fp}</span></div>
        <div className={`${styles.cmCell} ${styles.cmTn}`}><span className={styles.cmLabel}>TN</span><span className={styles.cmNum}>{tn}</span></div>
      </div>
    </div>
  );
}

function ProgressBar({ value, color }) {
  return (
    <div className={styles.barRow}>
      <div className={styles.barTrack}>
        <div className={styles.barFill} style={{ width: `${(value * 100).toFixed(1)}%`, background: color }} />
      </div>
      <span className={styles.barPct}>{(value * 100).toFixed(1)}%</span>
    </div>
  );
}

export default function Evaluate() {
  const [loading, setLoading] = useState(false);
  const [result, setResult]  = useState(null);
  const [error, setError]    = useState('');

  const run = async () => {
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const data = await evaluate();
      setResult(data);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Evaluation failed');
    } finally {
      setLoading(false);
    }
  };

  const m = result?.metrics;

  return (
    <div className={styles.page}>
      <div className={styles.inner}>

        <div className={styles.header}>
          <div className={styles.headerIcon}>
            <BarChart2 size={22} color="var(--green)" strokeWidth={1.5} />
          </div>
          <div>
            <h1 className={styles.title}>DETECTION EVALUATION</h1>
            <p className={styles.subtitle}>Run the built-in evaluation suite against the labelled test dataset</p>
          </div>
          <button className={styles.runBtn} onClick={run} disabled={loading}>
            {loading ? <span className={styles.spinner} /> : <Target size={14} />}
            {loading ? 'EVALUATING…' : 'RUN EVALUATION'}
          </button>
        </div>

        {error && <div className={styles.error}>{error}</div>}

        {result && m && (
          <>
            <div className={styles.statusRow}>
              <CheckCircle size={14} color="var(--green)" />
              <span>Evaluation complete — dataset size: <strong>{result.dataset_size}</strong></span>
            </div>

            {/* Metric cards */}
            <div className={styles.metricGrid}>
              <MetricCard label="PRECISION" value={`${(m.precision * 100).toFixed(1)}%`} color="var(--cyan)" sub="TP/(TP+FP)" />
              <MetricCard label="RECALL" value={`${(m.recall * 100).toFixed(1)}%`} color="var(--blue)" sub="TP/(TP+FN)" />
              <MetricCard label="F1 SCORE" value={`${(m.f1_score * 100).toFixed(1)}%`} color="var(--purple)" sub="Harmonic mean" />
              <MetricCard label="ACCURACY" value={`${(m.accuracy * 100).toFixed(1)}%`} color="var(--green)" sub="Overall" />
              <MetricCard label="SPECIFICITY" value={`${(m.specificity * 100).toFixed(1)}%`} color="var(--orange)" sub="TN/(TN+FP)" />
              <MetricCard label="FALSE POSITIVE RATE" value={`${(m.false_positive_rate * 100).toFixed(1)}%`} color="var(--red)" sub="FP/(FP+TN)" />
            </div>

            {/* Visual bars */}
            <div className={styles.barsCard}>
              <div className={styles.barsTitle}>METRIC VISUALIZATION</div>
              {[
                ['Precision', m.precision, 'var(--cyan)'],
                ['Recall', m.recall, 'var(--blue)'],
                ['F1 Score', m.f1_score, 'var(--purple)'],
                ['Accuracy', m.accuracy, 'var(--green)'],
                ['Specificity', m.specificity, 'var(--orange)'],
              ].map(([label, val, color]) => (
                <div key={label} className={styles.barItem}>
                  <div className={styles.barLabel}>{label}</div>
                  <ProgressBar value={val} color={color} />
                </div>
              ))}
            </div>

            {/* Confusion matrix */}
            <ConfusionMatrix cm={result.confusion_matrix} />
          </>
        )}

        {!result && !loading && (
          <div className={styles.emptyState}>
            <BarChart2 size={48} color="var(--text-3)" strokeWidth={1} />
            <p>Click "RUN EVALUATION" to run the detection suite against the labelled test dataset.</p>
            <p className={styles.hint}>Uses heuristic mock detector — no LLM inference required. Responds quickly.</p>
          </div>
        )}

      </div>
    </div>
  );
}
