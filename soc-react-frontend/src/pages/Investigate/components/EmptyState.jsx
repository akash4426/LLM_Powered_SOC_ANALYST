// src/pages/Investigate/components/EmptyState.jsx
import styles from './EmptyState.module.css';
import { Shield, Terminal, Cpu, Database, Zap } from 'lucide-react';

const SYSTEM_ITEMS = [
  { label: 'LSTM Anomaly Engine', status: 'READY', color: 'var(--green)' },
  { label: 'MITRE ATT&CK RAG',   status: 'READY', color: 'var(--green)' },
  { label: 'LLM Planner',        status: 'STANDBY', color: 'var(--cyan)' },
  { label: 'Decision Engine',    status: 'READY', color: 'var(--green)' },
];

export default function EmptyState() {
  return (
    <div className={styles.container}>
      {/* Orbital rings */}
      <div className={styles.orbitalWrap}>
        <div className={styles.orbRing1} />
        <div className={styles.orbRing2} />
        <div className={styles.orbRing3} />
        <div className={styles.orbCenter}>
          <Shield size={28} color="var(--cyan)" strokeWidth={1.5} />
        </div>
        <div className={styles.orbIcon1}><Cpu size={12} color="var(--blue)" /></div>
        <div className={styles.orbIcon2}><Database size={12} color="var(--purple)" /></div>
        <div className={styles.orbIcon3}><Zap size={12} color="var(--orange)" /></div>
      </div>

      <div className={styles.textBlock}>
        <div className={styles.title}>SYSTEM READY</div>
        <p className={styles.sub}>
          Autonomous agentic investigation platform awaiting input
        </p>
      </div>

      {/* System status */}
      <div className={styles.statusList}>
        {SYSTEM_ITEMS.map(({ label, status, color }) => (
          <div key={label} className={styles.statusRow}>
            <span className={styles.statusDot} style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
            <span className={styles.statusLabel}>{label}</span>
            <span className={styles.statusVal} style={{ color }}>{status}</span>
          </div>
        ))}
      </div>

      <div className={styles.hint}>
        <Terminal size={11} style={{ color: 'var(--text-3)' }} />
        <span>Load a scenario or paste logs in the left panel, then press <kbd>RUN</kbd></span>
      </div>
    </div>
  );
}
