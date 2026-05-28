// src/pages/Investigate/components/EmptyState.jsx
import styles from './EmptyState.module.css';
import { Shield, Terminal } from 'lucide-react';

export default function EmptyState() {
  return (
    <div className={styles.container}>
      <div className={styles.ascii}>
        <pre className={styles.art}>{`
╔══════════════════════════════╗
║   SYSTEM  READY              ║
║   AWAITING  LOG  INPUT       ║
║                              ║
║  > load scenario             ║
║  > paste raw logs            ║
║  > upload .log/.csv file     ║
║  > press RUN (⌘↵)            ║
╚══════════════════════════════╝`}
        </pre>
      </div>
      <div className={styles.icons}>
        <Shield size={20} color="var(--cyan)" opacity={0.3} />
        <Terminal size={20} color="var(--text-3)" />
      </div>
      <p className={styles.hint}>
        Select a scenario, paste logs, or upload a <strong>.log</strong> / <strong>.txt</strong> / <strong>.csv</strong> file using the left panel.
      </p>
    </div>
  );
}
