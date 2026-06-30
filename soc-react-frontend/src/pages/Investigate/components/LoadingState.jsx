// src/pages/Investigate/components/LoadingState.jsx
import { useState, useEffect } from 'react';
import { AGENT_PHASES } from '../../../constants/scenarios';
import styles from './LoadingState.module.css';

export default function LoadingState({ pipeStep, startTime }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const iv = setInterval(() => {
      setElapsed(Math.floor((Date.now() - (startTime || Date.now())) / 1000));
    }, 1000);
    return () => clearInterval(iv);
  }, [startTime]);

  const total = AGENT_PHASES.length;
  const progress = total > 0 ? Math.round((pipeStep / total) * 100) : 0;

  return (
    <div className={styles.container}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.spinnerBlock}>
          <div className={styles.spinner} />
          <div className={styles.spinnerRing} />
          <div className={styles.spinnerCore} />
        </div>
        <div>
          <div className={styles.title}>AGENT ORCHESTRATION IN PROGRESS</div>
          <div className={styles.sub}>Autonomous analyst investigating session events</div>
        </div>
      </div>

      {/* Progress bar */}
      <div className={styles.progressWrap}>
        <div className={styles.progressTrack}>
          <div className={styles.progressFill} style={{ width: `${progress}%` }} />
          <div className={styles.progressScan} />
        </div>
        <span className={styles.progressPct}>{progress}%</span>
      </div>

      {/* Phase steps */}
      <div className={styles.pipeline}>
        {AGENT_PHASES.map((phase, i) => {
          const done   = pipeStep > i;
          const active = pipeStep === i;

          const cls = [
            styles.step,
            done   ? styles.done    : '',
            active ? styles.active  : '',
            !done && !active ? styles.pending : '',
          ].filter(Boolean).join(' ');

          return (
            <div key={phase.id} className={cls}>
              <div className={styles.stepIcon}>
                {done
                  ? <span className={styles.iconDone}>✓</span>
                  : active
                    ? <span className={styles.iconActive} />
                    : <span className={styles.iconPending}>{phase.icon}</span>
                }
              </div>
              <div className={styles.stepInfo}>
                <div className={styles.stepLabel}>{phase.label}</div>
                <div className={styles.stepDesc}>
                  {active ? 'Running...' : done ? 'Completed' : phase.desc}
                </div>
              </div>
              {active && <div className={styles.scanLine} />}
            </div>
          );
        })}
      </div>

      {/* Footer */}
      <div className={styles.footer}>
        <div className={styles.elapsed}>
          <span className={styles.elapsedLabel}>ELAPSED</span>
          <span className={styles.elapsedVal}>{elapsed}s</span>
          <span className={styles.elapsedSep}>·</span>
          <span className={styles.elapsedLabel}>STEP</span>
          <span className={styles.elapsedVal}>{Math.min(pipeStep + 1, total)}/{total}</span>
        </div>
        <p className={styles.note}>LLM inference typically takes 20–60 s. Do not close this tab.</p>
      </div>
    </div>
  );
}
