// src/pages/Investigate/components/LoadingState.jsx
import { useState, useEffect } from 'react';
import { PIPELINE_STEPS } from '../../../constants/scenarios';
import styles from './LoadingState.module.css';

export default function LoadingState({ pipeStep, agentMode, startTime }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const iv = setInterval(() => {
      setElapsed(Math.floor((Date.now() - (startTime || Date.now())) / 1000));
    }, 1000);
    return () => clearInterval(iv);
  }, [startTime]);

  const steps = agentMode ? PIPELINE_STEPS : PIPELINE_STEPS.slice(0, 7);
  const progress = steps.length > 0 ? Math.round((pipeStep / steps.length) * 100) : 0;

  return (
    <div className={styles.container}>
      {/* ── Header ── */}
      <div className={styles.header}>
        <div className={styles.spinnerBlock}>
          <div className={styles.spinner} />
          <div className={styles.spinnerRing} />
          <div className={styles.spinnerCore} />
        </div>
        <div>
          <div className={styles.title}>INVESTIGATION IN PROGRESS</div>
          <div className={styles.sub}>
            Running {steps.length}-stage AI analysis pipeline
            {agentMode && <span className={styles.agentBadge}>AGENT MODE</span>}
          </div>
        </div>
      </div>

      {/* ── Progress bar ── */}
      <div className={styles.progressWrap}>
        <div className={styles.progressTrack}>
          <div className={styles.progressFill} style={{ width: `${progress}%` }} />
          <div className={styles.progressScan} />
        </div>
        <span className={styles.progressPct}>{progress}%</span>
      </div>

      {/* ── Pipeline steps ── */}
      <div className={styles.pipeline}>
        {steps.map((step, i) => {
          const done   = pipeStep > i;
          const active = pipeStep === i;
          const pending = pipeStep < i;
          return (
            <div
              key={step.id}
              className={`${styles.step} ${done ? styles.done : ''} ${active ? styles.active : ''} ${pending ? styles.pending : ''}`}
            >
              {/* Status icon */}
              <div className={styles.stepIcon}>
                {done   && <span className={styles.iconDone}>✓</span>}
                {active && <span className={styles.iconActive} />}
                {pending && <span className={styles.iconPending}>{String(i + 1).padStart(2,'0')}</span>}
              </div>

              {/* Step info */}
              <div className={styles.stepInfo}>
                <div className={styles.stepLabel}>{step.label}</div>
                <div className={styles.stepDesc}>{step.desc}</div>
              </div>

              {/* Active scan line */}
              {active && <div className={styles.scanLine} />}
            </div>
          );
        })}
      </div>

      {/* ── Footer ── */}
      <div className={styles.footer}>
        <div className={styles.elapsed}>
          <span className={styles.elapsedLabel}>ELAPSED</span>
          <span className={styles.elapsedVal}>{elapsed}s</span>
          <span className={styles.elapsedSep}>·</span>
          <span className={styles.elapsedLabel}>STEP</span>
          <span className={styles.elapsedVal}>{Math.min(pipeStep + 1, steps.length)}/{steps.length}</span>
        </div>
        <p className={styles.note}>LLM inference typically takes 20–60 s. Do not close this tab.</p>
      </div>
    </div>
  );
}
