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

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.spinnerBlock}>
          <div className={styles.spinner} />
          <div className={styles.spinnerRing} />
        </div>
        <div>
          <div className={styles.title}>INVESTIGATION IN PROGRESS</div>
          <div className={styles.sub}>Running {steps.length}-stage analysis pipeline…</div>
        </div>
      </div>

      <div className={styles.pipeline}>
        {steps.map((step, i) => {
          const done = pipeStep > i;
          const active = pipeStep === i;
          return (
            <div
              key={step.id}
              className={`${styles.step} ${done ? styles.done : ''} ${active ? styles.active : ''}`}
              style={{ animationDelay: `${i * 0.05}s` }}
            >
              <div className={styles.stepNum}>{String(i + 1).padStart(2, '0')}</div>
              <div className={styles.stepInfo}>
                <div className={styles.stepLabel}>{step.label}</div>
                <div className={styles.stepDesc}>{step.desc}</div>
              </div>
              <div className={styles.stepStatus}>
                {done ? '✓' : active ? <span className={styles.activeDot} /> : '○'}
              </div>
            </div>
          );
        })}
      </div>

      <div className={styles.footer}>
        <div className={styles.elapsed}>
          <span className={styles.elapsedLabel}>ELAPSED</span>
          <span className={styles.elapsedVal}>{elapsed}s</span>
        </div>
        <p className={styles.note}>LLM inference typically takes 20–60 seconds. Do not close this tab.</p>
      </div>
    </div>
  );
}
