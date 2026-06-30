import React from 'react';
import { AGENT_PHASES } from '../../../constants/scenarios';
import styles from './AgentPhaseTracker.module.css';
import { Check, Loader, Circle } from 'lucide-react';

export default function AgentPhaseTracker({ currentStep }) {
  return (
    <div className={styles.trackerContainer}>
      <div className={styles.trackerTitle}>Agent Orchestration Phases</div>
      <div className={styles.phaseList}>
        {AGENT_PHASES.map((phase, idx) => {
          const isCompleted = currentStep > idx;
          const isActive    = currentStep === idx;

          return (
            <div
              key={phase.id}
              className={`${styles.phaseItem} ${isActive ? styles.active : ''} ${isCompleted ? styles.completed : ''}`}
            >
              <div className={styles.iconBox}>
                {isCompleted
                  ? <Check size={12} />
                  : isActive
                    ? <Loader size={12} className={styles.spin} />
                    : <span>{phase.icon}</span>
                }
              </div>
              <div className={styles.phaseDetails}>
                <div className={styles.phaseHeader}>
                  <span className={styles.phaseLabel}>{phase.label}</span>
                </div>
                <div className={styles.phaseDesc}>{phase.desc}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
