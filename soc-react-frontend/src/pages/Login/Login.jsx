// src/pages/Login/Login.jsx
import { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Shield, Lock, User, Zap, AlertCircle, Brain, Database, Activity } from 'lucide-react';
import styles from './Login.module.css';

const FEATURES = [
  { icon: Brain,    label: 'LSTM Anomaly Detection', color: 'var(--cyan)' },
  { icon: Database, label: 'MITRE ATT&CK RAG',       color: 'var(--blue)' },
  { icon: Activity, label: 'ReAct Agent Reasoning',  color: 'var(--purple)' },
  { icon: Shield,   label: 'JWT Authentication',     color: 'var(--green)' },
];

export default function Login() {
  const { login, apiOnline } = useAuth();
  const [username, setUsername] = useState('analyst');
  const [password, setPassword] = useState('password123');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username, password);
    } catch (err) {
      setError(err?.response?.data?.detail || 'Authentication failed. Check credentials.');
    } finally {
      setLoading(false);
    }
  };

  const fillCreds = (u, p) => { setUsername(u); setPassword(p); };

  return (
    <div className={styles.loginPage}>
      {/* Background grid */}
      <div className={styles.grid} />
      {/* Glows */}
      <div className={styles.glow1} />
      <div className={styles.glow2} />

      {/* Left side — feature panel */}
      <div className={styles.featurePanel}>
        <div className={styles.fpLogo}>
          <Shield size={40} strokeWidth={1.5} color="var(--cyan)" />
          <div className={styles.fpOrbRing} />
        </div>
        <div className={styles.fpTitle}>LLM-Powered SOC Analyst</div>
        <div className={styles.fpSub}>AI-driven security investigation platform with multi-agent reasoning</div>
        <div className={styles.fpFeatures}>
          {FEATURES.map(({ icon: Icon, label, color }) => (
            <div key={label} className={styles.fpFeature}>
              <div className={styles.fpFeatureIcon} style={{ background: `${color}15`, border: `1px solid ${color}25` }}>
                <Icon size={14} color={color} />
              </div>
              <span className={styles.fpFeatureLabel}>{label}</span>
            </div>
          ))}
        </div>
        <div className={styles.fpStats}>
          {[['10', 'Pipeline Stages'], ['6', 'AI Agents'], ['500+', 'MITRE Techniques'], ['7', 'Attack Campaigns']].map(([v, l]) => (
            <div key={l} className={styles.fpStat}>
              <div className={styles.fpStatVal}>{v}</div>
              <div className={styles.fpStatLabel}>{l}</div>
            </div>
          ))}
        </div>
      </div>

      <div className={styles.card}>
        {/* Header */}
        <div className={styles.header}>
          <div className={styles.logoWrap}>
            <Shield size={32} strokeWidth={1.5} color="var(--cyan)" />
          </div>
          <h1 className={styles.title}>SOC ANALYST</h1>
          <p className={styles.subtitle}>LLM-Powered Security Operations Center</p>
          <div className={styles.version}>v5.0 · LSTM + RAG + LLM + ReAct Agent</div>
        </div>

        {/* API Status */}
        <div className={`${styles.apiStatus} ${apiOnline ? styles.online : styles.offline}`}>
          <Zap size={12} />
          {apiOnline ? 'API Server Online — Ready for authentication' : 'API Server Offline — Start backend on port 8000'}
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className={styles.form}>
          <div className={styles.field}>
            <label className={styles.label}>USERNAME</label>
            <div className={styles.inputWrap}>
              <User size={14} className={styles.inputIcon} />
              <input
                id="username"
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className={styles.input}
                placeholder="analyst"
                autoComplete="username"
              />
            </div>
          </div>

          <div className={styles.field}>
            <label className={styles.label}>PASSWORD</label>
            <div className={styles.inputWrap}>
              <Lock size={14} className={styles.inputIcon} />
              <input
                id="password"
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className={styles.input}
                placeholder="••••••••••"
                autoComplete="current-password"
              />
            </div>
          </div>

          {error && (
            <div className={styles.error}>
              <AlertCircle size={13} />
              {error}
            </div>
          )}

          <button type="submit" className={styles.submitBtn} disabled={loading}>
            {loading ? (
              <>
                <span className={styles.spinner} />
                AUTHENTICATING…
              </>
            ) : (
              <>
                <Shield size={14} />
                AUTHENTICATE
              </>
            )}
          </button>
        </form>

        {/* Demo credentials */}
        <div className={styles.demoBlock}>
          <div className={styles.demoTitle}>DEMO CREDENTIALS — click to fill</div>
          {[['analyst', 'password123'], ['admin', 'admin123'], ['soc_team', 'team123']].map(([u, p]) => (
            <div key={u} className={styles.demoRow} onClick={() => fillCreds(u, p)}>
              <span>{u}</span><span>{p}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

