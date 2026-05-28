// src/pages/Login/Login.jsx
import { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Shield, Lock, User, Zap, AlertCircle } from 'lucide-react';
import styles from './Login.module.css';

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

  return (
    <div className={styles.loginPage}>
      {/* Background grid */}
      <div className={styles.grid} />
      {/* Glows */}
      <div className={styles.glow1} />
      <div className={styles.glow2} />

      <div className={styles.card}>
        {/* Header */}
        <div className={styles.header}>
          <div className={styles.logoWrap}>
            <Shield size={32} strokeWidth={1.5} color="var(--cyan)" />
          </div>
          <h1 className={styles.title}>SOC ANALYST</h1>
          <p className={styles.subtitle}>LLM-Powered Security Operations Center</p>
          <div className={styles.version}>v4.0 · LSTM + RAG + Agent</div>
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
          <div className={styles.demoTitle}>DEMO CREDENTIALS</div>
          <div className={styles.demoRow}><span>analyst</span><span>password123</span></div>
          <div className={styles.demoRow}><span>admin</span><span>admin123</span></div>
          <div className={styles.demoRow}><span>soc_team</span><span>team123</span></div>
        </div>
      </div>
    </div>
  );
}
