// src/components/Topbar/Topbar.jsx
import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Shield, Zap } from 'lucide-react';
import styles from './Topbar.module.css';

export default function Topbar({ currentPage, onNavigate }) {
  const { apiOnline, user, logout } = useAuth();
  const [clock, setClock] = useState('');

  useEffect(() => {
    const tick = () => {
      const now = new Date();
      setClock(now.toTimeString().slice(0, 8));
    };
    tick();
    const iv = setInterval(tick, 1000);
    return () => clearInterval(iv);
  }, []);

  return (
    <header className={styles.topbar}>
      <div className={styles.left}>
        <div className={styles.logo}>
          <div className={styles.logoIcon}>
            <Shield size={14} color="white" strokeWidth={2.5} />
          </div>
          <span className={styles.logoText}>SOC_ANALYST</span>
        </div>
        <span className={styles.sep}>|</span>
        <span className={styles.version}>v4.0 · LSTM+RAG+LLM+Agent</span>
      </div>

      <div className={styles.right}>
        {/* API Status */}
        <div className={`${styles.statusChip} ${apiOnline ? styles.online : styles.offline}`}>
          <span className={styles.statusDot} />
          {apiOnline ? 'API ONLINE' : 'API OFFLINE'}
        </div>

        {/* Nav */}
        <button
          className={`${styles.navBtn} ${currentPage === 'investigate' ? styles.active : ''}`}
          onClick={() => onNavigate('investigate')}
        >INVESTIGATE</button>

        <button
          className={`${styles.navBtn} ${currentPage === 'ragtest' ? styles.active : ''}`}
          onClick={() => onNavigate('ragtest')}
        >RAG TEST</button>


        {/* User chip */}
        {user && (
          <div className={styles.userChip} onClick={logout} title="Click to logout">
            <div className={styles.userAvatar}>
              {user.username?.charAt(0).toUpperCase()}
            </div>
            {user.username}
          </div>
        )}

        <span className={styles.clock}>{clock}</span>
      </div>
    </header>
  );
}
