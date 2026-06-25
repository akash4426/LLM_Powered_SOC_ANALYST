// src/components/Topbar/Topbar.jsx
import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Shield, Zap, LayoutDashboard, Search, Database, BarChart2, LogOut } from 'lucide-react';
import styles from './Topbar.module.css';

const NAV_ITEMS = [
  { id: 'dashboard',   label: 'DASHBOARD',   icon: LayoutDashboard },
  { id: 'investigate', label: 'INVESTIGATE',  icon: Search },
  { id: 'ragtest',     label: 'RAG TEST',     icon: Database },
  { id: 'evaluate',   label: 'EVALUATE',     icon: BarChart2 },
];

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
        <span className={styles.version}>v5.0 · LSTM+RAG+LLM+ReAct</span>
      </div>

      <nav className={styles.nav}>
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            className={`${styles.navBtn} ${currentPage === id ? styles.active : ''}`}
            onClick={() => onNavigate(id)}
          >
            <Icon size={11} />
            {label}
          </button>
        ))}
      </nav>

      <div className={styles.right}>
        {/* API Status */}
        <div className={`${styles.statusChip} ${apiOnline ? styles.online : styles.offline}`}>
          <span className={styles.statusDot} />
          {apiOnline ? 'API ONLINE' : 'API OFFLINE'}
        </div>

        {/* User chip */}
        {user && (
          <div className={styles.userChip}>
            <div className={styles.userAvatar}>
              {user.username?.charAt(0).toUpperCase()}
            </div>
            <span>{user.username}</span>
            <button className={styles.logoutBtn} onClick={logout} title="Logout">
              <LogOut size={10} />
            </button>
          </div>
        )}

        <span className={styles.clock}>{clock}</span>
      </div>
    </header>
  );
}
